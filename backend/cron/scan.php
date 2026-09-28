<?php
/**
 * Sentinel Gate - Background Scan Runner
 * Called by Scanner::startScan() as a background process:
 *   nice -nX php backend/cron/scan.php --job-id=N --path=/home
 * Called by cron jobs:
 *   php backend/cron/scan.php quick|full|update-sigs
 */
error_reporting(E_ERROR);
ini_set('display_errors', '0');
set_time_limit(0);
ignore_user_abort(true);

require_once __DIR__ . '/../config/config.php';
require_once SG_ROOT . '/backend/lib/Database.php';
require_once SG_ROOT . '/backend/lib/Logger.php';
require_once SG_ROOT . '/backend/lib/Scanner.php';
require_once SG_ROOT . '/backend/lib/License.php';

// ── License gate ─────────────────────────────────────────────────────────────
// Scheduled scans never touch the API, so they must be gated here or an
// unlicensed server would keep receiving scans indefinitely via cron.
// publishFlag() also refreshes the flag monitor.py reads — this cron is the
// most reliable place to keep that fresh, since it runs hourly regardless of
// whether anyone opens the dashboard.
License::publishFlag();
License::requireValid('Scheduled scanning');

$jobId    = null;
$scanPath = null;
$scanType = 'quick';
$runMode  = 'job';

foreach (array_slice($argv, 1) as $arg) {
    if (preg_match('/^--job-id=(\d+)$/', $arg, $m)) {
        $jobId = (int) $m[1]; $runMode = 'job';
    } elseif (preg_match('/^--path=(.+)$/', $arg, $m)) {
        $scanPath = $m[1];
    } elseif ($arg === 'update-sigs') {
        $runMode = 'update-sigs';
    } elseif (in_array($arg, ['quick', 'full'], true)) {
        $runMode = 'cron'; $scanType = $arg;
    }
}

$scanner = new Scanner();

if ($runMode === 'update-sigs') {
    Logger::info('Cron: Updating ClamAV signatures');
    $t = microtime(true);
    $r = $scanner->updateSignatures();
    Database::insert('cron_log', [
        'job_name'=>'update-sigs','status'=>'ok',
        'message'=>$r['clam']??'',
        'duration_ms'=>(int)((microtime(true)-$t)*1000),'ran_at'=>time()
    ]);
    Logger::info('Cron: Signature update complete');
    exit(0);
}

if ($runMode === 'cron') {
    $raw      = Database::setting('scan_paths', '/home') ?? '/home';
    $scanPath = trim(explode(',', $raw)[0]);
    $jobId    = Database::insert('scan_jobs', [
        'scan_type'=>$scanType,'status'=>'running',
        'started_at'=>time(),'scan_path'=>$scanPath
    ]);
    Logger::info("Cron: Created $scanType scan job $jobId on $scanPath");
}

if ($jobId === null) {
    Logger::error('scan.php: no --job-id and no cron mode');
    exit(1);
}

$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$jobId]);
if (!$job) {
    Logger::error("scan.php: job $jobId not found");
    exit(1);
}
if ($scanPath === null) $scanPath = $job['scan_path'] ?? '/home';

// ── One scan at a time, enforced by the filesystem ──────────────────────────
//
// The guard in Scanner::startScan() covers the callers it knows about. This
// covers everything else: a cron entry firing while a manual scan runs, two
// cron entries installed by two upgrades, an operator running this by hand.
// The lock is held by the kernel for as long as this process lives, so it
// cannot be left behind by a worker that is killed.
//
// Several clamscan processes at once is not merely slower. Each one loads the
// entire ClamAV signature database into its own memory -- close to a gigabyte
// apiece -- so N scans cost N copies of the same data and N processes
// competing for the same disks.
if (!is_dir(SG_TMP)) { @mkdir(SG_TMP, 0750, true); }
$lockPath = SG_TMP . '/scan.lock';
$lockFh   = @fopen($lockPath, 'c');
if ($lockFh === false) {
    Logger::error('scan.php: cannot open ' . $lockPath . ' - refusing to run unguarded');
    exit(1);
}
if (!@flock($lockFh, LOCK_EX | LOCK_NB)) {
    Logger::warn('scan.php: another scan holds the lock - exiting without starting one');
    // Not an error: declining to pile a second scan onto the server is the
    // correct outcome, and a cron that reports failure for it would page
    // somebody every night.
    if ($jobId !== null) {
        Database::query(
            "UPDATE scan_jobs SET status='skipped', finished_at=? WHERE id=?",
            [time(), $jobId]
        );
    }
    exit(0);
}
// Kept in a global purely so the handle is not garbage collected: closing it
// releases the lock.
$GLOBALS['__sg_scan_lock'] = $lockFh;
@ftruncate($lockFh, 0);
@fwrite($lockFh, (string) getmypid());
@fflush($lockFh);

// Detach into a process group of our own, and record it.
//
// The worker forks clamscan once per batch. Killing the worker alone leaves the
// clamscan it is currently waiting on running -- which is exactly what was
// reported: the scan was stopped and clamscan kept going. Owning a process
// group means one signal reaches the worker and every child it has spawned.
$workerPid  = getmypid();
$ownGroup   = false;
if (function_exists('posix_setsid')) {
    $ownGroup = @posix_setsid() !== false;
}

// Record the group ONLY when this process leads it.
//
// posix_setsid() fails when the process is already a group leader, and the
// previous version fell back to whatever posix_getpgid(0) returned. That is
// the group of whatever launched us -- cpsrvd, or php-fpm. Storing it would
// have pointed stopScan() at a group full of other people's processes, and
// stopping a scan would have sent SIGTERM to the web server. Recording
// nothing is safe: the worker pid is still there to signal, and the batch
// loop still honours the cancel flag.
$workerPgid = 0;
if ($ownGroup && function_exists('posix_getpgid')) {
    $pgid = @posix_getpgid(0);
    if ($pgid && (int) $pgid === (int) $workerPid) {
        $workerPgid = (int) $pgid;
    }
}
if (!$ownGroup) {
    Logger::warn('scan.php: could not detach into its own process group; '
               . 'stopping this scan will signal the worker only');
}

Database::query(
    'UPDATE scan_jobs SET worker_pid=?, worker_pgid=? WHERE id=?',
    [$workerPid, $workerPgid, $jobId]
);

Logger::info("scan.php: Starting job $jobId ({$job['scan_type']}) on $scanPath"
           . " (pid $workerPid, pgid $workerPgid)");
$t = microtime(true);

try {
    // One worker covers every configured path.
    //
    // The scheduler used to call startScan() once per path, in a loop, each
    // spawning its own detached worker -- so a server with three scan paths
    // ran three scans, and three clamscans, simultaneously and by design.
    $paths = array_values(array_filter(array_map('trim', explode(',', (string) $scanPath))));
    if (!$paths) { $paths = ['/home']; }

    $threats = [];
    foreach ($paths as $one) {
        if (!is_dir($one)) {
            Logger::warn("scan.php: job $jobId skipping missing path $one");
            continue;
        }
        $threats = array_merge($threats, $scanner->runClamScan($one, $jobId));
        // Stopping must take effect between paths as well as between batches.
        if (Scanner::isCancelled($jobId)) {
            Logger::info("scan.php: job $jobId cancelled, skipping remaining path(s)");
            break;
        }
    }
    $ms      = (int)((microtime(true)-$t)*1000);

    // files_scanned is written incrementally by the scan itself. It used to be
    // overwritten here with countFiles($scanPath) -- a fresh directory walk
    // performed AFTER the scan, which counted what was present rather than what
    // was examined, and only ever appeared once the job had already finished.
    $row   = Database::fetchOne('SELECT files_scanned FROM scan_jobs WHERE id=?', [$jobId]);
    $files = (int)($row['files_scanned'] ?? 0);

    // A cancelled scan stops mid-way and returns what it found so far. Writing
    // 'done' over that would report a partial scan as a complete one -- the
    // operator would believe the tree had been examined when most of it had
    // not.
    $final = Database::fetchOne('SELECT status FROM scan_jobs WHERE id=?', [$jobId]);
    $wasCancelled = in_array($final['status'] ?? '', ['cancelling', 'cancelled'], true);

    Database::query(
        'UPDATE scan_jobs SET status=?,finished_at=?,threats_found=? WHERE id=?',
        [$wasCancelled ? 'cancelled' : 'done', time(), count($threats), $jobId]
    );
    Database::setSetting('last_scan', (string)time());

    $msg = count($threats) . " threat(s) found in $files files";
    Logger::info("scan.php: Job $jobId done -- $msg ({$ms}ms)");
    Database::insert('cron_log', [
        'job_name'=>"scan_$jobId",'status'=>'ok',
        'message'=>$msg,'duration_ms'=>$ms,'ran_at'=>time()
    ]);
} catch (Throwable $e) {
    Logger::error("scan.php: Job $jobId failed -- " . $e->getMessage());
    Database::query('UPDATE scan_jobs SET status=?,finished_at=? WHERE id=?',['error',time(),$jobId]);
    Database::insert('cron_log', [
        'job_name'=>"scan_$jobId",'status'=>'error',
        'message'=>$e->getMessage(),
        'duration_ms'=>(int)((microtime(true)-$t)*1000),'ran_at'=>time()
    ]);
    exit(1);
}
exit(0);

function countFiles(string $path): int {
    $c = 0;
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($it as $f) if ($f->isFile()) $c++;
    } catch (Exception $e) {}
    return $c;
}
