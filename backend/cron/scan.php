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

Logger::info("scan.php: Starting job $jobId ({$job['scan_type']}) on $scanPath");
$t = microtime(true);

try {
    $threats = $scanner->runClamScan($scanPath, $jobId);
    $files   = countFiles($scanPath);
    $ms      = (int)((microtime(true)-$t)*1000);

    Database::query(
        'UPDATE scan_jobs SET status=?,finished_at=?,files_scanned=?,threats_found=? WHERE id=?',
        ['done', time(), $files, count($threats), $jobId]
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
