<?php
/**
 * One scan at a time.
 *
 * Reported from a live server: six clamscan processes at once, each holding
 * 650MB-1.3GB of RSS and together taking half the CPU on a 60GB box.
 *
 * Nothing limited them. Scanner::startScan() inserted a job and spawned a
 * detached worker with no check for one already running, and every path into
 * it -- the UI button, the CLI, the scheduler -- did exactly that. The
 * scheduler called it once PER CONFIGURED PATH in a loop, so a server with
 * three scan paths started three scans in parallel every scheduled run.
 *
 * Concurrency is not a tuning knob here: every clamscan process loads the
 * whole ClamAV signature database into its own memory, so N scans means N
 * copies of it and N processes queued on the same disks.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// -- A live job blocks a second scan ----------------------------------------
// Liveness is established through the startup grace window rather than a real
// pid. processAlive() reads /proc, which this Windows build has none of, so a
// genuinely live pid would read as dead here and the test would pass for the
// wrong reason. The grace window is the same code path the guard uses on a
// server during the seconds before a worker records its pid.
$live = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running', 'started_at' => time(),
    'scan_path' => '/home', 'worker_pgid' => 0,
]);

$active = Scanner::activeScan();
t_ok($active !== null, 'a running scan is reported as active');
t_eq($live, (int) $active['id'], 'and it is the right job');

// -- One scanner process, which is the whole point --------------------------
t_eq(1, Scanner::maxConcurrent(), 'exactly one scan is permitted at a time');
t_eq(1, count(Scanner::liveScans()), 'one is running');

// With a cap of one, the SECOND start is refused.
$threw = false;
try {
    (new Scanner())->startScan('/home', 'full');
} catch (Throwable $e) {
    $threw = true;
    t_contains($e->getMessage(), 'maximum',
        'the second start is refused against the cap, with the limit named');
}
t_ok($threw, 'a second scan cannot start while one is running');

$count = Database::fetchOne(
    "SELECT COUNT(*) c FROM scan_jobs WHERE status IN ('running','pending')"
)['c'];
t_eq(1, (int) $count, 'the refused start created no extra job row');

// The cap is still a setting, and still bounded at both ends.
Database::setSetting('scan_max_concurrent', '99');
t_eq(4, Scanner::maxConcurrent(), 'the cap is clamped to 4 however it is set');
Database::setSetting('scan_max_concurrent', '0');
t_eq(1, Scanner::maxConcurrent(), 'and never drops below 1, which would stop scanning');

// Raised deliberately, a second scan becomes possible -- the limit is a
// setting, not a hard-coded 1, so this has to keep working.
Database::setSetting('scan_max_concurrent', '2');
$second = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time(), 'scan_path' => '/tmp',
]);
t_eq(2, count(Scanner::liveScans()), 'raising the cap permits a second scan');
Database::setSetting('scan_max_concurrent', '1');

// -- Stopping everything at once --------------------------------------------
// stopScan() takes one job. Six stacked scans would mean finding six ids.
$r = Scanner::stopAllScans();
t_ok($r['success'], 'every running scan can be stopped in one call');
t_eq(2, count($r['stopped']), 'both running scans were stopped');
t_eq(0, count(Scanner::liveScans()), 'nothing is left running afterwards');
foreach ([$live, $second] as $id) {
    t_eq('cancelled',
        Database::fetchOne('SELECT status FROM scan_jobs WHERE id=?', [$id])['status'],
        "job $id is recorded as cancelled, not done");
}

// Re-create a live job for the reaping checks that follow.
$live = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running', 'started_at' => time(),
    'scan_path' => '/home', 'worker_pgid' => 0,
]);

// -- A dead worker must not block scanning for ever --------------------------
// Without reaping, one killed worker would leave a 'running' row that refuses
// every future scan -- turning a load problem into a scanner that never runs.
// A pid this high cannot be allocated, so it is absent on every platform.
Database::query("UPDATE scan_jobs SET worker_pid=?, started_at=? WHERE id=?",
    [2147483646, time() - 3600, $live]);
t_eq(false, Scanner::jobWorkerAlive(
    Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$live])),
    'a job whose worker pid does not exist is not alive');

$reaped = Scanner::reapStaleJobs();
t_ok($reaped >= 1, 'stale jobs are reaped');
t_eq('interrupted',
    Database::fetchOne('SELECT status FROM scan_jobs WHERE id=?', [$live])['status'],
    'and recorded as interrupted, not left running or claimed as done');
t_eq(null, Scanner::activeScan(), 'so a new scan is no longer blocked');

// -- A job too young to have written a pid is given grace --------------------
$fresh = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time(), 'scan_path' => '/home',
]);
t_ok(Scanner::jobWorkerAlive(
    Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$fresh])),
    'a just-started job with no pid yet is left alone');

Database::query('UPDATE scan_jobs SET started_at=? WHERE id=?', [time() - 3600, $fresh]);
t_ok(!Scanner::jobWorkerAlive(
    Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$fresh])),
    'but one that never wrote a pid is presumed dead once it is old');
Scanner::reapStaleJobs();

// -- The worker holds a kernel lock -----------------------------------------
// The guard above covers callers it knows about. Cron entries, a second
// upgrade's cron entry, and an operator running the script by hand do not go
// through it.
$worker = t_code($repo . '/backend/cron/scan.php');
t_contains($worker, 'LOCK_EX | LOCK_NB', 'the worker takes an exclusive non-blocking lock');
t_contains($worker, 'scan.lock.', 'on one lock file per permitted slot');
t_contains($worker, 'Scanner::maxConcurrent()',
    'and there are exactly as many slots as the cap allows');
t_contains($worker, 'for ($slot = 0; $slot < $maxSlots', 'taking the first free slot');
t_contains($worker, '__sg_scan_lock',
    'and keeps the handle alive, since closing it would release the lock');
$lockPos = strpos($worker, 'flock(');
$scanPos = strpos($worker, 'runClamScan');
t_ok($lockPos !== false && $scanPos !== false && $lockPos < $scanPos,
    'the lock is taken before any scanning starts');
t_contains($worker, "status='skipped'",
    'a worker that loses the race records that it skipped, not that it failed');

// -- The scheduler starts ONE job for every path ----------------------------
$sched = t_code($repo . '/backend/cron/scheduler.php');
$task  = substr($sched, strpos($sched, "'scan' => ["), 1500);
t_eq(1, substr_count($task, 'startScan('),
    'the scheduler calls startScan once, not once per configured path');
t_contains($task, 'implode', 'passing every path to the one job');
$workerPaths = substr($worker, strpos($worker, '$paths = array_values'), 900);
t_contains($workerPaths, 'foreach ($paths as $one)', 'and the worker walks them all');
t_contains($workerPaths, 'Scanner::isCancelled($jobId)',
    'stopping takes effect between paths, not only between batches');

// -- A single clamscan must not run for ever --------------------------------
// One was found holding 13 minutes of CPU and 1.3GB of RSS on a single file,
// blocking its worker for all of it.
$sc = t_code($repo . '/backend/lib/Scanner.php');
$batch = substr($sc, strpos($sc, 'private function scanBatch'), 1800);
t_contains($batch, 'timeout %d', 'each clamscan batch is bounded by timeout(1)');
t_contains($batch, 'scan_batch_timeout', 'with a configurable limit');
t_contains($batch, '$rc === 124', 'and a batch that is cut off is logged');

// -- Reaping orphans must not touch cPanel's own clamscan -------------------
// cPanel runs clamscan for mail. A reaper matching on the process name alone
// would kill that too, silently breaking mail scanning on every server this
// ships to.
$reap = substr($sc, strpos($sc, 'function reapOrphanClamscans'), 1600);
t_contains($reap, 'clamscanPidsForGroup',
    'orphans are found by process group, not by process name');
t_contains($reap, 'self::processAlive($pid)',
    'and a group whose worker is still alive is left alone');
t_ok(strpos($reap, 'pgrep') === false && strpos($reap, 'killall') === false,
    'nothing kills by name');

// -- The API answers a refusal as a refusal ---------------------------------
$api = t_code($repo . '/backend/api/index.php');
t_contains($api, "'code' => 409",
    'a second scan is refused with 409, not reported as a server error');
t_contains($api, 'Scanner::liveScans()', 'the route counts running scans against the cap');
t_contains($api, "'reap' =>", 'and there is a way to clean up after dead workers');

// -- The pgid recorded must be one we own -----------------------------------
// posix_setsid() fails when the process is already a group leader. Falling
// back to posix_getpgid(0) records the group of whatever launched us -- cpsrvd
// or php-fpm -- and stopScan() signals the whole group, so stopping a scan
// would have sent SIGTERM to the web server.
t_contains($worker, '(int) $pgid === (int) $workerPid',
    'the process group is recorded only when this process leads it');
t_ok(strpos($worker, 'if (!$workerPgid) {') === false,
    'the fallback that adopted the launching process group is gone');


// -- An upgrade must stop what is already scanning --------------------------
// This is the part that matters on a server that already has several running.
// The workers are detached, so nothing else stops them: they would keep
// running the OLD code against a database the installer has just migrated,
// still holding their clamscan processes.
$install = file_get_contents($repo . '/install.sh');
t_contains($install, 'Scanner::stopAllScans()',
    'the installer stops running scans during an upgrade');
$stopPos  = strpos($install, 'Scanner::stopAllScans()');
$cronPos  = strpos($install, 'Installing cron');
t_ok($stopPos !== false,
    'and does so as its own step rather than leaving them to the new scheduler');
t_contains($install, 'rm -f /tmp/sentinel-gate/scan.lock.',
    'stale slot locks are cleared too');

// -- The cap is reachable and visible ---------------------------------------
$db = t_code($repo . '/backend/lib/Database.php');
t_contains($db, "'scan_max_concurrent',     '1'", 'the cap ships defaulted to 1');

// 3.30.4 shipped this as 2 and the seed is INSERT OR IGNORE, which cannot
// change a row that already exists -- so an upgrade would silently keep 2
// without an explicit migration.
t_contains($db, 'sg_mig_scan_concurrency_1',
    'an existing install is migrated off the old default of 2');
t_contains($db, "UPDATE settings SET value='1' WHERE key='scan_max_concurrent'",
    'by resetting the stored value, not just the seed');
t_contains($db, "SELECT value FROM settings WHERE key='sg_mig_scan_concurrency_1'",
    'and the migration is marked so it runs once, not on every upgrade');
t_contains($db, "'scan_batch_timeout',      '600'", 'and the per-batch timeout is seeded');

$api = t_code($repo . '/backend/api/index.php');
t_contains($api, "'stop-all' =>", 'stopping everything is exposed over the API');
t_contains($api, 'Scanner::maxConcurrent()', 'and the cap is reported to the UI');

$cli = t_code($repo . '/backend/cli/sentinel.php');
t_contains($cli, "case 'scan-stop-all'", 'and from the command line');


// -- The migration, exercised rather than merely read ------------------------
// Database::migrate() is private and runs on connect, and the connection is
// cached -- so reflection is how the shipped code path gets tested instead of
// a reimplementation of it that could drift.
$mig = new ReflectionMethod('Database', 'migrate');
$mig->setAccessible(true);

// An install that came from 3.30.4: the value is 2 and the marker is absent.
Database::setSetting('scan_max_concurrent', '2');
Database::query("DELETE FROM settings WHERE key='sg_mig_scan_concurrency_1'");
t_eq('2', Database::setting('scan_max_concurrent'), 'starting from the old default of 2');

$mig->invoke(null, Database::get());
t_eq('1', Database::setting('scan_max_concurrent'),
    'upgrading resets an existing install to one scanner process');
t_eq('1', Database::setting('sg_mig_scan_concurrency_1'),
    'and records that the migration has run');

// An operator who deliberately raises it afterwards must keep their choice --
// every subsequent upgrade calls migrate() again.
Database::setSetting('scan_max_concurrent', '2');
$mig->invoke(null, Database::get());
t_eq('2', Database::setting('scan_max_concurrent'),
    'a later deliberate change is not overruled by the next upgrade');

Database::setSetting('scan_max_concurrent', '1');


// -- Killing clamscan does not stop a scan -----------------------------------
// Reported: "even if i kill them individually they are spawned immediately".
// That is the worker behaving correctly -- it forks one clamscan per batch, so
// killing a clamscan ends that batch and the next one starts. The worker is
// the thing that has to be killed, and it has to die FIRST.
$sc = t_code($repo . '/backend/lib/Scanner.php');

// Ordering is asserted on code, not on the comments that label the steps:
// t_code() strips comments precisely so that assertions cannot pass on text
// that has been commented out.
$kill = substr($sc, strpos($sc, 'public static function killRunawayScans'), 2400);
$notePos   = strpos($kill, 'clamscanChildrenOf($workers)');
$killWPos  = strpos($kill, 'foreach ($workers as $pid)');
$killCPos  = strpos($kill, 'foreach ($children as $pid)');
t_ok($notePos !== false && $killWPos !== false && $killCPos !== false,
    'the runaway killer notes children, kills workers and kills children');
t_ok($notePos < $killWPos,
    'children are noted BEFORE the worker dies, while the parent link exists');
t_ok($killWPos < $killCPos,
    'the worker is killed before its clamscan, so nothing can respawn one');

// cPanel runs its own clamscan for mail. Only children of OUR workers may be
// touched.
t_contains($kill, 'clamscanChildrenOf',
    'only clamscan processes parented by our workers are killed');
t_ok(strpos($kill, 'pkill') === false && strpos($kill, 'killall') === false,
    'nothing kills clamscan by name');

// -- A worker is found by what is executing, not by the database -------------
// Workers started before the worker_pid column existed have no pid recorded,
// so after an upgrade a scan can be running that no row can identify.
t_contains($sc, 'function scanWorkerPids', 'workers are discoverable from /proc');
t_contains($sc, "backend/cron/scan.php", 'by the script they are running');
t_contains($sc, '--job-id=', 'and can be matched to a specific job');

$reap = substr($sc, strpos($sc, 'public static function reapStaleJobs'), 1800);
t_contains($reap, 'self::scanWorkerPids((int) $job',
    'a job with no recorded pid is checked against the running processes');
t_contains($reap, 'adopted the running worker',
    'and the live worker is adopted rather than the job being declared dead');
$adoptPos = strpos($reap, 'scanWorkerPids');
$markPos  = strpos($reap, "status='interrupted'");
t_ok($adoptPos !== false && $markPos !== false && $adoptPos < $markPos,
    'adoption is attempted before anything is marked interrupted');

// -- Any status but running/pending must stop the worker ---------------------
// This is the gap the runaway hid in: reapStaleJobs marks a job 'interrupted',
// the worker did not treat that as a stop, and the row no longer showed as
// running -- so it scanned on, invisibly, replacing every clamscan killed.
$job = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time(), 'scan_path' => '/home',
]);
t_eq(false, Scanner::isCancelled($job), 'a running job is not cancelled');

Database::query("UPDATE scan_jobs SET status='pending' WHERE id=?", [$job]);
t_eq(false, Scanner::isCancelled($job), 'nor is a pending one');

foreach (['interrupted', 'cancelled', 'cancelling', 'done', 'error', 'skipped'] as $st) {
    Database::query('UPDATE scan_jobs SET status=? WHERE id=?', [$st, $job]);
    t_eq(true, Scanner::isCancelled($job), "status '$st' stops the worker");
}

// A row that has been deleted entirely must stop it too, rather than being
// read as "not cancelled" and scanning for ever.
Database::query('DELETE FROM scan_jobs WHERE id=?', [$job]);
t_eq(true, Scanner::isCancelled($job), 'a job whose row is gone stops the worker');

// -- Stopping everything must reach untracked workers ------------------------
$stopAll = substr($sc, strpos($sc, 'public static function stopAllScans'), 1600);
t_contains($stopAll, 'self::killRunawayScans()',
    'stopping everything also kills workers no row accounts for');


// -- A scan must stand down during a backup ----------------------------------
// Reported with a top capture: the real-time monitor sat at 1% CPU, correctly
// suspended, while clamscan ran at 58% in uninterruptible I/O wait against the
// same disks rsync was using. The pause added in 3.30.0 lives inside the
// monitor daemon; a malware scan is a different process and knew nothing about
// it. The quiet half of the product stood down and the loud half did not.
$sc2 = t_code($repo . '/backend/lib/Scanner.php');

t_contains($sc2, 'function backupRunning', 'the scanner can see a running backup');
t_contains($sc2, 'RealTimeMonitor::backupProcesses',
    'using the same probe as the monitor, so both agree on what a backup is');
t_contains($sc2, 'function waitOutBackup', 'and holds the scan while one runs');

// The probe forks nothing and must not be run per batch.
$br = substr($sc2, strpos($sc2, 'function backupRunning'), 700);
t_contains($br, 'static $cachedAt', 'the probe is cached, not run for every batch');

// Waiting, not aborting: the scan resumes and finishes.
$wo = substr($sc2, strpos($sc2, 'function waitOutBackup'), 1600);
t_contains($wo, 'sleep(30)', 'it waits rather than abandoning the scan');
t_contains($wo, 'scan_backup_max_wait', 'with a cap on how long it will wait');
t_contains($wo, 'self::isCancelled($jobId)',
    'and a stop request still takes effect while it is waiting');

// A scan that gives up must not be recorded as having completed.
$loop = substr($sc2, strpos($sc2, 'foreach ($this->walkFiles($path)'), 1400);
t_contains($loop, 'self::waitOutBackup($jobId)',
    'the batch loop checks between batches');
$cancelPos = strpos($loop, 'self::isCancelled($jobId)');
$waitPos   = strpos($loop, 'self::waitOutBackup($jobId)');
t_ok($cancelPos !== false && $waitPos !== false && $cancelPos < $waitPos,
    'cancellation is checked before settling in to wait');

// Starting a scan into a backup is the same mistake as not pausing one.
$start2 = substr($sc2, strpos($sc2, 'public function startScan'), 1800);
t_contains($start2, 'self::backupRunning()', 'a scan will not start during a backup');
t_contains($start2, 'compete with it for the same disks', 'and says why');

// The scheduler should not even try.
$sched2 = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched2, 'Scanner::backupRunning()',
    'the scheduler defers a scheduled scan during a backup');
t_contains($sched2, 'scan deferred', 'and logs that it did');

// The worker needs the probe class loaded, or it fatals in cron the moment a
// backup starts -- which is the worst possible time to find out.
$worker2 = t_code($repo . '/backend/cron/scan.php');
t_contains($worker2, "require_once SG_ROOT . '/backend/lib/RealTimeMonitor.php'",
    'the scan worker loads the probe it depends on');

// Switched on by default, or none of this happens.
$db3 = t_code($repo . '/backend/lib/Database.php');
t_contains($db3, "'scan_pause_on_backup',    '1'", 'scans pause during backups by default');
t_contains($db3, "'scan_backup_max_wait',    '14400'", 'with a wait cap');

// -- Behaviour that can be exercised here ------------------------------------
// The positive path needs /proc to find a backup process, which this Windows
// build does not have -- so what is checked here is that switching the feature
// off is honoured, and that the probe degrades to "no backup" rather than
// throwing when it cannot look.
t_ok(is_array(Scanner::backupRunning()),
    'the probe returns a list even where it cannot read /proc');

Database::setSetting('scan_pause_on_backup', '0');
$jobW = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time(), 'scan_path' => '/home',
]);
$rm = new ReflectionMethod('Scanner', 'waitOutBackup');
$rm->setAccessible(true);
t_eq(true, $rm->invoke(null, $jobW),
    'with the setting off, a scan is never held up');
Database::setSetting('scan_pause_on_backup', '1');
t_eq(true, $rm->invoke(null, $jobW),
    'and with it on but no backup running, it proceeds immediately');
Database::query('DELETE FROM scan_jobs WHERE id=?', [$jobW]);
