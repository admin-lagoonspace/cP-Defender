<?php
/**
 * SHAKAAL PROBE — does the 5-second procSnapshot() cache let a reconciliation
 * pass declare a HEALTHY, JUST-STARTED scan dead?
 *
 * Reproduces the scheduler's own timeline inside ONE php process, on real /proc:
 *   t0   a reconcile pass takes a snapshot         (scheduler.php:981)
 *   t0+  a scan starts and its worker writes a pid (the 'scan' task)
 *   t0+n a later task calls liveScans() again      (scheduler.php:688)
 * If n < 5s the second pass reads the t0 snapshot, which predates the worker.
 */
$BASE = '/usr/local/serverscrub/backend';
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/Scanner.php';

function out($s) { echo $s . PHP_EOL; }

function spawn_worker(int $jobId): int {
    $cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id="
         . $jobId . " --path=/home' php -r 'sleep(120);' >/dev/null 2>&1 & echo \$!";
    return (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
}

out('--- probe: stale snapshot vs a brand new worker ---');

// t0: the tick's reconcile pass. Caches the snapshot for 5 seconds.
Scanner::reapStaleJobs();
out('t0  reconcile pass done, snapshot cached. /proc walks: ' . Scanner::procScanCount());

// The scan task starts a scan: row, then a real worker that writes its pid.
$jobId = Database::insert('scan_jobs', [
    'scan_type'    => 'full',
    'status'       => 'running',
    'started_at'   => time(),
    'progress_at'  => time(),
    'scan_path'    => '/home',
    'requested_by' => '@schedule',
]);
$pid = spawn_worker($jobId);
Database::query('UPDATE scan_jobs SET worker_pid=? WHERE id=?', [$pid, $jobId]);
out("t0+ job {$jobId} running, worker pid {$pid}");
out('    /proc/' . $pid . ' exists now: ' . (is_dir('/proc/' . $pid) ? 'YES' : 'no'));
out('    its cmdline: ' . str_replace("\0", ' ',
        (string) @file_get_contents('/proc/' . $pid . '/cmdline')));

// A later task in the SAME process, inside the 5s window. liveScans() is what
// scheduler.php:688 calls.
$live = Scanner::liveScans();
out('t0+ liveScans() (2nd pass, cached snapshot). /proc walks: '
    . Scanner::procScanCount());

$row = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$jobId]);
out('    ROW STATUS  : ' . $row['status']);
out('    STOP REASON : ' . ($row['stop_reason'] ?? ''));
out('    liveScans() now reports: ' . count($live) . ' scan(s)');
out('    worker ' . $pid . ' still running: '
    . (is_dir('/proc/' . $pid) ? 'YES — a live worker with no row claiming it' : 'no'));

// And what a FRESH look at /proc would have said, to attribute the difference
// to the cache alone.
$fresh = Scanner::procSnapshot(true);
out('    verdict on a FRESH snapshot: '
    . Scanner::judgeJob($row, $fresh)['verdict']);

@shell_exec('kill ' . $pid . ' 2>/dev/null');
