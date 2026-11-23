<?php
/** SHAKAAL second pass — bound, zombies, refusal card, stall floor. */
$BASE = '/usr/local/serverscrub/backend';
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/RealTimeMonitor.php';
require_once $BASE . '/lib/Scanner.php';
function out($s) { echo $s . PHP_EOL; }
function hdr($s) { echo PHP_EOL . '== ' . $s . ' ==' . PHP_EOL; }
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
Database::setSetting('scan_paused_for_backup', '0');

hdr('A. /proc enumerations: healthy pass vs acting pass');
$before = Scanner::procScanCount();
Scanner::reapStaleJobs();
out('no candidates at all      : ' . (Scanner::procScanCount() - $before) . ' read(s)');

// A healthy, identity-matching worker.
$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=600 --path=/home'"
     . " php -r 'sleep(120);' >/dev/null 2>&1 & echo \$!";
$w = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid,worker_pgid)
                 VALUES (600,'full','running',?,?,'/home',?,?)", [time() - 300, time() - 10, $w, $w]);
$before = Scanner::procScanCount();
Scanner::reapStaleJobs(); // forces a fresh look? should not: verdict is alive
out('one healthy row (no action): ' . (Scanner::procScanCount() - $before) . ' read(s) -- expect 1');
out('  row still: ' . Database::fetchOne('SELECT status FROM scan_jobs WHERE id=600')['status']);

// A row that must be acted on: pid belongs to nothing, well past the grace.
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid)
                 VALUES (601,'full','running',?,?,'/home',2147480000)", [time() - 207660, time() - 207660]);
$before = Scanner::procScanCount();
Scanner::reapStaleJobs();
out('a row needing action       : ' . (Scanner::procScanCount() - $before) . ' read(s) -- expect 2');
out('  601 -> ' . json_encode(Database::fetchOne('SELECT status,stop_reason FROM scan_jobs WHERE id=601')));
out('  600 (healthy) still: ' . Database::fetchOne('SELECT status FROM scan_jobs WHERE id=600')['status']);
shell_exec('kill ' . $w . ' 2>/dev/null');

hdr('B. zombie read as gone (the gap the container could not close before)');
$z = (int) trim(shell_exec('setsid sleep 300 >/dev/null 2>&1 & echo $!'));
shell_exec('kill ' . $z . ' 2>/dev/null'); usleep(400000);
$stat = (string) @file_get_contents('/proc/' . $z . '/stat');
$state = substr(substr($stat, strrpos($stat, ')') + 2), 0, 1);
out('pid ' . $z . ' state=' . $state . '  /proc dir still there: '
  . (is_dir('/proc/' . $z) ? 'yes' : 'no'));
$s = Scanner::procSnapshot(true);
out('procSnapshot pids includes it : ' . var_export(isset($s['pids'][$z]), true) . '  (expect false)');
$ref = new ReflectionMethod('Scanner', 'processAlive');
$ref->setAccessible(true);
out('processAlive() says alive     : ' . var_export($ref->invoke(null, $z), true) . '  (expect false)');

hdr('C. refusal card no longer claims a closed job is in progress');
Database::setSetting('scan_schedule_refused_at', (string) (time() - 900));
Database::setSetting('scan_schedule_refused_why', 'Already running 1 of a maximum 1 scan(s) (job 601)');
Database::setSetting('scan_schedule_refused_job', '601');
Database::setSetting('scan_schedule_refused_job_started', (string) (time() - 207660));
$r = Scanner::scheduleRefusal();
out('job 601 real status : ' . Database::fetchOne('SELECT status FROM scan_jobs WHERE id=601')['status']);
out('  job_live   : ' . var_export($r['job_live'], true) . '  (expect false)');
out('  job_status : ' . $r['job_status']);
out('  job_age    : ' . $r['job_age'] . 's  (expect 0)');
Database::setSetting('scan_schedule_refused_job', '600');
Database::setSetting('scan_schedule_refused_job_started', (string) (time() - 3600));
$r2 = Scanner::scheduleRefusal();
out('and for a genuinely live job 600: job_live=' . var_export($r2['job_live'], true)
  . ' status=' . $r2['job_status'] . ' age=' . $r2['job_age'] . 's');

hdr('D. stall floor is coupled to the batch timeout');
foreach ([['600','1800'], ['3600','1800'], ['600','300'], ['60','300'], ['3600','86400']] as $p) {
    Database::setSetting('scan_batch_timeout', $p[0]);
    Database::setSetting('scan_stall_timeout', $p[1]);
    printf("  batch=%-6s stall setting=%-6s -> batchTimeout()=%-5d stallTimeout()=%-6d %s\n",
        $p[0], $p[1], Scanner::batchTimeout(), Scanner::stallTimeout(),
        Scanner::stallTimeout() >= 3 * Scanner::batchTimeout() ? 'OK (>=3 batches)' : 'TOO LOW');
}
Database::setSetting('scan_batch_timeout', '600');
Database::setSetting('scan_stall_timeout', '1800');
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
