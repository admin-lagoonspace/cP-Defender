<?php
/**
 * SHAKAAL PROBE — the stall path is the only new code that signals. It signals
 * worker_pgid, which judgeJob() never verifies (identity is checked on
 * worker_pid only). What if the recorded pgid belongs to something else?
 */
$BASE = '/usr/local/serverscrub/backend';
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/Scanner.php';
function out($s) { echo $s . PHP_EOL; }
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
Database::setSetting('scan_paused_for_backup', '0');

// An innocent bystander in its own process group -- stand-in for cPanel's own
// mail clamscan, or anything else on a 132-account host.
$by = (int) trim(shell_exec("setsid sleep 300 >/dev/null 2>&1 & echo $!"));
$byPgid = (int) trim(shell_exec("ps -o pgid= -p {$by} 2>/dev/null"));
out("bystander pid {$by}, its own pgid {$byPgid}: "
  . trim((string) shell_exec("ps -o args= -p {$by}")));

// A real, identity-matching worker for job 500.
$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=500 --path=/home'"
     . " php -r 'sleep(300);' >/dev/null 2>&1 & echo \$!";
$w = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
out("worker    pid {$w}");

// The row: correct pid, WRONG pgid (the bystander's).
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid,worker_pgid,files_scanned)
                 VALUES (500,'full','running',?,?,'/home',?,?,1000)",
                [time() - 200000, time() - 200000, $w, $byPgid]);

$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=500');
out('verdict: ' . Scanner::judgeJob($job, Scanner::procSnapshot(true))['verdict']);
out('--- running one reconcile pass ---');
out('reaped: ' . Scanner::reapStaleJobs());
sleep(1);
out('bystander ' . $by . ' still alive: '
  . (is_dir('/proc/' . $by) ? 'yes' : 'NO - THE RECONCILE KILLED A PROCESS THAT IS NOT OURS'));
out('worker    ' . $w . ' still alive: ' . (is_dir('/proc/' . $w) ? 'yes' : 'no (stopped)'));
out('row: ' . json_encode(Database::fetchOne(
  'SELECT status,stop_reason FROM scan_jobs WHERE id=500')));
shell_exec("kill {$by} {$w} 2>/dev/null");
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
