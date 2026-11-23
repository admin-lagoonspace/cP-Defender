<?php
/**
 * SHAKAAL — the property that must never regress: a reconcile must not signal
 * a process that is not this job's worker. Bystander started with setsid so it
 * outlives the shell that spawned it (last time a command-substitution
 * subshell killed it and made the reconcile look guilty).
 */
$BASE = '/usr/local/serverscrub/backend';
foreach (['config/config.php','lib/Database.php','lib/Logger.php','lib/Heuristics.php',
          'lib/RealTimeMonitor.php','lib/Scanner.php'] as $f) { require_once $BASE . '/' . $f; }
function out($s) { echo $s . PHP_EOL; }
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
Database::setSetting('scan_paused_for_backup', '0');

$by = (int) trim(shell_exec('setsid sleep 900 >/dev/null 2>&1 & echo $!'));
sleep(1);
$pgid = (int) trim(shell_exec("ps -o pgid= -p {$by}"));
out('bystander pid ' . $by . ' pgid ' . $pgid . ' : '
  . trim((string) shell_exec("ps -o args= -p {$by}")));

// The production case: a two-day-old running row whose recorded pid AND pgid
// are a live process that is not a scan worker.
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,scan_path,worker_pid,worker_pgid,files_scanned,threats_found)
                 VALUES (12467,'full','running',?,'/home',?,?,289200,32003)",
                [time() - 207660, $by, $pgid]);
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=12467');
$v = Scanner::judgeJob($job, Scanner::procSnapshot(true));
out('verdict: ' . $v['verdict']);
out('reason : ' . $v['reason']);
out('--- reconcile pass ---');
out('reaped : ' . Scanner::reapStaleJobs());
sleep(1);
$row = Database::fetchOne('SELECT status,files_scanned,threats_found,stop_reason FROM scan_jobs WHERE id=12467');
out('row    : ' . json_encode($row));
out('bystander ' . $by . ' still alive: '
  . (is_dir('/proc/' . $by) ? 'YES - correct, it was never ours to signal'
                            : 'NO - THE RECONCILE SIGNALLED A STRANGER'));
out('its group still alive        : '
  . (trim((string) shell_exec("pgrep -g {$pgid} | head -1")) !== '' ? 'yes' : 'no'));
shell_exec('kill ' . $by . ' 2>/dev/null');
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
