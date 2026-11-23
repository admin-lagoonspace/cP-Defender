<?php
/**
 * SHAKAAL — pausedForBackup() now asks backupRunning(TRUE), which is its own
 * /proc walk inside RealTimeMonitor::backupProcesses(). It is called from
 * judgeJob(), once per candidate. Does the cost scale with the number of
 * candidate rows, or is it bounded by the number of live workers?
 *
 * procScanCount() only counts Scanner::procSnapshot(), so these extra walks
 * are invisible to it -- wall time is the measurement that sees them.
 */
$BASE = '/usr/local/serverscrub/backend';
foreach (['config/config.php','lib/Database.php','lib/Logger.php','lib/Heuristics.php',
          'lib/RealTimeMonitor.php','lib/Scanner.php'] as $f) { require_once $BASE . '/' . $f; }
function out($s) { echo $s . PHP_EOL; }

function reset_rows() {
    Database::query('DELETE FROM threats');
    Database::query('DELETE FROM scan_jobs');
}
function timed_pass(string $label) {
    sleep(6);                                   // expire the 5s snapshot cache
    $b = Scanner::procScanCount();
    $t = microtime(true);
    Scanner::reapStaleJobs();
    $ms = (microtime(true) - $t) * 1000;
    $p  = Scanner::lastReapPass();
    printf("  %-44s %6.0f ms  procSnapshot=%d  candidates=%d reaped=%d left=%d\n",
        $label, $ms, Scanner::procScanCount() - $b,
        $p['candidates'], $p['reaped'], $p['left']);
}

reset_rows();
Database::setSetting('scan_paused_for_backup', '0');

// A genuine backup, so the pause is real and pausedForBackup() takes the
// expensive branch (flag set AND a fresh walk that finds something).
$bk = (int) trim(shell_exec('setsid /tmp/fakebk/rsync 900 >/dev/null 2>&1 & echo $!'));
sleep(1);
out('backup running: ' . json_encode(Scanner::backupRunning(true)));

// One identity-confirmed worker, paused.
$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=1000 --path=/home'"
     . " php -r 'sleep(300);' >/dev/null 2>&1 & echo \$!";
$w = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,
                                        worker_pid,worker_pgid)
                 VALUES (1000,'full','running',?,?,'/home',?,?)",
                [time() - 200000, time() - 200000, $w, $w]);
Database::setSetting('scan_paused_for_backup', '1');

out('');
out('flag SET, a real backup, one identity-confirmed paused worker:');
timed_pass('1 candidate');

// Now 49 more candidates that are NOT identity-confirmed, so they never reach
// the pause check. If the walk were per row, this would cost ~50x.
for ($i = 0; $i < 49; $i++) {
    Database::query("INSERT INTO scan_jobs (scan_type,status,started_at,progress_at,scan_path,worker_pid)
                     VALUES ('full','running',?,?,'/home',2147480000)",
                    [time() - 207660, time() - 207660]);
}
timed_pass('50 candidates (49 of them to be reaped)');

reset_rows();
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,
                                        worker_pid,worker_pgid)
                 VALUES (1000,'full','running',?,?,'/home',?,?)",
                [time() - 200000, time() - 200000, $w, $w]);
Database::setSetting('scan_paused_for_backup', '0');
out('');
out('flag CLEAR (the healthy steady state) -- pausedForBackup() returns before any walk:');
timed_pass('1 candidate, flag clear');

out('');
out('pause check is gated on $mine === $id, so it is reached only by a row whose');
out('pid IS its own live worker -- bounded by maxConcurrent (' . Scanner::maxConcurrent()
  . '), not by candidate count.');

shell_exec('kill ' . $bk . ' ' . $w . ' 2>/dev/null');
Database::setSetting('scan_paused_for_backup', '0');
reset_rows();
