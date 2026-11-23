<?php
/** SHAKAAL — fix 2 verification: a stuck pause flag with NO backup running. */
$BASE = '/usr/local/serverscrub/backend';
foreach (['config/config.php','lib/Database.php','lib/Logger.php','lib/Heuristics.php',
          'lib/RealTimeMonitor.php','lib/Scanner.php'] as $f) { require_once $BASE . '/' . $f; }
function out($s) { echo $s . PHP_EOL; }
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
out('backupRunning(fresh): ' . json_encode(Scanner::backupRunning(true))
  . '   <- must be [] for this test to mean anything');

$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=991 --path=/home'"
     . " php -r 'sleep(240);' >/dev/null 2>&1 & echo \$!";
$w = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid,worker_pgid,files_scanned)
                 VALUES (991,'full','running',?,?,'/home',?,?,289200)",
                [time() - 200000, time() - 200000, $w, $w]);

// The state waitOutBackup() used to leave behind after a four-hour give-up.
Database::setSetting('scan_paused_for_backup', '1');
out('flag armed at 1 with no backup running, and NO in-progress row to close out');
out('  (the old mitigation needed a pass that reaped every row, so it could not fire)');
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=991');
$v = Scanner::judgeJob($job, Scanner::procSnapshot(true));
out('  verdict               : ' . $v['verdict'] . '   (want: stalled, not paused)');
out('  flag after judging    : ' . Database::setting('scan_paused_for_backup') . '   (want: 0)');
out('  pausedForBackup() now : ' . var_export(Scanner::pausedForBackup(), true));
shell_exec('kill ' . $w . ' 2>/dev/null');
Database::setSetting('scan_paused_for_backup', '0');
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
