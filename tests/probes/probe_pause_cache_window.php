<?php
/**
 * SHAKAAL — pausedForBackup() clears the pause from backupRunning(), which is
 * cached 30s and NOT asked fresh. One process, no fresh reads anywhere:
 *   1. cache "no backup"   2. a backup starts, a worker takes the pause
 *   3. pausedForBackup() inside the 30s window
 */
$BASE = '/usr/local/serverscrub/backend';
foreach (['config/config.php','lib/Database.php','lib/Logger.php','lib/Heuristics.php',
          'lib/RealTimeMonitor.php','lib/Scanner.php'] as $f) { require_once $BASE . '/' . $f; }
function out($s) { echo $s . PHP_EOL; }
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');

// 1. Cold cache, nothing running. NOTE: no (true) anywhere in this file.
out('1. backupRunning() cached with nothing running -> ' . json_encode(Scanner::backupRunning()));

// A worker waiting out a backup for hours, as waitOutBackup() leaves it.
$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=900 --path=/home'"
     . " php -r 'sleep(240);' >/dev/null 2>&1 & echo \$!";
$w = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid,worker_pgid)
                 VALUES (900,'full','running',?,?,'/home',?,?)",
                [time() - 200000, time() - 200000, $w, $w]);

// 2. The backup starts and the worker takes the pause.
$bk = (int) trim(shell_exec('/tmp/fakebk/rsync 240 >/dev/null 2>&1 & echo $!'));
Database::setSetting('scan_paused_for_backup', '1');
sleep(2);
$live = trim((string) shell_exec("ps -o comm= -p {$bk}"));
out('2. a backup is genuinely running: pid ' . $bk . ' comm=' . $live);

// 3. The decision, from the cached answer.
out('3. backupRunning() (still cached, <30s old) -> ' . json_encode(Scanner::backupRunning()));
$paused = Scanner::pausedForBackup();
out('   pausedForBackup() -> ' . var_export($paused, true));
out('   flag afterwards   -> ' . Database::setting('scan_paused_for_backup'));
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=900');
$v = Scanner::judgeJob($job, Scanner::procSnapshot(true));
out('   verdict           -> ' . $v['verdict']);
if ($v['verdict'] === 'stalled') {
    out('   *** a scan legitimately waiting out a REAL backup is judged stalled;');
    out('       reapStaleJobs() would stop it and close the row.');
} else {
    out('   the pause held.');
}
shell_exec('kill ' . $bk . ' ' . $w . ' 2>/dev/null');
Database::setSetting('scan_paused_for_backup', '0');
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
