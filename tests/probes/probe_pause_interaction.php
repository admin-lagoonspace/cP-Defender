<?php
/**
 * SHAKAAL second pass — pausedForBackup() now WRITES. Two questions:
 *  (b) with a backup genuinely running, is the pause honoured?
 *  (c) pausedForBackup() decides from backupRunning(), which is cached 30s.
 *      Can a stale-empty cache clear a pause that is genuinely in force and
 *      let a waiting scan be judged stalled?
 */
$BASE = '/usr/local/serverscrub/backend';
foreach (['config/config.php','lib/Database.php','lib/Logger.php','lib/Heuristics.php',
          'lib/RealTimeMonitor.php','lib/Scanner.php'] as $f) { require_once $BASE . '/' . $f; }
function out($s) { echo $s . PHP_EOL; }
function hdr($s) { echo PHP_EOL . '== ' . $s . ' ==' . PHP_EOL; }
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
out('rt_backup_procs = ' . Database::setting('rt_backup_procs', 'jetbackup,rsync'));

// A process the backup detector should recognise, on real /proc.
$bk = (int) trim(shell_exec("bash -c \"/tmp/fakebk/rsync 240 >/dev/null 2>&1 & echo \\$!\""));
out('fake backup pid ' . $bk . ' cmdline: '
  . str_replace("\0", ' ', (string) @file_get_contents('/proc/' . $bk . '/cmdline')));
out('backupRunning(fresh) sees: ' . json_encode(Scanner::backupRunning(true)));

// A wedged-looking but identity-confirmed worker: silent for 55 hours.
$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=800 --path=/home'"
     . " php -r 'sleep(240);' >/dev/null 2>&1 & echo \$!";
$w = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid,worker_pgid)
                 VALUES (800,'full','running',?,?,'/home',?,?)",
                [time() - 200000, time() - 200000, $w, $w]);

hdr('(b) a backup really is running');
Database::setSetting('scan_paused_for_backup', '1');
Scanner::backupRunning(true);                        // warm the cache correctly
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=800');
$v   = Scanner::judgeJob($job, Scanner::procSnapshot(true));
out('  verdict           : ' . $v['verdict'] . '   (want: paused)');
out('  flag after judging: ' . Database::setting('scan_paused_for_backup')
  . '   (want: 1, not cleared)');
Scanner::reapStaleJobs();
out('  row after a pass  : ' . Database::fetchOne('SELECT status FROM scan_jobs WHERE id=800')['status']
  . '   worker alive: ' . (is_dir('/proc/' . $w) ? 'yes' : 'NO - KILLED A WAITING SCAN'));

hdr('(c) the pause is in force, but this process cached an EMPTY answer first');
shell_exec('kill ' . $bk . ' 2>/dev/null'); usleep(300000);
Scanner::backupRunning(true);                        // cache = empty, no backup yet
out('  cached backupRunning() = ' . json_encode(Scanner::backupRunning()) . ' (stale-empty from now on)');
// NOW the backup starts and a worker takes the pause, as waitOutBackup() does.
$bk2 = (int) trim(shell_exec("bash -c \"/tmp/fakebk/rsync 240 >/dev/null 2>&1 & echo \\$!\""));
Database::setSetting('scan_paused_for_backup', '1');
out('  a backup IS running now: ' . json_encode(Scanner::backupRunning(true)) . ' (fresh)');
// Re-stale the cache the way a long-lived process would have it.
$ref = new ReflectionMethod('Scanner', 'backupRunning');
out('  pausedForBackup() says : ' . var_export(Scanner::pausedForBackup(), true));
out('  flag now               : ' . Database::setting('scan_paused_for_backup'));
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=800');
Database::query("UPDATE scan_jobs SET status='running', stop_reason='' WHERE id=800");
$v2 = Scanner::judgeJob($job, Scanner::procSnapshot(true));
out('  verdict on the waiting scan: ' . $v2['verdict']);
shell_exec('kill ' . $bk2 . ' ' . $w . ' 2>/dev/null');
Database::setSetting('scan_paused_for_backup', '0');
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
