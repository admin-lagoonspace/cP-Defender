<?php
$BASE = '/usr/local/serverscrub/backend';
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/Scanner.php';
function out($s) { echo $s . PHP_EOL; }
shell_exec("pkill -f 'cron/scan.php' 2>/dev/null"); sleep(1);
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');

$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=991 --path=/home'"
     . " php -r 'sleep(90);' >/dev/null 2>&1 & echo \$!";
$pid = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
out('wedged worker pid: ' . $pid . '  cmdline: '
  . str_replace("\0", ' ', (string) @file_get_contents('/proc/' . $pid . '/cmdline')));

Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid,worker_pgid,files_scanned)
                 VALUES (991,'full','running',?,?,'/home',?,?,289200)",
                [time() - 200000, time() - 200000, $pid, $pid]);

foreach (['0' => 'flag correctly clear', '1' => 'flag stuck at 1 by waitOutBackup()'] as $flag => $label) {
    Database::setSetting('scan_paused_for_backup', (string) $flag);
    Database::query("UPDATE scan_jobs SET status='running', stop_reason='' WHERE id=991");
    $job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=991');
    $v   = Scanner::judgeJob($job, Scanner::procSnapshot(true));
    out('');
    out("-- {$label} --");
    out('  verdict : ' . $v['verdict']);
    out('  reason  : ' . $v['reason']);
    out('  backupRunning() : ' . json_encode(Scanner::backupRunning()));
    out('  worker still alive after a pass: ' . (is_dir('/proc/' . $pid) ? 'yes' : 'no'));
}
shell_exec('kill ' . $pid . ' 2>/dev/null');
Database::setSetting('scan_paused_for_backup', '0');
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
