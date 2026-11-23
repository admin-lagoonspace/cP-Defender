<?php
/**
 * SHAKAAL PROBE — waitOutBackup() returns false on max-wait and on cancel
 * WITHOUT clearing scan_paused_for_backup. pausedForBackup() is now a global
 * gate on the stall rule, so a stuck '1' disables it for every later scan.
 */
$BASE = '/usr/local/serverscrub/backend';
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/Scanner.php';
function out($s) { echo $s . PHP_EOL; }

shell_exec("pkill -f 'cron/scan.php' 2>/dev/null"); sleep(1);
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');

// The state waitOutBackup() leaves behind when the backup outlasts
// scan_backup_max_wait: flag at '1', no scan running, nothing to reconcile.
Database::setSetting('scan_paused_for_backup', '1');
out('flag after a backup outlasted scan_backup_max_wait: '
    . Database::setting('scan_paused_for_backup'));
out('in-progress rows: ' . count(Database::fetchAll(
    "SELECT id FROM scan_jobs WHERE status IN ('running','pending','cancelling')")));

// Wasooli's reset needs a pass that closes out EVERY in-progress row. There
// are none, so n = 0 and the condition cannot fire.
Scanner::reapStaleJobs();
out('after a reconcile pass, flag is still: '
    . Database::setting('scan_paused_for_backup')
    . '  (pausedForBackup() = ' . var_export(Scanner::pausedForBackup(), true) . ')');

// Now a genuinely stalled scan, days without progress, identity-confirmed.
$pid = (int) trim(shell_exec("bash -c \"exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=991 --path=/home' php -r 'sleep(90);' >/dev/null 2>&1 & echo \$!\""));
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid,files_scanned)
                 VALUES (991,'full','running',?,?,'/home',?,289200)",
                [time() - 200000, time() - 200000, $pid]);
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=991');
$v   = Scanner::judgeJob($job, Scanner::procSnapshot(true));
out('');
out('a worker with NO progress for ' . intdiv(200000, 3600) . ' hours is judged: '
    . $v['verdict']);
out('  reason: ' . $v['reason']);
Scanner::reapStaleJobs();
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=991');
out('  row status after a pass: ' . $job['status']);
out('  the Scanner page will report paused = '
    . var_export(Scanner::pausedForBackup(), true) . ' with no backup running');
out('  backupRunning() actually says: '
    . json_encode(Scanner::backupRunning()));
shell_exec('kill ' . $pid . ' 2>/dev/null');
Database::setSetting('scan_paused_for_backup', '0');
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
