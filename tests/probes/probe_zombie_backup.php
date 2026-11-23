<?php
/**
 * SHAKAAL — finding 10, against a REAL zombie on real /proc.
 *
 * backupProcesses() matched on /proc/<pid>/comm, which survives into the
 * zombie state (unlike cmdline, which empties), so an rsync that had exited
 * and not been waited on read as a backup in progress. That gates the
 * real-time monitor's suspend/resume AND, since the second pass,
 * Scanner::pausedForBackup() -- so a corpse switched the scan stall watchdog
 * off and had the Scanner page reporting a backup.
 *
 * MAKING A ZOMBIE RELIABLY. Do not rely on pid 1 failing to reap: in this
 * image pid 1 is bash during the install (which reaps inherited orphans) and
 * php -S only once serving, so a setsid'd-and-killed process may or may not
 * persist. Instead keep the PARENT alive and never wait on the child:
 * proc_open() starts it, it exits on its own, and this process does not call
 * proc_close() or proc_get_status() -- both of which would reap it. The child
 * is then a zombie for as long as this script runs, whatever pid 1 does.
 *
 * The fixture must be a copy of a BINARY (comm is the executable name), and
 * proc_open is given an ARRAY so it execs directly instead of via a shell.
 */
$BASE = '/usr/local/serverscrub/backend';
foreach (['config/config.php','lib/Database.php','lib/Logger.php','lib/Heuristics.php',
          'lib/RealTimeMonitor.php','lib/Scanner.php'] as $f) { require_once $BASE . '/' . $f; }

function out($s) { echo $s . PHP_EOL; }
function hdr($s) { echo PHP_EOL . '== ' . $s . ' ==' . PHP_EOL; }
function state_of(int $pid): string {
    $stat = (string) @file_get_contents('/proc/' . $pid . '/stat');
    if ($stat === '') { return '-'; }
    return substr(substr($stat, strrpos($stat, ')') + 2), 0, 1);
}
/** The pid of a proc_open child, without proc_get_status (which reaps). */
function child_pid_by_comm(string $comm, array $exclude = []): int {
    foreach (glob('/proc/[0-9]*') ?: [] as $d) {
        $pid = (int) basename($d);
        if (in_array($pid, $exclude, true)) { continue; }
        if (trim((string) @file_get_contents($d . '/comm')) === $comm) { return $pid; }
    }
    return 0;
}

Database::query('DELETE FROM threats');
Database::query('DELETE FROM scan_jobs');
Database::setSetting('scan_paused_for_backup', '0');
out('rt_backup_procs = ' . Database::setting('rt_backup_procs', 'jetbackup,rsync'));
out('pid 1 here       = ' . str_replace("\0", ' ',
    (string) @file_get_contents('/proc/1/cmdline')));

/* A child named rsync that exits while THIS process stays alive and never
 * waits on it. Array form, so it execs the binary directly. */
$pipes = [];
$h = proc_open(['/tmp/fakebk/rsync', '1'], [], $pipes);
if (!is_resource($h)) { out('could not start the fixture'); exit(1); }
sleep(3);                                   // it exits after 1s; we never reap
$z = child_pid_by_comm('rsync');
out('zombie candidate pid ' . $z . ' state=' . state_of($z));

hdr('a REAL zombie whose comm is still rsync');
out('  state                  : ' . state_of($z) . '   (want Z)');
out('  /proc/' . $z . ' present      : ' . (is_dir('/proc/' . $z) ? 'yes' : 'no'));
out('  comm                   : "' . trim((string) @file_get_contents('/proc/' . $z . '/comm'))
  . '"   <- the name a corpse keeps');
out('  cmdline                : "' . trim((string) @file_get_contents('/proc/' . $z . '/cmdline'))
  . '"   <- and the thing it loses');
if (state_of($z) !== 'Z') {
    out('  !! not a zombie -- this run proves nothing about finding 10');
    exit(1);
}

out('');
out('  backupProcesses(/proc) : ' . json_encode(RealTimeMonitor::backupProcesses('/proc'))
  . '   (want [] -- a corpse is not a backup)');
out('  backupRunning(fresh)   : ' . json_encode(Scanner::backupRunning(true)) . '   (want [])');

hdr('so the stall watchdog is not stood down by a corpse');
$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=992 --path=/home'"
     . " php -r 'sleep(240);' >/dev/null 2>&1 & echo \$!";
$w = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
Database::query(
    "INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,
                            worker_pid,worker_pgid,files_scanned)
     VALUES (992,'full','running',?,?,'/home',?,?,289200)",
    [time() - 200000, time() - 200000, $w, $w]);
Database::setSetting('scan_paused_for_backup', '1');
out('  a worker silent for 55h, flag left at 1 by a worker that was killed');
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=992');
$v   = Scanner::judgeJob($job, Scanner::procSnapshot(true));
out('  verdict                : ' . $v['verdict'] . '   (want stalled, NOT paused)');
out('  flag after judging     : ' . Database::setting('scan_paused_for_backup') . '   (want 0)');

hdr('and a LIVE rsync is still detected -- the fix must not blind the gate');
$live = (int) trim(shell_exec('setsid /tmp/fakebk/rsync 900 >/dev/null 2>&1 & echo $!'));
sleep(1);
$lpid = child_pid_by_comm('rsync', [$z]);
out('  live pid ' . $lpid . ' state=' . state_of($lpid)
  . '   (zombie ' . $z . ' is still state ' . state_of($z) . ' alongside it)');
out('  backupProcesses(/proc) : ' . json_encode(RealTimeMonitor::backupProcesses('/proc'))
  . '   (want ["rsync"])');
Database::setSetting('scan_paused_for_backup', '1');
Database::query("UPDATE scan_jobs SET status='running', stop_reason='' WHERE id=992");
$job = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=992');
$v2  = Scanner::judgeJob($job, Scanner::procSnapshot(true));
out('  verdict                : ' . $v2['verdict'] . '   (want paused)');
out('  flag                   : ' . Database::setting('scan_paused_for_backup') . '   (want 1)');
out('  the waiting worker is still alive: ' . (is_dir('/proc/' . $w) ? 'yes' : 'NO'));

shell_exec('kill ' . $lpid . ' ' . $w . ' 2>/dev/null');
Database::setSetting('scan_paused_for_backup', '0');
Database::query('DELETE FROM threats');
Database::query('DELETE FROM scan_jobs');
