<?php
/** SHAKAAL — the /proc enumeration bound, measured with a COLD cache each time. */
$BASE = '/usr/local/serverscrub/backend';
foreach (['config/config.php','lib/Database.php','lib/Logger.php','lib/Heuristics.php',
          'lib/RealTimeMonitor.php','lib/Scanner.php'] as $f) { require_once $BASE . '/' . $f; }
function out($s) { echo $s . PHP_EOL; }
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
Database::setSetting('scan_paused_for_backup', '0');

function measure(string $label) {
    sleep(6);                               // let the 5s snapshot cache expire
    $b = Scanner::procScanCount();
    Scanner::reapStaleJobs();
    $n = Scanner::procScanCount() - $b;
    out(sprintf('  %-34s %d enumeration(s)', $label, $n));
    return $n;
}

out('cold cache, measured per pass:');
measure('no candidate rows');

$cmd = "exec -a 'php /usr/local/serverscrub/backend/cron/scan.php --job-id=700 --path=/home'"
     . " php -r 'sleep(180);' >/dev/null 2>&1 & echo \$!";
$w = (int) trim(shell_exec('bash -c ' . escapeshellarg($cmd)));
Database::query("INSERT INTO scan_jobs (id,scan_type,status,started_at,progress_at,scan_path,worker_pid,worker_pgid)
                 VALUES (700,'full','running',?,?,'/home',?,?)", [time() - 300, time() - 10, $w, $w]);
measure('one healthy worker, nothing to do');

// 60 stuck rows: bound is 50 candidates, and still only two enumerations.
for ($i = 0; $i < 60; $i++) {
    Database::query("INSERT INTO scan_jobs (scan_type,status,started_at,progress_at,scan_path,worker_pid)
                     VALUES ('full','running',?,?,'/home',2147480000)",
                    [time() - 207660, time() - 207660]);
}
out('  60 stuck rows inserted');
$b = Scanner::procScanCount();
sleep(6);
Scanner::reapStaleJobs();
$n = Scanner::procScanCount() - $b;
$p = Scanner::lastReapPass();
out(sprintf('  %-34s %d enumeration(s)', 'a pass that ACTS', $n));
out('    candidates=' . $p['candidates'] . '  examined=' . $p['examined']
  . '  reaped=' . $p['reaped'] . '  left=' . $p['left'] . '  unknown=' . $p['unknown']);
out('    still in progress afterwards: ' . count(Database::fetchAll(
  "SELECT id FROM scan_jobs WHERE status IN ('running','pending','cancelling')")));
out('    the healthy worker 700 is: '
  . Database::fetchOne('SELECT status FROM scan_jobs WHERE id=700')['status']
  . ', process alive: ' . (is_dir('/proc/' . $w) ? 'yes' : 'NO'));
shell_exec('kill ' . $w . ' 2>/dev/null');
Database::query('DELETE FROM threats'); Database::query('DELETE FROM scan_jobs');
