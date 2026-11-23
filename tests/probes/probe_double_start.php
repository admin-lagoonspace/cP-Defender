<?php
/**
 * SHAKAAL PROBE — after the stale snapshot wrongly reaps a live scan, does the
 * concurrency cap still hold? The cap exists because every clamscan loads the
 * whole signature database into its own memory.
 */
$BASE = '/usr/local/serverscrub/backend';
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/Scanner.php';
function out($s) { echo $s . PHP_EOL; }

Database::query("DELETE FROM scan_jobs");
$sc = new Scanner();

// t0: the tick's reconcile pass caches the snapshot.
Scanner::reapStaleJobs();
out('t0  reconcile pass; /proc walks: ' . Scanner::procScanCount());

// The scan task starts the real daily sweep.
$a = $sc->startScan('/home', 'full', false, '@schedule');
out("t0+ job {$a} started (the real daily sweep)");

// A later 'every' task, one second later, asks liveScans().
sleep(1);
$live = Scanner::liveScans();
out('t0+1s liveScans() says ' . count($live) . ' scan(s) are running');
$rowA = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$a]);
out('      job ' . $a . ' status: ' . $rowA['status']
    . ' / reason: ' . ($rowA['stop_reason'] ?? ''));
out('      its worker ' . $rowA['worker_pid'] . ' alive: '
    . (is_dir('/proc/' . $rowA['worker_pid']) ? 'YES' : 'no'));

// Now the cap. maxConcurrent() is 1.
out('      maxConcurrent(): ' . Scanner::maxConcurrent());
try {
    $b = $sc->startScan('/home', 'full', false, '@schedule');
    out('      SECOND scan STARTED as job ' . $b . ' - the cap did not refuse it');
} catch (Throwable $e) {
    out('      second scan refused: ' . $e->getMessage());
}

sleep(2);
out('--- scan workers running concurrently now ---');
out(trim((string) shell_exec("pgrep -af 'cron/scan.php' || echo '  none'")));
out('--- clamscan processes ---');
out(trim((string) shell_exec("pgrep -ac clamscan || echo 0")));
shell_exec("pkill -f 'cron/scan.php' 2>/dev/null");
