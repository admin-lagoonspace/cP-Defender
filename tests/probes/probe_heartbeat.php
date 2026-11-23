<?php
/** SHAKAAL PROBE — does progress_at advance during a REAL sweep on Linux? */
$BASE = '/usr/local/serverscrub/backend';
require_once $BASE . '/config/config.php';
require_once $BASE . '/lib/Database.php';
require_once $BASE . '/lib/Logger.php';
require_once $BASE . '/lib/Heuristics.php';
require_once $BASE . '/lib/Scanner.php';
function out($s) { echo $s . PHP_EOL; }

shell_exec("pkill -f 'cron/scan.php' 2>/dev/null"); sleep(1);
Database::query('DELETE FROM scan_jobs');
$sc = new Scanner();
$id = $sc->startScan('/home', 'full', false, 'shakaal-probe');
out("job {$id} started; batch size "
    . Database::setting('scan_batch_size', '200')
    . ", stall timeout " . Scanner::stallTimeout() . 's');
$seen = [];
for ($i = 0; $i < 14; $i++) {
    sleep(2);
    $r = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$id]);
    $beat = $r['progress_at'];
    $seen[] = (int) $beat;
    out(sprintf('t+%-3ds status=%-11s files=%-7s progress_at=%-11s idle=%ds',
        ($i + 1) * 2, $r['status'], $r['files_scanned'],
        $beat === null ? 'NULL' : $beat,
        time() - Scanner::heartbeatOf($r)));
    if (!in_array($r['status'], ['running', 'pending'], true)) { break; }
}
$distinct = count(array_unique(array_filter($seen)));
out('distinct heartbeat values observed: ' . $distinct
    . ($distinct > 1 ? ' - the heartbeat MOVES during a real sweep'
                     : ' - the heartbeat DID NOT MOVE'));
shell_exec("pkill -f 'cron/scan.php' 2>/dev/null");
