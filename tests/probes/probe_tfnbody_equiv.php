<?php
/**
 * SHAKAAL — independent check that swapping substr(...,1800) for t_fn_body()
 * did not weaken the two assertions. Two questions:
 *   1. does the extracted body stay INSIDE the function (no foreign text)?
 *   2. are the claims still asserted, and the ordering one still meaningful?
 */
require_once '/opt/serverscrub-src/tests/assert.php';
$sc = file_get_contents('/opt/serverscrub-src/backend/lib/Scanner.php');
function out($s) { echo $s . PHP_EOL; }

foreach (['reapStaleJobs', 'scanBatch', 'batchTimeout'] as $fn) {
    $body = t_fn_body($sc, $fn, 'php');
    $len  = strlen($body);
    // The body must start at this function and must not contain another
    // function's declaration -- otherwise a needle could be satisfied by code
    // belonging to a different function, which is what the old 1800-char
    // window risked when the function was SHORTER than the window.
    $inner = preg_match_all('/^\s*(?:public|private|protected|static|\s)*function\s+(\w+)\s*\(/m',
                            $body, $m);
    out(sprintf('%-16s body=%5d chars, function declarations inside: %d (%s)',
        $fn, $len, $inner, implode(',', $m[1])));
}

out('');
$reap = t_fn_body($sc, 'reapStaleJobs', 'php');
foreach (['self::scanWorkerPids((int) $job', 'adopted the running worker',
          "status='interrupted'"] as $n) {
    out(sprintf('  reapStaleJobs contains %-34s %s',
        '"' . substr($n, 0, 30) . '"', strpos($reap, $n) !== false ? 'yes' : 'NO'));
}
$a = strpos($reap, 'scanWorkerPids'); $b = strpos($reap, "status='interrupted'");
out('  adoption at ' . $a . ' precedes the interrupted write at ' . $b . ': '
  . ($a < $b ? 'yes' : 'NO'));

out('');
$batch = t_fn_body($sc, 'scanBatch', 'php');
foreach (['timeout %d', 'self::batchTimeout()', '$rc === 124'] as $n) {
    out(sprintf('  scanBatch contains %-26s %s', '"' . $n . '"',
        strpos($batch, $n) !== false ? 'yes' : 'NO'));
}
out('  batchTimeout() body contains "scan_batch_timeout": '
  . (strpos(t_fn_body($sc, 'batchTimeout', 'php'), 'scan_batch_timeout') !== false ? 'yes' : 'NO'));

out('');
out('For comparison, what the OLD fixed windows would do to the code as it is now:');
$oldReap  = substr($sc, strpos($sc, 'public static function reapStaleJobs'), 1800);
$oldBatch = substr($sc, strpos($sc, 'private function scanBatch'), 1800);
out('  old 1800-char reap window still finds "status=\'interrupted\'": '
  . (strpos($oldReap, "status='interrupted'") !== false ? 'yes' : 'NO - it would now fail'));
out('  old 1800-char batch window still finds "scan_batch_timeout": '
  . (strpos($oldBatch, 'scan_batch_timeout') !== false ? 'yes' : 'NO - it would now fail'));
