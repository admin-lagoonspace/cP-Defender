<?php
$sc = file_get_contents('/opt/serverscrub-src/backend/lib/Scanner.php');
$reap = substr($sc, strpos($sc, 'public static function reapStaleJobs'), 1800);
$needles = ['self::scanWorkerPids((int) $job', 'adopted the running worker', "status='interrupted'"];
$end = 0;
foreach ($needles as $n) {
    $p = strpos($reap, $n);
    printf("%-34s %s\n", substr($n, 0, 32), $p === false ? 'NOT FOUND' : 'at ' . $p);
    if ($p !== false) { $end = max($end, $p + strlen($n)); }
}
echo "window 1800 chars; last needle ends at {$end}; headroom " . (1800 - $end) . " chars\n";
