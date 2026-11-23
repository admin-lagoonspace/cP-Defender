<?php
/**
 * SHAKAAL — the remaining fixed-character test windows, measured.
 *
 * Wasooli reports that fixing finding 10 moved test_monitor_autoresume.php:40's
 * needle from 2,241 to 2,007 inside a 2,200-char slice (so it now passes), and
 * that waitOutBackup/sleep(30) has 93 characters left. Both measured here off
 * t_code(), which is what the tests actually read.
 */
require_once '/opt/serverscrub-src/tests/assert.php';
function out($s) { echo $s . PHP_EOL; }

$rtm = t_code('/opt/serverscrub-src/backend/lib/RealTimeMonitor.php');
$sc  = t_code('/opt/serverscrub-src/backend/lib/Scanner.php');

out('-- test_monitor_autoresume.php:40  substr(backupProcesses, 2200) --');
$probe = substr($rtm, strpos($rtm, 'public static function backupProcesses'), 2200);
foreach (['rt_backup_procs', 'ALWAYS_ON_BACKUP_DAEMONS', 'JETBACKUP_JOB_HINTS',
          'comm', 'pidIsZombie'] as $n) {
    $p = strpos($probe, $n);
    printf("   %-26s %s\n", $n, $p === false ? 'OUTSIDE the window' : 'at ' . $p);
}
$last = 0;
foreach (['rt_backup_procs', 'ALWAYS_ON_BACKUP_DAEMONS'] as $n) {
    $p = strpos($probe, $n);
    if ($p !== false) { $last = max($last, $p + strlen($n)); }
}
out('   window 2200; furthest needle of interest ends at ' . $last
  . '; headroom ' . (2200 - $last));

out('');
out('-- test_monitor_autoresume.php:142  substr(backupProcesses, 2600) --');
$probe2 = substr($rtm, strpos($rtm, 'public static function backupProcesses'), 2600);
foreach (['JETBACKUP_JOB_HINTS', 'jetbackup', 'continue 2'] as $n) {
    $p = strpos($probe2, $n);
    printf("   %-26s %s\n", $n, $p === false ? 'OUTSIDE the window' : 'at ' . $p);
}

out('');
out('-- test_scan_concurrency.php:388  substr(waitOutBackup, 1600) --');
$wo = substr($sc, strpos($sc, 'function waitOutBackup'), 1600);
$end = 0;
foreach (['sleep(30)', 'scan_backup_max_wait', 'scan_paused_for_backup'] as $n) {
    $p = strpos($wo, $n);
    printf("   %-26s %s\n", $n, $p === false ? 'OUTSIDE the window' : 'at ' . $p);
    if ($p !== false) { $end = max($end, $p + strlen($n)); }
}
out('   window 1600; furthest needle ends at ' . $end . '; headroom ' . (1600 - $end));

out('');
out('-- does t_code() strip comments but keep their indentation? --');
$raw = file_get_contents('/opt/serverscrub-src/backend/lib/RealTimeMonitor.php');
out('   raw file     : ' . strlen($raw) . ' chars');
out('   after t_code : ' . strlen($rtm) . ' chars');
$blank = 0; $ws = 0;
foreach (explode("\n", $rtm) as $l) {
    if (trim($l) === '') { $blank++; $ws += strlen($l); }
}
out('   lines that are now whitespace-only: ' . $blank
  . ', carrying ' . $ws . ' chars of surviving indentation');
out('   => a comment INSIDE a sliced function still costs its indentation;');
out('      a docblock ABOVE the slice start costs nothing. Confirms the note.');
