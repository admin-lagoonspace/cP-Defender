<?php
/**
 * File integrity monitoring, exercised rather than inspected.
 *
 * Reported: "File integrity monitor is not working". The UI has a Create
 * Baseline button, a Run Check button and four stat tiles, the API routes all
 * exist and the scheduler has an integrity task -- so nothing about reading the
 * code says it is broken. The only way to find out is to take a baseline of a
 * real directory, tamper with it, and see whether the tampering is reported.
 *
 * Note on the fixture content: the "dropped" file deliberately contains no
 * webshell-like source. An earlier draft used a real eval($_POST[...]) payload
 * and Windows Defender quarantined this test file on write -- it existed on
 * disk but every read returned Permission denied. What integrity monitoring
 * detects is that a file appeared, not what is in it, so the payload was never
 * needed to prove anything.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$watch = $ctx['sandbox'] . '/site';
@mkdir($watch . '/sub', 0777, true);
file_put_contents($watch . '/index.php',  '<?php echo "hello";');
file_put_contents($watch . '/config.php', '<?php $db = 1;');
file_put_contents($watch . '/sub/lib.php', '<?php // helper');

$fi = new FileIntegrity();

// -- Baseline ----------------------------------------------------------------
$b = $fi->createBaseline($watch, 'test');
t_ok(($b['success'] ?? false) === true || ($b['files'] ?? 0) > 0,
    'a baseline can be created');
t_ok(($b['files'] ?? 0) >= 3, 'it walks subdirectories (' . ($b['files'] ?? 0) . ' files)');

t_ok(count($fi->getWatchedPaths()) >= 1, 'the baselined path is reported as watched');

$stats = $fi->getStats();
t_ok(($stats['total_monitored'] ?? 0) >= 3,
    'the monitored count reflects the baseline (' . ($stats['total_monitored'] ?? 0) . ')');

// -- A clean re-check must report nothing ------------------------------------
// A monitor that cries wolf on an untouched tree is worse than none.
$clean = $fi->runCheck($watch);
t_eq(0, (int)($clean['changed'] ?? -1), 'an untouched tree reports no changes');

// -- Now tamper --------------------------------------------------------------
file_put_contents($watch . '/index.php', '<?php echo "TAMPERED";');
file_put_contents($watch . '/dropped.php', '<?php // a file that was not here before');
unlink($watch . '/config.php');

$c = $fi->runCheck($watch);
t_ok(($c['changed'] ?? 0) >= 3,
    'modification, addition and deletion are all detected (' . ($c['changed'] ?? 0) . ')');

$byStatus = [];
foreach ($fi->getChanges('') as $row) {
    $byStatus[$row['status'] ?? '?'][] = basename($row['file_path'] ?? '');
}

t_ok(in_array('index.php', $byStatus['modified'] ?? [], true),
    'the edited file is reported as modified');
t_ok(in_array('dropped.php', $byStatus['new'] ?? [], true),
    'the dropped file is reported as new');
t_ok(in_array('config.php', $byStatus['missing'] ?? [], true),
    'the deleted file is reported as missing');

// -- The stats the dashboard reads must move ---------------------------------
// The tiles are the only thing most operators will look at; if they stay at
// zero while changes exist, the module reads as broken whatever the table says.
$after = $fi->getStats();
t_ok(($after['modified'] ?? 0) >= 1, 'the modified tile is non-zero');
t_ok((($after['new_files'] ?? 0) + ($after['missing'] ?? 0)) >= 2,
    'the issues tile counts new and missing files');

// -- Filtering, which the page's four buttons depend on ----------------------
foreach (['modified', 'new', 'missing'] as $status) {
    $rows = $fi->getChanges($status);
    t_ok(count($rows) >= 1, "getChanges('$status') returns only that status");
    $wrong = array_filter($rows, fn($r) => ($r['status'] ?? '') !== $status);
    t_eq(0, count($wrong), "getChanges('$status') does not leak other statuses");
}

// -- Acknowledging clears a row from the operator's queue --------------------
$first = $fi->getChanges('modified')[0] ?? null;
t_ok($first !== null, 'there is a change to acknowledge');
if ($first) {
    t_ok($fi->acknowledgeChange((int)$first['id']), 'a change can be acknowledged');
}

// -- It has to be scheduled, or it only runs when a button is pressed --------
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "'integrity' => [", 'the integrity check is scheduled');
t_contains($sched, 'FileIntegrity())->runCheck', 'the scheduled task actually runs a check');

// -- And reachable from the API the page calls -------------------------------
$api = t_code($repo . '/backend/api/index.php');
foreach (['stats', 'baseline', 'check', 'changes', 'paths'] as $route) {
    t_contains($api, "'" . $route . "'", "integrity/$route is routed");
}
