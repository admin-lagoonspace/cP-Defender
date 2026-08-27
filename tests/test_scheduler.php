<?php
/**
 * Scheduled work, and the events it produces.
 *
 * Reported symptoms: Bot Shield "not working", Security Events "might not work
 * as well", CMS Guard showing zero.
 *
 * The cause was not in any of those modules. The cron dispatcher ran exactly
 * three tasks — scan, sigs, iprep. CMS Guard, Bot Shield, rootkit and file
 * integrity were never run by anything. Each of their panels reads a database
 * table, and nothing wrote to those tables unless a human pressed a button, so
 * they showed zero for ever and read as broken features.
 *
 * Security Events had a second problem: only two writers existed in the entire
 * codebase (a failed login, one firewall path), so the page was empty even on a
 * server actively finding malware.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── Every module with a panel must be scheduled ──────────────────────────────
$sched = t_code($repo . '/backend/cron/scheduler.php');

foreach (['scan', 'sigs', 'iprep', 'cmsguard', 'botshield', 'rootkit', 'integrity'] as $task) {
    t_contains($sched, "'{$task}' => [", "task '{$task}' is registered with the scheduler");
}

// A task whose class is never required is a fatal on the first cron run, and
// nothing would report it until a panel had been empty for a week.
foreach (['CMSGuard', 'BotShield', 'RootkitScanner', 'FileIntegrity'] as $cls) {
    t_contains($sched, "/backend/lib/{$cls}.php", "scheduler requires {$cls}");
}

// ── The tasks' methods must exist ────────────────────────────────────────────
// (new FileIntegrity())->checkAll() was written here and does not exist. The
// static call checker did not cover instance calls at the time; it does now,
// and this asserts the specific methods the scheduler depends on.
t_ok(method_exists('CMSGuard', 'scanInstalls'),      'CMSGuard::scanInstalls() exists');
t_ok(method_exists('BotShield', 'runAnalysis'),      'BotShield::runAnalysis() exists');
t_ok(method_exists('RootkitScanner', 'runScan'),     'RootkitScanner::runScan() exists');
t_ok(method_exists('FileIntegrity', 'runCheck'),     'FileIntegrity::runCheck() exists');
t_ok(!method_exists('FileIntegrity', 'checkAll'),    'FileIntegrity::checkAll() does not exist (the bug)');
t_ok(method_exists('RootkitEngine', 'scan'),         'RootkitEngine::scan() exists as a fallback');

// ── Security Events must have real writers ───────────────────────────────────
// Count call sites rather than asserting a number: the point is that detection
// paths report, not that there are exactly N of them.
$writers = 0;
foreach (glob($repo . '/backend/lib/*.php') as $lib) {
    $writers += substr_count(t_code($lib), 'Logger::event(');
}
t_ok($writers >= 2, "detection paths raise security events (found {$writers} call sites)");

$scannerSrc = t_code($repo . '/backend/lib/Scanner.php');
t_contains($scannerSrc, "Logger::event(", 'the scanner reports detections as events');
t_contains($scannerSrc, "'malware_detected'", 'malware detections use a malware_detected event type');

$botSrc = t_code($repo . '/backend/lib/BotShield.php');
t_contains($botSrc, "'bot_blocked'", 'bot blocks are reported as events');

// ── Logger::event actually persists ──────────────────────────────────────────
// The page reads security_events; if the writer is broken the wiring above is
// worthless.
$before = (int) (Database::fetchOne("SELECT COUNT(*) c FROM security_events")['c'] ?? 0);
Logger::event('test_event', 'high', '203.0.113.9', '/tmp/x', 'unit test event');
$after = (int) (Database::fetchOne("SELECT COUNT(*) c FROM security_events")['c'] ?? 0);
t_eq($before + 1, $after, 'Logger::event() writes a row to security_events');

$row = Database::fetchOne(
    "SELECT * FROM security_events WHERE type = 'test_event' ORDER BY id DESC LIMIT 1"
);
t_ok($row !== null, 'the event can be read back');
if ($row) {
    t_eq('high',        $row['severity'],    'severity is stored');
    t_eq('203.0.113.9', $row['source_ip'],   'source IP is stored');
    t_contains((string)$row['description'], 'unit test event', 'description is stored');
}

// ── The scheduler is dispatched often enough to honour an hourly task ────────
// Bot Shield is hourly because log lines age out: a bot seen only in yesterday's
// rotated access log cannot be acted on at all.
$install = file_get_contents($repo . '/install.sh');
t_ok(preg_match('~\*/(\d+)\s+\*\s+\*\s+\*\s+\*.*scheduler\.php~', $install, $m) === 1,
    'cron dispatches the scheduler on a sub-hourly interval');
if (!empty($m[1])) {
    t_ok((int)$m[1] <= 60, "dispatcher runs every {$m[1]} minutes, so hourly tasks can fire");
}
