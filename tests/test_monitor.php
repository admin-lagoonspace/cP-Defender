<?php
/**
 * Real-Time Monitor status.
 *
 * Reported symptom: the Real-Time Monitor page and its dashboard card do not
 * work; the card showed "Active" with "Watching ..." and every counter blank.
 *
 * Three faults, all in how status was determined:
 *
 *   1. `service_active` was actually isServiceEnabled(). Enabled means "starts
 *      at boot", not "running now" — so a dead monitor displayed as Active.
 *   2. isRunning() trusted only the PID file. It lives in /var/run (tmpfs), the
 *      daemon writes it itself, and a crash leaves it stale. Systemd is the
 *      authority for a unit it manages and was never consulted.
 *   3. A daemon can run and do nothing — wrong watch paths, a dead loop,
 *      inotify watches exhausted. Nothing measured that, so the UI could only
 *      show a green badge beside counters that never moved.
 *
 * exec() was called directly throughout, making all of it untestable. The
 * command runner is injectable now, so these paths run without systemd.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';

$sandbox = $ctx['sandbox'];
$pidFile     = $sandbox . '/monitor.pid';
$serviceFile = $sandbox . '/monitor.service';
$paths = ['pid' => $pidFile, 'service' => $serviceFile,
          'log' => $sandbox . '/logs/monitor.log',
          'daemon' => $sandbox . '/monitor.py'];

/** A fake systemctl. */
function fake_exec(array $answers): callable
{
    return function (string $cmd) use ($answers): array {
        foreach ($answers as $needle => $reply) {
            if (strpos($cmd, $needle) !== false) {
                return [[$reply], $reply === '' ? 1 : 0];
            }
        }
        return [[], 1];
    };
}

// ── Enabled is not running ───────────────────────────────────────────────────
file_put_contents($serviceFile, "[Unit]\n");
@unlink($pidFile);

$enabledButDead = new RealTimeMonitor($paths, fake_exec([
    'is-enabled' => 'enabled',
    'is-active'  => 'inactive',
]));

$st = $enabledButDead->getStatus();
t_eq(true,  $st['service_enabled'], 'an enabled unit reports service_enabled');
t_eq(false, $st['service_active'],  'an inactive unit is NOT reported as active');
t_eq(false, $st['running'],         'an enabled-but-dead monitor is not "running"');

// The exact regression: these two must not be the same value.
t_ok($st['service_enabled'] !== $st['service_active'],
    'service_enabled and service_active are distinct');

// ── Systemd is consulted when the PID file is missing ────────────────────────
// The daemon writes its own PID file into tmpfs. Losing it must not make a
// running monitor look stopped.
$activeNoPid = new RealTimeMonitor($paths, fake_exec([
    'is-enabled' => 'enabled',
    'is-active'  => 'active',
]));
t_eq(true, $activeNoPid->isRunning(),
    'a running unit is detected even with no PID file');
t_eq(true, $activeNoPid->getStatus()['running'],
    'getStatus() agrees the monitor is running');

// ── A stale PID file must not fake a running daemon ──────────────────────────
// PID 999999 will not exist; with systemd also reporting inactive, the answer
// must be "not running".
file_put_contents($pidFile, "999999\n");
$stalePid = new RealTimeMonitor($paths, fake_exec([
    'is-enabled' => 'enabled',
    'is-active'  => 'inactive',
]));
t_eq(false, $stalePid->isRunning(), 'a stale PID file does not report as running');
@unlink($pidFile);

// ── No unit installed at all ─────────────────────────────────────────────────
@unlink($serviceFile);
$notInstalled = new RealTimeMonitor($paths, fake_exec(['is-active' => 'active']));
t_eq(false, $notInstalled->getStatus()['service_installed'],
    'a missing unit file is reported as not installed');
t_eq(false, $notInstalled->isServiceActive(),
    'systemd is not consulted for a unit that was never installed');

// ── Staleness: running but doing nothing ─────────────────────────────────────
file_put_contents($serviceFile, "[Unit]\n");
$running = new RealTimeMonitor($paths, fake_exec([
    'is-enabled' => 'enabled', 'is-active' => 'active',
]));

Database::setSetting('rt_last_activity', (string) (time() - 10));
$fresh = $running->getStatus();
t_eq(false, $fresh['stale'], 'recent activity is not stale');
t_ok($fresh['last_activity_age'] < 60, 'last_activity_age is measured in seconds');

Database::setSetting('rt_last_activity', (string) (time() - 7200));
t_eq(true, $running->getStatus()['stale'],
    'a monitor silent for two hours is reported stale');

// A monitor that has never reported anything is stale too — that is precisely
// the "Active, all counters zero" case from the dashboard.
Database::query("DELETE FROM settings WHERE key = 'rt_last_activity'");
$never = $running->getStatus();
t_eq(null, $never['last_activity'], 'no activity yet reports null, not 0');
t_eq(true, $never['stale'],         'a monitor that never reported anything is stale');

// ── The dashboard card reads the same truth ──────────────────────────────────
$dash = $running->getDashboardStats();
foreach (['running', 'stale', 'engine', 'files_checked', 'detections_24h'] as $k) {
    t_ok(array_key_exists($k, $dash), "dashboard stats include {$k}");
}
t_eq($running->getStatus()['running'], $dash['running'],
    'the card and the page cannot disagree about running');
