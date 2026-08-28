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

/**
 * A fake systemctl.
 *
 * Answers `systemctl show -p ActiveState -p SubState -p NRestarts`, which is
 * what the code asks now. `is-active` alone could not distinguish a running
 * daemon from one being restarted in a loop -- and a crash loop reporting
 * "active" is exactly how "Monitor started" was displayed over a daemon that
 * had already died.
 *
 * @param string $state    ActiveState (active, inactive, failed)
 * @param string $sub      SubState    (running, auto-restart, dead)
 */
function fake_systemd(string $state, string $sub, int $restarts = 0, string $enabled = 'enabled'): callable
{
    return function (string $cmd) use ($state, $sub, $restarts, $enabled): array {
        if (strpos($cmd, 'systemctl show') !== false) {
            return [[
                'ActiveState=' . $state,
                'SubState=' . $sub,
                'NRestarts=' . $restarts,
            ], 0];
        }
        if (strpos($cmd, 'is-enabled') !== false) {
            return [[$enabled], 0];
        }
        if (strpos($cmd, 'tail') !== false || strpos($cmd, 'journalctl') !== false) {
            return [['(no log)'], 0];
        }
        // `systemctl start` exits 0 as soon as the process is LAUNCHED, whether
        // or not it survives. That is the whole reason start() has to confirm
        // afterwards, so the fake must reproduce it.
        if (strpos($cmd, 'systemctl start') !== false
            || strpos($cmd, 'systemctl stop') !== false) {
            return [[], 0];
        }
        return [[], 1];
    };
}

// ── Enabled is not running ───────────────────────────────────────────────────
file_put_contents($serviceFile, "[Unit]\n");
@unlink($pidFile);

$enabledButDead = new RealTimeMonitor($paths, fake_systemd('inactive', 'dead'));

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
$activeNoPid = new RealTimeMonitor($paths, fake_systemd('active', 'running'));
t_eq(true, $activeNoPid->isRunning(),
    'a running unit is detected even with no PID file');
t_eq(true, $activeNoPid->getStatus()['running'],
    'getStatus() agrees the monitor is running');

// ── A stale PID file must not fake a running daemon ──────────────────────────
// PID 999999 will not exist; with systemd also reporting inactive, the answer
// must be "not running".
file_put_contents($pidFile, "999999\n");
$stalePid = new RealTimeMonitor($paths, fake_systemd('inactive', 'dead'));
t_eq(false, $stalePid->isRunning(), 'a stale PID file does not report as running');
@unlink($pidFile);

// ── No unit installed at all ─────────────────────────────────────────────────
@unlink($serviceFile);
$notInstalled = new RealTimeMonitor($paths, fake_systemd('active', 'running'));
t_eq(false, $notInstalled->getStatus()['service_installed'],
    'a missing unit file is reported as not installed');
t_eq(false, $notInstalled->isServiceActive(),
    'systemd is not consulted for a unit that was never installed');

// ── Staleness: running but doing nothing ─────────────────────────────────────
file_put_contents($serviceFile, "[Unit]\n");
$running = new RealTimeMonitor($paths, fake_systemd('active', 'running'));

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

// ── Resource profile is visible and persists ─────────────────────────────────
// Real-time monitoring was reported as putting excessive load on a live server.
// The limits are settings now, so they must survive a round trip and be visible
// in status — an administrator calming a server down needs to see what took
// effect, not what they hoped would.
Database::setSetting('rt_profile', 'light');
Database::setSetting('rt_effective_profile', 'light');
Database::setSetting('rt_effective_files_per_sec', '5');
Database::setSetting('rt_watch_count', '4200');
Database::setSetting('rt_watch_capped', '1');

$st2 = $running->getStatus();
t_eq('light', $st2['profile'],            'the configured profile is reported');
t_eq('light', $st2['effective_profile'],  'the profile the daemon applied is reported');
t_eq(5,       $st2['effective_rate'],     'the effective file rate is reported');
t_eq(4200,    $st2['watch_count'],        'the inotify watch count is reported');
t_eq(true,    $st2['watch_capped'],       'hitting the watch ceiling is reported');

// The UI must offer the control, or the setting is unreachable.
$html = file_get_contents(dirname(__DIR__) . '/frontend/index.html');
t_contains($html, 'set-rt-profile', 'Settings exposes a resource profile control');
foreach (['light', 'balanced', 'thorough', 'custom'] as $prof) {
    t_contains($html, 'data-profile="' . $prof . '"', "the {$prof} profile is offered");
}

$appjs = file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
t_contains($appjs, 'rt_max_files_per_sec', 'the file rate is saved with the settings form');
t_contains($appjs, 'rt_exclude_dirs',      'directory exclusions are saved');

// settings/set only persists keys matching ^[a-z_]+$ — every key the form sends
// must actually be storable, or it is silently dropped.
foreach (['rt_profile', 'rt_max_files_per_sec', 'rt_max_file_size_mb', 'rt_nice',
          'rt_max_watches', 'rt_debounce_seconds', 'rt_exclude_dirs'] as $key) {
    t_ok(preg_match('/^[a-z_]+$/', $key) === 1,
        "setting key {$key} is accepted by settings/set");
}

// ── A crash loop is not "running" ────────────────────────────────────────────
// The daemon died on its first line (logging.basicConfig(force=) needs Python
// 3.8; the server has 3.6). systemd relaunched it on a loop, `systemctl start`
// returned 0 because the process HAD launched, and `is-active` answered
// "active" throughout -- so the dashboard reported "Monitor started" over
// something that had never worked.
$looping = new RealTimeMonitor($paths, fake_systemd('activating', 'auto-restart', 7));
t_eq(false, $looping->isServiceActive(), 'a unit in auto-restart is not "active"');
t_eq(false, $looping->isRunning(),       'a crash-looping daemon is not running');

$st3 = $looping->getStatus();
t_eq(true, $st3['crash_looping'], 'a crash loop is reported as such');
t_eq(7,    $st3['restarts'],      'the restart count is reported');

// A failed start must explain itself rather than returning success.
// start() checks for the daemon script first -- correctly -- so both it and the
// unit file have to exist for the systemd branch to be reached at all.
file_put_contents($paths['daemon'], "#!/usr/bin/env python3
print('x')
");
file_put_contents($serviceFile, "[Unit]
");

$failStart = new RealTimeMonitor($paths, fake_systemd('activating', 'auto-restart', 3));
$r = $failStart->start();
t_eq(false, $r['success'] ?? true, 'start() reports failure when the daemon does not stay up');
t_contains((string)($r['error'] ?? ''), 'did not stay running',
    'the failure says the service did not stay running');
t_contains((string)($r['error'] ?? ''), 'restarts',
    'the failure includes the restart count');
t_contains((string)($r['error'] ?? ''), 'Last log lines',
    'the failure includes what the daemon logged');

// The healthy path still succeeds.
$okStart = new RealTimeMonitor($paths, fake_systemd('active', 'running'));
$r2 = $okStart->start();
t_eq(true, $r2['success'] ?? false, 'start() succeeds when the daemon stays up');

// ── The daemon must run on the Python the servers actually have ──────────────
// cPanel runs on RHEL-family hosts, which ship Python 3.6. The test suite runs
// on the developer's Python, which is far newer -- so it proved nothing about
// the customer's interpreter until this check existed.
$compat = [];
$rc = 0;
@exec(escapeshellarg(PHP_BINARY) . ' -r "echo 1;" >/dev/null 2>&1', $compat, $rc);
$py = null;
foreach ([dirname(__DIR__) . '/python/python.exe', 'python3', 'python'] as $cand) {
    if (strpos($cand, '/') !== false ? is_file($cand) : true) { $py = $cand; break; }
}
if ($py) {
    $out = [];
    $code = 0;
    @exec(escapeshellarg($py) . ' ' . escapeshellarg(dirname(__DIR__) . '/scripts/check-python-compat.py')
          . ' 3.6 2>&1', $out, $code);
    t_eq(0, $code, 'the daemon is compatible with Python 3.6: ' . implode(' ', array_slice($out, 1, 2)));
} else {
    t_ok(false, 'no Python available to run the compatibility check');
}
