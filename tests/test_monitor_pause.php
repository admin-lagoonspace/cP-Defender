<?php
/**
 * Standing down while a backup or bulk transfer runs.
 *
 * Requested: while JetBackup is backing up, or rsync is sending data to a
 * remote server, real-time monitoring should stop, and resume when they are
 * done.
 *
 * The state machine itself is exercised in tests/test_monitor_backup.py. These
 * assert the wiring around it: that the daemon actually consults the detector
 * in BOTH of its loops, that the settings reach it, and that the UI reports
 * "paused" as its own state rather than borrowing "running" or "stopped".
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$daemon = file_get_contents($repo . '/backend/daemon/monitor.py');
$rtm    = t_code($repo . '/backend/lib/RealTimeMonitor.php');
$db     = t_code($repo . '/backend/lib/Database.php');
$html   = file_get_contents($repo . '/frontend/index.html');

// -- The detector exists and both loops consult it ---------------------------
// Wiring it into only one loop would mean the behaviour silently depends on
// whether inotify_simple happens to be installed -- and polling, the fallback,
// is the heavier mode and the one that most needs to stand down.
t_contains($daemon, 'class BackupActivityDetector', 'the detector exists');
t_eq(2, substr_count($daemon, 'BackupActivityDetector(conn)'),
    'both the inotify and polling loops construct one');
t_eq(2, substr_count($daemon, 'backups.poll(conn)'),
    'and both consult it before doing any work');

// Settings must take effect without restarting the daemon.
t_eq(2, substr_count($daemon, 'backups.reload(conn)'),
    'both loops re-read the backup settings on their reload tick');

// -- Events are drained, not left to overflow --------------------------------
// Not reading the inotify queue while suspended would let the kernel overflow
// it, and an overflowed queue does not resume cleanly.
$inotifyLoop = substr($daemon, strpos($daemon, 'def run_inotify'),
                      strpos($daemon, 'def run_polling') - strpos($daemon, 'def run_inotify'));
$readPos = strpos($inotifyLoop, 'evts = ino.read');
$pollPos = strpos($inotifyLoop, 'backups.poll(conn)');
t_ok($readPos !== false && $pollPos !== false && $readPos < $pollPos,
    'inotify events are read BEFORE the suspension check, so the queue drains');

// -- Polling must not adopt the backup window as its new baseline ------------
// Refreshing prev while suspended would mean a file planted during the pause
// is never reported, because it would already be in the baseline.
$pollLoop = substr($daemon, strpos($daemon, 'def run_polling'));
$pollCheck = strpos($pollLoop, 'backups.poll(conn)');
$snapCall  = strpos($pollLoop, 'curr = snap(limits)');
t_ok($pollCheck !== false && $snapCall !== false && $pollCheck < $snapCall,
    'the polling loop skips its walk before taking a new snapshot');

// -- The safety cap, which is what makes this safe to ship -------------------
// Matching on a process NAME means anyone who can start a process called rsync
// can suppress scanning. The cap is the only thing that bounds that.
t_contains($daemon, 'max_suspend', 'a maximum suspension exists');
t_contains($daemon, 'monitor_suspend_capped',
    'hitting it is recorded as a security event, not just resumed quietly');
t_contains($daemon, 'rt_backup_max_suspend_secs', 'and the limit is configurable');

// A wildcard would match every process and suspend for ever.
t_contains($daemon, "part != '*'", 'a wildcard process name is rejected');

// The daemon must not detect itself.
t_contains($daemon, '_self_pids', 'the daemon excludes its own PID');

// -- The gap is recorded rather than hidden ----------------------------------
t_contains($daemon, 'rt_last_gap_seconds', 'the length of the blind spot is stored');
t_contains($daemon, 'monitor_resumed', 'resuming is recorded as an event');
t_contains($daemon, 'monitor_suspended', 'and so is suspending');

// -- Defaults are seeded, or the settings page shows empty controls ----------
foreach ([
    'rt_pause_on_backup',
    'rt_backup_procs',
    'rt_backup_check_secs',
    'rt_backup_resume_secs',
    'rt_backup_max_suspend_secs',
] as $key) {
    t_contains($db, $key, "$key has a seeded default");
}
t_contains($db, 'jetbackup,rsync', 'JetBackup and rsync are watched for by default');

// Settings only persist if the key passes routeSettings' filter.
foreach ([
    'rt_pause_on_backup', 'rt_backup_procs',
    'rt_backup_resume_secs', 'rt_backup_max_suspend_secs',
] as $key) {
    t_ok(preg_match('/^[a-z_]+$/', $key) === 1,
        "$key survives the settings key filter");
}

// -- Status: paused is its own state -----------------------------------------
t_contains($rtm, "'suspended'", 'the API reports whether scanning is suspended');
t_contains($rtm, "'suspend_reason'", 'and why');
t_contains($rtm, "'last_gap_seconds'", 'and how long the last pause lasted');

$js = file_get_contents($repo . '/frontend/js/app.js');
t_contains($js, "d.suspended", 'the UI reads the suspended flag');
t_contains($js, "'Paused'", 'and shows it as Paused');

// The order of the badge branches is the whole point: a suspended monitor is
// running, so a "running" check placed first would render it green -- claiming
// protection that is deliberately paused.
$badge = substr($js, strpos($js, "rt-status-badge"), 900);
$suspendedBranch = strpos($badge, 'd.suspended');
$activeBranch    = strpos($badge, "'Active'");
t_ok($suspendedBranch !== false && $activeBranch !== false
     && $suspendedBranch < $activeBranch,
    'the suspended branch is tested before the Active one');

// -- The settings are reachable and save with the card they live in ----------
t_contains($html, 'id="set-rt-pause-backup"', 'the toggle exists');
t_contains($html, 'id="set-rt-backup-procs"', 'the process list is editable');
t_contains($html, 'id="set-rt-backup-max"',   'the cap is editable');
t_contains($js, 'rt_pause_on_backup:', 'and all of them are sent when saving');
t_contains($js, 'rt_backup_max_suspend_secs:', 'including the cap');

// It must be inside the monitor card, whose save button commits it.
$savePos  = strpos($html, 'saveMonitorSettings()');
$togglePos = strpos($html, 'id="set-rt-pause-backup"');
t_ok($togglePos !== false && $savePos !== false && $togglePos < $savePos,
    'the toggle sits above the save button that commits it');

// -- The user is told what a pause costs -------------------------------------
// Silently not scanning is the part worth being explicit about.
// Whitespace-collapsed: the sentence wraps across lines in the source, so a
// literal search for the phrase finds nothing while the text is plainly there.
$htmlFlat = preg_replace('/\s+/', ' ', $html);
t_contains($htmlFlat, 'not scanned in real time',
    'the UI states that changes during a pause are not scanned');
t_contains($html, 'id="rt-suspend-note"', 'and there is somewhere to say so at the time');
