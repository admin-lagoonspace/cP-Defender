<?php
/**
 * Bringing real-time monitoring back after a backup, without being asked.
 *
 * Two things were reported together: the monitor could not be turned on at all
 * once the backup had finished, and having to turn it on by hand is not
 * acceptable in the first place.
 *
 * The first was a real block. `stop()` gained `systemctl reset-failed` in
 * 3.30.1 but `start()` did not, so a unit sitting in 'failed' -- or one that
 * had hit systemd's start rate limit, which answers "start request repeated
 * too quickly" -- could not be started from the dashboard however many times
 * Start was pressed.
 *
 * The second is what the scheduler task is for. The daemon suspends its own
 * scanning during a backup, but a daemon that has been STOPPED cannot do
 * anything for itself: something outside it has to notice the backup has
 * finished and start it.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$rtm = t_code($repo . '/backend/lib/RealTimeMonitor.php');

// -- A failed or rate-limited unit must still be startable -------------------
$start = substr($rtm, strpos($rtm, 'public function start()'), 2600);
t_contains($start, 'systemctl reset-failed serverscrub-monitor',
    'starting clears a failed unit first');
t_contains($start, 'repeated too quickly',
    'and recognises systemd refusing on its start rate limit');

$resetPos = strpos($start, 'reset-failed');
$startPos = strpos($start, 'systemctl start serverscrub-monitor');
t_ok($resetPos !== false && $startPos !== false && $resetPos < $startPos,
    'the reset happens before the start, not after it has already failed');

// -- The probe answers from processes, not from the database -----------------
$probe = substr($rtm, strpos($rtm, 'public static function backupProcesses'), 2200);
t_contains($probe, "/proc", 'backup processes are found in /proc');
t_contains($probe, 'rt_backup_procs', 'using the configured process list');
// This asserted '/jetapps/' when it was written, which was the defect: every
// JetBackup process lives under that path, including the daemon that runs
// whether or not a backup is happening. The match must name a task.
t_contains($probe, 'JETBACKUP_JOB_HINTS',
    'a JetBackup job is matched by its task, not by the install path');
t_ok(strpos($probe, 'pgrep') === false,
    'without forking pgrep every 15 minutes for the life of the server');
t_contains($probe, "!== '*'",
    'a wildcard entry is rejected: it would make the server look permanently busy');

// The probe must never throw — it runs unattended from cron.
$found = RealTimeMonitor::backupProcesses();
t_ok(is_array($found), 'the probe returns a list even with no /proc to read');

// -- Auto-resume decisions ---------------------------------------------------
$m = new RealTimeMonitor();

Database::setSetting('rt_autostart_after_backup', '0');
$r = $m->autoResume();
t_eq(false, $r['acted'], 'nothing happens while auto-resume is switched off');
t_contains($r['reason'], 'disabled', 'and it says why');

// A deliberate stop is respected. Stopping the monitor when nothing is backing
// up is a decision, and a watchdog that overrules it is worse than no watchdog.
Database::setSetting('rt_autostart_after_backup', '1');
Database::setSetting('rt_manual_stop', '1');
$r = $m->autoResume();
t_eq(false, $r['acted'], 'a deliberate stop is left alone');
t_contains($r['reason'], 'deliberately', 'and named as such');

// -- Stopping during a backup is NOT a deliberate stop -----------------------
// This is the distinction the whole feature turns on: "off for the backup"
// must come back, "off because I said so" must not.
t_contains($rtm, 'function recordStopIntent', 'stopping records why it happened');
$intent = substr($rtm, strpos($rtm, 'function recordStopIntent'), 700);
t_contains($intent, 'self::backupProcesses()',
    'by checking whether a backup is running at that moment');
t_contains($intent, 'rt_manual_stop',
    'by writing the deliberate-stop flag');
t_contains($intent, '$backups ?',
    'whose value depends on whether a backup was running at the time');

$stop = substr($rtm, strpos($rtm, 'public function stop()'), 400);
t_contains($stop, 'recordStopIntent()', 'and stop() actually records it');

// Starting clears the flag: a person switching it on is intent too.
t_contains($start, "'rt_manual_stop', '0'",
    'a successful start clears the deliberate-stop flag');

// -- The task has to actually run from cron ----------------------------------
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "'rtguard' => [", 'the guard is a scheduled task');
t_contains($sched, 'autoResume()', 'which calls auto-resume');

// A task whose class is not loaded fatals in cron, and nothing would ever
// resume -- silently, since cron output goes to a log nobody reads.
t_contains($sched, "require_once SG_ROOT . '/backend/lib/RealTimeMonitor.php'",
    'and the scheduler requires the class it needs');

// The cadence must exist, or isDue() falls through to false and the task never
// runs -- indistinguishable from being switched off.
t_contains($sched, "case 'every':", "the 'every' cadence is implemented");
$due = substr($sched, strpos($sched, 'function isDue'), 1400);
t_contains($due, "case 'every':", 'inside isDue, where schedules are resolved');
t_contains($due, '$elapsed >= 60', 'with a floor so a double cron fire does not double-run');

// Cron fires the scheduler every 15 minutes, which is the requested cadence.
$install = file_get_contents($repo . '/install.sh');
t_contains($install, '*/15 * * * * root', 'cron runs the scheduler every 15 minutes');

// -- Defaults, or the feature ships switched off -----------------------------
$db = t_code($repo . '/backend/lib/Database.php');
t_contains($db, "'rt_autostart_after_backup', '1'", 'auto-resume is on by default');
t_contains($db, "'rt_autostart_schedule',     'every'", 'and checked every tick');
t_contains($db, "'rt_manual_stop',            '0'",
    'with no deliberate stop recorded on a fresh install');

// -- It is reachable from the UI ---------------------------------------------
$html = file_get_contents($repo . '/frontend/index.html');
$js   = file_get_contents($repo . '/frontend/js/app.js');
t_contains($html, 'id="set-rt-autostart"', 'the toggle exists');
t_contains($js, 'rt_autostart_after_backup:', 'and is saved with the monitor settings');
t_contains($js, "getElementById('set-rt-autostart')", 'and loaded into the form');


// -- An installed backup suite is not a running backup -----------------------
// The dashboard reported "Paused -- jetbackup" on a server with no backup
// running. JetBackup's daemon runs continuously, and both this probe and the
// Python detector matched it -- so monitoring was suspended permanently on
// every server with JetBackup installed, and auto-resume could never fire
// either, because the probe always saw a "backup".
t_contains($rtm, 'ALWAYS_ON_BACKUP_DAEMONS', 'always-on backup daemons are named');
t_contains($rtm, 'jetbackupd', 'including jetbackupd');
t_contains($rtm, 'jetbackup5d', 'and the JetBackup 5 daemon');

$probe2 = substr($rtm, strpos($rtm, 'public static function backupProcesses'), 2600);
t_ok(strpos($probe2, "'/jetapps/'") === false,
    'the bare install path is no longer treated as a running backup');
t_contains($probe2, 'JETBACKUP_JOB_HINTS',
    'a JetBackup match now requires a task, not an installation');
t_contains($probe2, 'isset($excl[$comm])', 'excluded daemons are skipped by name');
t_contains($probe2, 'rt_backup_exclude', 'and the exclusion list is configurable');

$db2 = t_code($repo . '/backend/lib/Database.php');
t_contains($db2, 'rt_backup_exclude', 'the exclusion list is seeded');
t_contains($db2, 'jetbackupd,jetbackup5d', 'with the always-on daemons in it');

// -- A suspension nothing corroborates must not be reported ------------------
// The flags live in the database and only the daemon writes them. A daemon
// killed while suspended never runs its resume path, so they persist for ever.
t_contains($rtm, 'function suspensionIsCurrent',
    'a stored suspension is checked before being believed');
$cur = substr($rtm, strpos($rtm, 'function suspensionIsCurrent'), 800);
t_contains($cur, 'if (!$daemonRunning) { return false; }',
    'nothing is suspended when the daemon is not running at all');
t_contains($cur, 'rt_backup_max_suspend_secs',
    'and a flag older than the maximum suspension is treated as stale');

// -- The pause must be checkable ---------------------------------------------
t_contains($rtm, 'rt_suspend_evidence',
    'the process that triggered the pause is reported');
$js2 = file_get_contents($repo . '/frontend/js/app.js');
t_contains($js2, 'd.suspend_evidence', 'and shown in the UI');

// -- The page has to refresh itself ------------------------------------------
// It loaded once when opened and then showed that snapshot until someone
// pressed Refresh -- so a state that changes on its own, which is the entire
// point of pausing and auto-resuming, was routinely wrong on screen.
t_contains($js2, 'function startMonitorPolling', 'the monitor page polls while it is open');
$poll = substr($js2, strpos($js2, 'function startMonitorPolling'), 900);
t_contains($poll, 'clearInterval', 'and stops polling when it is not');
t_contains($poll, '_monitorBusy', 'never mid-way through a start or stop');
t_contains($poll, 'document.hidden', 'and not in a background tab');
t_contains($js2, 'startMonitorPolling(name)', 'polling follows the visible page');
