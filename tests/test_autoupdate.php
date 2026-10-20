<?php
/**
 * Automatic updates — the policy, not the mechanics.
 *
 * update.sh already knows how to apply a release and roll one back. What is
 * tested here is the decision to run it at all, because that decision replaces
 * the security software on a production server with nobody watching.
 *
 * Every assertion below is a refusal. The yes case is one line; the rest of
 * the file is the conditions under which this must NOT touch a live server.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

$state = Updater::STATE_FILE;

/** Reset to a clean, update-available baseline. */
$baseline = function () {
    Database::setSetting('auto_update',             '1');
    Database::setSetting('auto_update_major',       '0');
    Database::setSetting('auto_update_failures',    '0');
    Database::setSetting('auto_update_last_fail',   '0');
    Database::setSetting('auto_update_seen_at',     '0');
};
$baseline();

/** A cached status standing in for UpdateChecker, so no network is touched. */
$avail = function (string $from, string $to): array {
    return ['update_available' => version_compare($to, $from, '>'),
            'current_version'  => $from, 'latest_version' => $to];
};

// ── Defaults ────────────────────────────────────────────────────────────────
//
// On by default, and that is the point of the feature: there was already a
// daily update CHECK that cached a notice and did nothing, so servers sat on
// old versions behind a badge nobody read.

t_eq(true, Updater::autoEnabled(),
     'automatic updating is on by default');
t_eq(false, Updater::autoMajorEnabled(),
     'but major versions are NOT applied automatically by default');

// ── It applies a patch and a minor ──────────────────────────────────────────

$d = Updater::shouldApply($avail('4.5.1', '4.6.0'));
t_eq(true, $d['go'], 'a minor update is applied');
t_contains($d['reason'], '4.6.0', 'and the reason names the version');

$d = Updater::shouldApply($avail('4.6.0', '4.6.1'));
t_eq(true, $d['go'], 'so is a patch');

// ── Refusals ────────────────────────────────────────────────────────────────

// A MAJOR bump. X is reserved in this product's versioning for a breaking
// change; installing one unattended is how a security tool becomes the outage.
$d = Updater::shouldApply($avail('4.6.0', '5.0.0'));
t_eq(false, $d['go'], 'a major update is refused by default');
t_contains($d['reason'], 'major', 'and says that is why');
t_contains($d['reason'], 'yourself', 'and tells the operator it is theirs to do');

t_eq(true, Updater::majorBump('4.9.9', '5.0.0'), '4.9.9 -> 5.0.0 is a major bump');
t_eq(false, Updater::majorBump('4.5.1', '4.6.0'), '4.5.1 -> 4.6.0 is not');

// ...unless explicitly opted in.
Database::setSetting('auto_update_major', '1');
t_eq(true, Updater::shouldApply($avail('4.6.0', '5.0.0'))['go'],
     'a major update IS applied once the operator opts in');
Database::setSetting('auto_update_major', '0');

// Switched off.
Database::setSetting('auto_update', '0');
$d = Updater::shouldApply($avail('4.5.1', '4.6.0'));
t_eq(false, $d['go'], 'nothing happens when the feature is off');
t_contains($d['reason'], 'switched off', 'and says so');
Database::setSetting('auto_update', '1');

// Nothing to do. "Up to date" must be a stated reason, not silence: a task
// that logs nothing is indistinguishable from a task that never ran, which is
// how several modules in this product sat broken for months.
$d = Updater::shouldApply($avail('4.6.0', '4.6.0'));
t_eq(false, $d['go'], 'an up-to-date server is left alone');
t_contains($d['reason'], 'latest', 'with a reason given rather than silence');

// A lower "latest" than installed — a rolled-back channel must never
// downgrade a server.
$d = Updater::shouldApply(['update_available' => true,
                           'current_version' => '4.6.0', 'latest_version' => '4.5.1']);
t_eq(false, $d['go'], 'a channel offering an OLDER version never downgrades');

// ── Failure backoff ─────────────────────────────────────────────────────────
//
// Each attempt rsyncs over the install directory of a live server, so a retry
// loop is not harmless.

Database::setSetting('auto_update_failures',  '1');
Database::setSetting('auto_update_last_fail', (string)time());
$d = Updater::shouldApply($avail('4.5.1', '4.6.0'));
t_eq(false, $d['go'], 'it backs off immediately after a failure');
t_contains($d['reason'], 'backing off', 'and says it is backing off');
t_contains($d['reason'], 'minute', 'and when it will try again');

// Once the window has passed it tries again.
Database::setSetting('auto_update_last_fail', (string)(time() - 7200));
t_eq(true, Updater::shouldApply($avail('4.5.1', '4.6.0'))['go'],
     'and tries again once the backoff window has passed');

// Three strikes: stop, and tell someone. A daily retry of an update that
// cannot work is a daily rsync over a production install directory.
Database::setSetting('auto_update_failures',  '3');
Database::setSetting('auto_update_last_fail', (string)(time() - 86400));
$d = Updater::shouldApply($avail('4.5.1', '4.6.0'));
t_eq(false, $d['go'], 'after three failures it stops trying');
t_contains($d['reason'], 'paused', 'and says it has paused');
t_contains($d['reason'], 'update.log', 'and names the log to read');
t_eq(3, Updater::failureCount(), 'the counter is readable');

// The operator can resume once they have looked.
Updater::clearFailures();
t_eq(0, Updater::failureCount(), 'clearing the counter resumes it');
t_eq(true, Updater::shouldApply($avail('4.5.1', '4.6.0'))['go'],
     'and the next check applies the update');

// ── Never while work is in progress ─────────────────────────────────────────
//
// update.sh rsyncs over the install directory with --delete, which would pull
// the scanner's own code out from under a worker mid-walk.

// No worker_pid, and started just now: jobWorkerAlive() takes its grace-period
// branch, which is the one path that does not depend on being able to inspect a
// live process. processAlive() needs /proc or posix_kill, so a pid-based
// fixture would pass on Linux and silently reap itself anywhere else -- and a
// guard that tests green because its fixture evaporated is worse than no test.
$job = Database::insert('scan_jobs', [
    'status' => 'running', 'scan_type' => 'quick', 'scan_path' => '/home',
    'started_at' => time(),
]);
t_ok(Scanner::activeScan() !== null,
     'the fixture scan really is seen as running, on any platform');
$d = Updater::shouldApply($avail('4.5.1', '4.6.0'));
t_eq(false, $d['go'], 'it refuses while a scan is running');
t_contains($d['reason'], 'scan', 'and says a scan is why');
Database::query("UPDATE scan_jobs SET status = 'completed' WHERE id = ?", [$job]);

t_eq(true, Updater::shouldApply($avail('4.5.1', '4.6.0'))['go'],
     'and proceeds once the scan has finished');

// ── A live run blocks a second one ──────────────────────────────────────────

@mkdir(dirname($state), 0755, true);
$wrote = @file_put_contents($state, json_encode([
    'status' => 'running', 'phase' => 'rsync', 'percent' => 60,
    'message' => 'Copying files', 'from_version' => '4.5.1',
    'to_version' => '4.6.0', 'updated_at' => time(),
]));

if ($wrote !== false) {
    $st = Updater::state();
    t_eq(true, $st['running'], 'a live run is reported as running');
    t_eq('rsync', $st['phase'], 'with its phase');
    t_eq(60, $st['percent'], 'and its progress');

    $d = Updater::shouldApply($avail('4.5.1', '4.6.0'));
    t_eq(false, $d['go'], 'a second update is refused while one is running');
    t_contains($d['reason'], 'already running', 'and says so');

    $r = Updater::launch();
    t_eq(false, $r['success'], 'and launch() refuses too');

    // A state file claiming to be running but untouched for fifteen minutes is
    // a crashed updater, not a slow one. Reporting it as running for ever
    // would block every later attempt on that server permanently.
    @file_put_contents($state, json_encode([
        'status' => 'running', 'phase' => 'rsync', 'percent' => 60,
        'message' => 'Copying files', 'from_version' => '4.5.1',
        'to_version' => '4.6.0', 'updated_at' => time() - 1200,
    ]));
    $st = Updater::state();
    t_eq(false, $st['running'], 'a stale run is not reported as running');
    t_eq('stalled', $st['status'], 'it is reported as stalled');

    // ── reconcile(): recording how the last run went ────────────────────────
    //
    // Done on the NEXT tick, because the updater replaces its own code
    // mid-run and cannot be relied on to write its own obituary.

    Database::setSetting('auto_update_failures', '0');
    Database::setSetting('auto_update_seen_at',  '0');

    $ts = time() - 60;
    @file_put_contents($state, json_encode([
        'status' => 'success', 'phase' => 'done', 'percent' => 100,
        'message' => 'Update complete', 'from_version' => '4.5.1',
        'to_version' => '4.6.0', 'updated_at' => $ts,
    ]));
    $r = Updater::reconcile();
    t_eq(true, $r['changed'],    'a finished run is reconciled');
    t_eq('success', $r['status'], 'as a success');
    t_eq(0, Updater::failureCount(), 'and the failure counter stays at zero');
    t_ok((int)Database::setting('auto_update_last_ok', '0') > 0,
         'the successful update is timestamped');

    // The same state is not counted twice, or one success would be reconciled
    // on every tick for ever.
    t_eq(false, Updater::reconcile()['changed'],
         'the same result is not reconciled twice');

    // A rollback counts as a failure: nothing landed.
    @file_put_contents($state, json_encode([
        'status' => 'rolled_back', 'phase' => 'verify', 'percent' => 100,
        'message' => 'New version did not answer; restored 4.5.1',
        'from_version' => '4.5.1', 'to_version' => '4.6.0',
        'updated_at' => time() - 30,
    ]));
    $r = Updater::reconcile();
    t_eq('rolled_back', $r['status'], 'a rollback is reconciled as such');
    t_eq(1, Updater::failureCount(),
         'and counts against the backoff — a rollback means nothing landed');

    @unlink($state);
} else {
    // /var/lib is not writable in this environment. Say so rather than
    // passing quietly: a skipped test that reports nothing is the same
    // mistake this whole module exists to avoid.
    t_ok(true, 'state-file tests skipped: ' . dirname($state) . ' is not writable here');
}

// ── status() is honest about what it cannot do ──────────────────────────────

$baseline();
$s = Updater::status();
t_ok(array_key_exists('next_action', $s),
     'status() always states what it will do next');
t_ok($s['next_action'] !== '',
     'and never leaves that blank — "on" must never quietly mean "blocked"');
t_ok(array_key_exists('can_launch', $s),
     'status() reports whether this PHP can even start the updater');

// PHPHardening in this very product offers to disable shell_exec. Without this
// check the panel would report a launched update that never started.
t_eq(function_exists('shell_exec')
     && !in_array('shell_exec',
                  array_map('trim', explode(',', (string)ini_get('disable_functions'))), true),
     Updater::canRunShell(),
     'canRunShell() reflects disable_functions');

// ── The checker and the updater must read the SAME source ──────────────────
//
// This is the defect that would have made the whole feature inert. The checker
// asked the GitHub Releases API while update.sh downloads latest.json from the
// release channel. publish.sh skips creating the Release when there is no gh
// binary and no GH_TOKEN -- which is exactly how v4.6.0 shipped -- so the API
// still described 4.5.1 while the manifest, the CDN and the committed zip all
// described 4.6.0. The panel would have reported "up to date" on a server a
// version behind, and automatic updating would never have fired.

$uc = t_code(dirname(__DIR__) . '/backend/lib/UpdateChecker.php');
t_contains($uc, 'latest.json',
     'UpdateChecker reads the release manifest');
t_ok(strpos($uc, 'api.github.com') === false,
     'and does NOT consult the GitHub Releases API, which can lag behind it');

$up = t_code(dirname(__DIR__) . '/update.sh');
t_contains($up, 'latest.json',
     'update.sh reads the same manifest');

// Both must try the CDN and the GitHub raw mirror, in that order.
foreach (['defender.lws-s1.com' => 'the CDN',
          'raw.githubusercontent.com' => 'the GitHub raw mirror'] as $host => $what) {
    t_contains($uc, $host, "UpdateChecker knows about $what");
    t_contains($up, $host, "update.sh knows about $what");
}

// ── The scheduler actually runs it ─────────────────────────────────────────
//
// Building a module and then never scheduling it is the single most common
// fault in this codebase, and it is why the update check existed for months
// without ever installing anything.

$sched = t_code(dirname(__DIR__) . '/backend/cron/scheduler.php');
t_contains($sched, "'autoupdate' => [", 'the scheduler has an autoupdate task');
t_contains($sched, 'Updater::shouldApply',  'which asks the policy');
t_contains($sched, 'Updater::reconcile',    'reconciles the previous run');
t_contains($sched, 'Updater::launch',       'and launches the updater');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/Updater.php';",
     'and requires the class it uses');
