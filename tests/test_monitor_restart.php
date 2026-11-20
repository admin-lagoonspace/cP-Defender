<?php
/**
 * An update must never leave the real-time monitor stopped.
 *
 * THE INCIDENT. v4.37.4 shipped a fix that made real-time detection contain
 * what it finds. On the server it was written for, it never ran once. The
 * updater stops the daemon near the top of the script and started it again
 * ~400 lines later, and "Fixing permissions" -- which could hang
 * indefinitely, walking a path read out of the database -- sits BETWEEN the
 * two. The permissions walk hung, the operator killed it, and the monitor was
 * left stopped while the panel reported the new version.
 *
 * So the operator saw malware "detected in realtime ... left as is ACtive on
 * the server", which reads as a containment bug and is not one: containment
 * was not running at all. The giveaway was that a log line the new code
 * writes on every decision never appeared once in monitor.log.
 *
 * Three things were wrong, and each is pinned below:
 *
 *   1. The restart was ~400 lines downstream of the stop, with everything
 *      that could fail in between.
 *   2. Nothing guaranteed it on an abnormal exit.
 *   3. It used `systemctl start`, which is a NO-OP on a unit that is already
 *      active -- so where the stop had not taken effect, the old process kept
 *      running the old code and the update reported success.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$up  = file_get_contents($repo . '/update.sh');
$mon = file_get_contents($repo . '/backend/daemon/monitor.py');

// ── The restart happens BEFORE anything that can hang ─────────────────────
$posStop    = strpos($up, 'systemctl stop serverscrub-monitor');
$posRestart = strpos($up, 'section "Restarting real-time protection"');
$posPerms   = strpos($up, 'section "Fixing permissions"');

t_ok($posStop !== false && $posRestart !== false && $posPerms !== false,
     'the stop, the restart and the permissions step are all still there');
t_ok($posStop < $posRestart,
     'the daemon is stopped before it is restarted');
t_ok($posRestart < $posPerms,
     'THE RESTART COMES BEFORE "FIXING PERMISSIONS": that section walks a '
   . 'path read from the database and is where a live server hung, leaving '
   . 'the monitor stopped. Real-time protection must not wait on tidying '
   . 'that it does not depend on');

// ── An abnormal exit still brings it back ─────────────────────────────────
t_contains($up, 'trap sg_on_exit_restore_monitor EXIT',
     'AN EXIT TRAP GUARANTEES IT: an update that dies, hangs and is killed, '
   . 'or rolls back must still leave the monitor running — a security daemon '
   . 'that is down is the one outcome an updater may never produce');
preg_match('/sg_on_exit_restore_monitor\(\) \{.*?\n\}/s', $up, $m);
$trap = $m[0] ?? '';
t_ok($trap !== '', 'the trap handler is defined');
t_contains($trap, '"${SG_MONITOR_RESTARTED:-0}" != "1"',
     'and does not restart twice on the normal path');
t_contains($trap, '"$SG_MONITOR_WAS_UP" == "1"',
     'NOR START A DAEMON THAT WAS NOT RUNNING: an operator who had stopped '
   . 'the monitor on purpose does not get it switched back on by an update');
t_contains($trap, 'rm -rf "${TMP_DIR:-}"',
     'and the temp-directory cleanup the previous EXIT trap did is kept, '
   . 'since setting a second EXIT trap replaces the first');

// ── restart, never start ──────────────────────────────────────────────────
preg_match('/sg_monitor_restore\(\) \{.*?\n\}/s', $up, $m2);
$fn = $m2[0] ?? '';
t_ok($fn !== '', 'sg_monitor_restore() is defined');
t_contains($fn, 'systemctl restart serverscrub-monitor',
     'RESTART, NOT START: `systemctl start` on an already-active unit does '
   . 'nothing, which would leave the pre-update process — holding the OLD '
   . 'code in memory — running after an update whose purpose was to replace '
   . 'it, while reporting success');
t_ok(strpos($up, 'systemctl start serverscrub-monitor') === false
  || strpos($up, 'systemctl start serverscrub-monitor 2>/dev/null || true') !== false,
     'and no bare `systemctl start` is left on the update path (the rollback '
   . 'helper may still use one: there, nothing newer exists to replace)');

// ── The update says whether protection is actually running ────────────────
//
// `systemctl restart` exits 0 for a unit that starts and immediately dies --
// a missing Python module, a syntax error in the daemon. Reporting the
// command's exit status would call that a successful restart.
t_contains($up, 'if systemctl is-active --quiet serverscrub-monitor 2>/dev/null; then',
     'THE STATE IS CHECKED, NOT THE EXIT CODE: a unit that starts and dies '
   . 'immediately still exits 0 from `systemctl restart`');
t_contains($up, 'Real-time monitor is running the new code',
     'and a working monitor is confirmed in so many words');
t_contains($up, 'warn "Monitor is NOT running after restart — real-time protection is OFF"',
     'while a dead one is reported as protection being OFF, not as a warning '
   . 'about a service name');

// ── The daemon says which version it is ───────────────────────────────────
//
// "Which code is this process running?" had no answer, which is why the
// incident took a log-line-absence argument to diagnose.
t_contains($mon, "log.info('ServerScrub RT Monitor starting v%s PID=%d SG_ROOT=%s'",
     'THE DAEMON LOGS ITS VERSION ON START: so "is this the new code?" is a '
   . 'one-line grep rather than an inference from a line that is missing');
t_contains($mon, "open(os.path.join(SG_ROOT, 'VERSION'))",
     'read from the installed VERSION file, which is what the update replaces');

// ── The stale claim in the comment is gone ────────────────────────────────
//
// update.sh used to say install.sh --register-only restarts the daemon
// afterwards. It does not: that block is inside `if ! $REGISTER_ONLY`, so on
// an upgrade install.sh never touches the service. A comment that tells the
// next reader the restart is handled elsewhere is worse than no comment.
t_ok(strpos($up, 'install.sh --register-only restarts it afterwards') === false,
     'THE FALSE COMMENT IS GONE: install.sh does NOT restart the monitor on '
   . '--register-only (that block is inside `if ! $REGISTER_ONLY`), and a '
   . 'comment claiming otherwise is what let the gap survive review');
