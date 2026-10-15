<?php
/**
 * A daily task must run at the time it is configured for.
 *
 * Reported from a live server, and visible in its own status report: the
 * malware scan was configured for 09:00 and had last run at 20:30 the previous
 * day. iprep was set to 03:00 and ran at 04:18. rootkit was set to 00:00 and
 * ran at 04:19. Cron was firing correctly and every task was running -- just
 * never at the hour the operator chose.
 *
 * The cause was a ratchet. isDue() required 23h55m to have elapsed since the
 * LAST RUN before it would even look at the clock:
 *
 *     if ($elapsed < 86400 - 300) { return false; }
 *     return pastTimeOfDay($atTime, $now, $last);
 *
 * So a task that once ran late could not run again until 23h55m later, by
 * which point its configured time had passed for the day -- so it ran at the
 * late time again, and again. Every run could drift later; none could drift
 * back. The configured time of day became meaningless after the first late
 * run, and a scan "set for 09:00" silently meant "whenever it happened to run
 * the first time".
 *
 * pastTimeOfDay() alone answers the real question -- has today's boundary
 * passed, and have we not run since it -- which both prevents a double-fire
 * and lets a drifted task recover.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$at = function (string $s): int { return strtotime($s . ' UTC'); };

// -- The exact case from the server ------------------------------------------
// Scan configured for 09:00. Last ran 2026-10-14 20:30. It is now
// 2026-10-15 19:00, so today's 09:00 has long passed.
$last = $at('2026-10-14 20:30:01');
$now  = $at('2026-10-15 19:00:00');

t_ok(Schedule::isDue('daily', $last, $now, '09:00'),
    'a daily task whose configured time passed today is due, even though less '
  . 'than 24h has elapsed since a late run -- this is the reported bug');

// The old gate, reproduced, to show it is genuinely what blocked it.
$elapsed = $now - $last;
t_ok($elapsed < (86400 - 300),
    'and it is blocked by an elapsed-since-last-run gate: only '
  . round($elapsed / 3600, 1) . 'h had passed');

// -- It must not fire twice in one day ---------------------------------------
$ranToday = $at('2026-10-15 09:00:04');
t_ok(!Schedule::isDue('daily', $ranToday, $at('2026-10-15 19:00:00'), '09:00'),
    'a task that already ran after today\'s boundary does not run again');
t_ok(!Schedule::isDue('daily', $ranToday, $at('2026-10-15 23:59:00'), '09:00'),
    'not even late the same evening');

// -- Before the boundary, it waits -------------------------------------------
t_ok(!Schedule::isDue('daily', $at('2026-10-14 09:00:02'), $at('2026-10-15 08:59:00'), '09:00'),
    'a minute before its time it is not due');
t_ok(Schedule::isDue('daily', $at('2026-10-14 09:00:02'), $at('2026-10-15 09:00:01'), '09:00'),
    'a second after, it is');

// -- A drifted task recovers its proper time ---------------------------------
// The whole point: the ratchet meant a task could only ever move later.
$drifted = $at('2026-10-14 20:30:00');
t_ok(Schedule::isDue('daily', $drifted, $at('2026-10-15 09:00:30'), '09:00'),
    'a task that drifted to the evening fires at 09:00 the next day, '
  . 'recovering the configured time instead of staying drifted for ever');

// -- Never run means run now --------------------------------------------------
t_ok(Schedule::isDue('daily', 0, $at('2026-10-15 19:00:00'), '09:00'),
    'a task that has never run is due immediately');

// -- Off is off ---------------------------------------------------------------
foreach (['off', 'disabled', ''] as $s) {
    t_ok(!Schedule::isDue($s, 0, $now, '09:00'),
        "a '{$s}' schedule never fires, even having never run");
}
t_ok(!Schedule::isDue('nonsense', 0, $now, '09:00'),
    'and an unrecognised schedule does not fire either');

// -- Weekly ------------------------------------------------------------------
// 2026-10-15 is a Thursday (w=4).
t_eq('4', date('w', $at('2026-10-15 12:00:00')), 'the test date is a Thursday');

t_ok(Schedule::isDue('weekly', $at('2026-10-08 01:00:00'), $at('2026-10-15 01:00:30'), '01:00', 4),
    'a weekly task fires on its day once the time has passed');
t_ok(!Schedule::isDue('weekly', $at('2026-10-08 01:00:00'), $at('2026-10-14 23:00:00'), '01:00', 4),
    'but not on the wrong day');
t_ok(!Schedule::isDue('weekly', $at('2026-10-15 01:00:05'), $at('2026-10-15 20:00:00'), '01:00', 4),
    'and not twice on the right one');

// A weekly task that drifted must also recover, for the same reason.
t_ok(Schedule::isDue('weekly', $at('2026-10-08 22:00:00'), $at('2026-10-15 01:00:30'), '01:00', 4),
    'a drifted weekly task recovers its configured time too');

// -- The cheap schedules are unchanged ---------------------------------------
t_ok(Schedule::isDue('every',  $now - 61,   $now), "'every' fires once a minute has passed");
t_ok(!Schedule::isDue('every', $now - 30,   $now), 'but guards against a double-fire');
t_ok(Schedule::isDue('hourly', $now - 3350, $now), "'hourly' allows tick jitter");
t_ok(!Schedule::isDue('hourly', $now - 600, $now), 'and does not fire every tick');

// -- The ratchet is gone from the source -------------------------------------
$sch = t_code($repo . '/backend/lib/Schedule.php');
$daily = substr($sch, strpos($sch, "case 'daily':"), 200);
t_ok(strpos($daily, '86400 - 300') === false,
    'the elapsed-since-last-run gate is gone from the daily case');
$weekly = substr($sch, strpos($sch, "case 'weekly':"), 220);
t_ok(strpos($weekly, '604800 - 300') === false, 'and from the weekly case');

// -- The scheduler uses it, rather than keeping its own copy ------------------
$cron = t_code($repo . '/backend/cron/scheduler.php');
t_contains($cron, 'Schedule::isDue(', 'the scheduler delegates the decision');
t_contains($cron, "require_once SG_ROOT . '/backend/lib/Schedule.php'",
    'and requires the class, or the task fatals in cron');
t_ok(strpos($cron, 'function pastTimeOfDay') === false,
    'the old copy of the time-of-day check is gone, so the two cannot disagree');
