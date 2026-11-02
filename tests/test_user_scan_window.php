<?php
/**
 * Two scans per twelve hours, and no queue.
 *
 * Asked for: remove the wait, and limit an account to two scans in twelve
 * hours.
 *
 * What was there before was a single cooldown plus a per-tick cap, picked up
 * by the 15-minute scheduler. Three separate things made a customer wait, and
 * only one of them was the actual limit:
 *
 *   - the cooldown, which forced an even spacing nobody asked for;
 *   - the per-tick cap, which queued accounts behind each other;
 *   - the 15-minute scheduler, which meant pressing the button and watching
 *     nothing happen for a quarter of an hour.
 *
 * Only the limit remains. The cap is gone, and a dedicated cron picks requests
 * up every minute.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$U = 'winuser';
Database::query("DELETE FROM settings WHERE key LIKE 'user_scan_%'");

// ── The allowance ───────────────────────────────────────────────────────────

t_eq(12 * 3600, UserScanRequest::windowSeconds(), 'the window is twelve hours by default');
t_eq(2, UserScanRequest::perWindow(), 'and two scans fit inside it');

t_ok(!UserScanRequest::atLimit($U), 'a fresh account may scan');
t_eq(0, UserScanRequest::retryIn($U), 'with no wait');

// Spend the allowance.
$now = time();
Database::setSetting('user_scan_starts_' . $U, json_encode([$now - 60]));
t_ok(!UserScanRequest::atLimit($U), 'one scan used, still allowed');
t_eq(0, UserScanRequest::retryIn($U), 'and no wait after the first');

Database::setSetting('user_scan_starts_' . $U, json_encode([$now - 3600, $now - 60]));
t_ok(UserScanRequest::atLimit($U),
     'THE LIMIT: two inside the window and the third is refused');

$wait = UserScanRequest::retryIn($U);
t_ok($wait > 0, 'which reports a wait');
t_eq(12 * 3600 - 3600, $wait,
     'measured from the OLDEST start, because that is the one whose expiry '
   . 'frees a slot — measuring from the newest would hold the account out for '
   . 'a further twelve hours after its second scan');

// A start that has aged out stops counting.
Database::setSetting('user_scan_starts_' . $U,
    json_encode([$now - (13 * 3600), $now - 60]));
t_ok(!UserScanRequest::atLimit($U),
     'a start older than the window no longer counts against the allowance');
t_eq(1, count(UserScanRequest::recentStarts($U)), 'and is dropped from the list');

// ── Clocks move ─────────────────────────────────────────────────────────────
Database::setSetting('user_scan_starts_' . $U,
    json_encode([$now + (48 * 3600), $now + (49 * 3600)]));
t_ok(!UserScanRequest::atLimit($U),
     'THE PERMANENT LOCKOUT AVOIDED: a timestamp in the future is discarded. '
   . 'It would never expire, so the account could never scan again — and '
   . 'clock changes do happen');

// Nonsense in the setting must not throw or lock anyone out.
Database::setSetting('user_scan_starts_' . $U, 'not json at all');
t_eq([], UserScanRequest::recentStarts($U), 'unparseable state reads as empty');
t_ok(!UserScanRequest::atLimit($U), 'and does not block the account');

Database::setSetting('user_scan_starts_' . $U, json_encode(['x', null, []]));
t_eq([], UserScanRequest::recentStarts($U), 'nor do non-numeric entries');

// ── Clamps ──────────────────────────────────────────────────────────────────
Database::setSetting('user_scan_per_window', '0');
t_eq(1, UserScanRequest::perWindow(), 'zero scans per window clamps to one');
Database::setSetting('user_scan_per_window', '9999');
t_eq(24, UserScanRequest::perWindow(), 'and an absurd allowance is capped');
Database::setSetting('user_scan_per_window', '2');

Database::setSetting('user_scan_window_hours', '0');
t_eq(600, UserScanRequest::windowSeconds(),
     'a zero window clamps to ten minutes — zero would make the allowance '
   . 'meaningless, since every start would age out instantly');
Database::setSetting('user_scan_window_hours', '12');

// ── The queue is gone ───────────────────────────────────────────────────────
$src = (string) file_get_contents($repo . '/backend/lib/UserScanRequest.php');

t_ok(strpos($src, 'maxPerRun') === false,
     'THE QUEUE: the per-tick cap is gone, so one customer no longer waits '
   . 'behind another');
t_ok(strpos($src, 'waiting_turn') === false, 'and nothing reports a queue position');
t_ok(strpos($src, 'cooldownSeconds') === false, 'the old cooldown is gone too');

// Concurrency is still bounded -- by the scanner, which is the right place.
$proc = t_fn_body($src, 'process', 'php');
t_contains($proc, 'startScan($home',
     'scans still go through Scanner::startScan(), which enforces '
   . 'scan_max_concurrent — removing our cap did not uncap ClamAV');
t_contains($proc, "self::note(\$user, 'blocked'",
     'and a refusal is recorded with its reason rather than being silent');

// Oldest first still matters: the scanner can still refuse, and the customer
// who has waited longest should get the slot when it frees.
t_contains($proc, 'usort(', 'pending requests are still served oldest first');

// ── The wait itself ─────────────────────────────────────────────────────────
$cron = $repo . '/backend/cron/user-scans.php';
t_ok(is_file($cron), 'there is a dedicated pickup script');
$cs = (string) file_get_contents($cron);
// The lock moved into process(), because the scheduler calls it too as a
// floor under this cron. Two scripts each holding their OWN lock would not
// exclude each other at all.
$us = (string) file_get_contents($repo . '/backend/lib/UserScanRequest.php');
t_contains(t_fn_body($us, 'lock', 'php'), 'LOCK_EX | LOCK_NB',
     'the pickup takes a lock — at a minute interval an overrun would '
   . 'otherwise stack, and each instance would try to start the same request');
t_contains(t_fn_body($us, 'process', 'php'), 'self::lock()',
     'and every caller goes through it, not just this cron');
t_ok(strpos($cs, 'flock(') === false,
     'the cron does NOT take its own second lock, which would exclude only '
   . 'other copies of itself');
t_contains($cs, 'License::protectionAllowed',
     'and a licensing fault does not become a scan nobody authorised');
t_contains($cs, 'UserScanRequest::process()', 'it does the one job');

$ins = (string) file_get_contents($repo . '/install.sh');
t_contains($ins, '* * * * * root ${SG_PHP} ${INSTALL_DIR}/backend/cron/user-scans.php',
     'THE 15-MINUTE WAIT: requests are picked up every minute, not once a '
   . 'quarter of an hour');
t_contains($ins, 'chmod +x "$INSTALL_DIR/backend/cron/user-scans.php"',
     'and the script is made executable');

// ── What the customer is told ───────────────────────────────────────────────
$page = (string) file_get_contents($repo . '/cpanel/serverscrub/index.live.php');
t_contains($page, 'It usually starts within a minute',
     'the queued message promises a minute, which is now true');
t_ok(strpos($page, 'ahead of you in the queue') === false,
     'and no longer talks about a queue that does not exist');
t_contains($page, 'scans left for the',
     'the button says how much of the allowance is left');
t_contains($page, 'used both of your',
     'and spells out why it is disabled when it is');
