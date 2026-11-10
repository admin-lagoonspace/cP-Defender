<?php
/**
 * The cached licence, and the grace window, actually executed.
 *
 * Shakaal flagged this as the edge of what had been demonstrated rather than
 * claiming it was wrong: `noteRemoteNegative()` is unreachable without a
 * parsed answer from the licence server, and a transport failure is supposed to
 * fall through to the cached local key and its grace period — but nobody had
 * run that path. Forging a signed stale key was not something he would do
 * safely, and he said so instead of reporting a pass.
 *
 * He was right to stop. The reason the path was untestable is that
 * buildLocalKey() dates every key it signs TODAY, and the checkdate is bound
 * into both md5 layers of the key, so a test cannot age one afterwards without
 * forging a signature. buildLocalKey() now takes an optional timestamp, used
 * by nothing in production, so a correctly-signed key with an older date can
 * be made through the product's own signer.
 *
 * ── WHY THE GRACE WINDOW MATTERS ─────────────────────────────────────────────
 *
 * It is the one deliberate softness in the licence logic: a licence that
 * verified successfully keeps protecting the server for GRACE_DAYS if the
 * licence server later becomes unreachable. The failure mode it exists to
 * prevent is a WAF and a scanner switching themselves off on 132 accounts
 * because a billing system had an outage. The failure mode it must NOT have is
 * being open-ended.
 *
 * No network is involved below. A back-off window in the future makes
 * remoteAllowed() false, so remoteCheck() returns null — which is precisely
 * what an unreachable server returns, and is the condition these branches are
 * written for.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';

$ref      = new ReflectionClass('License');
$cache    = $ref->getProperty('cache');
// setAccessible() is REQUIRED at the 7.4 floor install.sh accepts, is a no-op
// from 8.1, and is deprecated in 8.5 -- so it is called only where it does
// something, rather than printing a deprecation into every run.
$t_open = static function ($r) {
    if (PHP_VERSION_ID < 80100) { $r->setAccessible(true); }
    return $r;
};
$t_open($cache);
$build = $t_open($ref->getMethod('buildLocalKey'));

$LOCALKEY_DAYS = $ref->getConstant('LOCALKEY_DAYS');
$GRACE_DAYS    = $ref->getConstant('GRACE_DAYS');
t_ok($LOCALKEY_DAYS > 0 && $GRACE_DAYS > 0,
     'the key lifetime and the grace window are both real numbers ('
   . $LOCALKEY_DAYS . ' + ' . $GRACE_DAYS . ' days)');

/** An Active answer of the shape the licence server really returns. */
$activeResults = [
    'status'          => 'Active',
    'registeredname'  => 'ServerScrub Test',
    'productname'     => 'ServerScrub',
    'nextduedate'     => '2027-01-01',
    'validdomain'     => 'localhost',
    'validip'         => '127.0.0.1',
];

/**
 * Put a correctly-signed local key of a given age in place, and make the
 * licence server unreachable.
 */
$seed = function (int $daysOld) use ($build, $activeResults, $cache) {
    $key = $build->invoke(null, $activeResults, time() - ($daysOld * 86400));
    Database::setSetting('license_key', 'TEST-KEY-0000');
    Database::setSetting('license_localkey', $key);
    Database::setSetting('license_checked_at', (string) (time() - ($daysOld * 86400)));
    // In the back-off window, so remoteCheck() returns null without a request:
    // the same answer an unreachable server gives.
    Database::setSetting('license_remote_next_try', (string) (time() + 3600));
    $cache->setValue(null, null);
    return $key;
};

// ── A fresh cached key is used, and nothing is re-checked ──────────────────

$seed(1);
$st = License::status();
t_eq('Active', $st['status'], 'a cached key inside its lifetime is used as it stands');
t_ok($st['protection_allowed'] === true, 'protection stays on');
t_ok($st['degraded'] === false,
     'and the panel is not degraded: nothing is wrong, and saying so would '
   . 'train the operator to ignore the warning that matters');

// ── Past the key lifetime, inside grace: protect, and say why ──────────────

$seed($LOCALKEY_DAYS + 2);
$st = License::status();
t_ok($st['protection_allowed'] === true,
     'THE WHOLE POINT OF THE GRACE WINDOW: with the licence server '
   . 'unreachable and the cached key stale, protection stays ON. A WAF and a '
   . 'scanner that switch themselves off on 132 accounts because a billing '
   . 'system is down have done more damage than the outage');
t_ok($st['degraded'] === true,
     'and the state is reported as degraded, because it is');
t_contains($st['message'], 'cached license',
     'the operator is told the licence is being taken on trust');
t_contains($st['message'], 'more day(s)',
     'and for how much longer, which is the only actionable part of it');
$left = (int) ($GRACE_DAYS - 2);
t_contains($st['message'], (string) $left . ' more day(s)',
     'counted from the key\'s own date rather than approximated — ' . $left
   . ' of the ' . $GRACE_DAYS . '-day window is left');

// ── Past grace: stop claiming, keep protecting, degrade the UI ─────────────

$seed($LOCALKEY_DAYS + $GRACE_DAYS + 2);
$st = License::status();
t_eq('Unknown', $st['status'],
     'past the grace window the licence state is Unknown — not Active, which '
   . 'would be a claim about something that has not been verified in '
   . ($LOCALKEY_DAYS + $GRACE_DAYS + 2) . ' days');
t_ok($st['degraded'] === true, 'the UI is degraded');
t_ok($st['protection_allowed'] === false,
     'and protection is gated: the grace window is deliberately soft, and '
   . 'deliberately not open-ended');
t_contains($st['message'], 'grace period',
     'with a message that names the window rather than reporting a generic '
   . 'failure');

// ── The back-off is what made all of the above reachable ───────────────────
//
// It is also the fix for finding 13: the licence server ANSWERING "Invalid" is
// not a failure, so nothing was recorded, and a server with a key the licence
// server rejects paid a full round trip on every single request -- 1,456 ms
// for the first and ~500 ms for each one after, measured against the real
// server. remoteAllowed() being false is what these tests stand on, so it is
// worth asserting that it does what they assume.
Database::setSetting('license_remote_next_try', (string) (time() + 3600));
$allowed = $t_open($ref->getMethod('remoteAllowed'));
t_ok($allowed->invoke(null) === false,
     'inside the window, an ordinary request does not re-attempt the licence '
   . 'server');

Database::setSetting('license_remote_next_try', (string) (time() - 1));
t_ok($allowed->invoke(null) === true,
     'and once it has passed, the next request tries again');

// A deliberate refresh ignores the window entirely, which is what makes the
// back-off safe: an operator who has just fixed their licence must not have to
// wait it out.
Database::setSetting('license_remote_next_try', (string) (time() + 3600));
$bg = $t_open($ref->getProperty('background'));
$bg->setValue(null, true);
t_ok($allowed->invoke(null) === true,
     'a background check -- the refresh button, and the scheduler -- is never '
   . 'held back by the window');
$bg->setValue(null, false);

// ── The signer is not weakened by having a date parameter ──────────────────

$src = t_code(dirname(__DIR__) . '/backend/lib/License.php');
$fn  = t_fn_body($src, 'buildLocalKey', 'php');
t_contains($fn, "date('Ymd', \$when ?? time())",
     'production passes nothing and gets today');
t_contains($fn, 'md5($results[\'checkdate\'] . self::localSalt())',
     'and the date is still bound into the signature, so a key cannot be '
   . 'aged after the fact without the salt');

$decoded = $t_open($ref->getMethod('decodeLocalKey'));
$key = $build->invoke(null, $activeResults, time() - (3 * 86400));
t_ok($decoded->invoke(null, $key) !== null, 'a back-dated key still verifies');
// One character changed anywhere must invalidate it.
$tampered = substr($key, 0, 40) . (($key[40] === 'a') ? 'b' : 'a') . substr($key, 41);
t_eq(null, $decoded->invoke(null, $tampered),
     'and a tampered one does not, which is what the two md5 layers are for');

// ── A key dated in the FUTURE must not be immortal ─────────────────────────
//
// Shakaal went looking for a way to extend the window indefinitely and found
// one: `$age = (time() - checkdate) / 86400` goes NEGATIVE for a future date,
// so `$age < LOCALKEY_DAYS` stayed true for ever. A key dated ten years ahead
// read as freshly verified, never degraded, and the product silently stopped
// re-verifying it.
//
// Not an outsider's hole -- localSalt() is random_bytes(32) in a 0700
// root-owned database, so forging a key means already having root -- and it
// fails open, so no customer loses protection. The realistic causes are a
// clock set ahead, or one corrected backwards after a key was issued. The age
// is clamped at zero, which treats such a key as "checked just now": it then
// expires on schedule from the moment the clock is sane again.

foreach ([365, 3650] as $daysAhead) {
    $key = $build->invoke(null, $activeResults, time() + ($daysAhead * 86400));
    Database::setSetting('license_key', 'TEST-KEY-0000');
    Database::setSetting('license_localkey', $key);
    Database::setSetting('license_remote_next_try', (string) (time() + 3600));
    $cache->setValue(null, null);

    $st = License::status();
    // Clamped to "checked now", so it is inside the key lifetime and usable --
    // failing open is deliberate -- but the clamp is what stops it being
    // usable for ever.
    t_ok($st['protection_allowed'] === true,
         'a key dated ' . $daysAhead . ' days ahead still protects the server: '
       . 'a clock problem must not switch the WAF and the scanner off');
}

// The clamp itself, asserted where it lives, because the behavioural
// difference only shows up LOCALKEY_DAYS after the clock is corrected -- which
// no test can wait for.
$lic = t_code(dirname(__DIR__) . '/backend/lib/License.php');
t_contains($lic, "\$age = max(0, time() - (int)\$decoded['checkdate']) / 86400;",
     'THE CLAMP: the age cannot be negative, so a future-dated key is treated '
   . 'as checked now rather than as permanently fresh, and it expires on '
   . 'schedule once the clock is right');
t_ok(strpos($lic, "\$age = (time() - (int)\$decoded['checkdate']) / 86400;") === false,
     'and the unclamped form is gone');
