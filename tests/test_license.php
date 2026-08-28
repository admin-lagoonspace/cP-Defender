<?php
/**
 * Licensing regressions.
 *
 *   3.19.6  License::log() called Logger::write(), which is PRIVATE. That is an
 *           Error, not a warning, so the leading @ suppressed nothing. And log()
 *           is called from the catch block in status(), so the fatal REPLACED
 *           whatever it was reporting — every page that consults a licence went
 *           blank.
 *   3.19.7  License called Database::getSetting(), which does not exist.
 *
 * Licensing sits in front of every feature route, so a fault here is never
 * contained to the licence panel: it takes the whole product down. These tests
 * therefore care most about status() never throwing, whatever the state.
 */

require_once __DIR__ . '/assert.php';
require __DIR__ . '/bootstrap.php';

// ── status() must never throw ────────────────────────────────────────────────
t_no_throw(function () {
    License::status();
}, 'License::status() does not throw on a fresh install');

$s = License::status();
t_ok(is_array($s), 'status() returns an array');
t_ok(isset($s['status']), 'status() reports a status');
t_ok(array_key_exists('protection_allowed', $s), 'status() reports protection_allowed');

// ── Logging must never be the thing that breaks a request ────────────────────
$src = t_code(dirname(__DIR__) . '/backend/lib/License.php');
t_ok(strpos($src, 'Logger::write(') === false,
    'License does not call the private Logger::write()');
t_ok(strpos($src, 'Database::getSetting(') === false,
    'License does not call the non-existent Database::getSetting()');

// Reaching the logger from inside a failure path must be safe.
t_no_throw(function () {
    Logger::info('license: test');
}, 'the public Logger API is callable from outside Logger');

// ── The trial ────────────────────────────────────────────────────────────────
// A fresh install gets a full trial; the marker must be recorded so the clock
// cannot be reset by clearing one of its two homes.
$left = License::trialDaysLeft();
t_ok($left > 0 && $left <= License::TRIAL_DAYS,
    "a fresh install has a trial (got {$left} of " . License::TRIAL_DAYS . " days)");

$installed = License::installedAt();
t_ok($installed > 0, 'the install time is recorded');
t_eq((string)$installed, (string)Database::setting('installed_at', '0'),
    'the install time is persisted to the database');

// Backdating past the trial must end it — the trial is time-based, not a flag.
Database::setSetting('installed_at', (string)(time() - (License::TRIAL_DAYS + 1) * 86400));
t_eq(0, License::trialDaysLeft(), 'an expired trial reports zero days left');

// Even expired, status() must answer rather than throw: the activation screen
// depends on it.
t_no_throw(function () {
    License::status();
}, 'status() still answers once the trial has expired');

// ── The vendor secret must not be a placeholder in a release ─────────────────
// It ships as a placeholder deliberately (the repo is public), but a build must
// never claim to be configured when it is not.
t_ok(method_exists('License', 'secretConfigured'),
    'License exposes whether the licensing secret is configured');
t_eq(false, License::secretConfigured(),
    'the shipped placeholder secret is reported as NOT configured');

// ── An unset verification secret is NORMAL ──────────────────────────────────
// Determined from the wire against a live server: the WHMCS Licensing Addon
// v3.1 signs with md5(check_token) -- an empty secret -- and stores no secret in
// its configuration at all. Releases 3.21.1 through 3.22.1 treated that normal
// state as a misconfiguration, refused to activate, and sent the operator
// looking through WHMCS for a value that does not exist.
t_ok(method_exists('License', 'secretConfigured'), 'secretConfigured() exists');
t_eq(false, License::secretConfigured(),
    'no explicit verification secret is the default');

$st0 = License::status();
t_ok($st0['status'] !== 'Unconfigured',
    'an unset verification secret is not reported as a misconfiguration');

// ── The two secrets must be different things ────────────────────────────────
// They were the same value, which was wrong in both directions. The local key
// only needs a salt that is stable and secret ON THIS MACHINE; deriving it from
// a value shared with the licence server gained nothing, and once that shared
// value turned out to be empty, anyone knowing the scheme could mint an
// "Active" local key for any server.
$src = t_code(dirname(__DIR__) . '/backend/lib/License.php');
t_contains($src, 'verificationSecret', 'response verification has its own secret');
t_contains($src, 'localSalt',          'the local key has its own salt');
t_ok(strpos($src, 'md5(self::verificationSecret() . $checkToken)') !== false,
    'the response hash uses the verification secret');
t_ok(strpos($src, 'self::localSalt())') !== false,
    'the local key is signed with the local salt');
t_ok(strpos($src, 'md5($d . self::verificationSecret())') === false,
    'the local key is NOT signed with the shared verification secret');

// The local salt must be generated, persisted and non-trivial.
$salt2 = License::localSalt();           // generated on first use
t_ok(strlen($salt2) >= 32, 'a local salt is generated and stored (' . strlen($salt2) . ' chars)');
t_ok($salt2 !== 'CHANGEME_SET_IN_mode_php', 'the local salt is not the old placeholder');

// ── Setting the secret without hand-editing PHP ──────────────────────────────
// The fix above tells the operator to edit mode.php over SSH. That file is
// required by config.php, so a stray quote is a fatal on EVERY request -- a
// worse outcome than the licensing problem being solved. `sentinel license
// secret <value>` edits the one line, verifies the result parses before putting
// it in place, and keeps a backup.

$mode = SG_ROOT . '/backend/config/mode.php';
@mkdir(dirname($mode), 0777, true);
file_put_contents($mode, "<?php\n"
  . "if (!defined('INSTALL_MODE')) { define('INSTALL_MODE', 'cpanel'); }\n"
  . "define('SG_WHMCS_URL','https://clientarea.example.net');\n"
  . "define('SG_LICENSE_SECRET','CHANGEME_SET_IN_mode_php');\n");

$r = License::setSecret('s3cret-from-whmcs');
t_eq(true, $r['success'] ?? false, 'setSecret() writes the secret');

$after = (string) file_get_contents($mode);
t_contains($after, "'s3cret-from-whmcs'", 'the new secret is in mode.php');
t_ok(strpos($after, 'CHANGEME_SET_IN_mode_php') === false, 'the placeholder is replaced');
t_contains($after, 'SG_WHMCS_URL', 'unrelated settings survive');
t_contains($after, 'INSTALL_MODE', 'the install mode survives');
t_ok(is_file($mode . '.bak'), 'a backup is kept');

$lint = []; $code = 0;
@exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($mode) . ' 2>&1', $lint, $code);
t_eq(0, $code, 'the resulting mode.php parses');

t_eq(false, License::setSecret('')['success'] ?? false, 'an empty secret is refused');
t_eq(false, License::setSecret('CHANGEME_SET_IN_mode_php')['success'] ?? false,
    'the placeholder value is refused as a secret');

// A secret is an arbitrary string. Quotes and backslashes must not corrupt the
// file — var_export handles the escaping, and the parse check is the backstop.
t_eq(true, License::setSecret("has'quote\"and\slash")['success'] ?? false,
    'a secret containing quotes and backslashes is accepted');
$lint2 = []; $code2 = 0;
@exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($mode) . ' 2>&1', $lint2, $code2);
t_eq(0, $code2, 'mode.php still parses after a quoted secret');

// The value must never be echoed back: shell history is exposure enough.
$out = License::setSecret('never-print-me');
t_ok(strpos(json_encode($out), 'never-print-me') === false,
    'setSecret() does not return the secret in its response');

// The CLI must expose it, or the operator is back to editing PHP by hand.
$cli = t_code(dirname(__DIR__) . '/backend/cli/sentinel.php');
t_contains($cli, "case 'secret'", 'the CLI has a license secret subcommand');
t_contains($cli, 'License::setSecret', 'the CLI calls setSecret()');

// (Removed in 3.23.0: the assertions here pinned the "Unconfigured" gate, which
// was itself based on the false premise that a shared secret must exist. The
// wire says otherwise -- see the block at the top of this file.)

// ── The example text must not be accepted as a secret ────────────────────────
// It happened: the instructions said `sentinel license secret
// 'YOUR-WHMCS-ADDON-SECRET'` and that literal string was pasted. The result is
// worse than setting nothing -- the install reports "configured" while holding
// a value the licence server has never heard of, so the diagnosis shifts from
// "no secret" to "secret mismatch" and the operator starts comparing two values
// when only one was ever real.
foreach (['YOUR-WHMCS-ADDON-SECRET', 'your-whmcs-addon-secret', 'changeme',
          'secret', '<value>'] as $placeholder) {
    $r = License::setSecret($placeholder);
    t_eq(false, $r['success'] ?? false, "the placeholder '{$placeholder}' is refused");
}

$hint = License::setSecret('YOUR-WHMCS-ADDON-SECRET');
t_contains($hint['error'], 'WHMCS', 'the refusal says where the real value lives');
t_contains($hint['error'], 'openssl rand', 'the refusal says how to generate one');

// Too short to be a salt is almost certainly a paste error.
$short = License::setSecret('abc');
t_eq(false, $short['success'] ?? false, 'a very short secret is refused');
t_contains($short['error'], 'too short', 'the refusal explains why');

// A real-looking secret still works.
$good = License::setSecret(bin2hex(random_bytes(16)));
t_eq(true, $good['success'] ?? false, 'a genuine random secret is accepted');

// ── probe() must never leak the secret ───────────────────────────────────────
// It exists to be pasted into a support conversation, so the one thing it must
// not contain is the value that makes local keys unforgeable.
License::setSecret('probe-secret-value-not-for-print');
$probe = License::probe();          // no network here: post() returns null
$json  = json_encode($probe);
t_ok(strpos($json, 'probe-secret-value-not-for-print') === false,
    'probe() does not print the licensing secret');
t_ok(array_key_exists('reachable', $probe), 'probe() reports reachability');
t_ok(array_key_exists('diagnosis', $probe), 'probe() states a diagnosis');
t_contains($probe['url'], '/modules/servers/licensing/verify.php',
    'probe() targets the addon endpoint the real check uses');
t_ok(array_key_exists('secret_configured', $probe),
    'probe() reports whether a secret is set');

$cli = t_code(dirname(__DIR__) . '/backend/cli/sentinel.php');
t_contains($cli, "case 'probe'", 'the CLI exposes probe');

// ── Testing a candidate must not change anything ─────────────────────────────
// Finding the right secret otherwise means writing each guess into mode.php and
// re-running activation: editing live configuration to answer a question, and
// leaving the wrong value behind when the guess is wrong.
License::setSecret('known-good-secret-value');
$before = file_get_contents(License::modePhpPath());

$try = License::trySecret('some-other-candidate');   // no network in tests
t_ok(is_array($try), 'trySecret() returns a result');

$after = file_get_contents(License::modePhpPath());
t_eq($before, $after, 'trySecret() does not modify mode.php');
t_contains($after, 'known-good-secret-value', 'the stored secret is untouched');

t_eq(false, License::trySecret('')['success'] ?? false, 'an empty candidate is refused');

$cli = t_code(dirname(__DIR__) . '/backend/cli/sentinel.php');
t_contains($cli, "case 'try-secret'", 'the CLI exposes try-secret');
t_contains($cli, 'License::trySecret', 'the CLI calls trySecret()');

// ── Expiry display ───────────────────────────────────────────────────────────
// A live "Free Account" licence returns nextduedate 0000-00-00, which is not a
// date. The old code also fell back to registeredname when nextduedate was
// absent, so a licence with no due date showed the CUSTOMER'S NAME where the
// expiry belongs.
$src = t_code(dirname(__DIR__) . '/backend/lib/License.php');
t_ok(strpos($src, "\$r['nextduedate'] ?? \$r['registeredname']") === false,
    'expiry never falls back to the registered name');
t_contains($src, "'0000-00-00'", 'a zero date is recognised');
t_contains($src, "'No expiry'", 'a licence with no renewal date says so');
