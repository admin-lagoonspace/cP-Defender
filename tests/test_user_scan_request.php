<?php
/**
 * A cPanel user asking for a scan of their own account.
 *
 * Requested: every cPanel user should reach a limited version of this product
 * from the Security section of cPanel, the way cPGuard offered, and be able to
 * scan their own account rather than emailing their host.
 *
 * The whole difficulty is the boundary. The page runs as the customer and must
 * not reach the database (0700 root) or the API (admin role), so the request
 * crosses as a file in the customer's own home -- which means root reads a
 * path a hostile user controls and can rearrange between one call and the
 * next. These tests mostly guard that, and the limits that stop a button
 * every customer can press from becoming a way to flatten the server.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The request file ────────────────────────────────────────────────────────

$home = $ctx['sandbox'] . '/home/scanner';
@mkdir($home . '/.serverscrub', 0700, true);

// homeDir() resolves through passwd, which a sandbox has no entry for, so the
// path helpers are exercised directly against a stubbed home below.
t_ok(UserScanRequest::requestPath('../root') === null,
     'a traversal attempt never becomes a path');
t_ok(UserScanRequest::requestPath('') === null, 'nor does an empty username');

// ── Limits: enforced as root, not in the page ───────────────────────────────

Database::setSetting('user_scan_cooldown_hours', '6');
t_eq(6 * 3600, UserScanRequest::cooldownSeconds(), 'the cooldown is read from settings');

Database::setSetting('user_scan_cooldown_hours', '0');
t_eq(60, UserScanRequest::cooldownSeconds(),
     'THE OPEN DOOR: a zero cooldown clamps to a minute. Zero would leave the '
   . 'per-run cap as the only limit, and a customer holding the button down '
   . 'would start a scan every single tick');

Database::setSetting('user_scan_cooldown_hours', '99999');
t_eq(7 * 86400, UserScanRequest::cooldownSeconds(), 'and an absurd one clamps down');
Database::setSetting('user_scan_cooldown_hours', '6');

Database::setSetting('user_scan_max_per_run', '0');
t_eq(1, UserScanRequest::maxPerRun(), 'the per-tick cap is at least one');
Database::setSetting('user_scan_max_per_run', '500');
t_eq(10, UserScanRequest::maxPerRun(),
     'and at most ten — this runs on an 8-core server whose recurring problem '
   . 'is load, and ClamAV is not cheap');
Database::setSetting('user_scan_max_per_run', '1');

// ── The cooldown is per account ─────────────────────────────────────────────

Database::setSetting('user_scan_last_alice', (string) time());
t_ok(UserScanRequest::coolingDown('alice'), 'an account that just scanned is cooling down');
t_ok(!UserScanRequest::coolingDown('bob'),
     'while another account is unaffected — one customer cannot consume '
   . 'another customer\'s turn');

Database::setSetting('user_scan_last_alice', (string) (time() - 7 * 3600));
t_ok(!UserScanRequest::coolingDown('alice'), 'and it lapses once the window passes');

// ── Status, which is what the page renders ──────────────────────────────────

$st = UserScanRequest::statusFor('alice');
t_ok($st['enabled'], 'the feature reports as enabled by default');
t_eq(0, $st['retry_in'], 'with no wait once the cooldown has lapsed');

Database::setSetting('user_scan_last_alice', (string) time());
$st = UserScanRequest::statusFor('alice');
t_ok($st['retry_in'] > 0, 'and a wait while it has not');
t_ok($st['retry_in'] <= 6 * 3600, 'that never exceeds the window');

Database::setSetting('user_scan_enabled', '0');
t_ok(!UserScanRequest::enabled(), 'the operator can switch the whole feature off');
$off = UserScanRequest::process();
t_eq([], $off['started'], 'and nothing is started while it is off');
Database::setSetting('user_scan_enabled', '1');

// ── The page ────────────────────────────────────────────────────────────────

$page = (string) file_get_contents($repo . '/cpanel/serverscrub/index.live.php');

t_contains($page, "name=\"scan_now\"", 'the page offers a scan button');
t_contains($page, "REQUEST_METHOD'] ?? 'GET') === 'POST'",
     'which acts on POST only, so a link cannot trigger a scan');
t_contains($page, 'scan-request.json', 'and writes the request file');
t_contains($page, '@rename(',
     'written aside and moved into place, so the privileged side never reads '
   . 'a half-written file and throws the request away as malformed');

// The page must still not reach anything privileged. This is the rule the
// original user-plugin test exists to enforce, and a new button is exactly
// how it would get broken.
foreach (['SG_DB', 'Database::', 'serverscrub.db', 'backend/api', 'PDO', 'Scanner'] as $forbidden) {
    t_ok(strpos($page, $forbidden) === false,
         'the page still cannot reach ' . $forbidden
       . ' — it runs as the customer, and the database is 0700 root');
}

// It writes only inside the caller's own home.
t_ok(strpos($page, "rtrim(\$home, '/') . '/.serverscrub'") !== false,
     'the request is written inside the caller\'s own home directory');
t_ok(strpos($page, '$_POST[\'path\']') === false
     && strpos($page, '$_GET[\'user\']') === false,
     'and nothing about WHERE to scan comes from the request');

// ── The path scanned comes from passwd, never from the file ─────────────────
//
// This is the one that matters. A request file naming /root would otherwise be
// a request to scan /root, as root, on a customer's say-so.
$src  = (string) file_get_contents($repo . '/backend/lib/UserScanRequest.php');
$proc = t_fn_body($src, 'process', 'php');

t_contains($proc, 'UserReport::homeDir($user)',
     'THE PRIVILEGE BOUNDARY: the scan path is derived from the account, as '
   . 'root');
t_ok(strpos($proc, "\$req['path']") === false && strpos($proc, "\$req['dir']") === false,
     'and never read out of the request file');

$read = t_fn_body($src, 'read', 'php');
t_contains($read, 'is_link($path)',
     'the request file is never followed as a symlink — root opening a path a '
   . 'hostile user can replace between calls');
t_contains($read, 'fileowner($path)',
     'and must be owned by the account it claims to come from, or one '
   . 'customer could plant a request in another\'s directory');
t_contains($read, 'MAX_BYTES', 'the read is bounded');

// Ordering, so the cap cannot starve anyone.
t_contains($proc, 'usort(',
     'pending requests are served oldest first — directory order would let an '
   . 'account early in the alphabet starve one late in it every time the cap '
   . 'bites');

// A declined request is kept, not thrown away.
t_contains($proc, "'reason' => 'cooling down'", 'a cooling-down request is reported');
$coolAt  = strpos($proc, "'cooling down'");
$clearAt = strpos($proc, 'self::clear($user);');
t_ok($coolAt !== false && ($clearAt === false || $clearAt > $coolAt),
     'and is NOT cleared, or the customer\'s click would vanish silently and '
   . 'they would simply click again');

// ── It only exists where cPanel does ────────────────────────────────────────

$install = (string) file_get_contents($repo . '/install.sh');
t_contains($install, 'if [[ ! -d /usr/local/cpanel ]]; then',
     'the whole cPanel integration is skipped where cPanel is not installed');
t_contains($install, 'group=>security', 'and the menu entry sits in the Security group');
t_contains($install, 'features=any',
     'visible to every cPanel account, not only those on the default feature list');
