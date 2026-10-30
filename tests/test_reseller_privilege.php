<?php
/**
 * A reseller is not an administrator.
 *
 * Asked: can a user change settings from the CLI or from PHP? For a cPanel
 * customer the answer was already no, and by the right mechanism -- the
 * database is 0700 root, so neither the CLI nor any code they can run may
 * open it. Checking that question properly turned up the case nobody had
 * asked about.
 *
 * The WHM plugin is registered acls=any, so every reseller on the server can
 * open it. Signing in with a password gave them 'user' and settings were
 * refused. Signing in with a WHM API TOKEN gave them 'root' -- the top of the
 * hierarchy -- because validateWhmToken() only asks WHM whether the token
 * works, and /json-api/version answers for every account, resellers included.
 *
 * Two routes into one panel that disagreed about who you are. The token path
 * was the generous one.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The hierarchy that decides everything below ─────────────────────────────

t_no_throw(function () { Auth::requireRole('admin', ['role' => 'root']); },
     'root outranks admin');
t_no_throw(function () { Auth::requireRole('admin', ['role' => 'admin']); },
     'admin satisfies admin');

foreach (['user', 'reseller'] as $r) {
    $denied = false;
    try { Auth::requireRole('admin', ['role' => $r]); }
    catch (Throwable $e) { $denied = true; }
    t_ok($denied, "'" . $r . "' is refused an admin-only route");
}

$denied = false;
try { Auth::requireRole('admin', ['role' => 'nonsense']); }
catch (Throwable $e) { $denied = true; }
t_ok($denied, 'and an unrecognised role is refused rather than defaulted upward');

// ── Settings are admin-only, which is what makes the role matter ────────────

$api = (string) file_get_contents($repo . '/backend/api/index.php');
$rs  = t_fn_body($api, 'routeSettings', 'php');
t_contains($rs, "Auth::requireRole('admin', \$user);",
     'the settings route demands admin, so user_scan_cooldown_hours and the '
   . 'rest cannot be changed by a lesser role');

// ── THE BUG: the token path out-ranked the password path ────────────────────

$login = substr($api, (int) strpos($api, "'login' =>"), 2600);

// The cPanel branch only. Standalone mode assigns 'root' after a local
// credential check and is right to: there is one operator on that install, no
// resellers, and nobody else can reach the login at all. Banning the string
// everywhere flagged that as the bug, which it is not.
$cp = substr($login, (int) strpos($login, 'cPanel mode:'));

t_ok(strpos($cp, "\$role = 'root';") === false,
     'THE ESCALATION: no cPanel login branch hands out root unconditionally '
   . 'any more');

t_eq(2, substr_count($cp, "(\$u === 'root' || \$u === 'cpanel')"),
     'BOTH cPanel branches -- token and password -- decide the role from the '
   . 'username, and decide it the same way. One rule in one place was the '
   . 'whole fix; two rules is how they drifted apart');

// The token branch specifically.
$tokAt  = strpos($cp, "Auth::validateWhmToken");
$ruleAt = strpos($cp, "(\$u === 'root' || \$u === 'cpanel')", $tokAt);
t_ok($tokAt !== false && $ruleAt !== false && $ruleAt - $tokAt < 400,
     'the token branch assigns its role from the username it just verified');

// ── What the validator does and does not establish ──────────────────────────

$auth = (string) file_get_contents($repo . '/backend/lib/Auth.php');
$vwt  = t_fn_body($auth, 'validateWhmToken', 'php');

t_contains($vwt, 'json-api/version',
     'the validator calls an endpoint every WHM account can reach');
t_ok(strpos($vwt, 'acl') === false && strpos($vwt, 'privs') === false,
     'and checks no privilege of any kind — so its true/false says WHO, never '
   . 'WHAT they may do');

$doc = substr($auth, max(0, (int) strpos($auth, 'public static function validateWhmToken') - 900), 900);
t_contains($doc, 'AUTHENTICATION ONLY',
     'which is now stated at the function, because the next caller will '
   . 'otherwise read a true here as "this is an administrator" exactly as the '
   . 'last one did');

// ── The customer side, which was the original question ──────────────────────
//
// Kept here because it is the answer to "can a user change these settings",
// and because the guarantee is permissions rather than anything in PHP --
// encoding the source would not have changed any of it.
$install = (string) file_get_contents($repo . '/install.sh');
t_contains($install, 'chmod -R 700 "$INSTALL_DIR/database"',
     'the database is 0700, so a cPanel user cannot read or write settings '
   . 'however they try to reach them');
t_contains($install, 'chown -R root:nobody "$INSTALL_DIR"',
     'and the install tree is root-owned');
t_ok(strpos($install, 'chmod -R 755 "$INSTALL_DIR"') === false,
     'the tree is never made world-readable, which is what would actually '
   . 'leak the settings — not the source being plaintext');
