<?php
/**
 * The icon in cPanel's Security section.
 *
 * FROM A LIVE SERVER. Everything was installed -- plugin directory, icon,
 * install.json, dynamicui conf, AppConfig, all present and dated minutes ago
 * -- and no icon appeared in cPanel. No error anywhere either, which is what
 * made it expensive: every check said the plugin was registered.
 *
 * The conf was written as `key=value` lines. cPanel's dynamicui parser wants
 * ONE line of comma-separated `key=>value` pairs, Perl-hash style, so the file
 * was read and silently discarded. cPGuard sits in the same Security group on
 * the same cPanel and its conf is the single-line form, which is what these
 * assertions are taken from.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$install = (string) file_get_contents($repo . '/install.sh');

// Pull the line the installer actually writes.
t_ok(preg_match('/^description=>ServerScrub Security,.*width=>48$/m', $install, $m) === 1,
     'THE FORMAT: the conf is one line of comma-separated key=>value pairs, '
   . 'the shape cPanel actually parses');
$line = $m[0] ?? '';

// Fat arrows, not equals. This is the whole bug in one character.
t_ok(strpos($line, '=>') !== false, 'pairs use => , not =');
t_ok(preg_match('/(^|,)[a-z]+=[^>]/', $line) === 0,
     'and no pair uses a bare = , which is what the parser ignores');

// Every key cPGuard carries, because that conf demonstrably renders here.
foreach (['description', 'file', 'group', 'height', 'imgtype', 'itemdesc',
          'itemorder', 'subtype', 'type', 'url', 'width'] as $key) {
    t_ok(strpos($line, $key . '=>') !== false,
         'carries ' . $key . ', as cPGuard does');
}

t_contains($line, 'group=>security',
     'and lands in the Security group, which is where it was asked for');
t_contains($line, 'url=>serverscrub/index.php',
     'THE OTHER HALF: the url is RELATIVE to the theme directory. An absolute '
   . '/frontend/<theme>/... path does not resolve');
t_ok(strpos($line, 'url=>/frontend') === false, 'never an absolute url');

// No feature gate. Gating is what hid this from every account on a reseller's
// own feature list, which on a reseller box is most accounts.
t_ok(strpos($line, 'feature=>') === false,
     'no feature key, so the entry is not hidden from accounts whose feature '
   . 'list is a reseller\'s rather than the default one');

// ── The restart that makes it appear ────────────────────────────────────────
//
// register_appconfig restarts cpsrvd for the AppConfig it registered and knows
// nothing about the dynamicui conf, which is theme data cached separately. The
// restart used to run only when registration FAILED -- so on every install
// where everything went right, the icon did not appear.
$step8 = substr($install, (int) strpos($install, 'Step 8: Restart cpsrvd'), 1200);
t_ok(strpos($step8, 'if ! $_REG_OK; then') === false,
     'THE SKIPPED STEP: cpsrvd is no longer restarted only on failure');
t_contains($step8, 'restartsrv_cpsrvd', 'it is restarted');
t_contains($step8, 'warn ', 'and says so when the script is missing, rather than silently not restarting');

// ── The page it points at has to exist in the package ───────────────────────
t_ok(is_file($repo . '/cpanel/serverscrub/index.php'),
     'the page the entry points at is in the repo');

$mk = (string) file_get_contents($repo . '/scripts/make-release.sh');
t_contains($mk, 'cpanel',
     'and cpanel/ is in the release allowlist, or the menu entry would point '
   . 'at a file the zip does not carry');

$up = (string) file_get_contents($repo . '/update.sh');
t_contains($up, 'UPDATE_DIRS=( backend frontend whm cpanel )',
     'and updates overlay it, so a fix to the page reaches existing servers');
t_contains($up, '--register-only',
     'and re-run registration, so a fix to the CONF reaches them too');
