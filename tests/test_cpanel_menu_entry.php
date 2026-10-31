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
t_contains($line, 'url=>serverscrub/index.live.php',
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
t_ok(is_file($repo . '/cpanel/serverscrub/index.live.php'),
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

// ── The icon has to be 48x48 ────────────────────────────────────────────────
//
// The installer copied the WHM artwork: 256x256, 87KB. install_plugin
// accepted it, placed it correctly in assets/application_icons/, reported
// "Plugin installed ok" -- and Jupiter drew nothing. Every icon it renders
// from that directory is 48x48 (cPGuard's is 48x48, 967 bytes), and an
// oversized one is silently ignored rather than scaled. Nothing anywhere
// reported a problem, which is why this took five attempts to find.
$icon = $repo . '/cpanel/serverscrub/serverscrub.png';
t_ok(is_file($icon), 'a cPanel-sized icon ships beside the page');

$size = @getimagesize($icon);
t_eq(48, $size[0] ?? 0, 'THE SILENT REJECTION: it is 48 wide, the only size '
   . 'Jupiter renders from assets/application_icons/');
t_eq(48, $size[1] ?? 0, 'and 48 tall');
t_eq('image/png', $size['mime'] ?? '', 'and a PNG, as cPGuard\'s is');

t_ok(filesize($icon) < 20000,
     'and small — the 87KB original was the clue that this was the WHM '
   . 'artwork rather than an icon');

// The installer must prefer it, and fall back rather than break.
$iconBlock = substr($install, (int) strpos($install, '48x48, and that is not a detail'), 1400);
t_contains($iconBlock, 'cpanel/serverscrub/serverscrub.png',
     'the installer copies the cPanel-sized icon');
t_contains($iconBlock, '_ICON_SRC="${SCRIPT_DIR}/whm/serverscrub.png"',
     'falling back to the WHM one if it is absent, so a missing asset costs '
   . 'an icon rather than the whole registration');

// WHM keeps the large one: it serves the file directly and is not constrained.
t_ok(is_file($repo . '/whm/serverscrub.png'), 'the WHM artwork is still shipped');
$whm = @getimagesize($repo . '/whm/serverscrub.png');
t_ok(($whm[0] ?? 0) > 48,
     'and is still the large version — WHM serves it straight from '
   . 'addon_plugins, where size does not matter');

// ── Branding comes from the logo, not from taste ────────────────────────────
//
// The first version of both the plugin header and the marketing site used a
// hand-drawn SVG shield and #1668b3 / #1976b6 / #1d7a46 — colours that appear
// nowhere in the product's artwork. Counting pixels by hue family in
// frontend/images/logo.png gives the real palette:
//
//   green  10,948 px  #00b038   the word "Scrub" and the swoosh
//   navy   21,096 px  #000820   the shield body
//   blue               #0090f0  the shield highlight
//
// A brand colour is not a judgement call when the logo is sitting there to be
// measured.
$plugin = (string) file_get_contents($repo . '/cpanel/serverscrub/index.live.php');

t_contains($plugin, '--green:#00b03c', 'the plugin page uses the logo green');
t_contains($plugin, '--navy:#001a3d', 'and the logo navy');
t_contains($plugin, '--blue:#0090f0', 'and the logo blue');

// Strip comments before judging: the comment explaining the change names the
// colours it replaced, and a plain search would flag that explanation as the
// thing it warns about.
$pcode = (string) preg_replace(['~/\*.*?\*/~s', '~//[^\n]*~'], '', $plugin);
foreach (['#1668b3', '#1976b6', '#1d7a46'] as $invented) {
    t_ok(strpos($pcode, $invented) === false,
         'no invented colour ' . $invented . ' remains in the plugin page');
}

t_contains($plugin, '<img src="serverscrub.png"',
     'THE REAL MARK: the header uses the icon the installer already places '
   . 'beside the page, not a hand-drawn lookalike');
t_ok(strpos($pcode, 'M32 3 56 12v20c0 14-10 25-24 29') === false,
     'and the hand-drawn shield path is gone');

// ── The marketing site, same rule ───────────────────────────────────────────
$css = (string) file_get_contents($repo . '/website/assets/css/site.css');
$ccode = (string) preg_replace(['~/\*.*?\*/~s'], '', $css);
t_contains($css, '--green:#00b03c', 'the site uses the logo green');
t_contains($css, '--navy:#001a3d', 'and the logo navy');
t_ok(strpos($ccode, '#1668b3') === false, 'and none of the invented blue');

t_ok(is_file($repo . '/website/assets/img/logo.png'),
     'the real logo ships with the site');
t_ok(!is_file($repo . '/website/assets/img/logo.svg'),
     'and the hand-drawn one is gone');

// The header uses the MARK, not the full lockup.
//
// logo.png is a 480x304 lockup whose wordmark fills the lower half; scaled to
// a 38px header it rendered "ServerScrub" at about six pixels and read as a
// smudge. The shield survives being small; the words are set in type.
$idx = (string) file_get_contents($repo . '/website/index.html');
t_contains($idx, 'src="/assets/img/mark-64.png"',
     'THE LEGIBILITY FIX: the header uses the shield mark');
t_contains($idx, '<span class="wm">Server<b>Scrub</b></span>',
     'with the wordmark set in type, in the logo\'s own two colours');
t_contains($idx, 'footer', 'and the full lockup is kept for the footer');

$mark = @getimagesize($repo . '/website/assets/img/mark-64.png');
t_eq(64, $mark[0] ?? 0, 'the mark is square and small enough to stay sharp');

// Everything the deploy script uploads has to exist.
$dep = (string) file_get_contents($repo . '/scripts/deploy-site.sh');
foreach (['logo.png', 'icon-180.png', 'favicon.png', 'mark-64.png', 'hero.svg'] as $a) {
    t_contains($dep, $a, 'deploy-site.sh publishes ' . $a);
    t_ok(is_file($repo . '/website/assets/img/' . $a),
         'and ' . $a . ' exists to be published');
}
t_ok(strpos($dep, 'logo.svg') === false,
     'and no longer tries to publish a file that was deleted');
