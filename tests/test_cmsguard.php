<?php
/**
 * CMS Guard discovery.
 *
 * Reported symptom: "0 websites for CMS even though there are several
 * WordPress websites".
 *
 * The detection predicates were correct — wp-config.php plus
 * wp-includes/version.php is the right test. The fault was WHERE it looked:
 *
 *   glob("/home/*\/public_html")
 *
 * That is the primary document root of each account and nothing else. On cPanel
 * every addon domain and subdomain has its own document root, and WordPress is
 * routinely installed in a subdirectory (/public_html/blog). A server full of
 * WordPress sites could therefore report none, with no error to explain it.
 *
 * These tests build a fake hosting tree and assert each layout is found.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';

$root = $ctx['sandbox'] . '/fakehost';

/** Write a file, creating parents. */
function mk(string $path, string $body = "x"): void
{
    @mkdir(dirname($path), 0777, true);
    file_put_contents($path, $body);
}

/** Lay down the marker files that make a directory a WordPress install. */
function mkwp(string $dir, string $version = '6.4.2'): void
{
    mk($dir . '/wp-config.php', "<?php // fake\n");
    mk($dir . '/wp-includes/version.php', "<?php \$wp_version = '{$version}';\n");
}

// ── A realistic cPanel box ───────────────────────────────────────────────────
// 1. primary domain, WP at the document root
mkwp($root . '/home/alice/public_html');

// 2. WP in a subdirectory of the primary domain
mkwp($root . '/home/bob/public_html/blog');

// 3. an addon domain: its own document root under the account
mkwp($root . '/home/carol/public_html/shop.example.com');

// 4. an account with no CMS at all
mk($root . '/home/dave/public_html/index.html', '<h1>hi</h1>');

// 5. /var/www/html, the non-cPanel layout
mkwp($root . '/var/www/html');

// 6. a directory that must NOT be descended into: a plugin shipping its own
//    wp-config.php sample would otherwise register as a second install
mk($root . '/home/alice/public_html/wp-content/plugins/thing/wp-config.php', "<?php\n");
mk($root . '/home/alice/public_html/wp-content/plugins/thing/wp-includes/version.php', "<?php\n");

$guard = new CMSGuard([$root . '/home', $root . '/var/www'], $root . '/var/cpanel/userdata');
$found = $guard->scanInstalls();
$paths = array_column($found, 'install_path');

t_ok(in_array($root . '/home/alice/public_html', $paths, true),
    'WordPress at the document root is found');
t_ok(in_array($root . '/home/bob/public_html/blog', $paths, true),
    'WordPress in a subdirectory is found');
t_ok(in_array($root . '/home/carol/public_html/shop.example.com', $paths, true),
    'WordPress under an addon-domain directory is found');
t_ok(in_array($root . '/var/www/html', $paths, true),
    'WordPress at /var/www/html is found');

t_ok(!in_array($root . '/home/dave/public_html', $paths, true),
    'an account with no CMS is not reported as one');

$pluginPath = $root . '/home/alice/public_html/wp-content/plugins/thing';
t_ok(!in_array($pluginPath, $paths, true),
    'wp-content is not descended into (no phantom install from a plugin)');

t_eq(4, count($found), 'exactly the four real installs are found');

// ── cPanel userdata is authoritative ─────────────────────────────────────────
// A document root outside /home entirely — only cPanel's records know about it.
// This is the case that globbing can never find.
mkwp($root . '/srv/sites/oddball');
mk($root . '/var/cpanel/userdata/erin/oddball.com',
   "main_domain: oddball.com\ndocumentroot: {$root}/srv/sites/oddball\nuser: erin\n");

$guard2 = new CMSGuard([$root . '/home', $root . '/var/www'], $root . '/var/cpanel/userdata');
$docroots = $guard2->candidateDocroots();
t_ok(in_array($root . '/srv/sites/oddball', $docroots, true),
    'a document root is read from cPanel userdata');

$found2 = array_column($guard2->scanInstalls(), 'install_path');
t_ok(in_array($root . '/srv/sites/oddball', $found2, true),
    'a site outside the usual roots is found via cPanel userdata');

// A .cache sibling must not be parsed as a domain file.
mk($root . '/var/cpanel/userdata/erin/oddball.com.cache', "documentroot: /nonexistent\n");
$guard3 = new CMSGuard([$root . '/home'], $root . '/var/cpanel/userdata');
t_ok(!in_array('/nonexistent', $guard3->candidateDocroots(), true),
    'cPanel .cache files are ignored');

// ── The records themselves ───────────────────────────────────────────────────
$alice = null;
foreach ($found as $rec) {
    if ($rec['install_path'] === $root . '/home/alice/public_html') { $alice = $rec; }
}
t_ok($alice !== null, 'a record was built for the primary install');
if ($alice) {
    t_eq('wordpress', $alice['cms_type'], 'the CMS type is recorded');
    t_eq('6.4.2', $alice['version'],      'the WordPress version is read from version.php');
}

// ── Persistence: stats read the table, so the scan must write to it ──────────
// "0 websites" is also what an un-run scan looks like, and the two are
// indistinguishable in the UI. Confirm a scan actually persists.
$stats = $guard->getStats();
t_ok($stats['total_installs'] >= 4, 'scanInstalls() persists what it finds');
t_ok($stats['wordpress'] >= 4,      'the WordPress count is populated');

// Re-scanning must not duplicate rows: install_path is UNIQUE and the upsert
// has to hold, or a nightly scan would fail on the second run.
$guard->scanInstalls();
$after = $guard->getStats();
t_eq($stats['total_installs'], $after['total_installs'],
    'a second scan updates rather than duplicating');

// ── "Never scanned" must be distinguishable from "found nothing" ─────────────
// A fresh install and a CMS-free server both showed "0 websites", which reads
// as a broken product rather than as a next step.
$fresh = new CMSGuard([$ctx['sandbox'] . '/empty'], $ctx['sandbox'] . '/none');
Database::setSetting('cms_last_scan_at', '0');
$s0 = $fresh->getStats();
t_eq(false, $s0['ever_scanned'], 'ever_scanned is false before any scan');
t_eq(0, $s0['last_scan_at'],     'last_scan_at is 0 before any scan');

$fresh->scanInstalls();
$s1 = $fresh->getStats();
t_eq(true, $s1['ever_scanned'],  'ever_scanned is true after a scan');
t_ok($s1['last_scan_at'] > 0,    'last_scan_at is stamped by the scan');

// ── The UI must read the keys the API actually returns ───────────────────────
// The counter read d.total while getStats() returns total_installs, so it
// displayed 0 regardless of what was found. The demo fixture used `total` and
// only the demo was ever exercised.
$app = file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
t_contains($app, 'total_installs', 'the CMS panel reads total_installs from the API');

// Demo fixtures drift from the real response shape unless something checks.
// Every key the demo supplies for this panel must exist in the real payload.
if (preg_match('/Demo\.active \? \{ success: true, data: \{([^}]*)\} \} : API\.cmsStats\(\)/', $app, $m)) {
    preg_match_all('/(\w+)\s*:/', $m[1], $keys);
    $realKeys = array_keys($fresh->getStats());
    $drift = [];
    foreach ($keys[1] as $k) {
        if (!in_array($k, $realKeys, true)) { $drift[] = $k; }
    }
    t_eq(0, count($drift), 'the cmsStats demo fixture matches the real response shape'
        . ($drift ? ' — demo-only keys: ' . implode(', ', $drift) : ''));
} else {
    t_ok(false, 'could not locate the cmsStats demo fixture to compare shapes');
}

// ── Risk verdict and the threshold it was judged against ─────────────────────
// Reported: the table "is not giving a complete list of cms installations,
// their version and which ones do we think is at risk or are outdated".
//
// The version and an outdated flag were there; what was missing was any way to
// see what that flag MEANT. The threshold was a hard-coded 6.4 -- a WordPress
// release from 2023 -- so sites well behind current were reported as fine, and
// the operator had no number to check the verdict against.
$rows = $guard->getInstalls();
t_ok(count($rows) >= 1, 'installs are listed (' . count($rows) . ')');

foreach ($rows as $r) {
    t_ok(array_key_exists('target_version', $r),
        $r['cms_type'] . ' row carries the version it was judged against');
    t_ok(array_key_exists('risk', $r),
        $r['cms_type'] . ' row carries a risk verdict');
    t_ok(in_array($r['risk'], ['high', 'medium', 'low', 'ok', 'unknown'], true),
        $r['cms_type'] . ' risk is one of the known levels (' . $r['risk'] . ')');
}

// An ancient install must not be reported as current.
$old = array_values(array_filter($rows, fn($r) => ($r['version'] ?? '') !== 'unknown'
                                              && version_compare($r['version'], '5.0', '<')));
foreach ($old as $r) {
    t_ok($r['risk'] !== 'ok',
        'a very old ' . $r['cms_type'] . ' (' . $r['version'] . ') is not reported as current');
}

// ── The threshold is configurable ────────────────────────────────────────────
// Hard-coded minimums in a shipped release go stale the day after it ships.
Database::setSetting('cms_min_wordpress', '99.0');
$strict = new CMSGuard([$root . '/home', $root . '/var/www'], $root . '/var/cpanel/userdata');
$wpRows = array_values(array_filter($strict->getInstalls(),
    fn($r) => $r['cms_type'] === 'wordpress' && ($r['version'] ?? '') !== 'unknown'));
t_ok(count($wpRows) >= 1, 'there is a WordPress row to re-judge');
foreach ($wpRows as $r) {
    t_eq('99.0', $r['target_version'], 'the configured threshold is the one applied');
}

// A malformed override must not silently disable the check.
Database::setSetting('cms_min_wordpress', 'not-a-version');
$safe = new CMSGuard([$root . '/home'], $root . '/var/cpanel/userdata');
$wp2 = array_values(array_filter($safe->getInstalls(), fn($r) => $r['cms_type'] === 'wordpress'));
if ($wp2) {
    t_ok($wp2[0]['target_version'] !== 'not-a-version',
        'a malformed threshold is ignored rather than accepted');
}
Database::setSetting('cms_min_wordpress', '');
