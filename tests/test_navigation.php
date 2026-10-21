<?php
/**
 * The navigation must survive layout work.
 *
 * The dashboard was rebuilt in 4.1.0 by inserting markup into the dashboard
 * page. A mis-placed insertion point is one of the easiest ways to damage a
 * single-file UI: land inside the sidebar and nav items vanish, land after the
 * wrong closing tag and a whole page ends up nested in another. Nothing here
 * would fail a syntax check, and the only symptom is a menu entry that is
 * quietly gone.
 *
 * So the nav is pinned: every entry, every target, and the structure that
 * holds them.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$html = file_get_contents($repo . '/frontend/index.html');

// ── Every sidebar entry, by name ────────────────────────────────────────────
// Listed explicitly rather than counted: a count still passes when one item is
// swapped for another, and the point is that each of these is reachable.
$expected = [
    'dashboard'  => 'Dashboard',
    'scanner'    => 'Malware Scanner',
    'firewall'   => 'Firewall',
    'waf'        => 'WAF',
    'iprep'      => 'IP Reputation',
    'botshield'  => 'Bot Shield',
    'cms'        => 'CMS Guard',
    'bruteforce' => 'Brute Force',
    'rootkit'    => 'Rootkit Scan',
    'integrity'  => 'File Integrity',
    'php'        => 'PHP Hardening',
    'monitor'    => 'Real-Time Monitor',
    'logs'       => 'Log Analyzer',
    'events'     => 'Security Events',
    'settings'   => 'Settings',
];

foreach ($expected as $page => $label) {
    t_contains($html, 'data-page="' . $page . '"', "the nav has an entry for {$page}");
    t_contains($html, 'id="page-' . $page . '"', "and a page container for {$page}");
}

// ── Nothing orphaned in either direction ────────────────────────────────────
preg_match_all('/data-page="([a-z]+)"/', $html, $m);
$navTargets = array_values(array_unique($m[1]));
preg_match_all('/id="page-([a-z]+)"/', $html, $m2);
$pages = array_values(array_unique($m2[1]));

sort($navTargets); sort($pages);
$missingPage = array_diff($navTargets, $pages);
$missingNav  = array_diff($pages, $navTargets);

t_eq(0, count($missingPage),
    'every nav entry points at a page that exists'
    . ($missingPage ? ' — missing: ' . implode(', ', $missingPage) : ''));
t_eq(0, count($missingNav),
    'every page is reachable from the nav'
    . ($missingNav ? ' — unreachable: ' . implode(', ', $missingNav) : ''));

// ── The sidebar structure itself ────────────────────────────────────────────
t_contains($html, 'class="sidebar-item"', 'sidebar entries use the expected class');
t_ok(substr_count($html, 'class="sidebar-item"') >= 14,
    'the sidebar still holds its full set of entries');

// The grouping headings, which are what make a fifteen-item menu readable.
// Title case in the markup; the uppercase on screen is CSS.
foreach (['Modules', 'Protection', 'Monitoring'] as $heading) {
    t_contains($html, '<div class="sidebar-section-label">' . $heading . '</div>',
        "the sidebar keeps its {$heading} grouping");
}
t_eq(3, substr_count($html, 'class="sidebar-section-label"'),
    'all three groupings are present');

// ── New dashboard markup is inside the dashboard, not the nav ───────────────
// This is the specific accident the test exists to catch: an insertion that
// lands in the sidebar, or that straddles a page boundary.
$lastSidebar = strrpos($html, 'class="sidebar-item"');
$dashStart   = strpos($html, 'id="page-dashboard"');
$nextPage    = strpos($html, 'id="page-scanner"');

t_ok($lastSidebar !== false && $dashStart !== false && $lastSidebar < $dashStart,
    'the sidebar is closed before the dashboard page begins');

foreach (['ov-cards', 'ov-donut', 'ov-compare', 'ov-alerts',
          'ov-waf-chart', 'ov-threat-chart', 'ov-summary'] as $id) {
    $at = strpos($html, 'id="' . $id . '"');
    t_ok($at !== false && $at > $dashStart && $at < $nextPage,
        "#{$id} sits inside the dashboard page, not in the nav or another page");
}

// ── The top navigation bar ──────────────────────────────────────────────────
t_contains($html, 'class="nav-item"', 'the top navigation bar is present');
t_ok(substr_count($html, 'class="nav-item"') >= 6,
    'with its entries intact');

// ── The brand mark in the sidebar header ────────────────────────────────────
t_contains($html, 'ServerScrub', 'the product name is in the shell');
t_contains($html, 'images/icon-64.png', 'and the icon mark');

// ── Every nav entry must actually load its page ─────────────────────────────
//
// FROM A LIVE SERVER. The dispatch was a 16-arm switch and `monitor` was not
// one of them. Opening Real-Time Monitor therefore loaded nothing: the panel
// sat on "Loading…" and "Checking…" indefinitely, and the operator had to hit
// Refresh every single time. That button works because it calls the loader
// directly, which made it look like a refresh bug rather than a missing wire.
//
// A missing arm in a long switch is invisible. A missing key in a table is
// not, and this test makes it fail the build.

$app = file_get_contents($repo . '/frontend/js/app.js');

t_ok(preg_match('/const PAGE_LOADERS = \{(.*?)
  \};/s', $app, $m) === 1,
     'the page dispatch is a table that can be checked');
$table = $m[1];

preg_match_all('/data-page="([a-z0-9_-]+)"/', $html, $nav);
$pages = array_values(array_unique($nav[1]));
t_ok(count($pages) > 10, 'the sidebar has its full set of entries');

preg_match_all('/^\s{4}([a-z0-9_]+):/m', $table, $km);
$keys = $km[1];

foreach ($pages as $page) {
    t_ok(in_array($page, $keys, true),
         "the \"$page\" nav entry has a loader — without one the page opens "
       . "empty and only a manual Refresh fills it");
}

// A loader for a page that does not exist is dead weight and usually a typo
// in the key, which silently breaks the page it was meant to serve.
foreach ($keys as $k) {
    t_ok(in_array($k, $pages, true),
         "the loader \"$k\" corresponds to a real nav entry");
}

// ── Every page shows that it is loading ─────────────────────────────────────
//
// Only `firewall` went through API.withBusy(); every other page loaded in
// silence, so a slow endpoint was indistinguishable from a broken one.
// Dispatching through one call site means it cannot be forgotten again.

t_contains($app, 'API.withBusy(entry[0], entry[1])',
     'page loads go through the busy overlay');
t_eq(1, preg_match_all('/API\.withBusy\(entry/', $app),
     'from exactly one place, so no page can be missed');

// Each entry must RETURN its work, or the overlay lifts immediately and the
// indicator flashes instead of covering the load.
foreach (explode("
", $table) as $line) {
    if (!preg_match('/^\s{4}[a-z0-9_]+:\s*\[/', $line)) continue;
    if (strpos($line, '=>') === false) continue;   // continuation line
    t_ok(preg_match('/=>\s*(?:Promise\.all\(|[A-Za-z_]\w*\()/', $line) === 1,
         'a loader entry returns its promise: ' . trim(substr($line, 0, 48)));
}

// A failing loader must not leave the splash up over the whole UI.
t_contains($app, '.catch(err =>',
     'a page load that throws is caught');
t_contains($app, 'Could not load this page',
     'and the operator is told, rather than left looking at a blank panel');
