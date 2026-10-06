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
