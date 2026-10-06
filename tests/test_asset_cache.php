<?php
/**
 * Every shipped front-end asset must be cache-busted.
 *
 * The dashboard rebuilt in 4.1.0 added donut() and bars() to charts.js. The
 * cache-busting step in make-release.sh stamped a hand-kept list of three
 * files -- app.css, api.js, app.js -- and charts.js was not on it. So after
 * updating, a browser kept the pre-4.1.0 charts.js: `Charts` was defined and
 * the old charts still drew, but `Charts.donut` and `Charts.bars` were
 * undefined, the new dashboard skipped those panels rather than throwing, and
 * three sections were simply blank with nothing in the console to explain it.
 *
 * A guard that is a list of filenames will be out of date the first time
 * somebody adds a file, so this checks the markup instead.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$html    = file_get_contents($repo . '/frontend/index.html');
$version = trim(file_get_contents($repo . '/VERSION'));

// ── Every local css/js reference carries a version ──────────────────────────
preg_match_all('/(?:src|href)="((?:css|js)\/[\w.\-]+\.(?:css|js))(\?v=([^"]*))?"/',
               $html, $m, PREG_SET_ORDER);

t_ok(count($m) >= 3, 'the page references its local assets');

$unstamped = [];
$stale     = [];
foreach ($m as $hit) {
    $file = $hit[1];
    $v    = $hit[3] ?? null;
    if ($v === null || $v === '') { $unstamped[] = $file; continue; }
    if ($v !== $version)          { $stale[] = $file . ' (' . $v . ')'; }
}

t_eq(0, count($unstamped),
    'every local asset is cache-busted'
    . ($unstamped ? ' — unstamped: ' . implode(', ', $unstamped) : ''));

t_eq(0, count($stale),
    'and stamped with the current version'
    . ($stale ? ' — expected ' . $version . ', got: ' . implode(', ', $stale) : ''));

// charts.js specifically, since that is the one that was missed and the one
// the dashboard depends on.
t_contains($html, 'js/charts.js?v=', 'charts.js is cache-busted');

// ── The release script stamps by pattern, not by a list ─────────────────────
$rel = file_get_contents($repo . '/scripts/make-release.sh');
t_contains($rel, 'js/[A-Za-z0-9_.-]+\.js',
    'the release script stamps any js file, not named ones');
t_contains($rel, 'css/[A-Za-z0-9_.-]+\.css',
    'and any css file');
t_ok(strpos($rel, 'js/api\.js|js/app\.js') === false,
    'the hand-kept list that missed charts.js is gone');

// ── The dashboard depends on methods that must exist in charts.js ───────────
// If a cached charts.js lacks these, the panels silently do not draw -- which
// is exactly what happened, so the dependency is worth pinning.
$charts = file_get_contents($repo . '/frontend/js/charts.js');
foreach (['donut(', 'bars(', 'timeline(', 'sparkline('] as $method) {
    t_contains($charts, $method, "charts.js provides {$method}");
}

$js = file_get_contents($repo . '/frontend/js/app.js');
t_contains($js, 'Charts.donut', 'the dashboard uses the donut');
t_contains($js, 'Charts.bars', 'and the bar chart');

// The guards must skip rather than throw, so a mismatch degrades to a blank
// panel instead of taking the whole page down -- but they must test the right
// binding, which is the const, not window.
t_contains($js, "typeof Charts !== 'undefined' && Charts.donut",
    'the donut guard checks the const binding');
t_eq(0, substr_count($js, 'window.Charts'),
    'nothing checks window.Charts, which a const never populates');
