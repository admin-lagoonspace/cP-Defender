<?php
/**
 * The dashboard redesign, the loading mark, and a guard that never guarded.
 *
 * Asked for: a dashboard laid out like the reference product, the full logo as
 * the first-load splash, the icon used everywhere a spinner was, and a loading
 * state for each left-menu page.
 *
 * The interesting find was none of those. charts.js declares `const Charts`,
 * and a top-level const is NOT a property of window -- so every
 * `window.Charts?.x` guard was permanently false. The guard meant to be
 * defensive silently disabled the chart instead, and the brute-force chart
 * shipped in 3.36.0 had never drawn once.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$js    = file_get_contents($repo . '/frontend/js/app.js');
$html  = file_get_contents($repo . '/frontend/index.html');
$css   = file_get_contents($repo . '/frontend/css/app.css');
$chart = file_get_contents($repo . '/frontend/js/charts.js');

// ── The guard that disabled what it was guarding ────────────────────────────
t_ok(strpos($chart, 'const Charts') !== false,
    'charts.js declares Charts with const, which does not attach to window');
t_eq(0, substr_count($js, 'window.Charts'),
    'nothing guards on window.Charts, which is always undefined');
t_ok(substr_count($js, "typeof Charts !== 'undefined'") >= 3,
    'the guards test the binding that actually exists');

// ── New chart types ─────────────────────────────────────────────────────────
t_contains($chart, 'donut(svgEl, slices, centre)', 'there is a donut renderer');
t_contains($chart, 'bars(svgEl, labels, series)', 'and a bar renderer');
// A donut of nothing is a full circle, which reads as "all of one thing".
t_contains($chart, 'A donut of nothing is a circle',
    'an empty donut is drawn as an empty ring, not a full one');

// ── Headline figures compare periods ────────────────────────────────────────
$api = t_code($repo . '/backend/api/index.php');
t_contains($api, 'function routeOverview', 'the overview is a route');
t_contains($api, "'overview'   => routeOverview", 'and is dispatched');

// Percentage change has awkward cases, and faking them is worse than omitting.
t_contains($api, 'return $cur === 0 ? 0.0 : null;',
    'a period with no predecessor reports no change rather than a fabricated one');
t_contains($js, 'no earlier period',
    'and the UI says so instead of printing a percentage');

// ── Only measured things appear in the summary ──────────────────────────────
// "Database infections: 0" on a product that never looks at a database is a
// claim, not a reading.
$ov = substr($api, strpos($api, 'function routeOverview'), 6000);
// Asserted on the rows themselves, not on a comment: t_code() strips comments,
// and a claim about intent is worth less than the list it produced anyway.
foreach (['Outdated applications', 'Files in quarantine', 'Changed system files'] as $row) {
    t_contains($ov, $row, "the summary reports {$row}");
}
t_ok(strpos($ov, 'Database infections') === false,
    'and does not report something the product never looks at');

// ── Counts are cast, or they silently return nothing ────────────────────────
// Same trap as the brute-force threshold: PDO binds every parameter as TEXT.
t_contains($ov, 'CAST(? AS INTEGER)', 'time comparisons cast their bound values');

// ── The loading mark replaces the spinner ───────────────────────────────────
t_contains($css, '.ss-load', 'there is a loading mark');
t_contains($css, 'ss-breathe', 'which animates');
t_contains($css, 'prefers-reduced-motion',
    'and sits still for anyone who has asked for less motion');
t_contains($js, 'function loadingMark', 'pages can render it');
t_contains($js, 'function loadingRow', 'including inside a table');
t_contains($html, 'images/icon.png', 'it uses the product icon');

// The blocking overlay uses the mark rather than a ring.
$busy = substr($html, strpos($html, 'id="sg-busy"'), 600);
t_contains($busy, 'ss-load', 'the blocking overlay uses the mark');
t_ok(strpos($busy, 'sg-spin') === false, 'and no longer a spinning ring');

// ── First-load splash ───────────────────────────────────────────────────────
t_contains($html, 'id="ss-splash"', 'there is a first-load splash');
t_contains($html, 'images/logo.png', 'showing the full lockup');
t_contains($js, 'function dismissSplash', 'which is dismissed');
// Dismissing on a timer would either cover a ready page or uncover a blank one.
$op = substr($js, strpos($js, 'function openPage(name)'), 3000);
t_contains($op, 'dismissSplash()', 'once a page has actually been drawn');
t_contains($html, 'dismissSplash', 'and when the login form is shown instead');

// ── Icons ───────────────────────────────────────────────────────────────────
foreach (['icon.png', 'icon-180.png', 'icon-64.png', 'icon-32.png'] as $f) {
    $p = $repo . '/frontend/images/' . $f;
    t_ok(is_file($p) && filesize($p) > 500, "ships images/{$f}");
}
t_ok(is_file($repo . '/whm/serverscrub.png'), 'and the WHM/cPanel plugin icon');
t_contains($html, 'rel="apple-touch-icon"', 'there is a touch icon');
t_contains($html, 'sizes="32x32"', 'and a tab icon');

// ── The dashboard sections exist and are filled ─────────────────────────────
foreach (['ov-cards', 'ov-donut', 'ov-compare', 'ov-alerts',
          'ov-waf-chart', 'ov-threat-chart', 'ov-summary'] as $id) {
    t_contains($html, 'id="' . $id . '"', "the dashboard has #{$id}");
}
t_contains($js, 'async function loadOverview', 'and something that fills them');
t_contains($js, 'function renderOverviewAlerts', 'including the alerts panel');

// Alerts are built from what the dashboard already loaded, not a second round
// of requests.
t_contains($js, 'State.lastDash = data', 'the dashboard payload is kept for the alerts');
t_contains($js, 'State.lastMonitor = d', 'and the monitor status');

// Everything rendered from the summary and alerts is escaped: the labels are
// ours, but the values and page names flow through the same helper.
$sum = substr($js, strpos($js, "const sum = document.getElementById('ov-summary')"), 700);
t_contains($sum, 'esc(r.label)', 'summary labels are escaped');
