<?php
/**
 * Numbers on the attack timeline.
 *
 * Reported: the dashboard charts WAF blocks, brute force and malware over 30
 * days with no values on the points, so the shape of the line was all it
 * conveyed. A peak you cannot read a number off is not worth the space.
 *
 * Fixing it turned up a second fault. The renderer replaced the <svg> with
 * `outerHTML`, and the markup it generated carried no id -- so after the first
 * render `getElementById('timeline-chart')` found nothing and every later
 * refresh silently did nothing. The dashboard has been showing whatever was
 * true when the page was first opened.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$charts = file_get_contents($repo . '/frontend/js/charts.js');
$tl = substr($charts, strpos($charts, 'timeline(svgEl, data, datasets)'), 9000);

// -- The element must survive a re-render ------------------------------------
t_ok(strpos($tl, 'svgEl.outerHTML') === false,
    'the chart element is no longer replaced, which used to discard its id');
t_contains($tl, 'svgEl.innerHTML = svg', 'its contents are replaced instead');
t_contains($tl, "svgEl.setAttribute('viewBox'", 'and the viewBox set on the element itself');

// -- Values are printed on the points ----------------------------------------
t_contains($tl, 'paint-order="stroke"',
    'value labels are stroked behind the glyphs so they stay legible over lines');
t_contains($tl, 'toLocaleString',
    'and carry thousands separators, since 97400 beside 3174 is hard to compare');

// -- But not on every point --------------------------------------------------
// Thirty days times three series is ninety labels on one small chart, which is
// less readable than none.
t_contains($tl, 'const labelled = datasets.map',
    'the points that carry a value are chosen deliberately');
t_contains($tl, 'v > 0 && (i % 5 === 0', 'the regularly spaced non-zero points');
t_contains($tl, 'values.indexOf(Math.max(...values))',
    'and each series peak, which is the number people actually want');

// A flat run of zeros labelled "0 0 0 0 0" hides the numbers that matter.
$lblBlock = substr($tl, strpos($tl, 'const labelled = datasets.map'), 420);
t_contains($lblBlock, 'v > 0', 'zeros are never labelled');

// -- Labels must not land on top of each other -------------------------------
// Offsetting by series index alone is not enough: two series at ADJACENT dates
// with similar values collide, which is how "120" and "58" came to be printed
// over one another.
t_contains($tl, 'const placed = []', 'placed labels are tracked');
t_contains($tl, 'const hits =', 'and a new one is tested against them');
// Both loops: one searching upward, one searching downward after a flip.
// Asserting only that the string appears somewhere would pass with either
// removed, which is not the behaviour being protected.
t_eq(2, substr_count($tl, 'while (hits('),
    'a label is moved clear going up, and again after flipping below');
t_contains($tl, 'ptY(v) + 16', 'flipping below the point when there is no room above');

// -- Every day is readable, even unlabelled ones -----------------------------
t_contains($tl, '<title>', 'each day carries a hover value');
t_contains($tl, 'fill="transparent"', 'via a transparent hit area');
$hover = substr($tl, strpos($tl, 'const band = cW'), 600);
t_contains($hover, 'ds.label', 'naming each series');
t_contains($hover, 'ds.values[i]', 'with its value for that date');

// -- The caller still passes labels, which the hover text needs ---------------
$js = file_get_contents($repo . '/frontend/js/app.js');
$call = substr($js, strpos($js, 'Charts.timeline(svgEl'), 420);
t_contains($call, "label: 'WAF Blocks'",    'the dashboard labels its WAF series');
t_contains($call, "label: 'Brute Force'",   'and brute force');
t_contains($call, "label: 'Malware'",       'and malware');
