<?php
/**
 * The Detected Threats table has to reach past its newest page.
 *
 * Reported: "Malware scanner logs do not paginate i need them to start with
 * 50 records a page. then 50, 100, 200, 500, All." -- and then, after a
 * release that did not fix it: "also there is no paginatio for malware scan
 * logs."
 *
 * The first attempt paginated the wrong table. The Malware Scanner page holds
 * two: the scan HISTORY log (scanner/jobs) lower down, and Detected Threats
 * (scanner/threats), the list of findings an operator actually works in. The
 * word "logs" matched the first; the screenshot was of the second.
 *
 * Its query was `ORDER BY detected_at DESC LIMIT 200` with no offset and no
 * total, so a server with months of findings showed its newest 200 and
 * offered no way to reach the rest -- nor any sign that a rest existed. The
 * only control on the card was a STATUS FILTER whose first option is "All",
 * which looks like a page-size control and is not one.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$api  = t_code($repo . '/backend/api/index.php');
$js   = t_js($repo . '/frontend/js/app.js');
$apij = t_js($repo . '/frontend/js/api.js');
$html = file_get_contents($repo . '/frontend/index.html');

// ── The route can serve a page other than the first ───────────────────────
preg_match('/case \'threats\':.*?\}\)\(\);/s', $api, $m);
$route = $m[0] ?? '';
t_ok($route !== '', 'the scanner/threats route is still there');

t_contains($route, "\$offset   = max(0, (int) (\$q['offset'] ?? 0));",
     'AN OFFSET EXISTS AT ALL: without one there was no second page to ask '
   . 'for, whatever the UI did');
t_contains($route, 'LIMIT {$limit} OFFSET {$offset}',
     'and the query uses it');
t_ok(strpos($route, 'ORDER BY detected_at DESC LIMIT 200') === false,
     'the bare LIMIT 200 is gone');

// ── The total is counted under the SAME filter as the rows ────────────────
//
// Counting without the WHERE would make "51-100 of 900" appear above a
// filtered list of twelve.
t_contains($route, 'SELECT COUNT(*) AS c FROM threats $sqlWhere', $params ?? '',
     'THE TOTAL RESPECTS THE FILTER: it is counted with the same WHERE and '
   . 'the same bound parameters as the page itself');

// `total` and `active` are different questions and must not be conflated:
// active is outstanding findings regardless of filter; total is rows matching
// what is on screen.
t_contains($route, "'active' => \$active,",
     'the outstanding count survives');
t_contains($route, "'total'  => \$total,",
     'alongside the page total, which is a different number — outstanding '
   . 'findings are filter-independent, the total is not');

// ── "All" is bounded, and says when it was ────────────────────────────────
t_contains($route, '$limit    = $raw <= 0 ? $HARD_MAX : max(1, min($HARD_MAX, $raw));',
     'limit <= 0 means All, which the UI sends for that option');
t_contains($route, '$HARD_MAX = 5000;',
     'ALL IS STILL BOUNDED: a browser asked to lay out a hundred thousand '
   . 'rows stops responding');
t_contains($route, "'capped' => (\$raw <= 0 && \$total > \$HARD_MAX)",
     'and when All could not be honoured in full the response says so, '
   . 'rather than showing a prefix and calling it everything');

// ── The sizes asked for, in order, defaulting to 50 ───────────────────────
t_contains($js, 'const THREATS_PAGE_SIZES = [50, 100, 200, 500, 0];',
     'THE REQUESTED SIZES: 50, 100, 200, 500 and All (0)');
t_contains($js, 'return THREATS_PAGE_SIZES.includes(n) ? n : 50;',
     'defaulting to 50, as asked');

preg_match('/<select class="form-input threats-page-size".*?<\/select>/s', $html, $sm);
$sel = $sm[0] ?? '';
t_ok($sel !== '', 'the page-size control exists in the markup');
foreach ([['50','50'],['100','100'],['200','200'],['500','500'],['0','All']] as [$v,$label]) {
    t_contains($sel, '<option value="' . $v . '">' . $label . '</option>',
         "the selector offers {$label}");
}

// ── 0 is a real choice, not a falsy accident ──────────────────────────────
preg_match('/function threatsPageSize\(\).*?\n}/s', $js, $pm);
$sizeFn = $pm[0] ?? '';
t_ok($sizeFn !== '', 'threatsPageSize() is defined');
t_ok(strpos($sizeFn, '|| 50;') === false,
     'ZERO IS A REAL CHOICE: a falsy fallback would silently turn a saved '
   . '"All" back into 50 on every load, which reads as the setting not saving');
t_contains($sizeFn, 'catch (e) { n = NaN; }',
     'and a private window, where sessionStorage throws, falls back cleanly');

// The API helper has the same trap: `if (limit)` would drop All.
t_contains($apij, "if (limit  !== undefined) p.set('limit',  String(limit));",
     'and the API helper tests against undefined, not falsiness, so limit=0 '
   . 'reaches the server instead of being dropped');

// ── Edges ─────────────────────────────────────────────────────────────────
preg_match('/function threatsPage\(dir\).*?\n}/s', $js, $gm);
t_contains($gm[0] ?? '', 'if (!size) { return; }',
     'ALL IS ONE PAGE: Previous/Next do nothing when everything is shown');
t_contains($gm[0] ?? '', 'if (next < 0 || next >= ThreatsPage.total) { return; }',
     'and neither button walks past the data');

preg_match('/function threatsSetPageSize\(v\).*?\n}/s', $js, $sp);
t_contains($sp[0] ?? '', 'ThreatsPage.offset = 0;',
     'changing the page size returns to the first page — page 3 of 50 is not '
   . 'page 3 of 500, and the old offset would land past the end');

// ── Changing the FILTER also returns to page one ──────────────────────────
//
// Filtering to "Active" while on page 3 of everything would otherwise ask for
// rows 101-150 of a list that may hold four.
t_contains($html, 'onchange="threatsFilterChanged()"',
     'the status filter goes through a handler, not straight to loadThreats');
preg_match('/function threatsFilterChanged\(\).*?\n}/s', $js, $fc);
t_contains($fc[0] ?? '', 'ThreatsPage.offset = 0;',
     'A NEW FILTER IS A NEW LIST: it starts at the first page, rather than '
   . 'asking for rows 101-150 of a list that may hold four');
