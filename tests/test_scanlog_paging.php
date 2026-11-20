<?php
/**
 * The scanner log has to reach past its newest page.
 *
 * Reported: "Malware scanner logs do not paginate i need them to start with
 * 50 records a page. then 50, 100, 200, 500, All".
 *
 * The route fetched a fixed `scanner/jobs?limit=50`, the API clamped limit to
 * 200 and had no offset at all, and the table rendered whatever came back.
 * So a server with months of nightly sweeps showed its most recent fifty and
 * offered no way to reach the rest -- nor any sign that a rest existed. The
 * footer said "last 50 scan(s)", which reads like a total.
 *
 * This is the same defect the WAF events table had, and it is fixed the same
 * way on purpose: two tables that page differently are two things to learn.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$api  = t_code($repo . '/backend/api/index.php');
$js   = t_js($repo . '/frontend/js/app.js');
$html = file_get_contents($repo . '/frontend/index.html');

// ── The API can actually serve a page other than the first ────────────────
preg_match('/case \'jobs\':.*?\}\)\(\);/s', $api, $m);
$route = $m[0] ?? '';
t_ok($route !== '', 'the scanner/jobs route is still there');

t_contains($route, "\$offset = max(0, (int) (\$q['offset'] ?? 0));",
     'AN OFFSET EXISTS AT ALL: without one there was no second page to ask '
   . 'for, whatever the UI did');
t_contains($route, 'LIMIT {$limit} OFFSET {$offset}',
     'and the query uses it');
t_contains($route, "'total'  => \$total,",
     'THE TOTAL IS RETURNED: "last 50 scan(s)" reads as a total when it is a '
   . 'page size, so the count has to come from the server — the UI cannot '
   . 'infer how many it did not receive');
t_contains($route, "'SELECT COUNT(*) AS c FROM scan_jobs'",
     'counted over the whole table, not the page');

// ── "All" is bounded, and says when it was ────────────────────────────────
t_contains($route, '$limit  = $raw <= 0 ? $HARD_MAX : max(1, min($HARD_MAX, $raw));',
     'limit <= 0 means All, which the UI sends for that option');
t_contains($route, '$HARD_MAX = 5000;',
     'ALL IS STILL BOUNDED: a browser asked to lay out a hundred thousand '
   . 'rows stops responding, and a log you cannot scroll is no more use than '
   . 'one you cannot page');
t_contains($route, "'capped' => (\$raw <= 0 && \$total > \$HARD_MAX),",
     'and when "All" could not be honoured in full the response says so, '
   . 'rather than showing a prefix and calling it everything');

// The old clamp would have made 500 impossible.
t_ok(strpos($route, 'min(200,') === false,
     'the old 200 ceiling is gone — it would have silently served 200 rows '
   . 'to a request for 500 and shown no sign of the truncation');

// ── The sizes the user asked for, in order, defaulting to 50 ──────────────
t_contains($js, 'const SCANLOG_PAGE_SIZES = [50, 100, 200, 500, 0];',
     'THE REQUESTED SIZES: 50, 100, 200, 500 and All (0)');
t_contains($js, 'return SCANLOG_PAGE_SIZES.includes(n) ? n : 50;',
     'defaulting to 50, as asked');

preg_match('/<select class="form-input scanlog-page-size".*?<\/select>/s', $html, $sm);
$sel = $sm[0] ?? '';
t_ok($sel !== '', 'the page-size control exists in the markup');
foreach ([['50', '50'], ['100', '100'], ['200', '200'], ['500', '500'], ['0', 'All']] as [$v, $label]) {
    t_contains($sel, '<option value="' . $v . '">' . $label . '</option>',
         "the selector offers {$label}");
}
t_ok(strpos($sel, '<option value="50">50</option>') < strpos($sel, '<option value="0">All</option>'),
     'with All last, as the largest step');

// ── 0 is a VALID size, not a falsy accident ───────────────────────────────
//
// The obvious `parseInt(...) || 0` idiom would turn a stored "All" back into
// 50 on every page load, which is the kind of bug that looks like the setting
// not saving.
preg_match('/function scanLogPageSize\(\).*?\n}/s', $js, $pm);
$sizeFn = $pm[0] ?? '';
t_ok($sizeFn !== '', 'scanLogPageSize() is defined');
t_ok(strpos($sizeFn, '|| 0;') === false,
     'ZERO IS A REAL CHOICE: the size reader does not use a falsy fallback, '
   . 'which would silently turn a saved "All" back into 50');
t_contains($sizeFn, 'catch (e) { n = NaN; }',
     'and a private window, where sessionStorage throws, falls back cleanly');

// ── Paging controls behave at the edges ───────────────────────────────────
preg_match('/function scanLogPage\(dir\).*?\n}/s', $js, $gm);
t_contains($gm[0] ?? '', 'if (!size) return;',
     'ALL IS ONE PAGE: Previous/Next do nothing when everything is shown, '
   . 'rather than paging off the end of a list that has no pages');

preg_match('/async function loadScanJobs\(\).*?\n  const first/s', $js, $lm);
$loader = $lm[0] ?? '';
t_ok($loader !== '', 'loadScanJobs() is still the loader');
t_contains($loader, 'if (prev) prev.disabled = !size || ScanLogPage.offset <= 0;',
     'Previous is disabled on the first page');
t_contains($loader, 'if (next) next.disabled = !size || (ScanLogPage.offset + size) >= total;',
     'and Next on the last, so neither button walks past the data');
t_contains($loader, 'No scans on this page',
     'A PAGE PAST THE END SAYS SO: distinguishing it from "no scans have run '
   . 'yet", which would read as a server that has never scanned');

// ── Both response shapes are accepted ─────────────────────────────────────
//
// A browser holding a cached app.js against a freshly updated backend, or the
// reverse, must not render an empty log.
t_contains($loader, 'const jobs  = Array.isArray(d) ? d : (d?.items || []);',
     'MID-UPGRADE SAFETY: the bare-array shape and the items/total shape are '
   . 'both read, so a cached script against a new backend still shows the log');

// ── Changing the size returns to the first page ───────────────────────────
preg_match('/function scanLogSetPageSize\(v\).*?\n}/s', $js, $sp);
t_contains($sp[0] ?? '', 'ScanLogPage.offset = 0;',
     'changing the page size resets to the first page — page 3 of 50 is not '
   . 'page 3 of 500, and the old offset would land past the end');
t_contains($sp[0] ?? '', 'sessionStorage.setItem(SCANLOG_PAGE_KEY',
     'and the choice is remembered for the session, like the WAF table');
