<?php
/**
 * The WAF event log is pageable, and says what the WAF actually did.
 *
 * Two asks against the same table: "add a new column for Action performed for
 * that threat" and "This page is missing pagination keep it the same way that
 * we have in Bot sheild UI".
 *
 * The second is the plainer problem. getEvents() returned a bare list capped
 * at 100 with no total and no offset, so a server with 148,551 events showed
 * the newest hundred and offered no way to reach the rest -- or to know there
 * was a rest. An attack from last Tuesday was in the database and unreachable
 * from the product.
 *
 * The first turned out to be the worse one. The table already HAD an `action`
 * column and the detail dialog already displayed it, but saveWafEvent() wrote
 * the literal string 'block' on every row it ever inserted. It was never read
 * from the audit log. On an engine running in DetectionOnly -- a mode this
 * product offers and sets itself -- every one of those rows claimed a request
 * had been blocked when it had been served. Adding the column to the table
 * without fixing that would have printed the lie 148,551 times in a wider
 * typeface.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$waf = new WAF();

// ── Paging, against real rows ──────────────────────────────────────────────
for ($i = 0; $i < 120; $i++) {
    Database::insert('waf_events', [
        'rule_id'    => (string) (430000 + $i),
        'rule_msg'   => 'test rule ' . $i,
        'severity'   => $i < 10 ? 'critical' : 'warning',
        'ip_address' => '203.0.113.' . ($i % 250),
        'uri'        => '/test/' . $i,
        'method'     => 'GET',
        'action'     => $i % 2 ? 'blocked' : 'detected',
        'timestamp'  => 1000 + $i,
    ]);
}

$page = $waf->getEvents(50, null, null, 0);
t_ok(isset($page['items'], $page['total']),
     'THE TOTAL COMES BACK: a page without one cannot say "of 148,551", and '
   . 'a pager that does not know the total cannot disable its Next button');
t_eq(50,  count($page['items']), 'a page holds the requested number of rows');
t_eq(120, $page['total'], 'and the total counts every matching event, not the page');

$p2 = $waf->getEvents(50, null, null, 50);
t_eq(50, count($p2['items']), 'the second page is full too');
t_ok($p2['items'][0]['id'] !== $page['items'][0]['id'],
     'and holds different rows — an offset that was ignored would show the '
   . 'same fifty events on every page');

$p3 = $waf->getEvents(50, null, null, 100);
t_eq(20, count($p3['items']), 'the last page holds the remainder');
t_eq(120, $p3['total'], 'with the total unchanged');

$past = $waf->getEvents(50, null, null, 5000);
t_eq(0, count($past['items']), 'an offset past the end returns nothing');
t_eq(120, $past['total'], 'but still reports the total, so the UI can recover');

// Newest first, which is the only ordering that makes paging mean anything
// here: an operator opening this page is asking "what is happening now".
t_ok((int) $page['items'][0]['timestamp'] >= (int) $page['items'][49]['timestamp'],
     'events are newest first');

// ── The total is counted under the SAME filter as the rows ─────────────────
//
// Counting the whole table while listing a filtered page puts "Showing 1-10
// of 120" under ten critical events, which is worse than showing no count at
// all: it invites the operator to look for 110 more that do not exist.
$crit = $waf->getEvents(50, 'critical', null, 0);
t_eq(10, count($crit['items']), 'the severity filter still filters');
t_eq(10, $crit['total'],
     'AND THE TOTAL FOLLOWS THE FILTER — counting the whole table here would '
   . 'claim 120 matching events when there are ten');

// ── The page size cannot be asked past what the server will serve ──────────
t_eq(WAF::EVENTS_MAX_PAGE, $waf->getEvents(100000, null, null, 0)['limit'],
     'an absurd page size is clamped rather than loading the whole table into '
   . 'the browser');
t_eq(WAF::EVENTS_MIN_PAGE, $waf->getEvents(1, null, null, 0)['limit'],
     'and a tiny one is raised to the floor');
t_eq(0, $waf->getEvents(50, null, null, -10)['offset'],
     'a negative offset is not passed to SQL');

// ── The action is read, not invented ───────────────────────────────────────
t_eq('blocked', WAF::actionFromMessage(
     'ModSecurity: Access denied with code 403 (phase 2). Matched "Operator Rx"'),
     'THE REAL ACTION: "Access denied" is a block');
t_eq('detected', WAF::actionFromMessage(
     'ModSecurity: Warning. Matched "Operator Rx" against "REQUEST_URI"'),
     'and "Warning." is ModSecurity\'s word for "matched, and served anyway" — '
   . 'reporting that as Blocked tells an operator they are protected when '
   . 'they are not');
t_eq('unknown', WAF::actionFromMessage('something entirely unexpected'),
     'A LINE THAT SAYS NOTHING IS NOT A BLOCK: silence reads as unknown, '
   . 'which is the whole point — guessing "blocked" from no evidence is how '
   . 'the column came to say it 148,551 times');
t_eq('unknown', WAF::actionFromMessage(''), 'and an empty message too');

// One transaction, several rules. Four warnings and one denial is a blocked
// request; taking the last line seen would report it by whichever rule
// happened to be written last in the config.
t_eq('blocked', WAF::strongerAction('detected', 'blocked'),
     'THE STRONGEST WINS: a transaction where any rule denied it was denied');
t_eq('blocked', WAF::strongerAction('blocked', 'detected'),
     'whichever order they arrive in');
t_eq('detected', WAF::strongerAction('unknown', 'detected'),
     'and anything observed beats nothing observed');
t_eq('unknown', WAF::strongerAction(null, null), 'two blanks stay blank');

$src = (string) file_get_contents($repo . '/backend/lib/WAF.php');
t_ok(strpos($src, "'action'     => 'block',") === false,
     'THE FABRICATED VALUE IS GONE: every row ever written said \'block\' '
   . 'because the code said so, not because the WAF did');
t_contains($src, "Engine-Mode",
     'DetectionOnly is read from the audit log and is decisive — in that mode '
   . 'nothing is blocked, whatever an individual rule message claims');
t_contains($src, "^Action:\\s*Intercepted",
     'and section H is read where ModSecurity states the outcome outright');

// ── The old rows are not left claiming a block ─────────────────────────────
$dbsrc = (string) file_get_contents($repo . '/backend/lib/Database.php');
t_contains($dbsrc, "UPDATE waf_events SET action = 'unknown'",
     'existing rows are reset to unknown — there is nothing to recover, the '
   . 'value was never observed, and a confident wrong answer is worse than '
   . 'an admitted gap');
t_contains($dbsrc, "once(\$db, 'waf_action_honesty_4330'",
     'keyed so it runs once and does not overwrite real values later');

// ── The UI ─────────────────────────────────────────────────────────────────
$html = (string) file_get_contents($repo . '/frontend/index.html');
$js   = (string) file_get_contents($repo . '/frontend/js/app.js');

t_contains($html, '<th>Action</th>', 'the table has the Action column');
t_contains($html, 'colspan="7"',
     'and the empty-state row spans the new width — a stale colspan leaves '
   . 'the "no events" message short of the last column');

t_contains($html, 'id="wafEvents-prev"', 'with a Previous button');
t_contains($html, 'id="wafEvents-next"', 'a Next button');
t_contains($html, 'id="wafEvents-note"', 'and a "showing x of y" note');
t_contains($html, 'class="form-input waf-page-size"', 'and a page-size selector');

// Same shape as Bot Shield's, which is what was asked for: the same control
// in two places should be learned once.
foreach (['50', '100', '200', '500'] as $n) {
    t_contains($html, '<option value="' . $n . '">' . $n . '</option>',
        'offering the same page size as Bot Shield: ' . $n);
}
t_contains($js, "botPagerNote('wafEvents'",
     'and it reuses Bot Shield\'s pager note rather than a second '
   . 'implementation that can drift from it');

t_contains($js, 'function wafActionBadge(',
     'the action is rendered as a badge');
t_contains($js, 'wafActionBadge(e.action)',
     'in the table');
t_ok(substr_count($js, 'wafActionBadge(e.action)') >= 2,
     'AND in the detail dialog, from the same function, so the row and the '
   . 'dialog cannot disagree about whether a request was blocked');
t_contains($js, 'Not recorded',
     'an unknown action renders as a dash that explains itself, rather than '
   . 'as the word "unknown" or as a guess');
t_contains($js, 'SERVED anyway',
     'and a detection-only match says the request WAS served — the one thing '
   . 'an operator must not misread');

t_contains($js, 'function wafFilterChanged(',
     'changing the severity filter resets to page one: page 20 of everything '
   . 'is not page 20 of the critical events, and keeping the offset lands '
   . 'past the end and shows an empty table');
t_contains($js, 'WafPage.offset = 0;',
     'as does changing the page size');
t_contains($js, 'sessionStorage.setItem(WAF_PAGE_KEY',
     'the page size is a reading preference, kept for the session like Bot '
   . 'Shield\'s');
t_contains($js, "catch (e) { n = 0; }",
     'and every storage read is wrapped — sessionStorage throws in a private '
   . 'window, which must not break the table');

t_contains($js, 'Array.isArray(d) ? d : (d.items',
     'a cached app.js against a new backend, or the reverse, degrades to one '
   . 'unpaged page rather than to an empty table');
