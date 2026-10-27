<?php
/**
 * Bot Shield paging.
 *
 * Both tables used to fetch a fixed slab. Recent Bot Events was the worse of
 * the two: the route returned up to 100 rows and the renderer then did
 * `events.slice(0, 50)`, so a server with thousands of events displayed fifty
 * and said nothing at all. A table that shows part of the data without saying
 * so invites the wrong conclusion — that there is nothing more to see.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

$bs = new BotShield();
Database::query('DELETE FROM bot_events');

// 137 events across 7 addresses, so the two tables have different totals and
// a pager that counted the wrong one would be visible.
for ($i = 0; $i < 137; $i++) {
    Database::insert('bot_events', [
        'ip_address'  => '203.0.113.' . (($i % 7) + 1),
        'user_agent'  => 'probe/' . $i,
        'threat_type' => 'scanner',
        'uri'         => '/.env',
        'action'      => 'block',
        'hits'        => 1,
        'timestamp'   => time() - $i,
    ]);
}

// ── Events ──────────────────────────────────────────────────────────────────

$p = $bs->getBotEvents();
t_eq(50, count($p['items']), 'the default page is 50 items');
t_eq(137, $p['total'],
     'THE POINT: the page carries the TOTAL, so the table can say "50 of 137" '
   . 'rather than showing fifty rows and implying that is all there is');
t_eq(0, $p['offset'], 'starting at the first');

$p2 = $bs->getBotEvents(50, 50);
t_eq(50, count($p2['items']), 'the second page is full');
t_eq(137, $p2['total'], 'and reports the same total');
t_ok($p['items'][0]['id'] !== $p2['items'][0]['id'],
     'and holds different rows — an offset that was ignored would repeat the '
   . 'first page forever while the pager counted up');

$last = $bs->getBotEvents(50, 100);
t_eq(37, count($last['items']), 'the last page is the remainder, not padded');

$past = $bs->getBotEvents(50, 500);
t_eq(0, count($past['items']), 'past the end is empty rather than an error');
t_eq(137, $past['total'], 'and still reports the total');

// ── Blocked addresses: grouped, so the total must be of GROUPS ──────────────

$b = $bs->getBlockedBots();
t_eq(7, $b['total'],
     'the blocked total counts ADDRESSES, not events — counting rows would '
   . 'report 137 and offer pages that do not exist');
t_eq(7, count($b['items']), 'and all seven fit on one page');

// ── Page size is clamped ────────────────────────────────────────────────────

t_eq(50,  BotShield::clampPage(1),    'below the minimum clamps up to 50');
t_eq(50,  BotShield::clampPage(0),    'and zero does not mean "everything"');
t_eq(50,  BotShield::clampPage(-10),  'nor does a negative');
t_eq(500, BotShield::clampPage(9999), 'above the maximum clamps down to 500');
t_eq(200, BotShield::clampPage(200),  'a value in range is kept');
t_eq(50,  count($bs->getBotEvents(1)['items']),
     'and the clamp is applied by the query, not just advertised');

$neg = $bs->getBotEvents(50, -5);
t_eq(0, $neg['offset'], 'a negative offset becomes zero rather than an SQL error');

// ── The UI ──────────────────────────────────────────────────────────────────

$html = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
$app  = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');

foreach (['botBlocked', 'botEvents'] as $prefix) {
    t_contains($html, 'id="' . $prefix . '-prev"', $prefix . ' has a Previous button');
    t_contains($html, 'id="' . $prefix . '-next"', 'and a Next button');
    t_contains($html, 'id="' . $prefix . '-note"', 'and somewhere to say how many of how many');
    t_contains($app, 'function ' . $prefix . 'Page', 'with a handler behind them');
}

t_eq(2, substr_count($html, 'class="form-input bot-page-size"'),
     'both tables carry the page-size selector');
foreach (['50', '100', '200', '500'] as $n) {
    t_contains($html, '<option value="' . $n . '">', "offers $n per page");
}

// Session-scoped: a reading preference, not server configuration.
t_contains($app, 'sessionStorage', 'the page size is remembered for the session');
t_ok(strpos($app, "localStorage.setItem(BOT_PAGE_KEY") === false,
     'and NOT persisted beyond it');
$ps = t_fn_body($app, 'botPageSize');
t_contains($ps, 'catch',
     'every read is wrapped — sessionStorage throws in a private window, and '
   . 'that must not break a table');
t_contains($ps, 'BOT_PAGE_SIZES.includes',
     'and a hand-edited value is clamped to an offered size');

$sps = t_fn_body($app, 'botSetPageSize');
t_contains($sps, 'offset = 0',
     'changing the size resets both offsets — page 3 of 50 is not page 3 of '
   . '500, and landing past the end would show an empty table');
t_contains($sps, 'catch', 'and the write is wrapped too');

// The silent truncation is gone.
$le = t_fn_body($app, 'loadBotEvents');
// Specifically: no slice on the ROW COLLECTION. `ua.slice(0, 50)` is a
// legitimate truncation of one user-agent string for display, and an
// assertion blunt enough to catch that reports a bug that is not there.
t_ok(preg_match('/(?:rows|events|items)\s*\.slice\s*\(/', $le) === 0,
     'THE SILENT TRUNCATION IS GONE: the browser no longer re-cuts a page the '
   . 'server already sized');
t_contains($le, 'rows.map(',
     'it renders every row the server sent');

// Log-derived text is escaped. The user-agent is whatever a stranger sent.
t_contains($le, 'esc(ua)', 'the user-agent is escaped in the title attribute');
t_contains($le, 'esc(ua.slice', 'and in the cell');
t_ok(strpos($le, '${e.user_agent}') === false,
     'and never interpolated raw — it is attacker-controlled log data');
$lb = t_fn_body($app, 'loadBotBlocked');
t_ok(strpos($lb, '${b.ip_address}') === false,
     'nor is the address, which reached us the same way');
