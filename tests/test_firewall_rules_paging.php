<?php
/**
 * Firewall rules paging.
 *
 * FROM A LIVE SERVER. The Firewall page "took forever to load" and killed the
 * browser tab. The cause was not slowness: getRules() returned EVERY row —
 * 343,000 of them — and the panel turned all of them into table markup in a
 * single innerHTML assignment. The tab stops responding long before the
 * request finishes, which is why it looked like a hang rather than a lot of
 * data.
 *
 * Nothing needs all of them at once.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

$fw = new Firewall();
Database::query('DELETE FROM firewall_rules');

for ($i = 0; $i < 250; $i++) {
    Database::insert('firewall_rules', [
        'name'      => ($i % 10 === 0) ? "BLOCK_SSH_$i" : "rule_$i",
        'direction' => 'in',
        'protocol'  => ($i % 2) ? 'tcp' : 'udp',
        'port'      => (string) (1000 + $i),
        'action'    => 'DROP',
        'enabled'   => 1,
        'priority'  => $i,
    ]);
}

// ── Pages ───────────────────────────────────────────────────────────────────

$p = $fw->getRules();
t_eq(100, count($p['items']), 'the default page is 100 rules');
t_eq(250, $p['total'],
     'THE POINT: the page carries the total, so the panel can say "100 of '
   . '250" rather than attempting to render all of them');

$p2 = $fw->getRules(100, 100);
t_eq(100, count($p2['items']), 'the second page is full');
t_ok($p['items'][0]['id'] !== $p2['items'][0]['id'],
     'and holds different rules — an ignored offset would repeat page one '
   . 'forever while the pager counted up');

t_eq(50, count($fw->getRules(100, 200)['items']),
     'the last page is the remainder, not padded');
t_eq(0,  count($fw->getRules(100, 900)['items']),
     'past the end is empty rather than an error');

// Ordering survives paging, or page 2 is meaningless.
t_ok((int)$p['items'][0]['priority'] < (int)$p2['items'][0]['priority'],
     'priority ordering is preserved across pages');

// ── Clamps ──────────────────────────────────────────────────────────────────

t_eq(25,  count($fw->getRules(1)['items']),   'a tiny page size clamps up');
t_eq(250, count($fw->getRules(99999)['items']),
     'and an absurd one clamps down to at most 500 — here bounded by the data');
t_eq(0,   $fw->getRules(100, -5)['offset'],
     'a negative offset becomes zero rather than an SQL error');

// ── Search, because paging to rule 200,000 is not a way to find it ──────────

$s = $fw->getRules(100, 0, 'BLOCK_SSH');
t_eq(25, $s['total'], 'search narrows the total, not just the page');
t_eq(25, count($s['items']), 'and returns the matches');
foreach ($s['items'] as $r) {
    t_ok(strpos($r['name'], 'BLOCK_SSH') !== false, 'every row matches: ' . $r['name']);
    break;
}
t_eq('BLOCK_SSH', $s['search'], 'the search term comes back, so the UI can echo it');

t_eq(125, $fw->getRules(100, 0, 'tcp')['total'], 'protocol is searchable');
t_eq(1,   $fw->getRules(100, 0, '1001')['total'], 'and port');
t_eq(0,   $fw->getRules(100, 0, 'nothing-matches-this')['total'],
     'a search with no matches is empty, not everything');

// A search term containing SQL must not become SQL.
t_no_throw(function () use ($fw) { $fw->getRules(100, 0, "'; DROP TABLE firewall_rules; --"); },
     'a hostile search term is bound, not interpolated');
t_eq(250, (int)(Database::fetchOne('SELECT COUNT(*) c FROM firewall_rules')['c'] ?? 0),
     'and the table is still there afterwards');

// ── The UI ──────────────────────────────────────────────────────────────────

$html = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');
$app  = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');

t_contains($html, 'id="fw-rules-prev"', 'there is a Previous button');
t_contains($html, 'id="fw-rules-next"', 'and a Next button');
t_contains($html, 'id="fw-rules-note"', 'and somewhere to say how many of how many');
t_contains($html, 'id="fw-rules-search"', 'and a search box');
t_contains($html, 'id="fw-rules-size"', 'and a page-size selector');

$lfr = t_fn_body($app, 'loadFirewallRules');
t_ok($lfr !== '', 'the rules table has its own loader');
t_contains($lfr, 'sg-spin',
     'which shows the spinner while a page loads — a table that simply sits '
   . 'there is indistinguishable from one that has broken, which is exactly '
   . 'how 343,000 rules presented itself');
t_contains($lfr, 'API.fwRules(', 'and fetches one page');

// The loader must not re-render everything it was given.
t_ok(preg_match('/\b(?:rows|items)\s*\.slice\s*\(/', $lfr) === 0,
     'no second truncation in the browser');

// Rule text is escaped. A rule name is operator input, and on a server with
// an imported deny list it is whatever that list contained.
t_contains($lfr, 'esc(r.name', 'the rule name is escaped');
t_ok(strpos($lfr, '${r.name}') === false, 'and never interpolated raw');
t_ok(strpos($lfr, '${r.port}') === false, 'nor the port');
t_contains($lfr, 'Number(r.id)',
     'and the id is forced numeric before it reaches an event attribute');

// The spinner has to work outside the global overlay, or it never shows here.
t_ok(preg_match('/^\s*\.sg-spin\s*\{/m', $html) === 1,
     'the spinner class is no longer scoped to #sg-busy, so a table can use it');

// ── Why there were 343,000 of them ──────────────────────────────────────────
//
// The paging above is the symptom. The cause was that the schema seeds ten
// default rules with INSERT OR IGNORE, and firewall_rules had no UNIQUE
// constraint for OR IGNORE to conflict against — so all ten were appended
// again on EVERY database open, which is every API request. Roughly 34,000
// page loads is all it takes to reach six figures.

Database::query('DELETE FROM firewall_rules');

$migrate = new ReflectionMethod('Database', 'migrate');
$reopen = function () use ($migrate) {
    $migrate->invoke(null, Database::get());
    return (int)(Database::fetchOne('SELECT COUNT(*) c FROM firewall_rules')['c'] ?? 0);
};

$first = $reopen();
t_ok($first > 0, 'the default rules are seeded (' . $first . ')');
t_eq($first, $reopen(),
     'THE BUG: a second database open must not seed them again. Before the '
   . 'unique index this grew by ten every single request.');
t_eq($first, $reopen(), 'nor a third');

t_eq(1, (int)(Database::fetchOne(
        "SELECT COUNT(*) c FROM firewall_rules WHERE name = 'BLOCK_NULL_PACKETS'")['c'] ?? 0),
     'including the rule whose port IS NULL — SQLite treats NULLs as distinct, '
   . 'so a plain unique index would have let that one keep duplicating');

t_ok(Database::fetchOne(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_fw_identity'") !== null,
     'the identity index exists, so OR IGNORE now has something to ignore');

// A duplicate can no longer be written at all — which is the point, and also
// means every writer has to expect it. There are two: the seeding INSERT above,
// which says OR IGNORE, and Firewall::addRule(), checked below.
$ins = "INSERT INTO firewall_rules (name, direction, protocol, port, action)
         VALUES ('DUPE_ME', 'in', 'tcp', '9999', 'DROP')";
Database::query($ins);
$blocked = false;
try { Database::query($ins); } catch (PDOException $e) { $blocked = true; }
t_ok($blocked, 'a second identical rule is refused by the database itself');
t_eq(1, (int)(Database::fetchOne(
        "SELECT COUNT(*) c FROM firewall_rules WHERE name = 'DUPE_ME'")['c'] ?? 0),
     'so only one row exists');

// Adding a rule the operator already has is a no-op, not a 500.
$fw2 = new Firewall();
$a = $fw2->addRule(['name' => 'OP_RULE', 'direction' => 'in', 'action' => 'DROP',
                    'protocol' => 'tcp', 'port' => '8443']);
$b = $fw2->addRule(['name' => 'OP_RULE', 'direction' => 'in', 'action' => 'DROP',
                    'protocol' => 'tcp', 'port' => '8443']);
t_ok(!empty($a['success']), 'a new rule is added');
t_ok(!empty($b['success']), 'adding it twice still reports success');
t_ok(!empty($b['duplicate']), 'but says it was a duplicate');
t_eq($a['id'], $b['id'], 'and hands back the rule they already have');
t_eq(1, (int)(Database::fetchOne(
        "SELECT COUNT(*) c FROM firewall_rules WHERE name = 'OP_RULE'")['c'] ?? 0),
     'with only one row to show for it');
