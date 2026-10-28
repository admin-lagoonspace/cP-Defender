<?php
/**
 * Blocked Bots says what the bot was doing.
 *
 * The Type column read "bot" on every single row. threat_type was recorded
 * from the first version and the renderer already fell back to it — the
 * grouped query simply never selected the column, so the fallback fired every
 * time. An operator reading a list of blocked addresses needs to know whether
 * they stopped a vulnerability scanner or an SEO crawler; those warrant
 * completely different reactions, and "bot" distinguishes nothing.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

// ── The sentence ────────────────────────────────────────────────────────────

t_contains(BotShield::describe('scanner', 'sqlmap/1.7'), 'Scanning for known vulnerabilities',
     'a scanner says it is scanning');
t_contains(BotShield::describe('scanner', 'sqlmap/1.7'), '(sqlmap)',
     'and names the tool, because "scanner" alone does not tell an operator '
   . 'whether to worry');
t_contains(BotShield::describe('scraper', 'Mozilla/5.0 (compatible; AhrefsBot/7.0)'),
     '(AhrefsBot)', 'an SEO crawler is named');
t_contains(BotShield::describe('scraper', 'AhrefsBot'), 'Crawling the site',
     'and described as crawling rather than attacking — a scraper costs '
   . 'bandwidth, it is not a break-in');
t_contains(BotShield::describe('exploit', 'python-requests/2.31'),
     'Attacking WordPress login or XML-RPC', 'an exploit attempt says so plainly');
t_contains(BotShield::describe('exploit', 'python-requests/2.31'), '(a Python script)',
     'and describes the client in words rather than echoing a version string');

// Every classification the detector can produce must have a description.
foreach (['scanner', 'scraper', 'exploit'] as $t) {
    t_ok(trim(BotShield::describe($t, 'curl/8.0')) !== '',
         $t . ' has a description');
    t_ok(strlen(BotShield::describe($t, 'curl/8.0')) < 70,
         $t . ' fits one line of a narrow table (it is '
       . strlen(BotShield::describe($t, 'curl/8.0')) . ' characters)');
}

// ── Rows that predate the type being recorded ───────────────────────────────

t_contains(BotShield::describe(null, 'Mozilla/5.0'), 'Automated client',
     'an unclassified row still says something');
t_ok(strpos(BotShield::describe(null, 'Mozilla/5.0'), '(') === false,
     'and does not invent a tool it did not recognise');
t_contains(BotShield::describe(null, ''), 'sent no user agent',
     'an empty agent is called out — an ordinary browser always sends one, so '
   . 'its absence is itself the finding');
t_contains(BotShield::describe(null, '-'), 'sent no user agent',
     'and a log placeholder counts as empty, not as an agent named "-"');

t_eq('', BotShield::toolLabel('Mozilla/5.0 (Windows NT 10.0) Chrome/120'),
     'an ordinary browser string yields no tool');
t_eq('', BotShield::toolLabel(null), 'and neither does a missing agent');
t_eq('Nikto', BotShield::toolLabel('Mozilla/5.00 (Nikto/2.5.0)'),
     'a tool buried in a disguised agent is still found');

// ── The query actually selects it ───────────────────────────────────────────

$bs = new BotShield();
Database::query('DELETE FROM bot_events');
foreach ([['1.2.3.4', 'sqlmap/1.7', 'scanner'],
          ['5.6.7.8', 'AhrefsBot/7.0', 'scraper']] as [$ip, $ua, $type]) {
    Database::insert('bot_events', ['ip_address' => $ip, 'user_agent' => $ua,
                                    'threat_type' => $type, 'action' => 'block']);
}

$page = $bs->getBlockedBots();
$byIp = [];
foreach ($page['items'] as $r) { $byIp[$r['ip_address']] = $r; }

t_eq('scanner', $byIp['1.2.3.4']['threat_type'] ?? '',
     'THE BUG: threat_type is selected, so the panel no longer falls back to '
   . 'the literal word "bot" on every row');
t_contains($byIp['1.2.3.4']['description'] ?? '', 'sqlmap', 'and carries the one-liner');
t_contains($byIp['5.6.7.8']['description'] ?? '', 'AhrefsBot', 'for each row');

$ev = $bs->getBotEvents();
t_ok(isset($ev['items'][0]['description']), 'the events list carries it too');

// ── The panel renders it ────────────────────────────────────────────────────

$app = (string) file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
$lbb = t_fn_body($app, 'loadBotBlocked');

t_contains($lbb, 'esc(b.description', 'the description is rendered');
t_ok(strpos($lbb, "b.threat_type || 'bot'") === false,
     'and the meaningless "bot" fallback is gone');
t_contains($lbb, "b.threat_type || 'unclassified'",
     'an unknown type now says it is unknown rather than claiming a type');
t_contains($lbb, 'esc(b.user_agent', 'the full user agent is on the tooltip');

$lbe = t_fn_body($app, 'loadBotEvents');
t_ok(strpos($lbe, "e.threat_type || 'scanner'") === false,
     'THE QUIET LIE: the events table defaulted an unknown type to "scanner", '
   . 'labelling anything unclassified as an attack');
