<?php
/**
 * Proxy addresses are never blocked, and the real client is used instead.
 *
 * FROM A LIVE SERVER. Two Cloudflare edges were in /etc/csf/csf.deny with our
 * name on them. A site behind Cloudflare logs the EDGE as its client, so a few
 * hundred failed logins arriving through one edge looked like one attacker.
 * Blocking it stops nothing — the attacker returns through another of
 * thousands of edges — and silently drops every real visitor routed that way.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

// ── The two addresses that were actually blocked ────────────────────────────

t_eq('Cloudflare', ProxyRanges::nameFor('104.21.83.159'),
     'THE BUG: 104.21.83.159 is Cloudflare (104.16.0.0/13), not a visitor');
t_eq('Cloudflare', ProxyRanges::nameFor('172.67.178.100'),
     'and 172.67.178.100 is Cloudflare (172.64.0.0/13)');

// ── Range matching ──────────────────────────────────────────────────────────

t_ok(ProxyRanges::inRange('104.16.0.0', '104.16.0.0/13'),   'the first address of a range matches');
t_ok(ProxyRanges::inRange('104.23.255.255', '104.16.0.0/13'), 'and the last');
t_ok(!ProxyRanges::inRange('104.15.255.255', '104.16.0.0/13'),
     'the address just below does not — a /13 is where 32-bit arithmetic '
   . 'goes wrong, which is why this compares packed bytes');
t_ok(!ProxyRanges::inRange('104.24.0.0', '104.16.0.0/13'), 'nor the one just above');

t_ok(ProxyRanges::inRange('2606:4700::1', '2606:4700::/32'), 'IPv6 matches too');
t_ok(!ProxyRanges::inRange('2606:4701::1', '2606:4700::/32'), 'and is bounded');
t_ok(!ProxyRanges::inRange('104.16.0.1', '2606:4700::/32'),
     'a v4 address never matches a v6 range');
t_ok(!ProxyRanges::inRange('garbage', '104.16.0.0/13'), 'nonsense does not match');

// Ordinary addresses, including the attackers from this incident.
foreach (['185.177.72.49', '8.8.8.8', '51.68.163.24', '213.209.159.11'] as $ip) {
    t_ok(ProxyRanges::nameFor($ip) === null, $ip . ' is not a proxy address');
}

// ── Recovering the real client ──────────────────────────────────────────────

$withXff = '104.21.83.159 - - [26/Oct/2026:18:45:01 +0000] "GET /wp-login.php HTTP/1.1" '
         . '200 1234 "-" "Mozilla/5.0 (X11; Linux) Chrome/120" "203.0.113.9"';
t_eq('203.0.113.9', ProxyRanges::clientFromLine($withXff),
     'the forwarded client is recovered, so the attacker is blocked instead '
   . 'of the proxy');

$chain = '104.21.83.159 - - [26/Oct/2026:18:45:01 +0000] "GET / HTTP/1.1" 200 1 '
       . '"-" "curl/8" "203.0.113.9, 104.21.83.159"';
t_eq('203.0.113.9', ProxyRanges::clientFromLine($chain),
     'the FIRST entry of a chain is the originating client');

// A line with no forwarded field must not hand back the user agent.
$noXff = '104.21.83.159 - - [26/Oct/2026:18:45:01 +0000] "GET /wp-login.php HTTP/1.1" '
       . '200 1234 "https://example.com/" "Mozilla/5.0 (X11; Linux) Chrome/120"';
t_ok(ProxyRanges::clientFromLine($noXff) === null,
     'a log format without the header yields nothing rather than the user '
   . 'agent — matching on SHAPE, not field position, is what makes that safe');

t_ok(ProxyRanges::clientFromLine('"-" "-"') === null, 'empty quoted fields yield nothing');
t_ok(ProxyRanges::clientFromLine('"not an ip"') === null, 'nor does prose');
t_ok(ProxyRanges::clientFromLine('"104.21.83.159"') === null,
     'and a chain that is only proxies yields nothing, rather than blocking '
   . 'another intermediary');

// ── The gate ────────────────────────────────────────────────────────────────

$fw = new Firewall();
$r = $fw->blockIP('104.21.83.159', 'Brute force: 300 failures');
t_ok(empty($r['success']), 'THE FIX: the block is refused');
t_eq('Cloudflare', $r['proxy'] ?? '', 'and names the provider');
t_contains($r['error'] ?? '', 'real visitors',
     'and says what blocking it would cost');
t_contains($r['error'] ?? '', 'mod_remoteip',
     'and what the operator should do instead — a refusal without a remedy '
   . 'just moves the puzzle');

t_ok(Database::fetchOne('SELECT id FROM blocked_ips WHERE ip_address = ?',
                        ['104.21.83.159']) === null,
     'and nothing is recorded as blocked, so the panel cannot claim a block '
   . 'that did not happen');

// An operator who means it can still override.
$f = $fw->blockIP('104.21.83.159', 'operator override', false, 3600, true);
t_ok(isset($f['success']), 'an explicit force reaches the firewall backend');

// Ordinary addresses are unaffected.
$ok = $fw->blockIP('203.0.113.77', 'Brute force: 50 failures');
t_ok(!isset($ok['proxy']), 'a normal address is not treated as a proxy');

// ── parseLine ───────────────────────────────────────────────────────────────

$p = HttpFlood::parseLine($withXff);
t_eq('203.0.113.9', $p['ip'] ?? '',
     'THE COUNTING BUG: requests are attributed to the visitor, not to the '
   . 'edge that merged thousands of them into one apparent attacker');
t_eq('Cloudflare', $p['via'] ?? '', 'while still recording which proxy they came through');

$p2 = HttpFlood::parseLine($noXff);
t_eq('104.21.83.159', $p2['ip'] ?? '',
     'with no forwarded address the edge is kept, so the operator still sees '
   . 'the traffic and the gate explains why it cannot be blocked');

$p3 = HttpFlood::parseLine(
    '185.177.72.49 - - [27/Oct/2026:03:00:01 +0000] "GET /.env HTTP/1.1" 404 0 "-" "python"');
t_eq('185.177.72.49', $p3['ip'] ?? '', 'a direct request is unchanged');
t_ok(($p3['via'] ?? null) === null, 'and is marked as having come through no proxy');

// ── The reason has to survive the trip to the panel ─────────────────────────

$r2 = $fw->blockIP('172.67.178.100', 'Brute force: 200 failures');
t_ok(strlen((string)($r2['error'] ?? '')) <= 200,
     'the refusal fits brute_force_offenders.block_error, which truncates at '
   . '200 — a remedy cut off mid-sentence is not a remedy (it is '
   . strlen((string)($r2['error'] ?? '')) . ' characters)');
t_contains($r2['error'] ?? '', 'mod_remoteip', 'and still carries the remedy');

// CSF must not overwrite it. Both Cloudflare addresses are already in
// csf.deny from before this guard existed, so ExternalDefence would answer
// "already in csf.deny" and bury the only actionable reason.
$bf = t_fn_body((string)file_get_contents(dirname(__DIR__) . '/backend/lib/BruteForce.php'),
                'evaluate', 'php');
t_contains($bf, "if (empty(\$res['proxy'])) {",
     'THE REASON THAT WOULD HAVE BEEN BURIED: CSF is only consulted when the '
   . 'refusal did not come from our own proxy guard');

// ── Every blocking path goes through the gate ───────────────────────────────
//
// Bot Shield shelled out to `csf -d` itself, so it bypassed the guard
// entirely: after 4.21.3 shipped it could still put a Cloudflare edge into
// csf.deny. A guard each caller has to remember is a guard the next caller
// will not have.
$bsSrc = (string) file_get_contents(dirname(__DIR__) . '/backend/lib/BotShield.php');
$blockBot = t_fn_body($bsSrc, 'blockBot', 'php');

t_contains($blockBot, '$fw->blockIP(',
     'THE HOLE: Bot Shield blocks through Firewall::blockIP(), the one gate');
t_ok(strpos($blockBot, 'CSF_BIN') === false,
     'and no longer shells out to csf directly, around every check');
t_ok(strpos($blockBot, 'IPTABLES_BIN') === false, 'nor to iptables');

// Order matters: ask the firewall, THEN record. The reverse is how a panel
// comes to list an address as blocked while packets from it keep arriving.
$askAt = strpos($blockBot, '$fw->blockIP(');
$recAt = strpos($blockBot, "Database::insert('bot_events'");
t_ok($askAt !== false && $recAt !== false && $askAt < $recAt,
     'and asks before it records, so a refused block is not written down as '
   . 'a block');
