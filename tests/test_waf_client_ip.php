<?php
/**
 * A WAF event names the client, not the proxy standing in front of it.
 *
 * On a live server the attacker list read:
 *
 *     51.68.163.24   1780      <- the server's OWN address
 *     20.217.186.29  1485
 *     20.46.43.126   1288
 *     127.0.0.1       848      <- nginx
 *
 * The machine was the busiest attacker against itself, and loopback was
 * fourth. Neither was an attack from the box: both are cPanel's nginx, which
 * proxies to Apache for accounts with caching turned on. ModSecurity writes
 * its section A from the CONNECTION, so that is the address we filed.
 *
 * What those 848 loopback events were actually asking for settles any doubt
 * that they mattered:
 *
 *     /....//....//....//..../.env                            93
 *     /api/uploads/%2e%2e%2f%2e%2e%2f.env                     74
 *     /cache/original/%2e%2e/%2e%2e/.env                      55
 *     /.aws/credentials                                       14
 *
 * Not one wp-cron.php. Real credential theft, with no recorded source.
 *
 * AND MOD_REMOTEIP WAS NOT AT FAULT, which is where this was first wrongly
 * pinned. It was configured correctly: cPanel points it at a secret-suffixed
 * header name, nginx sends the plain X-Forwarded-For, and it rightly refuses
 * to trust an unsigned one. Section A comes from the connection regardless.
 * The address was sitting in the request headers the whole time:
 *
 *     GET /this_is_a_new_hello_world.php HTTP/1.0
 *     Host: hotelshilparesidency.co.in
 *     X-Forwarded-For: 20.218.73.251
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];
require_once $repo . '/backend/lib/WAFTriage.php';

// ── The chain is parsed, not guessed at ────────────────────────────────────
t_eq(['20.218.73.251'], WAF::forwardedChain('20.218.73.251'),
     'a single forwarded address is read');
t_eq(['8.8.8.8', '1.2.3.4'], WAF::forwardedChain(' 8.8.8.8 , 1.2.3.4 '),
     'and a chain keeps its order, left to right');
t_eq(['20.218.73.251'], WAF::forwardedChain('20.218.73.251:54221'),
     'a :port suffix is stripped — some proxies append one');
t_eq(['2a00:1450:4001:80b::200e'], WAF::forwardedChain('[2a00:1450:4001:80b::200e]:443'),
     'including a bracketed IPv6 address with a port');
t_eq([], WAF::forwardedChain('unknown, garbage, -'),
     'and anything that is not an address is dropped rather than stored');
t_eq([], WAF::forwardedChain(''), 'an absent header is an empty chain');

// ── RIGHTMOST, which is the whole security of this ─────────────────────────
//
// nginx builds the header with $proxy_add_x_forwarded_for: it APPENDS the
// address it saw to whatever the client sent. So the left of the chain is
// attacker-controlled text and only the rightmost entry was written by our own
// proxy. Taking the leftmost -- the conventional "original client" reading,
// and the obvious thing to write -- hands any scanner the power to choose who
// gets reported and firewalled.
$spoofed = WAF::resolveClientIp([
    'ip_address' => '127.0.0.1',
    'server_ip'  => '51.68.163.24',
    'xff'        => '8.8.8.8, 20.218.73.251',
]);
t_eq('20.218.73.251', $spoofed['ip'],
     'SPOOF-RESISTANT: the attacker sent "X-Forwarded-For: 8.8.8.8" and nginx '
   . 'appended what it actually saw. Reading the leftmost entry would have us '
   . 'report, and offer to firewall, Google');
t_eq('x-forwarded-for', $spoofed['source'], 'and the source is recorded as the header');
t_eq('8.8.8.8, 20.218.73.251', $spoofed['chain'],
     'with the full chain kept, so the claim can be audited rather than trusted');

// ── The server's own address is a proxy, not an attacker ───────────────────
$own = WAF::resolveClientIp([
    'ip_address' => '51.68.163.24',
    'server_ip'  => '51.68.163.24',
    'xff'        => '20.218.73.251',
]);
t_eq('20.218.73.251', $own['ip'],
     'THE TOP OF THE LIST: 1,780 events were filed against the machine itself '
   . 'because nginx proxies over the public interface for some vhosts. '
   . 'Section A hands us the server address for that same connection, so this '
   . 'needs no configured list of our own IPs to spot');

t_ok(WAF::isProxyAddress('51.68.163.24', '51.68.163.24'), 'our own IP is a proxy address');
t_ok(!WAF::isProxyAddress('51.68.163.24', '203.0.113.9'),
     'but the same address is a genuine client when it is not OUR server — '
   . 'the test is identity with this connection, not a hardcoded range');
t_ok(WAF::isProxyAddress('127.0.0.1'), 'loopback is a proxy address');
t_ok(WAF::isProxyAddress('10.1.2.3'), 'so is RFC1918');
t_ok(WAF::isProxyAddress(''), 'and so is nothing at all');
t_ok(!WAF::isProxyAddress('20.46.43.126'), 'a routable address is not');

// ── A direct connection's headers are only the client's claim ──────────────
$direct = WAF::resolveClientIp([
    'ip_address' => '20.46.43.126',
    'server_ip'  => '51.68.163.24',
    'xff'        => '8.8.8.8',
]);
t_eq('20.46.43.126', $direct['ip'],
     'A REQUEST THAT REACHED APACHE DIRECTLY already has a trustworthy '
   . 'source. Letting its header override that would make every attacker '
   . 'anonymous by choice — they need only send the header');
t_eq('direct', $direct['source'], 'and it is labelled as coming from the connection');

// ── Cloudflare, where the nearest hop is an edge and not the visitor ───────
//
// For a site behind Cloudflare the chain's rightmost entry is a CF edge
// address. CF-Connecting-IP holds the visitor, and Cloudflare overwrites it,
// so it is better -- but only once something shows the request really came
// through Cloudflare.
$cf = WAF::resolveClientIp([
    'ip_address' => '127.0.0.1',
    'server_ip'  => '51.68.163.24',
    'xff'        => '20.218.73.251, 162.158.1.1',
    'cf_ip'      => '20.218.73.251',
]);
t_eq('20.218.73.251', $cf['ip'], 'the Cloudflare visitor address is used');
t_eq('cf-connecting-ip', $cf['source'],
     'BECAUSE THE NEAREST HOP IS CLOUDFLARE, which corroborates the header. '
   . 'Without that check a forged CF-Connecting-IP on any non-Cloudflare site '
   . 'would be believed');

$forged = WAF::resolveClientIp([
    'ip_address' => '127.0.0.1',
    'server_ip'  => '51.68.163.24',
    'xff'        => '20.218.73.251',          // nginx saw the attacker
    'cf_ip'      => '8.8.8.8',                // and the attacker claimed this
]);
t_eq('20.218.73.251', $forged['ip'],
     'A FORGED CF-Connecting-IP is ignored when the nearest hop is not '
   . 'Cloudflare — the proxy-written address wins over the claimed one');

$cfOnly = WAF::resolveClientIp([
    'ip_address' => '127.0.0.1', 'server_ip' => '51.68.163.24', 'cf_ip' => '20.218.73.251',
]);
t_eq('cf-connecting-ip-uncorroborated', $cfOnly['source'],
     'with no chain to corroborate it the header is still used, but labelled '
   . 'so an operator can see which rows rest on it');

t_ok(WAF::cidrMatch('162.158.1.1', '162.158.0.0/15'), 'CIDR matching works across octets');
t_ok(!WAF::cidrMatch('162.160.1.1', '162.158.0.0/15'), 'and excludes what is outside');
t_ok(WAF::cidrMatch('2606:4700::1111', '2606:4700::/32'), 'IPv6 too');
t_ok(!WAF::cidrMatch('162.158.1.1', '2606:4700::/32'),
     'and a v4 address never matches a v6 range, whatever its bits look like');

// ── Nothing to resolve it with is said, not guessed ───────────────────────
$blind = WAF::resolveClientIp(['ip_address' => '127.0.0.1', 'server_ip' => '51.68.163.24']);
t_eq('127.0.0.1', $blind['ip'], 'with no header the proxy address is kept');
t_eq('proxy-unresolved', $blind['source'],
     'AND NAMED: an unattributable event is a fact about the log. Inventing a '
   . 'plausible source would be worse than reporting that there is not one');

// ── The parser actually reads those headers ────────────────────────────────
$src = (string) file_get_contents($repo . '/backend/lib/WAF.php');
t_contains($src, "preg_match('/^X-Forwarded-For:\\s*(.+)/i'",
     'the ingest loop captures X-Forwarded-For — it was reading Host and '
   . 'User-Agent out of the same section and walking past this one');
t_contains($src, "preg_match('/^CF-Connecting-IP:\\s*(.+)/i'", 'and CF-Connecting-IP');

$save = t_fn_body($src, 'saveWafEvent', 'php');
t_contains($save, 'self::resolveClientIp($e)', 'and the saved row is the resolved one');
t_contains($save, "'ip_address' => \$who['ip']",
     'the resolved address is what lands in ip_address, so every existing '
   . 'query, the attacker list and the firewall all benefit without change');

// Resolution has to happen BEFORE the duplicate check, or the 60-second
// rule+IP window groups by proxy address and collapses unrelated attackers
// arriving through the same nginx into one another.
$posResolve = strpos($save, 'resolveClientIp');
$posDedup   = strpos($save, 'SELECT id FROM waf_events');
t_ok($posResolve !== false && $posDedup > $posResolve,
     'ORDER MATTERS: deduplicating on the proxy address would discard real '
   . 'events from different attackers as repeats of one another');

// ── Attribution is auditable ───────────────────────────────────────────────
$cols = array_column(
    Database::get()->query('PRAGMA table_info(waf_events)')->fetchAll(PDO::FETCH_ASSOC), 'name');
t_ok(in_array('ip_source', $cols, true),
     'ip_source is stored: an operator about to firewall an address can see '
   . 'whether it came from the connection, from a header, or not at all');
t_ok(in_array('forwarded_for', $cols, true), 'and the chain it was taken from');

$dbsrc = (string) file_get_contents($repo . '/backend/lib/Database.php');
t_contains($dbsrc, "ALTER TABLE waf_events ADD COLUMN ip_source",
     'an existing install gains the column — 148,551 rows predate it');
t_contains($dbsrc, "ALTER TABLE waf_events ADD COLUMN forwarded_for", 'and the other');

// ── The triage no longer sends the operator to fix the wrong thing ─────────
$tri = (string) file_get_contents($repo . '/backend/lib/WAFTriage.php');
t_ok(strpos($tri, 'mod_remoteip is not') === false,
     'THE NOTE WAS WRONG AND ACTIONABLE, which is the bad combination: it told '
   . 'the operator mod_remoteip was not reading X-Forwarded-For, on a server '
   . 'where it was configured correctly and rightly declining to trust an '
   . 'unsigned header. It would have sent them to change working config');
t_contains($tri, "ip_source = 'proxy-unresolved'",
     'and it now separates rows that predate the fix from rows that arrived '
   . 'with no usable header, because only the second kind is still a problem');
t_contains($tri, 'should ever be firewalled',
     'while keeping the warning that matters — blocking 127.0.0.1 or the '
   . "server's own address takes the machine off the air");

// ── The report does not name the server as its own attacker ────────────────
//
// isLocalOrPrivate caught loopback and let 51.68.163.24 through, because it
// IS a public address -- it just happens to be this machine. It led the
// attacker list with 1,780 hits, and the report's top line is exactly what an
// operator acts on first.
t_ok(WAFTriage::isProxyNotAttacker('127.0.0.1'), 'loopback is not an attacker');
t_ok(WAFTriage::isProxyNotAttacker('10.0.0.5'), 'nor is a private address');
t_ok(!WAFTriage::isProxyNotAttacker('20.46.43.126'), 'but a real scanner is');

t_ok(is_array(WAFTriage::serverAddresses()),
     "THE SERVER'S OWN ADDRESSES are read from the RemoteIPInternalProxy "
   . 'entries cPanel already writes into httpd.conf, and from the hostname. '
   . 'On a machine with neither the list is empty, which is the old behaviour '
   . 'rather than a wrong answer');

$trisrc = (string) file_get_contents($repo . '/backend/lib/WAFTriage.php');
t_contains($trisrc, 'self::isProxyNotAttacker((string) $a[\'ip_address\'])',
     'and the attacker list filters on that, not on private ranges alone');
t_contains($trisrc, "strpos(\$tok, '/') === false",
     'CIDR blocks in that config are skipped: the ranges there are '
   . "Cloudflare's edge, a real intermediary rather than this machine");
