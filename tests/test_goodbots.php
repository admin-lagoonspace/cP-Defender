<?php
/**
 * Search engine crawlers are never blocked.
 *
 * FROM A LIVE SERVER. At 00:15 on 30 Oct this product put Googlebot into
 * csf.deny:
 *
 *     66.249.73.8 # ServerScrub - Fri Oct 30 00:15:06 2026
 *
 * Nothing stopped it. Bot Shield's good-bot check matches the USER AGENT and
 * exists only in Bot Shield; HttpFlood and BruteForce had no concept of one,
 * so a crawler working through a site with dead links tripped the not-found
 * threshold and was blocked outright.
 *
 * The cost is asymmetric: a blocked crawler drops a customer's pages out of
 * the search index, discovered weeks later as unexplained lost traffic. A
 * crawler we decline to block costs a few requests.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

// ── The address that was actually blocked ───────────────────────────────────

t_eq('Googlebot', GoodBots::nameFor('66.249.73.8'),
     'THE BUG: 66.249.73.8 is Googlebot (66.249.64.0/19), and this product '
   . 'blocked it');
t_ok(GoodBots::isGoodBot('66.249.65.129'), 'as is the rest of that range');
t_ok(GoodBots::isGoodBot('66.249.64.0'),   'the first address of the range');
t_ok(GoodBots::isGoodBot('66.249.95.255'), 'and the last');
t_ok(!GoodBots::isGoodBot('66.249.96.0'),
     'but not the address just outside it — a range check that is too wide is '
   . 'an allow list an attacker can sit in');

t_eq('Bingbot', GoodBots::nameFor('157.55.39.10'), 'Bing is recognised too');

// ── Addresses that must stay blockable ──────────────────────────────────────
//
// Including the Google Cloud address this server blocked the same night. A GCP
// virtual machine is not a crawler, and treating the whole of Google's address
// space as untouchable would hand an allow list to anyone who can rent an
// instance for an hour.
foreach (['35.210.114.224', '185.177.72.49', '45.138.12.65', '8.8.8.8'] as $ip) {
    t_ok(!GoodBots::isGoodBot($ip), $ip . ' is not treated as a crawler');
}

t_ok(GoodBots::nameFor('not-an-ip') === null, 'nonsense is not a crawler');
t_ok(GoodBots::nameFor('') === null, 'nor is an empty string');

// ── The gate ────────────────────────────────────────────────────────────────

$fw = new Firewall();
$r  = $fw->blockIP('66.249.73.8', 'HTTP flood: 412 not-founds');
t_ok(empty($r['success']), 'THE FIX: the block is refused');
t_eq('Googlebot', $r['crawler'] ?? '', 'and names the crawler');
t_contains($r['error'] ?? '', 'search results',
     'and states the consequence, because "declined" alone reads like a fault');

t_ok(Database::fetchOne('SELECT id FROM blocked_ips WHERE ip_address = ?',
                        ['66.249.73.8']) === null,
     'and nothing is recorded as blocked');

// An operator who has genuinely decided can still force it.
$f = $fw->blockIP('66.249.73.8', 'operator override', false, 3600, true);
t_ok(isset($f['success']), 'an explicit force still reaches the backend');

// ── A user agent is not evidence ────────────────────────────────────────────
//
// Anyone can send "Googlebot", and scrapers do precisely because so many
// products allow-list on that string. If this file trusted it, claiming to be
// Googlebot would make an attacker unblockable.
$src = (string) file_get_contents(dirname(__DIR__) . '/backend/lib/GoodBots.php');
t_ok(strpos($src, 'user_agent') === false && strpos($src, '$ua') === false,
     'verification never looks at the user agent');
t_contains($src, 'forward', 'it forward-confirms the reverse lookup instead');

// Dot-boundary matching: whoever owns an address owns its PTR, so a suffix
// test without a boundary is a trivial bypass.
$m = new ReflectionMethod('GoodBots', 'verifyByDns');
t_ok($m->isPrivate(), 'the DNS path is internal');
t_contains($src, "'.' . \$suffix",
     'the rDNS suffix is matched on a dot boundary, so evil-googlebot.com and '
   . 'googlebot.com.attacker.net cannot pass');

// ── Every blocker is covered, because the check is at the gate ──────────────
$fwSrc = (string) file_get_contents(dirname(__DIR__) . '/backend/lib/Firewall.php');
$body  = t_fn_body($fwSrc, 'blockIP', 'php');
t_contains($body, 'GoodBots::nameFor(',
     'THE REASON IT HAPPENED: the check lives in blockIP(), so HttpFlood and '
   . 'BruteForce get it too — a check only Bot Shield performed is what let '
   . 'Googlebot through');

$gateAt = strpos($body, 'GoodBots::nameFor(');
$dbAt   = strpos($body, "Database::insert('blocked_ips'");
t_ok($gateAt !== false && $dbAt !== false && $gateAt < $dbAt,
     'and runs before anything is written down');

// ── Nothing on this path may be unbounded ───────────────────────────────────
//
// The first version fell back to gethostbyaddr() when dig was missing. That
// call cannot be given a timeout, and this runs on the path that blocks an
// attacker — on a loaded server DNS is the first thing to go slow, so the
// fallback would stall the response to an attack exactly when the attack is
// what made it slow. It hung the test suite, which is how it was caught.
// Checked against CODE, not prose: the comment above explains why
// gethostbyaddr() is not used, and a plain strpos() over the file flagged that
// explanation as the thing it warns about.
$code = (string) preg_replace(['~/\*.*?\*/~s', '~//[^
]*~'], '', $src);
t_ok(strpos($code, 'gethostbyaddr(') === false,
     'no unbounded reverse lookup is CALLED');
t_ok(strpos($code, 'gethostbyname') === false,
     'and no unbounded forward lookup');
t_contains($src, '+time=2', 'every lookup carries a hard timeout');
t_contains($src, '+tries=1', 'and does not retry into one');

// Ranges must therefore work with no DNS at all, since that is the case that
// actually occurred.
t_eq('Googlebot', GoodBots::nameFor('66.249.73.8'),
     'and the published ranges still answer without any lookup');
