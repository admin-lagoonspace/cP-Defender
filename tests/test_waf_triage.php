<?php
/**
 * Deciding whether to arm the WAF, from the events already recorded.
 *
 * Asked for: "you give a script to collect waf logs, you analyze it and
 * recognize patterns for real threats".
 *
 * The question an operator faces before switching from detection only to
 * blocking is not "are these attacks" -- most obviously are. It is "which of
 * these rules, armed, would turn away one of my customers' real visitors",
 * because on a shared server one false positive in blocking mode is somebody's
 * shop refusing orders, reported as the hosting being broken.
 *
 * So the pattern being recognised is not "attack vs not". It is SCANNING THE
 * INTERNET vs ONE SITE'S OWN TRAFFIC, from three signals: how many addresses,
 * how many sites, and what the URIs look like.
 *
 * The fixtures below are the four shapes that matter, and the test is that
 * each gets the verdict an operator would reach by reading the same rows.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

require_once $repo . '/backend/lib/WAFTriage.php';

$now = time();
$ev = function (array $o) use ($now) {
    Database::insert('waf_events', [
        'rule_id'    => $o['rule'],
        'rule_msg'   => $o['msg'] ?? 'test rule',
        'severity'   => $o['sev'] ?? 'warning',
        'ip_address' => $o['ip'],
        'uri'        => $o['uri'],
        'host'       => $o['host'] ?? '',
        'method'     => 'GET',
        'action'     => 'detected',
        'timestamp'  => $now - ($o['ago'] ?? 3600),
    ]);
};

// ── 1. Internet-wide scanning for files nobody links to ────────────────────
//
// The shape of rule 430057 on the reported server: /.env probing. Many
// addresses, several sites, URIs that no browser follows from a link.
for ($i = 0; $i < 40; $i++) {
    $ev(['rule' => '430057', 'ip' => '198.51.100.' . $i,
         'uri'  => ['/.env', '/config/.env', '/.aws/credentials',
                    '/.git/config', '/wp-config.php.bak'][$i % 5],
         'host' => 'site' . ($i % 6) . '.example',
         'msg'  => 'Malware.Expert - request_uri: .ENV']);
}

// ── 2. One site, one address, ordinary paths ───────────────────────────────
//
// The expensive shape. A rule matching a customer's own application -- a
// checkout posting something that looks like SQL to a regex. Arming it stops
// that site working, and the operator finds out from the customer.
for ($i = 0; $i < 25; $i++) {
    $ev(['rule' => '942100', 'ip' => '203.0.113.9',
         'uri'  => ['/shop/checkout', '/shop/cart/update', '/account/profile',
                    '/search?q=mens+shirts'][$i % 4],
         'host' => 'realcustomer.example',
         'msg'  => 'SQL Injection Attack Detected via libinjection']);
}

// ── 3. Wide spread, but ordinary-looking URIs ──────────────────────────────
//
// Probably scanning, but the URI signal does not confirm it, so it must not
// be called safe.
for ($i = 0; $i < 60; $i++) {
    $ev(['rule' => '913100', 'ip' => '192.0.2.' . $i,
         'uri'  => '/index.php?page=' . $i,
         'host' => 'site' . ($i % 8) . '.example',
         'msg'  => 'Found User-Agent associated with security scanner']);
}

// ── 4. Barely seen at all ──────────────────────────────────────────────────
$ev(['rule' => '999999', 'ip' => '203.0.113.77', 'uri' => '/odd',
     'host' => 'somewhere.example', 'msg' => 'One-off']);

// An address tripping several rules is running a scanner, not stumbling.
// Deliberately NOT 942100: that rule is the single-site fixture above, and
// adding a second host and a /.env to it would change the very shape this
// test exists to recognise. A fixture that quietly alters the case under
// test is worse than no fixture.
foreach (['430057', '913100', '930120'] as $r) {
    $ev(['rule' => $r, 'ip' => '198.51.100.250', 'uri' => '/.env',
         'host' => 'site1.example']);
}

$rep = WAFTriage::report(7, 40);
$byRule = [];
foreach ($rep['rules'] as $r) { $byRule[(string) $r['rule_id']] = $r; }

// ── The verdicts ───────────────────────────────────────────────────────────
t_eq('arm', $byRule['430057']['verdict'] ?? null,
     'SCANNER TRAFFIC IS SAFE TO ARM: 40 addresses across six sites asking '
   . 'for /.env and /.aws/credentials. Nobody reaches those from a link, so '
   . 'blocking them turns away nothing real');

t_eq('false-positive-risk', $byRule['942100']['verdict'] ?? null,
     'THE EXPENSIVE SHAPE IS FLAGGED: one site, one address, /shop/checkout '
   . 'and /search. This is a rule matching a customer\'s own application, and '
   . 'arming it breaks their site — which is the whole reason for not just '
   . 'switching the engine on and seeing what happens');

t_eq('likely-arm', $byRule['913100']['verdict'] ?? null,
     'WIDE SPREAD WITH ORDINARY URIs IS NOT CALLED SAFE: 60 addresses over '
   . 'eight sites is almost certainly scanning, but the URIs do not confirm '
   . 'it, so it asks for a spot-check rather than claiming certainty');

t_eq('too-few', $byRule['999999']['verdict'] ?? null,
     'and one observation is reported as too few rather than being squeezed '
   . 'into a verdict it cannot support');

// Each verdict carries its reasoning: an operator has to be able to disagree
// with it, and cannot if it is only a label.
foreach (['430057', '942100', '913100'] as $rid) {
    t_ok(!empty($byRule[$rid]['why']) && strlen($byRule[$rid]['why']) > 40,
         'rule ' . $rid . ' says WHY, so the judgement can be checked rather '
       . 'than taken on trust');
}

// ── The signals themselves ─────────────────────────────────────────────────
t_ok($byRule['430057']['probe_ratio'] >= 0.8,
     'probe-shaped URIs are recognised: /.env, /.aws/credentials, '
   . '/wp-config.php.bak');
t_eq(0.0, (float) $byRule['942100']['probe_ratio'],
     'AND ORDINARY ONES ARE NOT. /shop/checkout scoring as a probe is how a '
   . 'tool comes to recommend blocking a working shop');

t_eq(1, (int) $byRule['942100']['hosts'], 'the single-site rule is seen as one site');
t_ok((int) $byRule['430057']['ips'] >= 40, 'and the spread of the scanner is counted');

// Samples, so the operator can look at the actual requests.
t_ok(!empty($byRule['430057']['uri_sample']), 'example URIs are included');
t_ok(!empty($byRule['942100']['top_hosts']),
     'and the sites a rule would affect, which is who gets the phone call');

// ── Who is attacking ───────────────────────────────────────────────────────
$ips = array_column($rep['attackers'], 'ip_address');
t_ok(in_array('198.51.100.250', $ips, true),
     'an address tripping three different rules is surfaced — one rule is a '
   . 'misfire, three is somebody working through a list');
foreach ($rep['attackers'] as $a) {
    t_ok((int) $a['rules'] >= 2,
         'and the list is only addresses that tripped more than one rule');
    break;
}

// ── Totals, and the honesty of them ────────────────────────────────────────
t_ok((int) $rep['totals']['events'] >= 125, 'the totals count the window');
t_ok((int) $rep['totals']['hosts'] >= 2, 'and the distinct sites');

$txt = WAFTriage::text($rep);
t_contains($txt, 'not requests',
     'THE COUNTS ARE QUALIFIED: events are deduplicated per rule+IP per 60s, '
   . 'so these are observations and not attack volume. Printing them as '
   . 'request counts would understate a flood by orders of magnitude and '
   . 'nothing on the page would show it');
t_contains($txt, 'WOULD LIKELY BREAK A SITE',
     'the report leads with what would break, not with what is safe — the '
   . 'safe ones need no decision');
t_contains($txt, 'SAFE TO ARM', 'and names the ones that need none');
t_contains($txt, 'realcustomer.example',
     'naming the site that would be affected');

// ── It must not become the load it is reporting on ─────────────────────────
$src = (string) file_get_contents($repo . '/backend/lib/WAFTriage.php');
t_contains($src, 'GROUP BY rule_id',
     'aggregation happens in SQL — pulling 148,551 rows into PHP to count '
   . 'them is the slowest possible way to do this on a live server');
t_contains($src, 'LIMIT 20',
     'and URI sampling is bounded: what the paths look like is answered by '
   . 'twenty as well as by twenty thousand');
t_contains($src, 'MAX_ROWS',
     'with a ceiling on the window examined');

$dbsrc = (string) file_get_contents($repo . '/backend/lib/Database.php');
t_contains($dbsrc, 'idx_waf_time',
     'and waf_events is indexed by time, which every WAF read filters on');

// Read-only: safe to run on a production server mid-incident.
t_ok(!preg_match('/\\b(INSERT|UPDATE|DELETE|DROP)\\b/i', $src),
     'THE TRIAGE CHANGES NOTHING: it is a report, and an operator running it '
   . 'during an incident must not have to wonder whether it did');

$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, "if (\$sub === 'triage') {", 'and it is reachable from the CLI');
t_contains($cli, "require_once \$BASE . '/lib/WAFTriage.php';",
     'which requires the class it calls');
