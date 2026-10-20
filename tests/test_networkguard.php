<?php
/**
 * Port-scan detection, connection flood limits and egress policy.
 *
 * Most of this file is about NOT acting. Every one of these guards can block a
 * legitimate address, and the addresses that must never be blocked include the
 * operator's own and two JetBackup servers — a backup server opening dozens of
 * parallel connections looks exactly like a flood, and losing backups to a
 * false positive is worse than the attack being guarded against.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

// ── /proc/net parsing ───────────────────────────────────────────────────────
//
// Separate from everything else because getting it wrong does not fail loudly:
// it blocks the WRONG address. IPv4 is little-endian within a 32-bit word and
// IPv6 is four little-endian words, which is easy to reverse by accident.

t_eq('127.0.0.1', NetworkGuard::hexToIp('0100007F'),
     'an IPv4 address is decoded with the right byte order');
t_eq('192.168.2.15', NetworkGuard::hexToIp('0F02A8C0'),
     'and so is another, so the test is not passing on a palindrome');
t_eq('8.8.4.4', NetworkGuard::hexToIp('04040808'), 'and a third');
t_eq('::1', NetworkGuard::hexToIp('00000000000000000000000001000000'),
     'IPv6 loopback decodes to ::1');
t_eq('', NetworkGuard::hexToIp('ZZ'),
     'junk yields an empty string rather than a wrong address');
t_eq('', NetworkGuard::hexToIp(''), 'and so does nothing at all');

// A real /proc/net/tcp sample, parsed from a file so no root or Linux is needed.
$tmp = sys_get_temp_dir() . '/sg-ng-' . getmypid();
@mkdir($tmp, 0700, true);
$proc = $tmp . '/tcp';
file_put_contents($proc,
  "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
. "   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n"
. "   1: 0100007F:1F90 0F02A8C0:C350 01 00000000:00000000 00:00000000 00000000     0        0 2\n"
. "   2: 0100007F:0CEA 04040808:D431 03 00000000:00000000 00:00000000 00000000     0        0 3\n");

$rows = NetworkGuard::procNet('tcp', $proc);
t_eq(3, count($rows), 'every socket line is parsed and the header skipped');
t_eq('0A', $rows[0]['st'], 'a listening socket is recognised');
t_eq(22,   $rows[0]['local_port'], 'with its local port in decimal');
t_eq('01', $rows[1]['st'], 'an established socket is recognised');
t_eq(8080, $rows[1]['local_port'], 'with the right port');
t_eq('192.168.2.15', $rows[1]['remote_ip'], 'and the right remote address');
t_eq('03', $rows[2]['st'], 'a SYN_RECV socket is recognised');
t_eq(3306, $rows[2]['local_port'], 'with its port');

t_eq([], NetworkGuard::procNet('tcp', $tmp . '/nope'),
     'a missing /proc file yields nothing rather than throwing');

// A file of nothing but a header must not be read as "no sockets, so every
// port is closed".
file_put_contents($tmp . '/empty', "  sl  local_address rem_address   st\n");
t_eq([], NetworkGuard::procNet('tcp', $tmp . '/empty'), 'a header-only file is empty');

// ── Refusing to act on bad input ────────────────────────────────────────────
//
// THE IMPORTANT ONE. If the listening set cannot be read, every port looks
// closed and every normal visitor looks like a scanner. Reporting the whole
// internet as scanning the server, and then escalating it through the block
// ladder, would take the server off the internet.

Database::setSetting('ng_scan_enabled', '1');
$r = NetworkGuard::detectScans();
t_ok(isset($r['skipped']) || $r['scanners'] === 0,
     'with no readable listening set, nothing is reported as a scan');
if (isset($r['skipped'])) {
    t_contains($r['skipped'], 'not guessing',
         'and it says it declined to guess rather than reporting zero quietly');
}

// Switched off means off, and says so rather than returning a silent zero.
Database::setSetting('ng_scan_enabled', '0');
$off = NetworkGuard::detectScans();
t_ok(isset($off['skipped']), 'a disabled detector reports that it is disabled');
t_contains($off['skipped'], 'switched off', 'in as many words');
Database::setSetting('ng_scan_enabled', '1');

Database::setSetting('ng_flood_enabled', '0');
$foff = NetworkGuard::detectFloods();
t_contains($foff['skipped'] ?? '', 'switched off',
     'and the same for flood limits');
Database::setSetting('ng_flood_enabled', '1');

// ── Thresholds are clamped ──────────────────────────────────────────────────
//
// A threshold of 1 would block every address that touches one closed port,
// which every port scanner on the internet does to this server continuously
// and which a misconfigured client does by accident.

Database::setSetting('ng_scan_ports', '1');
t_ok(NetworkGuard::scanPortThreshold() >= 3,
     'a scan threshold below 3 is clamped — one closed port is not a scan');
Database::setSetting('ng_scan_ports', '999999');
t_ok(NetworkGuard::scanPortThreshold() <= 1000, 'and an absurd one is capped');
Database::setSetting('ng_scan_ports', '10');
t_eq(10, NetworkGuard::scanPortThreshold(), 'a sane value is kept');

Database::setSetting('ng_flood_limit', '1');
t_ok(NetworkGuard::floodLimit() >= 10,
     'a flood limit below 10 is clamped — a single browser opens six connections');
Database::setSetting('ng_flood_limit', '150');
t_eq(150, NetworkGuard::floodLimit(), 'and a sane one is kept');

// 80 and 443 exempt by default, and this is load-bearing: the dashboard is on
// 443, so a flood limit there locks the operator out of the page they would
// need to turn it off.
$ex = NetworkGuard::floodExemptPorts();
t_ok(in_array(80, $ex, true),  'port 80 is exempt from flood limits by default');
t_ok(in_array(443, $ex, true), 'and port 443, which serves this dashboard');

// ── The whitelist, which is what keeps backups working ──────────────────────

t_ok(NetworkGuard::isWhitelisted('1.2.3.4', ['1.2.3.4']),
     'an exact address matches');
t_ok(!NetworkGuard::isWhitelisted('1.2.3.5', ['1.2.3.4']),
     'a different one does not');
t_ok(NetworkGuard::isWhitelisted('10.1.2.3', ['10.0.0.0/8']),
     'a CIDR range matches');
t_ok(!NetworkGuard::isWhitelisted('11.1.2.3', ['10.0.0.0/8']),
     'and does not match outside itself');
t_ok(NetworkGuard::isWhitelisted('192.168.1.7', ['192.168.1.0/24']),
     'a /24 matches inside');
t_ok(!NetworkGuard::isWhitelisted('192.168.2.7', ['192.168.1.0/24']),
     'and not next door');
t_ok(!NetworkGuard::isWhitelisted('1.2.3.4', ['', '  ']),
     'blank whitelist entries match nothing — an empty line must not '
   . 'whitelist the internet');
t_ok(!NetworkGuard::isWhitelisted('1.2.3.4', ['garbage/99']),
     'and an unparseable entry matches nothing rather than everything');

// The real addresses from the October incident handoff. Named explicitly
// because a backup server opening many parallel connections is exactly what
// the flood detector is looking for, and these must survive it.
$safe = ['51.68.163.24', '51.68.163.25', '24.150.90.129',
         '51.255.209.208', '144.217.169.187'];
foreach ($safe as $ip) {
    t_ok(NetworkGuard::isWhitelisted($ip, $safe),
         "$ip is protected when whitelisted");
}

// ── Egress: the guard that can take the server off the air ──────────────────

$prev = NetworkGuard::applyEgress([], true);
t_eq(true, $prev['dry_run'], 'egress defaults to a DRY RUN');
t_ok(!empty($prev['rules']), 'and returns the rules it would apply');
t_contains($prev['note'] ?? '', 'Nothing was applied',
     'saying plainly that nothing was changed');

// An empty allow-list is refused. Applying one would cut the server off from
// DNS, its package mirrors, its own update channel and its licence server.
$empty = NetworkGuard::applyEgress([0], true);
t_eq(false, $empty['success'], 'an empty allow-list is refused');
t_contains($empty['error'], 'DNS', 'and the refusal explains the consequence');

// A policy without DNS is refused even if other ports are allowed: without
// resolution nothing works and every downstream failure looks unrelated.
$noDns = NetworkGuard::applyEgress([80, 443], true);
t_eq(false, $noDns['success'], 'an outbound policy with no port 53 is refused');
t_contains($noDns['error'], '53', 'naming the port');

$defaults = NetworkGuard::defaultEgressPorts();
foreach ([53 => 'DNS', 80 => 'HTTP', 443 => 'HTTPS', 123 => 'NTP',
          25 => 'SMTP'] as $port => $what) {
    t_ok(in_array($port, $defaults, true),
         "the default outbound policy allows $port ($what)");
}

// Egress is off until somebody turns it on.
t_eq('0', Database::setting('ng_egress_enabled', '0'),
     'outbound filtering is OFF by default');

// ── It must not have its own blocking path ──────────────────────────────────
//
// One escalation ladder, one whitelist, one release. A second blocking path
// means a second set of rules about who must never be blocked, and that is
// the thing most expensive to get wrong.

$ng = t_code(dirname(__DIR__) . '/backend/lib/NetworkGuard.php');
t_ok(strpos($ng, 'FirewallEngine::block') === false,
     'NetworkGuard never blocks an address itself');
t_ok(strpos($ng, 'Firewall::blockIP') === false,
     'nor through the other firewall path');
t_contains($ng, 'BruteForce::evaluate',
     'it records and lets the existing ladder escalate');
t_contains($ng, 'BruteForce::whitelist',
     'and honours the whitelist that ladder already uses');

// The provenance note matters as much as the code, and it lives in a comment —
// so it is asserted against the RAW file. t_code() strips comments by design,
// which is right for "this feature exists" assertions and wrong for this one.
//
// CSF and its surviving forks are GPLv3. A derived implementation would make
// this whole product a derivative work and oblige it to be GPLv3 too, which is
// incompatible with licensing it commercially. The note is the record that the
// capabilities were implemented from the kernel's interfaces instead.
$ngRaw = (string)file_get_contents(dirname(__DIR__) . '/backend/lib/NetworkGuard.php');
t_contains($ngRaw, 'Clean-room',
     'the provenance of these capabilities is recorded in the source');
t_contains($ngRaw, 'GPLv3',
     'naming the licence that makes deriving from CSF impossible here');
t_contains($ngRaw, 'No CSF or CPGuard source was consulted',
     'and stating plainly that no CSF source was read');

// ── The scheduler actually runs it ──────────────────────────────────────────
//
// Building a module and never scheduling it is the most common fault in this
// codebase; several panels read zero for months because of it.

$sched = t_code(dirname(__DIR__) . '/backend/cron/scheduler.php');
t_contains($sched, "'netguard' => [", 'the scheduler has a netguard task');
t_contains($sched, 'NetworkGuard::run', 'which runs the detectors');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/NetworkGuard.php';",
     'and requires the class');

// 'every' is a real frequency in Schedule.php. A made-up one would never fire
// and the panel would read zero for ever.
t_ok(preg_match("/'netguard'.*?'schedule' => setting\('netguard_schedule', '(\w+)'\)/s",
                $sched, $m) === 1,
     'the netguard schedule default is readable');
t_ok(in_array($m[1], ['every', 'hourly', 'daily', 'weekly'], true),
     'and is a frequency Schedule.php actually implements, not an invented one');

@unlink($proc);
@unlink($tmp . '/empty');
@rmdir($tmp);
