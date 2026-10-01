<?php
/**
 * Parsing a real ModSecurity audit log.
 *
 * Reported twice: the IP column is empty for every WAF event. The address
 * parsing has now been wrong twice, both times because the audit log on the
 * target server was not laid out the way the code assumed:
 *
 *   1. The original pattern looked for an address immediately after the
 *      closing bracket of the timestamp. That is where the unique id sits, so
 *      it never matched anything at all.
 *   2. The replacement assumed the unique id was always present. Servers
 *      without mod_unique_id have no such token, and it missed every one.
 *
 * So this test does not check a regex. It writes audit logs in the layouts
 * ModSecurity actually produces, runs the real ingester over them, and looks
 * at what ends up in the database.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

/** One audit-log entry in ModSecurity's native format. */
function modsec_entry(string $boundary, string $aLine, string $uri,
                      string $ua, string $ruleId, string $msg): string
{
    return implode("\n", [
        "--{$boundary}-A--",
        $aLine,
        "--{$boundary}-B--",
        "GET {$uri} HTTP/1.1",
        "Host: victim.example",
        "User-Agent: {$ua}",
        "",
        "--{$boundary}-H--",
        "Message: Access denied with code 403 (phase 2). "
            . "[file \"/etc/rules.conf\"] [line \"12\"] [id \"{$ruleId}\"] "
            . "[msg \"{$msg}\"] [severity \"CRITICAL\"]",
        "--{$boundary}-Z--",
        "",
    ]) . "\n";
}

$dir = $ctx['sandbox'] . '/wafsamples';
@mkdir($dir, 0777, true);

// ── Layout 1: with mod_unique_id (the common case) ──────────────────────────
$log1 = $dir . '/with_id.log';
file_put_contents($log1,
    modsec_entry('a1b2c3d4',
        '[01/Oct/2026:16:21:03 +0000] aYx9QwAAQgEAAFt2 203.0.113.77 54321 198.51.100.10 443',
        '/.env', 'curl/8.4.0', '430057', 'Malware.Expert - request_uri: .ENV Files')
);

Database::setSetting('waf_audit_log_override', $log1);
Database::setSetting('waf_audit_log', '');      // force re-resolution
Database::setSetting('waf_ingest_offset', '0');
Database::query('DELETE FROM waf_events');

$waf = new WAF();
$n   = $waf->ingestModSecLog();
t_ok($n >= 1, 'an entry with a unique id is ingested');

$e = Database::fetchOne('SELECT * FROM waf_events ORDER BY id DESC LIMIT 1');
t_ok($e !== null, 'and stored');
t_eq('203.0.113.77', $e['ip_address'],
    'the CLIENT address is stored, which is the whole point of the column');
t_eq('430057', $e['rule_id'], 'with the rule id');
t_eq('/.env', $e['uri'], 'and the URI');
t_eq('curl/8.4.0', $e['user_agent'], 'and the user agent');
t_contains($e['rule_msg'], 'ENV Files', 'and the rule message');

// ── Layout 2: no mod_unique_id — the layout that broke 3.34.0 ───────────────
$log2 = $dir . '/no_id.log';
file_put_contents($log2,
    modsec_entry('b2c3d4e5',
        '[01/Oct/2026:16:22:10 +0000] 198.51.100.44 51000 203.0.113.9 80',
        '/wp-login.php', 'Mozilla/5.0', '580800', 'Suspicious WordPress login')
);

Database::setSetting('waf_audit_log_override', $log2);
Database::setSetting('waf_audit_log', '');
Database::setSetting('waf_ingest_offset', '0');
Database::query('DELETE FROM waf_events');

$n = (new WAF())->ingestModSecLog();
t_ok($n >= 1, 'an entry without a unique id is ingested');
$e = Database::fetchOne('SELECT * FROM waf_events ORDER BY id DESC LIMIT 1');
t_eq('198.51.100.44', $e['ip_address'],
    'and its client address is still found, which 3.34.0 could not do');

// ── Layout 3: IPv6 ──────────────────────────────────────────────────────────
$log3 = $dir . '/v6.log';
file_put_contents($log3,
    modsec_entry('c3d4e5f6',
        '[01/Oct/2026:16:23:00 +0000] Zm9vYmFy 2001:db8::dead:beef 51000 2001:db8::1 443',
        '/xmlrpc.php', 'python-requests/2.31', '580006', 'Wordpress xmlrpc')
);

Database::setSetting('waf_audit_log_override', $log3);
Database::setSetting('waf_audit_log', '');
Database::setSetting('waf_ingest_offset', '0');
Database::query('DELETE FROM waf_events');

(new WAF())->ingestModSecLog();
$e = Database::fetchOne('SELECT * FROM waf_events ORDER BY id DESC LIMIT 1');
t_eq('2001:db8::dead:beef', $e['ip_address'], 'an IPv6 client address is parsed');

// ── Reading is incremental ──────────────────────────────────────────────────
// Scheduled every 15 minutes, re-reading from the top would be gigabytes of
// I/O and would duplicate everything older than the 60-second dedup window.
Database::setSetting('waf_audit_log_override', $log1);
Database::setSetting('waf_audit_log', '');
Database::setSetting('waf_ingest_offset', '0');
Database::query('DELETE FROM waf_events');

$waf = new WAF();
$first = $waf->ingestModSecLog();
t_ok($first >= 1, 'first pass reads the file');
$second = $waf->ingestModSecLog();
t_eq(0, $second, 'a second pass with no new data reads nothing');

$before = (int) Database::fetchOne('SELECT COUNT(*) c FROM waf_events')['c'];

// Appending must be picked up without re-reading what came before.
file_put_contents($log1,
    modsec_entry('d4e5f6a7',
        '[01/Oct/2026:16:25:00 +0000] uniq123 192.0.2.55 40000 198.51.100.10 443',
        '/.git/config', 'nmap', '430058', 'request_uri: .git config'),
    FILE_APPEND);

$third = $waf->ingestModSecLog();
t_ok($third >= 1, 'appended entries are picked up');
$after = (int) Database::fetchOne('SELECT COUNT(*) c FROM waf_events')['c'];
t_eq($before + 1, $after, 'and only the new one is added, not the whole file again');

$newest = Database::fetchOne('SELECT * FROM waf_events ORDER BY id DESC LIMIT 1');
t_eq('192.0.2.55', $newest['ip_address'], 'with its address parsed too');

// ── Rotation restarts from the top ──────────────────────────────────────────
file_put_contents($log1,
    modsec_entry('e5f6a7b8',
        '[01/Oct/2026:16:30:00 +0000] rot1 198.51.100.200 1234 203.0.113.1 443',
        '/rotated', 'rotator', '999001', 'After rotation')
);
$rot = $waf->ingestModSecLog();
t_ok($rot >= 1, 'a rotated (smaller) log is read from the start again');

// ── The diagnostic reports the real file ────────────────────────────────────
$pt = $waf->parseTest(3);
t_ok(!empty($pt['ok']), 'the parse test runs against the real log');
t_eq($log1, $pt['log_path'], 'and names the file it read');
t_ok($pt['sampled'] >= 1, 'it samples entries');
t_ok($pt['with_ip'] >= 1, 'and reports how many yielded an address');
t_ok(isset($pt['samples'][0]['raw']) && $pt['samples'][0]['raw'] !== '',
    'showing the raw line, so a layout we do not handle can be seen rather than guessed at');

// ── Re-ingest, for rows stored before the parser was fixed ──────────────────
// Events already stored keep whatever was parsed at the time; the offset has
// moved past them, so a parser fix alone does nothing for them.
Database::query("UPDATE waf_events SET ip_address=''");
$blank = (int) Database::fetchOne(
    "SELECT COUNT(*) c FROM waf_events WHERE ip_address=''")['c'];
t_ok($blank > 0, 'simulating rows stored by the old parser');

$r = $waf->reingest(true);
t_ok($r['success'], 're-ingesting succeeds');
t_eq(true, $r['cleared'], 'clearing first is honoured');
$stillBlank = (int) Database::fetchOne(
    "SELECT COUNT(*) c FROM waf_events WHERE ip_address IS NULL OR ip_address=''")['c'];
t_eq(0, $stillBlank, 'and the re-read rows all have an address');

Database::setSetting('waf_audit_log_override', '');
Database::setSetting('waf_audit_log', '');
