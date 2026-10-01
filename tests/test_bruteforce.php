<?php
/**
 * Brute-force detection.
 *
 * The dashboard has charted a "Brute Force" series since it was written, and
 * queries security_events for type='brute_force'. Nothing had ever written
 * one, so the line sat flat at zero on servers that were certainly being
 * hammered — and `rate_limit_ssh` was seeded as a setting that nothing read.
 *
 * These exercise the detector against the log formats it will actually meet:
 * real lines from sshd, cPanel's login_log, Exim and pure-ftpd, run through
 * the real collector, with the database checked afterwards.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

BruteForce::ensureSchema();

$dir = $ctx['sandbox'] . '/bflogs';
@mkdir($dir, 0777, true);

/** Point a source at a file of our own and reset its read position. */
function bf_use(string $key, string $path): void {
    Database::setSetting('bf_log_' . $key, $path);
    Database::setSetting('bf_offset_' . $key, '0');
}

function bf_reset(): void {
    Database::query('DELETE FROM brute_force_attempts');
    Database::query('DELETE FROM brute_force_offenders');
    Database::query("DELETE FROM security_events WHERE type='brute_force'");
}

// ── SSH, the format that matters most ───────────────────────────────────────
$ssh = $dir . '/secure';
file_put_contents($ssh, implode("\n", [
    'Oct  1 12:00:01 host sshd[1001]: Failed password for invalid user admin from 203.0.113.9 port 51000 ssh2',
    'Oct  1 12:00:02 host sshd[1002]: Failed password for root from 203.0.113.9 port 51001 ssh2',
    'Oct  1 12:00:03 host sshd[1003]: Invalid user oracle from 203.0.113.9',
    'Oct  1 12:00:04 host sshd[1004]: Accepted password for realuser from 198.51.100.5 port 2222 ssh2',
    'Oct  1 12:00:05 host sshd[1005]: Connection closed by authenticating user test 203.0.113.9 port 51002 [preauth]',
    '',
]));

bf_reset();
bf_use('ssh', $ssh);
$n = BruteForce::collect();
t_ok($n >= 4, 'failed SSH logins are collected');

$rows = Database::fetchAll('SELECT * FROM brute_force_attempts ORDER BY id');
t_eq('203.0.113.9', $rows[0]['ip_address'], 'the source address is parsed');
t_eq('admin', $rows[0]['username'], 'and the username being tried');
t_eq('ssh', $rows[0]['service'], 'attributed to the right service');

// A successful login is not an attack. Counting it would eventually block
// someone for logging in correctly too often.
$ips = array_column($rows, 'ip_address');
t_ok(!in_array('198.51.100.5', $ips, true),
    'a successful login is not recorded as a failure');

// ── Reading is incremental ──────────────────────────────────────────────────
// An auth log on a server under attack grows fast; re-reading it from the top
// every few minutes is how a detector becomes the load problem it reports on.
$again = BruteForce::collect();
t_eq(0, $again, 'a second pass with no new lines collects nothing');

file_put_contents($ssh,
    "Oct  1 12:05:00 host sshd[1006]: Failed password for root from 192.0.2.77 port 4000 ssh2\n",
    FILE_APPEND);
$third = BruteForce::collect();
t_eq(1, $third, 'only the appended line is read');

// ── The threshold ───────────────────────────────────────────────────────────
bf_reset();
Database::setSetting('bf_threshold', '5');
Database::setSetting('bf_window', '600');
Database::setSetting('bf_auto_block', '0');   // blocking tested separately

$lines = [];
for ($i = 0; $i < 4; $i++) {
    $lines[] = "Oct  1 12:10:0{$i} host sshd[20{$i}]: Failed password for root from 203.0.113.50 port 5000{$i} ssh2";
}
file_put_contents($ssh, implode("\n", $lines) . "\n");
bf_use('ssh', $ssh);
BruteForce::collect();
$r = BruteForce::evaluate();
t_eq(0, $r['offenders'], 'four failures with a threshold of five is not an attack');

file_put_contents($ssh,
    "Oct  1 12:10:09 host sshd[209]: Failed password for root from 203.0.113.50 port 50009 ssh2\n",
    FILE_APPEND);
BruteForce::collect();
$r = BruteForce::evaluate();
t_eq(1, $r['offenders'], 'the fifth crosses the threshold');

$off = Database::fetchOne('SELECT * FROM brute_force_offenders WHERE ip_address=?', ['203.0.113.50']);
t_ok($off !== null, 'the offender is recorded');
t_eq(5, (int) $off['attempts'], 'with the number of attempts');

// ── The dashboard series ────────────────────────────────────────────────────
// This is the bug that started it: the chart queries this type and nothing
// ever wrote one.
$ev = Database::fetchOne(
    "SELECT * FROM security_events WHERE type='brute_force' AND source_ip=?", ['203.0.113.50']);
t_ok($ev !== null, 'a brute_force security event is written, which the dashboard counts');
t_contains($ev['description'], '203.0.113.50', 'naming the source');

// One event per offender per window, not one per failed password: a thousand
// events for one attack buries everything else.
BruteForce::evaluate();
BruteForce::evaluate();
$count = (int) Database::fetchOne(
    "SELECT COUNT(*) c FROM security_events WHERE type='brute_force' AND source_ip=?",
    ['203.0.113.50'])['c'];
t_eq(1, $count, 'repeated evaluation does not flood the event log');

// ── Addresses that must never be blocked ────────────────────────────────────
bf_reset();
Database::setSetting('bf_threshold', '3');
$local = [];
for ($i = 0; $i < 5; $i++) {
    $local[] = "Oct  1 12:20:0{$i} host sshd[30{$i}]: Failed password for root from 127.0.0.1 port 600{$i} ssh2";
    $local[] = "Oct  1 12:20:0{$i} host sshd[31{$i}]: Failed password for root from 10.0.0.5 port 601{$i} ssh2";
}
file_put_contents($ssh, implode("\n", $local) . "\n");
bf_use('ssh', $ssh);
BruteForce::collect();
$r = BruteForce::evaluate();
t_eq(0, $r['offenders'],
    'loopback and private addresses are never treated as offenders');
// Locking the operator out of the server while defending it is not a trade
// worth making.
t_eq(null, Database::fetchOne(
    'SELECT * FROM brute_force_offenders WHERE ip_address=?', ['127.0.0.1']),
    'loopback is not recorded at all');

// The whitelist does the same for addresses the operator names.
bf_reset();
Database::setSetting('bf_whitelist', '203.0.113.200');
$w = [];
for ($i = 0; $i < 5; $i++) {
    $w[] = "Oct  1 12:30:0{$i} host sshd[40{$i}]: Failed password for root from 203.0.113.200 port 700{$i} ssh2";
}
file_put_contents($ssh, implode("\n", $w) . "\n");
bf_use('ssh', $ssh);
BruteForce::collect();
$r = BruteForce::evaluate();
t_eq(0, $r['offenders'], 'a whitelisted address is never an offender');
Database::setSetting('bf_whitelist', '');

// ── The other log formats ───────────────────────────────────────────────────
bf_reset();
$cp = $dir . '/login_log';
file_put_contents($cp,
    '203.0.113.77 - baduser [10/01/2026:12:00:00 -0000] "GET / HTTP/1.1" FAILED LOGIN webmaild: user baduser' . "\n");
bf_use('cpanel', $cp);
BruteForce::collect();
$row = Database::fetchOne("SELECT * FROM brute_force_attempts WHERE service='cpanel'");
t_ok($row !== null, 'a cPanel failed login is recognised');
t_eq('203.0.113.77', $row['ip_address'], 'with its address');

bf_reset();
$mail = $dir . '/exim_mainlog';
file_put_contents($mail,
    '2026-10-01 12:00:00 dovecot_login authenticator failed for (x) [198.51.100.23]: 535 Incorrect authentication data' . "\n");
bf_use('mail', $mail);
BruteForce::collect();
$row = Database::fetchOne("SELECT * FROM brute_force_attempts WHERE service='mail'");
t_ok($row !== null, 'a mail auth failure is recognised');
t_eq('198.51.100.23', $row['ip_address'], 'with its address');

bf_reset();
$ftp = $dir . '/messages';
file_put_contents($ftp,
    'Oct  1 12:00:00 host pure-ftpd: (?@192.0.2.44) [WARNING] Authentication failed for user [bob]' . "\n");
bf_use('ftp', $ftp);
BruteForce::collect();
$row = Database::fetchOne("SELECT * FROM brute_force_attempts WHERE service='ftp'");
t_ok($row !== null, 'an FTP auth failure is recognised');
t_eq('192.0.2.44', $row['ip_address'], 'with its address');

// ── Reporting ───────────────────────────────────────────────────────────────
$stats = BruteForce::stats();
t_ok(isset($stats['attempts_24h']), 'stats report attempts in the last day');
t_ok(isset($stats['sources']['ssh']['log_found']),
    'and whether each log source was actually found');
t_eq(true, $stats['sources']['ssh']['log_found'], 'ssh resolves to the override path');

$tl = BruteForce::timeline(7);
t_eq(7, count($tl), 'the timeline covers the requested number of days');
t_ok(isset($tl[0]['date']) && isset($tl[0]['attempts']), 'with a count per day');

// ── Retention ───────────────────────────────────────────────────────────────
// Without pruning the attempts table grows without limit on a server under
// sustained attack, which is the server that can least afford it.
Database::query(
    'INSERT INTO brute_force_attempts (ip_address, service, username, attempted_at) VALUES (?,?,?,?)',
    ['203.0.113.1', 'ssh', 'old', time() - (40 * 86400)]
);
Database::setSetting('bf_retention_days', '7');
BruteForce::prune();
t_eq(null, Database::fetchOne(
    'SELECT * FROM brute_force_attempts WHERE username=?', ['old']),
    'attempts older than the retention window are pruned');

// ── Releasing an address ────────────────────────────────────────────────────
$bad = BruteForce::release('not-an-ip');
t_eq(false, $bad['success'], 'releasing a malformed address is refused');

// ── Disabled means disabled ─────────────────────────────────────────────────
Database::setSetting('bf_enabled', '0');
$r = BruteForce::run();
t_eq(false, $r['enabled'], 'nothing runs while detection is switched off');
t_eq(0, $r['collected'], 'and nothing is collected');
Database::setSetting('bf_enabled', '1');

// ── Settings are bounded ────────────────────────────────────────────────────
Database::setSetting('bf_threshold', '1');
t_ok(BruteForce::threshold() >= 3,
    'a threshold low enough to block on a typo is clamped');
Database::setSetting('bf_window', '5');
t_ok(BruteForce::window() >= 60, 'and an unusably short window');
Database::setSetting('bf_threshold', '10');
Database::setSetting('bf_window', '600');


// ── The dashboard query, exactly as the dashboard runs it ───────────────────
// This is the bug that started all of it: the chart has drawn this series
// since it was written and nothing ever produced a row for it.
bf_reset();
Database::setSetting('bf_threshold', '5');
Database::setSetting('bf_auto_block', '0');
$l = [];
for ($i = 0; $i < 8; $i++) {
    $l[] = "Oct  1 13:00:0{$i} host sshd[90{$i}]: Failed password for root from 203.0.113.99 port 600{$i} ssh2";
}
file_put_contents($ssh, implode("\n", $l) . "\n");
bf_use('ssh', $ssh);
BruteForce::run();

$day  = strtotime('today');
$next = $day + 86400;
$c = (int) Database::fetchOne(
    "SELECT COUNT(*) as c FROM security_events WHERE type='brute_force' AND timestamp >= ? AND timestamp < ?",
    [$day, $next])['c'];
t_ok($c >= 1, 'the dashboard timeline query now returns a non-zero count');

// ── The integer-comparison trap ─────────────────────────────────────────────
// PDO's SQLite driver binds every parameter as TEXT. A column comparison is
// fine, because SQLite applies the column's INTEGER affinity to the text
// operand -- but COUNT(*) is an expression with no affinity, so COUNT(*) >= ?
// is false for every count. The detector collected failures correctly and
// then silently never crossed its own threshold.
$src = t_code($repo . '/backend/lib/BruteForce.php');
t_contains($src, 'HAVING COUNT(*) >= CAST(? AS INTEGER)',
    'the threshold comparison casts, or it matches nothing at all');
t_ok(strpos($src, 'HAVING attempts >= ?') === false,
    'the uncast form that silently never fired is gone');

// Proving it, rather than trusting the comment.
Database::query('DELETE FROM brute_force_attempts');
for ($i = 0; $i < 5; $i++) {
    Database::query(
        'INSERT INTO brute_force_attempts (ip_address, service, attempted_at) VALUES (?,?,?)',
        ['198.51.100.9', 'ssh', time()]
    );
}
$uncast = Database::fetchAll(
    'SELECT ip_address, COUNT(*) AS attempts FROM brute_force_attempts GROUP BY ip_address HAVING attempts >= ?',
    [5]);
$cast = Database::fetchAll(
    'SELECT ip_address, COUNT(*) AS attempts FROM brute_force_attempts GROUP BY ip_address HAVING COUNT(*) >= CAST(? AS INTEGER)',
    [5]);
t_eq(0, count($uncast), 'the uncast comparison genuinely returns nothing');
t_eq(1, count($cast),   'and the cast one finds the group');

// ── Wiring ──────────────────────────────────────────────────────────────────
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "'bruteforce' => [", 'detection runs on a schedule');
t_contains($sched, 'BruteForce::run()', 'calling the detector');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/BruteForce.php'",
    'and the scheduler requires the class, or the task fatals in cron');

$api = t_code($repo . '/backend/api/index.php');
t_contains($api, 'routeBruteForce', 'the module is routed');
t_contains($api, "'bruteforce'=> BruteForce::stats()",
    'and the dashboard payload carries the counts it was missing');

$html = file_get_contents($repo . '/frontend/index.html');
$js   = file_get_contents($repo . '/frontend/js/app.js');
t_contains($html, 'data-page="bruteforce"', 'there is a nav entry');
t_contains($html, 'id="page-bruteforce"', 'and a page');
t_contains($js, "case 'bruteforce': loadBruteForce()", 'which loads when opened');
t_contains($html, 'id="dash-bf-24h"', 'the dashboard shows the counts');
t_contains($js, "setText('dash-bf-24h'", 'and fills them in');

// Settings an operator can actually reach.
foreach (['bf-set-enabled', 'bf-set-block', 'bf-set-threshold',
          'bf-set-window', 'bf-set-duration', 'bf-set-whitelist'] as $id) {
    t_contains($html, 'id="' . $id . '"', "the {$id} control exists");
}
t_contains($js, 'bf_threshold:', 'and the settings are saved');
// Minutes in the UI, seconds in the setting: an operator thinks in minutes.
t_contains($js, "parseInt(g('bf-set-window')?.value, 10)   || 10) * 60",
    'the window is converted from minutes to seconds');

// Offender rows come from log lines written by whoever is attacking, so every
// field rendered from them is escaped.
$render = substr($js, strpos($js, "tb.innerHTML = rows.map"), 1200);
foreach (['ip_address', 'service', 'usernames'] as $f) {
    t_contains($render, 'esc(r.' . $f, "the {$f} column is escaped");
}

$db = t_code($repo . '/backend/lib/Database.php');
t_contains($db, "'bf_enabled',              '1'", 'detection ships switched on');
t_contains($db, "'bf_auto_block',           '1'", 'with automatic blocking on');
