<?php
/**
 * HTTP flood and scanner detection.
 *
 * FROM A LIVE SERVER, 2026-10-27. One address took all eight cores to load 22
 * with 1.2% idle, and nothing in this product noticed:
 *
 *   185.177.72.49 — 1,963 of 2,000 requests on one vhost, brute-forcing
 *                   filenames across every site on the box: /.env,
 *                   /.git/config, /settings.py, ~/.aws/credentials
 *
 * Every request was a 404. No failed logins, no malware on disk, no error-rate
 * spike — nothing any existing check watches. But WordPress serves 404s in
 * PHP, so each miss was a full framework boot. That is the shape this detects.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

HttpFlood::ensureSchema();
Database::query('DELETE FROM http_flood_offenders');
Database::setSetting('bf_whitelist', '');
Database::setSetting('hf_admin_ips', '');

// ── Parsing ─────────────────────────────────────────────────────────────────

$line = '185.177.72.49 - - [27/Oct/2026:10:22:14 +0530] "GET /.env HTTP/1.1" 404 199 "-" "-"';
$p = HttpFlood::parseLine($line);
t_ok($p !== null, 'a combined-log line parses');
t_eq('185.177.72.49', $p['ip'], 'the address is read');
t_eq(404, $p['status'], 'and the status, which is the whole signal here');
t_eq('/.env', $p['path'], 'and the path');
t_ok($p['ts'] > 0, 'and a usable timestamp');

t_ok(HttpFlood::parseLine('garbage') === null, 'junk is rejected rather than guessed at');
t_ok(HttpFlood::parseLine('') === null, 'and so is an empty line');

// ── Safety rails: the part that matters most ────────────────────────────────
//
// An automatic blocker that locks the administrator out of the server it is
// defending has done more damage than the attack.

t_ok(HttpFlood::isLocal('127.0.0.1'), 'loopback is never an attacker');
t_ok(HttpFlood::isLocal('10.0.0.5'),  'nor a private address');
t_ok(HttpFlood::isLocal('192.168.1.1'), 'nor another');
t_ok(!HttpFlood::isLocal('185.177.72.49'), 'but a public address can be');

// The operator's own address, recorded on every authenticated request.
HttpFlood::rememberAdminIp('203.0.113.55');
$never = HttpFlood::neverBlock();
t_ok(isset($never['203.0.113.55']),
     'THE RAIL THAT MATTERS: an address that has reached the panel is never '
   . 'blocked — on the day this was built the operator own IP appeared in the '
   . 'logs with 261 requests, inside some of the thresholds');
t_contains($never['203.0.113.55'], 'panel', 'and the reason says why');

// The Brute Force allow list governs both, so there is one list to maintain.
Database::setSetting('bf_whitelist', '51.68.163.24, 24.150.90.129');
$never = HttpFlood::neverBlock();
t_ok(isset($never['51.68.163.24']), 'the Brute Force allow list is honoured here too');
t_ok(isset($never['24.150.90.129']), 'for every address on it');

// Recording is cheap: a second call inside the hour must not rewrite.
$before = Database::setting('hf_admin_ips', '');
HttpFlood::rememberAdminIp('203.0.113.55');
t_eq($before, Database::setting('hf_admin_ips', ''),
     'a repeat visit does not rewrite the setting, so a busy panel is not a '
   . 'settings write per request');

// Private addresses are not worth remembering.
HttpFlood::rememberAdminIp('10.1.2.3');
t_ok(strpos((string)Database::setting('hf_admin_ips', ''), '10.1.2.3') === false,
     'a private address is not recorded');

// ── Thresholds are clamped ──────────────────────────────────────────────────

Database::setSetting('hf_miss_threshold', '0');
t_ok(HttpFlood::missThreshold() >= 10, 'a zero miss threshold is clamped up');
Database::setSetting('hf_miss_threshold', '999999');
t_ok(HttpFlood::missThreshold() <= 10000, 'and an absurd one is clamped down');
Database::setSetting('hf_miss_threshold', '100');

Database::setSetting('hf_window', '5');
t_ok(HttpFlood::window() >= 60, 'the window cannot be made meaninglessly short');
Database::setSetting('hf_window', '300');

// ── Monitor-only is the honest default for a new auto-blocker ───────────────

Database::setSetting('hf_monitor_only', '1');
$r = HttpFlood::enforce();
t_ok(!empty($r['monitor_only']), 'monitor-only is reported in the result');
t_eq(0, $r['blocked'], 'and nothing is blocked while it is on');
Database::setSetting('hf_monitor_only', '0');

// Switched off entirely means switched off.
Database::setSetting('hf_enabled', '0');
$r = HttpFlood::enforce();
t_ok(isset($r['skipped']), 'disabled is reported as skipped, not as a clean run');
t_eq(0, $r['blocked'], 'and nothing happens');
Database::setSetting('hf_enabled', '1');

// ── Bounds, because this runs on a box already in trouble ───────────────────

$src = t_code(dirname(__DIR__) . '/backend/lib/HttpFlood.php');
t_contains($src, 'MAX_LOGS',  'the number of logs read is capped');
t_contains($src, 'MAX_LINES', 'the lines per log are capped');
t_contains($src, 'MAX_BYTES', 'and the bytes, so one enormous line cannot blow memory');
t_contains($src, 'fseek', 'logs are tailed, never read whole');
t_ok(strpos($src, 'file_get_contents(') === false,
     'nothing slurps a log file — /var/log/nginx/domains was 5.4 GB on the '
   . 'server this was written for');

// It must read the logs that actually carry traffic.
t_contains($src, '/var/log/nginx/domains',
     'THE REASON BOT SHIELD MISSED IT: per-vhost logs, not '
   . '/var/log/nginx/access.log, which on a cPanel box carries almost nothing');
t_contains($src, 'bytes_log',
     'and byte logs are excluded — selecting one of those by mistake cost a '
   . 'round trip during the incident');

// Most recently MODIFIED, not largest.
$lf = t_fn_body($src, 'logFiles', 'php');
t_contains($lf, 'filemtime',
     'logs are chosen by last write, not size — sorting by size picked files '
   . 'eleven days stale while the live attack was in a smaller one');
t_ok(strpos($lf, 'filesize') === false, 'size is not used to choose them');

// ── A refused block must never vanish ───────────────────────────────────────
$enf = t_fn_body($src, 'enforce', 'php');
t_contains($enf, 'block_error',
     'a refused block records its reason — this product spent a week saying '
   . '"Watching" against addresses it had never managed to block');
t_contains($enf, 'could NOT block', 'and logs it at error level');

// ── The shapes it looks for ─────────────────────────────────────────────────
t_contains($src, 'xmlrpc.php', 'xmlrpc is treated as a costly endpoint');
t_contains($src, 'wp-login.php', 'and wp-login');
t_contains($src, '/.env', 'and .env is treated as a secret-hunting path');
t_contains($src, '/.git/config', 'and .git/config');
t_contains($src, 'aws/credentials',
     'and the AWS credential path this was actually caught probing');

$an = t_fn_body($src, 'analyse', 'php');
t_contains($an, "status'] === 404",
     'the 404 storm is detected by status, which is what made the real attack '
   . 'invisible to everything else');
t_contains($an, 'vhosts',
     'and counts how many sites one address touched — a scanner sweeps the '
   . 'whole box, a real visitor does not');
t_contains($an, 'endpoints',
     'and a distributed endpoint flood is detected separately, because each '
   . 'sender can be modest on its own and never trip a per-address rate rule');

// ── Replay of the real attack ───────────────────────────────────────────────
//
// The detector is only worth anything if it catches what actually happened.
// This reconstructs the 2026-10-27 traffic shape and runs it through the same
// code path the cron uses, with the logs pointed at a sandbox.

$logDir = sys_get_temp_dir() . '/sg-hf-' . getmypid() . '-' . mt_rand(1000, 9999);
@mkdir($logDir, 0700, true);
register_shutdown_function(function () use ($logDir) {
    foreach (glob($logDir . '/*') ?: [] as $f) { @unlink($f); }
    @rmdir($logDir);
});

$stamp = date('d/M/Y:H:i:s O');
$mk = function (string $ip, string $path, int $status) use ($stamp): string {
    return sprintf('%s - - [%s] "GET %s HTTP/1.1" %d 199 "-" "-"',
                   $ip, $stamp, $path, $status);
};

// The scanner: one address, hundreds of 404s, across several vhosts.
$secretPaths = ['/.env', '/.git/config', '/settings.py', '/stack.json',
                '/server-status', '/.aws/credentials', '/config.json'];
foreach (['blogs.example.com', 'suggest.example.com', 'vault.example.com'] as $vhost) {
    $lines = [];
    for ($i = 0; $i < 80; $i++) {
        $lines[] = $mk('185.177.72.49', $secretPaths[$i % count($secretPaths)], 404);
    }
    // A real visitor on the same vhost, who must not be swept up.
    for ($i = 0; $i < 5; $i++) { $lines[] = $mk('198.51.100.9', '/', 200); }
    file_put_contents($logDir . '/' . $vhost . '-ssl_log', implode("\n", $lines) . "\n");
}

// The xmlrpc flood: ten addresses, none individually enormous.
$lines = [];
for ($n = 1; $n <= 10; $n++) {
    for ($i = 0; $i < 30; $i++) {
        $lines[] = $mk('203.0.113.' . $n, '/xmlrpc.php', 200);
    }
}
file_put_contents($logDir . '/maitri.example.com-ssl_log', implode("\n", $lines) . "\n");

// Point the detector at the sandbox. Everything else is the real code path:
// LOG_DIRS is a const, so only the directory listing is overridden and every
// other line of analyse() is the shipped one.
eval('class HttpFloodTest extends HttpFlood {
    public static $dir = "";
    public static function logFiles(int $max = 25): array {
        $out = [];
        foreach (glob(self::$dir . "/*") ?: [] as $f) {
            if (strpos(basename($f), "bytes_log") !== false) { continue; }
            $out[$f] = (int) @filemtime($f);
        }
        arsort($out);
        return array_slice(array_keys($out), 0, $max);
    }
}');
HttpFloodTest::$dir = $logDir;

Database::setSetting('hf_miss_threshold', '100');
Database::setSetting('hf_endpoint_threshold', '200');
Database::setSetting('hf_rate_threshold', '600');
Database::setSetting('bf_whitelist', '');
Database::setSetting('hf_admin_ips', '');

$res = HttpFloodTest::analyse();

$ips = array_column($res['findings'], 'ip');
t_ok(in_array('185.177.72.49', $ips, true),
     'THE ATTACK THAT TOOK THE SERVER DOWN IS CAUGHT: 240 not-found responses '
   . 'across three sites from one address');

$scan = null;
foreach ($res['findings'] as $f) { if ($f['ip'] === '185.177.72.49') { $scan = $f; } }
t_eq('scanner', $scan['kind'] ?? '', 'and classified as a scanner, not a rate case');
t_eq(3, (int) ($scan['vhosts'] ?? 0),
     'with the number of sites it swept — a scanner hits the whole box, a '
   . 'real visitor does not');
t_ok((int) ($scan['secrets'] ?? 0) > 0, 'and the secret-hunting paths counted');
t_contains($scan['reason'] ?? '', 'not-found', 'the reason says what it saw');

t_ok(!in_array('198.51.100.9', $ips, true),
     'the ordinary visitor on the same vhost is NOT caught — 200s do not look '
   . 'like a scan however many there are');

// The xmlrpc flood: no single address is big enough for a rate rule, which is
// exactly why it needs its own detector.
$paths = array_column($res['endpoints'], 'path');
t_ok(in_array('/xmlrpc.php', $paths, true),
     'THE XMLRPC FLOOD IS CAUGHT as an endpoint flood');
$ep = null;
foreach ($res['endpoints'] as $e) { if ($e['path'] === '/xmlrpc.php') { $ep = $e; } }
t_eq(300, (int) ($ep['total'] ?? 0), 'with the total across all senders');
t_eq(10, (int) ($ep['sources'] ?? 0), 'and the number of addresses involved');
t_ok(!in_array('203.0.113.1', $ips, true),
     'while no individual sender trips the per-address rate rule — which is '
   . 'precisely why a rate rule alone would have missed this');

// And the rail holds under a real attack: an allow-listed scanner is spared.
Database::setSetting('bf_whitelist', '185.177.72.49');
$res2 = HttpFloodTest::analyse();
t_ok(!in_array('185.177.72.49', array_column($res2['findings'], 'ip'), true),
     'an allow-listed address is spared even when it is unmistakably scanning');
Database::setSetting('bf_whitelist', '');
