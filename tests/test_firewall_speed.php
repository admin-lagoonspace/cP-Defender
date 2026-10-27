<?php
/**
 * The firewall page must not be able to be slow.
 *
 * Reported three times. The first fix removed a pointless `csf -l`; the second
 * bounded the commands and cached them for 60 seconds. Both missed the actual
 * problem: the work was still ON the request path. A 60-second cache means one
 * request a minute still pays for an iptables call that can sit waiting on the
 * xtables lock, and because cpsrvd serialises requests, that one request
 * stalls every other page behind it.
 *
 * So the rule asserted here is not "it is bounded" or "it is cached" — it is
 * that rendering this page spawns no processes at all. Measuring happens in
 * the scheduler; the page reads what it left behind.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$fw  = t_code($repo . '/backend/lib/Firewall.php');

// -- Nothing on the read path shells out -------------------------------------
// Bounded by the next function, not by a comment banner: t_code() strips
// comments, so a banner is not there to find.
$statsStart = strpos($fw, 'public function getStats');
$statsEnd   = strpos($fw, 'function ', $statsStart + 30);
$stats      = substr($fw, $statsStart, max(200, $statsEnd - $statsStart));

foreach (['exec(', 'shell_exec(', 'popen(', 'shBounded', 'proc_open('] as $call) {
    t_ok(strpos($stats, $call) === false,
        "getStats() does not call {$call} — nothing on a page load spawns a process");
}
t_contains($stats, 'self::cachedOnly(', 'it reads measurements taken elsewhere');

// getCSFStatus was two process spawns per page load on its own.
$csfStart = strpos($fw, 'public function getCSFStatus');
$csfEnd   = strpos($fw, 'function ', $csfStart + 30);
$csf      = substr($fw, $csfStart, max(120, $csfEnd - $csfStart));
t_ok(strpos($csf, 'shBounded') === false && strpos($csf, 'exec(') === false,
    'getCSFStatus() does not spawn pgrep and csf --version on a page load');

// The cache helper must not fall back to producing the value, which is what
// kept the cost on the request path through two previous attempts.
t_ok(strpos($fw, 'private static function cached(string $key, int $ttl, callable $produce)') === false,
    'the produce-on-miss cache is gone');
t_contains($fw, 'function cachedOnly', 'replaced by a read-only lookup');

// -- Measuring happens in the scheduler --------------------------------------
t_contains($fw, 'function refreshProbes', 'there is a way to take the measurements');
$probe = substr($fw, strpos($fw, 'function refreshProbes'), 1400);
t_contains($probe, '-w 2', 'iptables is given a bounded wait for the xtables lock');
t_contains($probe, 'shBounded', 'and the command itself is bounded by timeout');

$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "'fwprobe' => [", 'the probe runs on a schedule');
t_contains($sched, 'Firewall::refreshProbes()', 'calling it');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/Firewall.php'",
    'and the scheduler requires Firewall, or the task fatals in cron');

$install = file_get_contents($repo . '/install.sh');
t_contains($install, 'Firewall::refreshProbes()',
    'and it is taken once at install, so the first page load has a reading');

// -- Behaviour: the read path is actually fast -------------------------------
// Measured rather than asserted structurally: a server under attack has
// thousands of blocked addresses, which is exactly when the page matters.
$db = Database::get();
$db->beginTransaction();
$st = $db->prepare('INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?,?,?)');
for ($i = 0; $i < 3000; $i++) {
    $st->execute(['198.51.' . ($i % 254) . '.' . (($i % 250) + 1), 'test', time() - ($i * 60)]);
}
$db->commit();

$f = new Firewall();
$f->getStats();                       // warm any lazy init

$t0 = microtime(true);
for ($i = 0; $i < 10; $i++) { $s = $f->getStats(); }
$avg = (microtime(true) - $t0) * 1000 / 10;

// Generous, because CI machines vary. The point is orders of magnitude: this
// was capable of taking seconds.
t_ok($avg < 150,
    sprintf('getStats() returns in %.1fms with 3000 blocked rows (budget 150ms)', $avg));

$t0 = microtime(true);
$f->getBlockedIPs(100, 0);
$bl = (microtime(true) - $t0) * 1000;
t_ok($bl < 150, sprintf('getBlockedIPs() returns in %.1fms (budget 150ms)', $bl));

// -- Unknown is reported as unknown, not as zero -----------------------------
// "0 iptables rules" reads as "no firewall", which is a very different claim
// from "we have not measured yet".
Database::setSetting('fwcache_iptables_rules', '');
Database::setSetting('fwcache_taken_at', '0');
$s = (new Firewall())->getStats();
t_eq(true, $s['probe_pending'], 'an unmeasured server says so');
t_eq(true, $s['iptables_unknown'], 'rather than claiming zero rules');
t_eq(null, Firewall::probeAge(), 'and reports no probe age');

// A timed-out measurement is distinguishable from a real zero.
Database::setSetting('fwcache_iptables_rules', '-1');
Database::setSetting('fwcache_taken_at', (string) time());
$s = (new Firewall())->getStats();
t_eq(false, $s['probe_pending'], 'a taken-but-failed measurement is not pending');
t_eq(true, $s['iptables_unknown'], 'but is still reported as unknown');

Database::setSetting('fwcache_iptables_rules', '42');
$s = (new Firewall())->getStats();
t_eq(false, $s['iptables_unknown'], 'a real reading is reported as known');
t_eq(42, $s['iptables_rules'], 'with its value');
t_ok(Firewall::probeAge() !== null, 'and an age');

$js = file_get_contents($repo . '/frontend/js/app.js');
t_contains($js, 'probe_pending', 'the UI distinguishes not-yet-measured');
t_contains($js, 'not measured yet', 'and says so');

// -- Slowness must be measurable next time -----------------------------------
// Two attempts were spent reasoning about which call was slow without ever
// timing one.
$api = t_code($repo . '/backend/api/index.php');
t_contains($api, "SG_REQ_START", 'requests are timed');
t_contains($api, "\$response['ms'] = \$__ms", 'and the duration returned to the caller');
t_contains($api, 'Slow API request', 'with slow ones logged server-side');


// ── The licence gate, which is on the path of EVERY request ─────────────────
// Three attempts at "the firewall page is slow" looked only at firewall code.
// The cost was not there: License::status() runs on the licence gate for every
// request, and with a licence key whose local key has gone stale it called the
// licence server with a 12-second timeout. A failure was recorded nowhere, so
// the next request tried again, and the next. The firewall page fires three
// requests and cpsrvd serialises them.
$lic = t_code($repo . '/backend/lib/License.php');

t_contains($lic, 'REMOTE_RETRY_SECS', 'a failed licence check backs off');
t_contains($lic, 'function noteRemoteFailure', 'failures are recorded');
t_contains($lic, 'function remoteAllowed', 'and checked before calling out again');
t_contains($lic, 'TIMEOUT_INTERACTIVE',
    'a request gets a shorter timeout than a background refresh');

$rc = substr($lic, strpos($lic, 'function remoteCheck'), 700);
t_contains($rc, 'self::remoteAllowed()',
    'the remote check bails out while backing off');

// The scheduler and the refresh button must still get a real check.
t_contains($lic, 'self::$background = true',
    'a deliberate refresh ignores the back-off');

// ── Behaviour: repeated requests must not each pay a timeout ────────────────
Database::setSetting('license_key', 'TEST-KEY-0000');
Database::setSetting('license_localkey', '');
Database::setSetting('license_remote_next_try', '0');

$ref = new ReflectionClass('License');
$cacheProp = $ref->getProperty('cache');
$cacheProp->setAccessible(true);

// First call may attempt the server; that is allowed once.
$cacheProp->setValue(null, null);
License::status();

$next = (int) Database::setting('license_remote_next_try', '0');
t_ok($next > time(), 'a failed check sets a back-off window');

// Every subsequent request, each a fresh PHP process, must be instant.
$worst = 0;
for ($i = 0; $i < 5; $i++) {
    $cacheProp->setValue(null, null);
    $t0 = microtime(true);
    License::status();
    $worst = max($worst, (microtime(true) - $t0) * 1000);
}
t_ok($worst < 150,
    sprintf('subsequent requests do not re-attempt the licence server (worst %.1fms)', $worst));

Database::setSetting('license_key', '');
Database::setSetting('license_remote_next_try', '0');

// ── The firewall page loads in stages ───────────────────────────────────────
// Fetched together, the slowest call decided when ANY panel appeared, so the
// page sat blank until the last one landed.
$js = file_get_contents($repo . '/frontend/js/app.js');
t_contains($js, 'async function loadFirewallStages', 'the page loads in stages');
t_contains($js, "API.withBusy('Loading firewall", 'behind a blocking overlay');

$fw = substr($js, strpos($js, 'async function loadFirewallStages'), 4000);
t_contains($fw, 'Stage 1', 'the counts come first');
t_contains($fw, 'Stage 2', 'then the rules');
t_contains($fw, 'Stage 3', 'then the blocked list');

// Each stage must fetch where it renders, not up front -- otherwise it is the
// old all-at-once load with comments on it.
// Stage 2 now delegates to the paged rules loader rather than fetching
// inline: rendering EVERY rule is what made this page unusable on a server
// with 343,000 of them. The intent of this check is unchanged — each stage
// fetches where it renders — so it follows the one hop.
$s1 = strpos($fw, 'API.fwStats()');
$s2 = strpos($fw, 'loadFirewallRules()');
$s3 = strpos($fw, 'API.fwBlocked()');
t_ok($s1 !== false && $s2 !== false && $s3 !== false, 'all three stages are present');
t_ok($s1 < $s2 && $s2 < $s3, 'and issued in stage order');
t_contains(t_fn_body($js, 'loadFirewallRules'), 'API.fwRules(',
     'and the rules stage really does fetch, one page of it');
t_ok(strpos($fw, 'Promise.all') === false,
    'they are no longer awaited together, which is what made one slow call blank the page');

// ── "the firewall refused the block", on a server running CSF ───────────────
//
// Reported from a live cPanel box with CSF installed: every offending address
// read "Block FAILED · the firewall refused the block". Three separate faults
// stacked up, and each one hid the next.
//
//   1. detect() asked `command -v csf`. A CGI does not get a login shell's
//      PATH — under cPanel it is typically /usr/local/bin:/bin:/usr/bin, with
//      no /usr/sbin — so csf was not found, detection fell through to "none",
//      and block() correctly returned "No firewall backend available".
//
//   2. Firewall::blockIP() returned only `success` and `output`. The
//      brute-force escalation reads `error`, found nothing, and substituted
//      its own generic sentence. The real reason existed and was discarded.
//
//   3. blockIP() wrote the blocked_ips row BEFORE checking success, so a
//      refused block still showed in the Firewall page as blocked.

$fwSrc = t_code(dirname(__DIR__) . '/backend/lib/FirewallEngine.php');

// 1. Discovery must not depend on the caller's PATH.
t_contains($fwSrc, 'private const SBIN_PATH',
     'the engine carries its own PATH for firewall tools');
t_contains($fwSrc, "@exec('PATH=' . self::SBIN_PATH",
     'and exports it for every command it runs');
t_contains($fwSrc, 'function csfPath',
     'CSF is located on disk rather than through the shell');
t_ok(strpos($fwSrc, "file_exists('/usr/sbin/csf')") === false,
     'and is no longer pinned to one install location');

// The csf binary is invoked by absolute path, not by bare name.
t_ok(strpos($fwSrc, "self::sh('csf -d ") === false,
     'csf is not called by bare name, which needs a PATH we may not have');
t_contains($fwSrc, "self::csfPath()) . ' -d '",
     'but by the path it was found at');

// 2. A failure must carry its reason.
FirewallEngine::resetBackend();
FirewallEngine::setRunner(function (string $cmd) {
    // No firewall tools at all: command -v finds nothing.
    return ['out' => '', 'code' => 1];
});
$r = FirewallEngine::block('203.0.113.77');
t_ok(empty($r['success']), 'with no backend the block fails');
t_contains(strtolower((string)($r['error'] ?? '')), 'no firewall backend',
     'and says exactly that, rather than a generic refusal');

// A backend that runs but rejects the address reports the tool's own words.
FirewallEngine::resetBackend();
FirewallEngine::setRunner(function (string $cmd) {
    if (strpos($cmd, 'command -v') !== false) { return ['out' => '/usr/sbin/nft', 'code' => 0]; }
    if (strpos($cmd, 'systemctl') !== false)  { return ['out' => 'inactive', 'code' => 3]; }
    return ['out' => 'Error: Could not process rule: No such file or directory', 'code' => 1];
});
$r = FirewallEngine::block('203.0.113.78');
t_ok(empty($r['success']), 'a backend that rejects the rule fails');
t_contains((string)($r['error'] ?? ''), 'Could not process rule',
     'and the tool\'s own message is what reaches the caller');

// Success is still success.
FirewallEngine::resetBackend();
FirewallEngine::setRunner(function (string $cmd) {
    if (strpos($cmd, 'command -v') !== false) { return ['out' => '/usr/sbin/nft', 'code' => 0]; }
    if (strpos($cmd, 'systemctl') !== false)  { return ['out' => 'inactive', 'code' => 3]; }
    return ['out' => '', 'code' => 0];
});
$r = FirewallEngine::block('203.0.113.79');
t_ok(!empty($r['success']), 'a backend that accepts the rule succeeds');
t_ok(!isset($r['error']), 'and carries no error');

FirewallEngine::setRunner(null);
FirewallEngine::resetBackend();

// 3. A refused block must not be recorded as a block.
$fwLib = t_code(dirname(__DIR__) . '/backend/lib/Firewall.php');
$blk   = substr($fwLib, (int)strpos($fwLib, 'function blockIP'), 2000);
$failAt = strpos($blk, 'if ($code !== 0)');
$dbAt   = strpos($blk, "Database::insert('blocked_ips'");
t_ok($failAt !== false && $dbAt !== false && $failAt < $dbAt,
     'THE DISHONEST ROW: blockIP() returns on failure BEFORE writing '
   . 'blocked_ips, so the panel cannot list an address as blocked while '
   . 'packets from it are still arriving');
t_contains($blk, "'error' => \$why",
     'and the reason is returned to the caller');
t_contains($blk, "'backend' =>",
     'along with which backend answered, so this is diagnosable');
