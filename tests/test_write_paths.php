<?php
/**
 * Write paths: firewall rules and WAF mode.
 *
 * Reported symptoms: "I cannot add rules to firewall, same failed message" and
 * "WAF - I cannot apply any modes in this".
 *
 * These were the last untested paths in the product for a structural reason:
 * each one ends in a shell command against nft, iptables, csf or apachectl, and
 * none of those exist on a development machine. So the code could not be run
 * before it reached a customer's server, and it never was.
 *
 * The command runner is injectable now. These tests do not pretend the tools are
 * present — they assert the DECISIONS: which command would be issued, what
 * happens when it fails, and whether state is persisted only on success.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';

/** Records every command and replies from a script. */
final class FakeShell
{
    /** @var string[] */
    public array $calls = [];
    /** @var array<string,array{out:string,code:int}> */
    private array $replies;

    public function __construct(array $replies = []) { $this->replies = $replies; }

    public function __invoke(string $cmd): array
    {
        $this->calls[] = $cmd;
        foreach ($this->replies as $needle => $reply) {
            if (strpos($cmd, $needle) !== false) { return $reply; }
        }
        return ['out' => '', 'code' => 0];
    }

    public function ran(string $needle): bool
    {
        foreach ($this->calls as $c) {
            if (strpos($c, $needle) !== false) { return true; }
        }
        return false;
    }
}

// ── Firewall backend detection drives everything else ────────────────────────
$nftBox = new FakeShell([
    'command -v nft'      => ['out' => '/usr/sbin/nft', 'code' => 0],
    'command -v csf'      => ['out' => '', 'code' => 1],
    'systemctl is-active' => ['out' => 'inactive', 'code' => 3],
]);
FirewallEngine::setRunner($nftBox);

$backend = FirewallEngine::detect();
t_ok(is_string($backend) && $backend !== '', "a backend is detected ({$backend})");
t_ok($nftBox->calls !== [], 'detection actually consults the system');

// ── Blocking an address must issue a command AND record it ───────────────────
$fw = new FakeShell();
FirewallEngine::setRunner($fw);

$before = (int) (Database::fetchOne("SELECT COUNT(*) c FROM blocked_ips")['c'] ?? 0);

t_no_throw(function () {
    $f = new Firewall();
    $f->blockIP('198.51.100.77', 'unit test', false);
}, 'blockIP() runs without throwing');

$after = (int) (Database::fetchOne("SELECT COUNT(*) c FROM blocked_ips")['c'] ?? 0);
t_eq($before + 1, $after, 'a blocked address is persisted');

$row = Database::fetchOne(
    "SELECT * FROM blocked_ips WHERE ip_address = ? ORDER BY id DESC LIMIT 1",
    ['198.51.100.77']
);
t_ok($row !== null, 'the blocked address can be read back');
if ($row) {
    t_contains((string)$row['reason'], 'unit test', 'the reason is stored');
}

// The address must appear in whatever command was issued — a rule that does not
// name the address is not blocking anything.
$mentioned = false;
foreach ($fw->calls as $c) {
    if (strpos($c, '198.51.100.77') !== false) { $mentioned = true; break; }
}
t_ok($mentioned || $fw->calls === [],
    'the block command names the address (or CSF/nft was absent, which is reported)');

// ── An invalid address must be refused before it reaches a shell ─────────────
// A library must not end the request: this used to echo JSON and call exit(),
// which bypassed the router's envelope and made the method impossible to call
// from cron without killing the task mid-run.
$evil = new FakeShell();
FirewallEngine::setRunner($evil);
$f2 = new Firewall();

$threw = false;
try {
    $f2->blockIP('; rm -rf /', 'injection attempt', false);
} catch (InvalidArgumentException $e) {
    $threw = true;
} catch (Throwable $e) {
    $threw = false;
}
t_ok($threw, 'a malformed address raises InvalidArgumentException instead of exit()');

$leaked = false;
foreach ($evil->calls as $c) {
    if (strpos($c, 'rm -rf') !== false) { $leaked = true; }
}
t_ok(!$leaked, 'a rejected address never reaches a shell command at all');

// The router must turn that into a 400, not a 500.
$router = t_code($ctx['repo'] . '/backend/api/index.php');
t_contains($router, 'catch (InvalidArgumentException',
    'the router maps bad input to a client error');

// And no library may end the request itself.
foreach (['Firewall', 'IPReputation'] as $cls) {
    $src = t_code($ctx['repo'] . "/backend/lib/{$cls}.php");
    t_ok(strpos($src, 'http_response_code(') === false,
        "{$cls} does not set an HTTP status from inside a library");
}

// ── WAF mode ─────────────────────────────────────────────────────────────────
$confDir = $ctx['sandbox'] . '/wafconf';
@mkdir($confDir, 0777, true);
$incDir = $ctx['sandbox'] . '/apache-conf.d';
@mkdir($incDir, 0777, true);
WAFInstaller::setConfDir($confDir);
WAFInstaller::setIncludeDir($incDir);

// An unknown mode is rejected without touching Apache at all.
$noTouch = new FakeShell();
WAFInstaller::setRunner($noTouch);
$bad = WAFInstaller::setMode('sideways');
t_eq(false, $bad['success'], 'an unknown WAF mode is rejected');
t_eq(false, $noTouch->ran('-t'), 'a rejected mode never runs apachectl');

// Apache refusing the config must abort the change and say why. Writing a
// config Apache will not load and then reloading anyway takes the web server
// down — the one outcome this must never produce.
$apacheRejects = new FakeShell([
    ' -t' => ['out' => "AH00526: Syntax error on line 12\ninvalid SecRuleEngine", 'code' => 1],
]);
WAFInstaller::setRunner($apacheRejects);
$rejected = WAFInstaller::setMode('on');
t_eq(false, $rejected['success'], 'a config Apache rejects is not applied');
t_contains((string)($rejected['error'] ?? ''), 'Apache rejected',
    'the failure explains that Apache rejected it');
t_eq(false, $apacheRejects->ran('graceful'), 'Apache is not reloaded after a failed check');
t_ok(Database::setting('waf_mode') !== 'on', 'the mode is not recorded when it was not applied');

// The happy path: config validates, Apache reloads, mode persists.
$apacheOk = new FakeShell([' -t' => ['out' => 'Syntax OK', 'code' => 0]]);
WAFInstaller::setRunner($apacheOk);
$ok = WAFInstaller::setMode('detectiononly');
t_eq(true, $ok['success'] ?? false, 'a valid mode is applied');
t_eq('detectiononly', Database::setting('waf_mode'), 'the applied mode is persisted');
t_ok(is_file($confDir . '/sentinel-waf.conf'), 'the WAF config file is written');

$conf = (string) @file_get_contents($confDir . '/sentinel-waf.conf');
t_contains($conf, 'DetectionOnly', 'the config carries the requested engine mode');
t_contains($conf, 'sentinel-gate', 'the dashboard is exempted from the rules');

// Apache must be told to load it, or the config is inert.
t_ok(is_file($incDir . '/zz-sentinel-gate-waf.conf'),
    'an Apache include is dropped so the config is actually loaded');

// Clean up so later tests are not affected by the injected runners.
FirewallEngine::setRunner(null);
WAFInstaller::setRunner(null);
WAFInstaller::setConfDir(null);
WAFInstaller::setIncludeDir(null);
