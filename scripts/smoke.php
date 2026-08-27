<?php
/**
 * Sentinel Gate — API smoke test.
 *
 * Executes every read-only API route through the real router, in a throwaway
 * install, and reports any that fail to return JSON or that raise a PHP error.
 *
 * This exists because six separate user-facing failures — a blank dashboard,
 * scanner, firewall, WAF and IP reputation all "failing" — were one runtime
 * Error each in code that parsed perfectly. Nothing in the pipeline had ever
 * RUN the code it shipped; every gate checked it statically. A route that is
 * never executed before release is a route the customer executes first.
 *
 * Only side-effect-free routes are called. Nothing here starts a scan, writes a
 * firewall rule, or touches the network.
 *
 * Usage:  php scripts/smoke.php
 * Exit 0 = every route returned JSON.
 */

$repo = dirname(__DIR__);

// ── Throwaway install ────────────────────────────────────────────────────────
$sandbox = sys_get_temp_dir() . '/sg-smoke-' . getmypid();
@mkdir($sandbox . '/database', 0700, true);
@mkdir($sandbox . '/logs', 0700, true);
@mkdir($sandbox . '/quarantine', 0700, true);

// mode.php normally comes from the installer. Point SG_ROOT at the sandbox so
// the real config computes every path inside it.
file_put_contents($sandbox . '/mode.php', "<?php\n"
    . "if (!defined('INSTALL_MODE')) { define('INSTALL_MODE', 'cpanel'); }\n"
    . "if (!defined('SG_ROOT'))      { define('SG_ROOT', " . var_export($sandbox, true) . "); }\n");

$routes = [
    ['GET', 'auth/status'],
    ['GET', 'auth/auto-login'],
    ['GET', 'license/status'],
    ['GET', 'dashboard/stats'],
    ['GET', 'scanner/stats'],
    ['GET', 'scanner/threats'],
    ['GET', 'firewall/stats'],
    ['GET', 'firewall/rules'],
    ['GET', 'firewall/blocked'],
    ['GET', 'waf/status'],
    ['GET', 'waf/stats'],
    ['GET', 'waf/categories'],
    ['GET', 'iprep/top-attackers'],
    ['GET', 'events/list'],
    ['GET', 'settings/get'],
    ['GET', 'monitor/status'],
    ['GET', 'monitor/stats'],
    ['GET', 'storage/stats'],
    ['GET', 'botshield/stats'],
    ['GET', 'cmsguard/stats'],
    ['GET', 'rootkit/status'],
    ['GET', 'integrity/stats'],
    ['GET', 'phphard/stats'],
    ['GET', 'update/status'],
    ['GET', 'update/progress'],
];

$php = PHP_BINARY;
$runner = $sandbox . '/run.php';

// Each route runs in its OWN process: a fatal must not take the harness with it,
// and constants defined by one request would leak into the next.
file_put_contents($runner, <<<'RUNNER'
<?php
$repo    = $argv[1];
$sandbox = $argv[2];
$route   = $argv[3];

$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI']    = '/cgi/sentinel_gate/sentinel_gate.cgi?r=' . $route;
$_SERVER['REMOTE_USER']    = 'root';
$_SERVER['REMOTE_ADDR']    = '127.0.0.1';
$_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
$_GET['r'] = $route;

// Use the sandbox's mode.php rather than the developer's own installed one.
copy($sandbox . '/mode.php', $repo . '/backend/config/.smoke-mode.php');

ob_start();
require $repo . '/backend/api/index.php';
$out = ob_get_clean();
echo $out;
RUNNER);

echo "Smoke-testing " . count($routes) . " routes\n\n";

$fails = [];
foreach ($routes as [$method, $route]) {
    $cmd = escapeshellarg($php) . ' ' . escapeshellarg($runner) . ' '
         . escapeshellarg($repo) . ' ' . escapeshellarg($sandbox) . ' '
         . escapeshellarg($route) . ' 2>&1';
    $out = shell_exec($cmd);
    $out = (string)$out;

    // The JSON body is the last {...} in the output. Anything before it is noise
    // from shell_exec of tools absent on this machine (nft, ps, systemctl)
    // writing to stdout -- expected when smoke-testing a Linux product from a
    // workstation, and not a failure of the route under test.
    $body = trim($out);
    $start = strpos($body, '{');
    if ($start !== false) { $body = substr($body, $start); }

    $json = json_decode($body, true);
    $bad  = null;

    if (stripos($out, 'Fatal error') !== false || stripos($out, 'Uncaught') !== false) {
        $bad = 'PHP FATAL';
    } elseif ($json === null) {
        $bad = 'not JSON';
    } elseif (isset($json['detail'])) {
        $bad = 'internal error';
    }

    if ($bad !== null) {
        $first = strtok(preg_replace('/\s+/', ' ', $body), "\n");
        $fails[] = sprintf("  %-24s %-14s %s", $route, $bad, substr($first, 0, 400));
        printf("  [x] %-24s %s\n", $route, $bad);
    } else {
        printf("  [+] %-24s ok\n", $route);
    }
}

@unlink($repo . '/backend/config/.smoke-mode.php');

echo "\n";
if ($fails) {
    echo "FAILED routes:\n" . implode("\n", $fails) . "\n\n";
    echo count($fails) . " of " . count($routes) . " routes failed.\n";
    exit(1);
}
echo "All " . count($routes) . " routes returned JSON.\n";
exit(0);
