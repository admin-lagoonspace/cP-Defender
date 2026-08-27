<?php
/**
 * Router regressions — backend/api/index.php.
 *
 *   3.19.0  Route parsing searched for a literal "api" path segment, so it
 *           mis-parsed under any path without one (e.g. a cpsrvd CGI path).
 *   3.19.0  Routing moved to ?r=module/action, which needs neither mod_rewrite
 *           nor PATH_INFO and therefore behaves the same under cpsrvd, Apache
 *           and the standalone router.
 *   3.19.0  error_reporting(0) hid errors AND stopped them being logged, so a
 *           failure could only ever appear as "Server error" with no trace.
 *   3.19.7  "Internal server error" with the cause hidden in a log file cost
 *           several diagnosis cycles.
 *
 * The router is a script, not a class, so these run it in a subprocess and
 * inspect the response — the same way a browser would.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

/** Execute one request against the real router; returns the decoded body. */
function call_route(string $route, array $extraGet = []): array
{
    $repo = dirname(__DIR__);
    $runner = sys_get_temp_dir() . '/sg-route-' . getmypid() . '.php';
    $payload = '<?php' . "\n"
        . '$_SERVER["REQUEST_METHOD"]="GET";' . "\n"
        . '$_SERVER["REMOTE_USER"]="root";' . "\n"
        . '$_SERVER["REMOTE_ADDR"]="127.0.0.1";' . "\n"
        . '$_SERVER["REQUEST_URI"]=' . var_export('/cgi/sentinel_gate/sentinel_gate.cgi', true) . ';' . "\n"
        . '$_GET=' . var_export(array_merge(['r' => $route], $extraGet), true) . ';' . "\n"
        . 'ob_start(); require ' . var_export($repo . '/backend/api/index.php', true) . '; echo ob_get_clean();' . "\n";
    file_put_contents($runner, $payload);
    $out = (string)shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' 2>&1');
    @unlink($runner);
    $start = strpos($out, '{');
    $json = $start === false ? null : json_decode(substr($out, $start), true);
    return is_array($json) ? $json : ['__raw' => $out];
}

// ── ?r= routing works, which is the only form that survives every server ─────
$res = call_route('auth/status');
t_ok(($res['success'] ?? false) === true, '?r=auth/status routes correctly');
t_eq(SG_VERSION, $res['version'] ?? null, 'the route returns live data, not a stub');

// A hyphenated action must survive path sanitisation.
$res = call_route('auth/auto-login');
t_ok(isset($res['success']), 'a hyphenated action (auth/auto-login) routes');

// ── Unknown routes are refused cleanly, not with a crash ─────────────────────
$res = call_route('nosuchmodule/nosuchaction');
t_ok(($res['success'] ?? true) === false, 'an unknown module is refused');
t_ok(!isset($res['__raw']), 'an unknown module still returns JSON, not an HTML error');

// ── Traversal must not survive parsing ───────────────────────────────────────
$res = call_route('../../etc/passwd');
t_ok(!isset($res['__raw']), 'a traversal attempt returns JSON rather than crashing');
t_ok(($res['success'] ?? true) === false, 'a traversal attempt is refused');

// ── Every response is JSON ───────────────────────────────────────────────────
// The whole "Server error — please try again" class of bug was the client being
// handed HTML (a 403, a 501, a PHP warning) where it expected JSON.
foreach (['license/status', 'settings/get', 'events/list'] as $route) {
    $res = call_route($route);
    t_ok(!isset($res['__raw']), "{$route} returns parseable JSON");
}

// ── Errors are reported, not swallowed ───────────────────────────────────────
$src = t_code($repo . '/backend/api/index.php');
t_ok(strpos($src, 'error_reporting(0)') === false,
    'error_reporting(0) is gone — errors must be logged, just never printed');
t_contains($src, 'register_shutdown_function',
    'a fatal still produces a JSON envelope');
t_contains($src, "'detail'",
    'API errors carry the cause, not just "Internal server error"');
