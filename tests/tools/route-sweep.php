<?php
/**
 * Exercise EVERY API route, one process per route.
 *
 * DEVELOPMENT ONLY. Not packaged, not globbed by tests/run.php.
 *
 * ── WHY ──────────────────────────────────────────────────────────────────────
 *
 * 9c5917e converted 27 match() expressions in backend/api/index.php to switch,
 * a ~2,900 line mechanical diff in the file every single API request passes
 * through. A conversion that is right 26 times and wrong once looks exactly
 * like a conversion that is right 27 times, until the one route nobody opened
 * returns a 500.
 *
 * tests/test_router.php checks six routes. This checks all of them: it reads
 * the module table and each route function's `case` labels straight out of the
 * source, so a route added tomorrow is swept tomorrow without anyone
 * remembering to add it here.
 *
 * Each route runs in its OWN process, because a fatal in one must not take the
 * sweep with it — the run that matters most is the one where something fatals.
 *
 *   php tests/tools/route-sweep.php            sweep, print a table
 *   php tests/tools/route-sweep.php --verbose  include every response body
 *
 * Exit 1 if any route produced a non-JSON body, a PHP error, or an HTTP 5xx.
 *
 * ── WHAT THIS IS NOT ─────────────────────────────────────────────────────────
 *
 * GET only, and no parameters beyond the defaults. It proves each route
 * dispatches, runs, and returns a JSON envelope. It does not prove the route
 * does the right thing — that is what the rest of the suite is for. POST
 * routes are reported as "method refused", which is itself the correct
 * behaviour and worth seeing.
 */

$repo = dirname(dirname(__DIR__));
$api  = $repo . '/backend/api/index.php';
$src  = (string) file_get_contents($api);
$verbose = in_array('--verbose', $argv, true);

/* The module table: `case 'waf': $response = routeWAF(...)` */
if (!preg_match_all("/case\s+'([a-z-]+)':\s*\\\$response\s*=\s*(route[A-Za-z]+)\s*\(/", $src, $m, PREG_SET_ORDER)) {
    fwrite(STDERR, "Could not read the module table out of {$api}\n");
    exit(2);
}

$modules = [];
foreach ($m as $hit) { $modules[$hit[1]] = $hit[2]; }

/* For each route function, the `case` labels inside its body. The body runs
 * from the function's opening brace to the start of the next function. */
$routes = [];
foreach ($modules as $module => $fn) {
    $start = strpos($src, 'function ' . $fn . '(');
    if ($start === false) { $routes[$module] = ['(function not found)']; continue; }
    $next = strlen($src);
    foreach ($modules as $otherFn) {
        if ($otherFn === $fn) { continue; }
        $p = strpos($src, 'function ' . $otherFn . '(');
        if ($p !== false && $p > $start && $p < $next) { $next = $p; }
    }
    $body = substr($src, $start, $next - $start);
    preg_match_all("/case\s+'([a-z0-9\-_]+)'\s*:/", $body, $cm);
    $actions = array_values(array_unique($cm[1] ?? []));
    if (!$actions) { $actions = ['']; }
    $routes[$module] = $actions;
}

$runner = sys_get_temp_dir() . '/sg-sweep-' . getmypid() . '.php';
$fails  = 0;
$total  = 0;

if ((string) getenv('SG_SWEEP_TOKEN') === '') {
    echo "NOTE: no SG_SWEEP_TOKEN set, so every route will stop at the auth\n";
    echo "      gate and this sweep proves only that the dispatcher works.\n\n";
}
printf("%-12s %-26s %-6s %-5s %s\n", 'MODULE', 'ACTION', 'JSON', 'OK', 'NOTE');
echo str_repeat('-', 86) . "\n";

foreach ($routes as $module => $actions) {
    foreach ($actions as $action) {
        $total++;
        $route = $action === '' ? $module : "{$module}/{$action}";

        /* A bearer token, when one was supplied. Without it every route stops
         * at the auth gate and the sweep proves only that the DISPATCHER
         * works -- 177 identical "Missing authorization token" lines, and not
         * one of the 27 converted switch bodies ever executed. Generate one
         * with Auth::generateToken() and pass it in SG_SWEEP_TOKEN. */
        $token = (string) getenv('SG_SWEEP_TOKEN');
        $payload = '<?php' . "\n"
            . '$_SERVER["REQUEST_METHOD"]="GET";' . "\n"
            . '$_SERVER["REMOTE_USER"]="root";' . "\n"
            . '$_SERVER["REMOTE_ADDR"]="127.0.0.1";' . "\n"
            . ($token !== ''
                ? '$_SERVER["HTTP_AUTHORIZATION"]=' . var_export('Bearer ' . $token, true) . ';' . "\n"
                : '')
            . '$_SERVER["REQUEST_URI"]=' . var_export('/cgi/serverscrub/serverscrub.cgi', true) . ';' . "\n"
            . '$_GET=' . var_export(['r' => $route], true) . ';' . "\n"
            . 'ob_start(); require ' . var_export($api, true) . '; echo ob_get_clean();' . "\n";
        file_put_contents($runner, $payload);

        $out = (string) shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' 2>&1');

        $hasPhpError = (bool) preg_match('/(PHP )?(Fatal error|Parse error|Warning|Notice|Deprecated):/i', $out);
        $brace = strpos($out, '{');
        $json  = $brace === false ? null : json_decode(substr($out, $brace), true);
        $isJson = is_array($json);

        $note = '';
        $ok   = true;

        if (!$isJson) {
            $ok = false;
            $note = 'NOT JSON: ' . trim(preg_replace('/\s+/', ' ', substr($out, 0, 110)));
        } elseif ($hasPhpError) {
            $ok = false;
            preg_match('/((?:PHP )?(?:Fatal error|Parse error|Warning|Notice|Deprecated):[^\n]*)/i', $out, $em);
            $note = 'PHP DIAGNOSTIC: ' . trim(substr($em[1] ?? '', 0, 100));
        } else {
            $code = (int) ($json['code'] ?? 200);
            if ($code >= 500) { $ok = false; $note = 'HTTP ' . $code . ': ' . substr((string)($json['error'] ?? ''), 0, 70); }
            elseif (($json['success'] ?? null) === false) {
                // A refusal is a perfectly good answer: wrong method, needs a
                // licence, needs an argument. It is still a JSON envelope.
                $note = 'refused (' . $code . '): ' . substr((string) ($json['error'] ?? ''), 0, 60);
            }
        }

        if (!$ok) { $fails++; }
        printf("%-12s %-26s %-6s %-5s %s\n",
            $module, $action === '' ? '(none)' : $action,
            $isJson ? 'yes' : 'NO', $ok ? 'ok' : 'FAIL', $note);

        if ($verbose) { echo '    ' . trim(substr($out, 0, 400)) . "\n"; }
    }
}
@unlink($runner);

echo str_repeat('-', 86) . "\n";
printf("%d route(s) swept across %d module(s); %d problem(s)\n",
       $total, count($routes), $fails);
exit($fails > 0 ? 1 : 0);
