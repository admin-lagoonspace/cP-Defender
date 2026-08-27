<?php
/**
 * The UI must not invent data.
 *
 * A malware scanner that had examined ZERO files displayed "51%", because the
 * progress percentage was Math.random(). In a security product that is not a
 * cosmetic bug: the customer cannot tell a working scan from a dead one, and
 * every number on screen becomes suspect once one of them is known to be made
 * up.
 *
 * Demo mode is exempt and must stay clearly separated — it exists to show the
 * product without a server, and its fixtures live in named demo functions.
 * Everything else renders what the API returned or renders nothing.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

/**
 * Strip JS comments.
 *
 * The first version of this test flagged the COMMENT explaining why
 * Math.random() was removed. Assertions about what code does must never read
 * prose about what it used to do — the same mistake was made once already in
 * the PHP tests, which is why t_code() exists there.
 */
function js_code(string $js): string
{
    $js = (string)preg_replace('#/\*.*?\*/#s', '', $js);

    // Line comments, done by hand rather than by regex: the escaping needed to
    // spare "http://" inside a pattern is exactly the kind of thing that breaks
    // silently and makes a test pass for the wrong reason.
    $out = '';
    foreach (explode("\n", $js) as $line) {
        $pos = strpos($line, '//');
        while ($pos !== false && $pos > 0 && $line[$pos - 1] === ':') {
            $pos = strpos($line, '//', $pos + 2);   // a URL, not a comment
        }
        $out .= ($pos === false ? $line : substr($line, 0, $pos)) . "\n";
    }
    return $out;
}

/** Strip the demo-only functions, which are allowed to fabricate. */
function without_demo(string $js): string
{
    // simulateDemoScan() runs only when Demo.active is true.
    $start = strpos($js, 'function simulateDemoScan');
    if ($start !== false) {
        $end = strpos($js, "\nfunction ", $start + 10);
        $js = substr($js, 0, $start) . ($end === false ? '' : substr($js, $end));
    }
    // The Demo object holds mock fixtures by design.
    $start = strpos($js, 'const Demo = {');
    if ($start !== false) {
        $end = strpos($js, "\n};", $start);
        $js = substr($js, 0, $start) . ($end === false ? '' : substr($js, $end + 3));
    }
    return $js;
}

foreach (['app.js', 'api.js'] as $file) {
    $path = $repo . '/frontend/js/' . $file;
    $js   = js_code(without_demo(file_get_contents($path)));

    // Random numbers must never reach a rendered value.
    $randoms = preg_match_all('/Math\.random\s*\(/', $js);
    t_eq(0, $randoms, "{$file}: no Math.random() outside demo code");

    // The demo fixture's file count leaked into the live path once.
    t_ok(strpos($js, '1284930') === false,
        "{$file}: the demo file-count fixture is not used in live rendering");
}

// ── The specific regression ──────────────────────────────────────────────────
$app = file_get_contents($repo . '/frontend/js/app.js');
$live = js_code(substr($app, 0, strpos($app, 'function simulateDemoScan') ?: strlen($app)));

t_ok(strpos($live, "Math.floor(Math.random() * 5) + 50") === false,
    'the fabricated 50-54% scan progress is gone');
t_contains($live, 'indeterminate',
    'an unknown total renders as indeterminate rather than as a number');
t_contains($live, 'files_scanned',
    'the live scan panel reads the real file count from the job');

// A scan that reports nothing for a long time must say so rather than animate
// forever: the scan runs detached, so the UI cannot observe it dying.
t_contains($live, '_scanStallTicks', 'a stalled scan is detected and reported');

// ── Every sidebar page must have a client method behind it ───────────────────
// Log Analyzer shipped as a navigation entry with no API client at all: the
// `logs` module existed server-side and nothing ever called it.
$api = file_get_contents($repo . '/frontend/js/api.js');
$router = file_get_contents($repo . '/backend/api/index.php');

preg_match_all("/^\s+'([a-z]+)'\s*=> route/m", $router, $m);
$serverModules = array_unique($m[1]);
t_ok(count($serverModules) > 5, 'router modules were detected');

$missing = [];
foreach ($serverModules as $mod) {
    if ($mod === 'auth') { continue; }
    if (!preg_match("#['\"`]{$mod}/#", $api)) { $missing[] = $mod; }
}
t_eq(0, count($missing), 'every server module has at least one client method'
    . ($missing ? ' — unreachable: ' . implode(', ', $missing) : ''));
