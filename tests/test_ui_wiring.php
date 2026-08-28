<?php
/**
 * Buttons must do something, and failures must be visible.
 *
 * Reported: "Real time monitor section on dashboard does not work, it doesn't
 * start or stop services", "I started a quick scan and it just does nothing",
 * "Refresh button does not work for any of these modules".
 *
 * Every one of those handlers resolved to a real function -- that was checked
 * and it passed. The functions ran and failed silently: the pattern
 * `if (!res?.success) return;` appears throughout, rendering nothing and
 * logging nothing, so a failing endpoint is indistinguishable from a dead
 * button.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The scan worker needs a CLI interpreter ──────────────────────────────────
// This is the actual reason a scan "did nothing": under cpsrvd the API runs as
// php-cgi, PHP_BINARY is therefore php-cgi, and php-cgi refuses to run a script
// from the command line without REDIRECT_STATUS. The worker exited immediately.
$sc = t_code($repo . '/backend/lib/Scanner.php');
t_contains($sc, 'isCliBinary', 'the worker interpreter is checked for the CLI SAPI');
t_contains($sc, 'PHP_SAPI', 'the check asks the binary rather than guessing from its name');
t_ok(strpos($sc, "if (defined('PHP_BINARY') && PHP_BINARY !== '' && is_executable(PHP_BINARY)) {\n            return PHP_BINARY;") === false,
    'PHP_BINARY is no longer returned unconditionally');

$bin = Scanner::phpBinary();
t_ok(is_string($bin) && $bin !== '', 'phpBinary() resolves to something');
// On this machine PHP_BINARY is the CLI build, so it should be chosen.
t_ok(strpos(basename($bin), 'cgi') === false,
    'a CGI binary is never chosen for the worker (' . basename($bin) . ')');

// ── Server errors must reach the user ────────────────────────────────────────
$api = file_get_contents($repo . '/frontend/js/api.js');
t_contains($api, 'r.status >= 400', 'api.js notices HTTP error statuses');
t_contains($api, "toast(", 'api.js surfaces them to the user');
t_contains($api, 'r.status !== 401', '401 is excluded (handled as a session expiry)');
t_contains($api, 'r.status !== 402', '402 is excluded (handled as a licence block)');

// ── A failed monitor action must say why ─────────────────────────────────────
$app = file_get_contents($repo . '/frontend/js/app.js');
t_ok(strpos($app, "toast('Action failed', 'error')") === false,
    'the contentless "Action failed" toast is gone');
t_contains($app, "'Monitor: ' + why", 'monitor failures report the server reason');

// ── The resource limits must be editable without hunting for a mode ──────────
$html = file_get_contents($repo . '/frontend/index.html');
t_ok(strpos($html, '<div id="rt-custom-fields" class="hidden"') === false,
    'the limit fields are not hidden behind selecting a preset');
t_contains($html, 'oninput="rtLimitEdited()"',
    'editing a limit is wired to something');
t_contains($app, 'function rtLimitEdited',
    'rtLimitEdited() exists');
t_contains($app, "selectRtProfile('custom')",
    'editing a limit switches the profile to Custom automatically');

// Every preset must publish the numbers it stands for, or the cards and the
// fields can disagree about what is actually in force.
foreach (['light', 'balanced', 'thorough'] as $p) {
    t_contains($app, $p . ':', "the {$p} preset has values in the UI");
}

// ── Every handler in the markup resolves ─────────────────────────────────────
// Cheap, and it is the check that proves a button is at least connected.
$out = [];
$code = 0;
@exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($repo . '/scripts/check-ui-handlers.php') . ' 2>&1', $out, $code);
t_eq(0, $code, 'every onclick/onchange resolves to a defined function');
