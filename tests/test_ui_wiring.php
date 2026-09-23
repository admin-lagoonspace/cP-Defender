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

// ── The monitor section saves itself ─────────────────────────────────────────
// Asked for more than once. The limits were previously committed only by the
// page-level "Save Changes" at the top of Settings, so editing a value here
// meant leaving the section to commit it, with no confirmation that these
// particular values had landed.
$html = file_get_contents($repo . '/frontend/index.html');
t_contains($html, 'id="rt-save-btn"', 'the monitor section has its own save button');
t_contains($html, 'saveMonitorSettings()', 'the button is wired to a handler');
t_contains($html, 'id="rt-save-status"', 'there is somewhere to report the outcome');

$app = file_get_contents($repo . '/frontend/js/app.js');
t_contains($app, 'function saveMonitorSettings', 'saveMonitorSettings() exists');

// It must send every limit, or a field silently does nothing.
foreach (['rt_profile', 'rt_max_files_per_sec', 'rt_max_file_size_mb', 'rt_nice',
          'rt_max_watches', 'rt_debounce_seconds', 'rt_exclude_dirs',
          'cpu_limit_percent', 'rt_poll_interval'] as $key) {
    t_contains($app, $key . ':', "saveMonitorSettings() sends {$key}");
}

// Failure must be visible in the section, not just swallowed.
t_contains($app, "'Not saved — '", 'a failed save is reported in place');

// The confirmation must reflect what the server stored: values out of range are
// clamped, so echoing the typed number back would be a small lie.
t_contains($app, 'API.getSettings()', 'the saved values are read back from the server');

// ── A clean server must not look like a stuck panel ──────────────────────────
// Reported: "Threat Breakdown — Loading..." forever, on a server that had just
// scanned 600 files and found nothing. Every chart did `return` on empty data,
// which leaves the static "Loading…" placeholder in place. The GOOD outcome --
// no threats -- rendered as a broken panel.
$charts = file_get_contents($repo . '/frontend/js/charts.js');
t_contains($charts, 'empty(container, message)', 'charts have a shared empty state');
t_contains($charts, "'No threats detected.'", 'an empty breakdown says so');
t_ok(strpos($charts, 'if (!container || !data?.length) return;') === false,
    'threatBars no longer bails silently on empty data');
t_ok(strpos($charts, 'if (!svgEl || !data?.length) return;') === false,
    'the SVG charts no longer bail silently on empty data');

// ── Start/stop must be responsive and confirmed ──────────────────────────────
// Reported as "laggy and isn't guaranteed that it will work". systemctl takes
// seconds and the daemon needs longer still to write its PID file, so the
// button returned immediately, a second click could race the first, and the
// state it flipped to was assumed rather than observed.
$app = file_get_contents($repo . '/frontend/js/app.js');
t_contains($app, '_monitorBusy', 'a second click cannot race the first');
t_contains($app, "'Starting…'", 'the button reports that it is working');
t_contains($app, 'API.monitorStatus()', 'the result is confirmed against the server');
t_ok(strpos($app, 'monitorRunning = !monitorRunning;') === false,
    'the state is no longer flipped optimistically');
t_contains($app, 'is not running yet',
    'an accepted command that did not take effect is reported honestly');

// The button must be re-enabled on every path, or one failure disables it for
// the rest of the session.
t_contains($app, 'const restore =', 'there is a single restore path for the buttons');

// ── Refresh must be observable ───────────────────────────────────────────────
// Reported twice as "refresh does not work". Both times the handler resolved
// and really did refetch -- which is why the handler check passed and I said it
// was fixed. Nothing on screen changed: on an idle server the numbers are
// identical, so a working refresh and a dead button are indistinguishable.
$html = file_get_contents($repo . '/frontend/index.html');
$app  = file_get_contents($repo . '/frontend/js/app.js');

t_contains($app, 'async function doRefresh', 'there is a refresh wrapper that gives feedback');
t_contains($app, 'Refreshing', 'the button says it is working');
t_contains($app, 'refresh-stamp', 'a timestamp records when data last arrived');

// Every Refresh button must go through it, or some stay silent.
$bare = preg_match_all('/onclick="(refreshDashboard|loadWafEngine|loadTopAttackers'
      . '|loadStorageStats|loadMonitor|loadBotShield|loadCMSGuard|loadRootkit'
      . '|loadIntegrity|loadPHPHardening)\(\)"/', $html);
t_eq(0, $bare, 'no Refresh button still calls its loader directly');
t_ok(substr_count($html, 'doRefresh(this,') >= 10,
    'all ten Refresh buttons report progress (' . substr_count($html, 'doRefresh(this,') . ')');

// ── The threats table must escape what it renders ────────────────────────────
// A file path is attacker-controlled: naming a file is exactly what malware
// does. Interpolating it raw into innerHTML made the threats table an XSS sink
// in the dashboard of a security product.
t_ok(strpos($app, 'title="${t.file_path}"') === false,
    'the file path is no longer interpolated raw into the row');
t_contains($app, 'esc(path)',        'the full path is escaped');
t_contains($app, 'esc(t.threat_name', 'the threat name is escaped');
t_contains($app, 'esc(status', 'the status badge escapes an unknown status');

// ── Select-all and bulk actions ──────────────────────────────────────────────
t_contains($html, 'id="threat-check-all"', 'the table has a select-all checkbox');
t_contains($html, 'toggleAllThreats(this)', 'select-all is wired');
t_contains($app,  'function toggleAllThreats', 'toggleAllThreats() exists');
t_contains($app,  'function selectedThreatIds', 'the selection can be read');
t_contains($app,  'indeterminate', 'a partial selection is shown as partial, not as all');

t_contains($html, 'id="threat-bulk-bar"', 'there is a bulk action bar');
t_contains($html, "bulkThreatAction('quarantine')", 'bulk quarantine is offered');
t_contains($html, "bulkThreatAction('delete')", 'bulk delete is offered');
t_contains($app,  'async function bulkThreatAction', 'bulkThreatAction() exists');
t_contains($app,  'cannot be undone', 'bulk delete warns that it is irreversible');
t_contains($app,  'confirm(', 'a destructive bulk action is confirmed first');

// Per-file reasons, not one pass/fail for the batch.
t_contains($app, 'res.results', 'the bulk result is read per file');
t_contains($app, 'succeeded, ', 'a partial failure reports both counts');

// ── The safe viewer ──────────────────────────────────────────────────────────
t_contains($html, 'id="file-view-overlay"', 'there is a file viewer dialog');
t_contains($html, 'never executed', 'the dialog states that the file is not run');
t_contains($app,  'async function viewThreatFile', 'viewThreatFile() exists');
t_contains($app,  'viewThreatFile(${id})', 'every row offers a View button');

// The single most important property: hostile content is inserted as TEXT.
t_contains($app, 'body.textContent = res.binary', 'file content is set with textContent');
$viewStart = strpos($app, 'async function viewThreatFile');
$viewBody  = substr($app, $viewStart, 2400);
t_ok(strpos($viewBody, 'innerHTML') === false,
    'the viewer never assigns file content to innerHTML');

$api = file_get_contents($repo . '/frontend/js/api.js');
t_contains($api, 'viewThreat:',  'the API client can fetch a file');
t_contains($api, 'bulkThreats:', 'the API client can submit a bulk action');

// ── The bulk bar must be on the page it was asked for ────────────────────────
// It was inserted into the DASHBOARD's events table, because the patch anchored
// on the first <thead> in the file. It was also a <div> placed directly inside
// <table>, which browsers hoist out or discard. So the buttons existed in the
// source and were absent from the malware scanner page.
//
// The old assertion was t_contains($html, 'id="threat-bulk-bar"') -- true of a
// bar sitting in the wrong table, in invalid markup. Existing somewhere is not
// the property that matters.
// Strip HTML comments first. The comment explaining this very fix contains the
// text "<div> directly inside <table>", and the first version of this check
// found that literal and reported the bar as nested. Assertions about markup
// must not read prose about markup -- the same trap as t_code() and js_code().
$markup    = preg_replace('/<!--.*?-->/s', '', $html);

$barPos    = strpos($markup, 'id="threat-bulk-bar"');
$tablePos  = strpos($markup, 'id="threats-body"');
$eventsPos = strpos($markup, 'id="dash-events-table"');

t_ok($barPos !== false, 'the bulk bar exists');
t_ok($barPos < $tablePos, 'it sits above the threats table');

// Between the bar and the threats tbody there must be exactly one <table> open:
// the threats table itself. More than that means it landed in another table.
$between = substr($markup, $barPos, $tablePos - $barPos);
t_eq(1, substr_count($between, '<table'),
    'exactly one table opens between the bar and the threats rows');

// And it must not be inside a table element at all. Walk backwards: the nearest
// table tag before the bar has to be a closing one (or none at all).
$beforeBar   = substr($markup, 0, $barPos);
$lastOpen    = strrpos($beforeBar, '<table');
$lastClose   = strrpos($beforeBar, '</table>');
t_ok($lastOpen === false || ($lastClose !== false && $lastClose > $lastOpen),
    'the bar is not nested inside a <table> element');

// It must be nowhere near the dashboard events table.
if ($eventsPos !== false) {
    t_ok($barPos > $eventsPos ? substr_count(substr($markup, $eventsPos, $barPos - $eventsPos), '</table>') > 0 : true,
        'the bar is not inside the dashboard events table');
}

// ── The buttons must be visible, not hidden until a selection exists ─────────
// Hiding the whole bar made the feature undiscoverable: someone looking for a
// way to delete several files sees nothing and concludes it was never built.
t_ok(strpos($html, 'id="threat-bulk-bar" class="hidden"') === false,
    'the bar is not hidden by default');
t_contains($html, 'id="threat-bulk-delete"',   'the delete-selected button has an id');
t_contains($html, 'id="threat-bulk-quarantine"', 'the quarantine-selected button has an id');
t_contains($html, 'Delete selected',  'the delete button is labelled plainly');
t_contains($html, 'Quarantine selected', 'the quarantine button is labelled plainly');

// Disabled until something is ticked, then enabled -- rather than appearing.
$barBlock = substr($markup, $barPos, 1200);
t_contains($barBlock, 'disabled', 'the buttons start disabled');
t_contains($app, "b.disabled = ids.length === 0",
    'the buttons enable when a selection exists');
t_ok(strpos($app, "bar.classList.toggle('hidden', ids.length === 0)") === false,
    'the bar no longer disappears when nothing is selected');

// ── The header colspan must match the real column count ──────────────────────
// Two columns were added (checkbox, View) and the empty-state row still spanned
// eight, so "no threats" rendered short of the table width.
// The LAST thead before the threats tbody is the threats table's own; scanning
// a fixed window found a different table's header and counted twelve.
$headStart = strrpos(substr($markup, 0, $tablePos), '<thead>');
$headEnd   = strpos($markup, '</thead>', $headStart);
// '<th' also matches '<thead', which inflated the count by one and made the
// assertion pass while reporting a number nobody could check against the
// colspan below.
$cols      = preg_match_all('/<th[\s>]/', substr($markup, $headStart, $headEnd - $headStart));
t_eq(10, $cols, 'the threats table has exactly 10 columns');

// The empty-state row must span all of them, or "no threats" renders short.
preg_match('/colspan="(\d+)"[^>]*>No threats detected/', $markup, $span);
t_eq((string)$cols, $span[1] ?? '', 'the empty-state row spans every column');
t_ok(strpos($html, 'colspan="8" style="text-align:center;color:var(--txt3);padding:28px">No threats detected') === false,
    'the empty-state row no longer spans the old column count');
