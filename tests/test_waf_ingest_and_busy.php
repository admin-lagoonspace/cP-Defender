<?php
/**
 * WAF log ingestion, and the busy overlay.
 *
 * Reported together: no WAF events anywhere, which makes it impossible to
 * decide which ruleset to apply; and every button should block the UI while it
 * works, so the app cannot be clicked into a queue of overlapping requests.
 *
 * The WAF table was empty because nothing ever read a ModSecurity log.
 * ingestModSecLog() existed and was correct, but its only caller was an API
 * route nothing invoked -- no scheduled run, no call on page load. And the path
 * it read, /var/log/modsec_audit.log, is the Debian default; cPanel's
 * EasyApache 4 writes to /var/log/apache2. So even a manual call would have
 * found nothing on the server it shipped to.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$waf   = t_code($repo . '/backend/lib/WAF.php');
$sched = t_code($repo . '/backend/cron/scheduler.php');

// -- Something must actually run the ingester --------------------------------
t_contains($sched, "'wafingest' => [", 'reading the WAF log is a scheduled task');
t_contains($sched, 'ingestModSecLog()', 'which calls the ingester');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/WAF.php'",
    'and the scheduler requires WAF, or the task fatals in cron');

// -- The log has to be found where cPanel actually puts it -------------------
t_contains($waf, 'function auditLogPath', 'the audit log path is resolved, not assumed');
t_contains($waf, '/var/log/apache2/modsec_audit.log',
    'including the EasyApache 4 path, which is what cPanel uses');
t_contains($waf, '/usr/local/apache/logs/modsec_audit.log',
    'and the older cPanel location');
t_contains($waf, 'waf_audit_log_override',
    'with an override for a server that logs somewhere else again');

$cands = WAF::auditLogCandidates();
t_ok(is_array($cands) && count($cands) >= 4, 'several candidate paths are checked');
t_ok(in_array('/var/log/apache2/modsec_audit.log', $cands, true),
    'the cPanel path is among them');
// The Debian default must still be checked, just not exclusively.
t_ok(in_array(MODSEC_AUDIT, $cands, true), 'the configured path is still checked');

// -- Reading must be incremental ---------------------------------------------
// The old version opened the file and read from the top on every call. Run on
// a schedule that would re-parse the whole audit log every 15 minutes --
// gigabytes of I/O on a busy server, on a product that has just spent a week
// fixing I/O problems -- and would duplicate every row older than the 60
// second dedup window.
t_contains($waf, 'waf_ingest_offset', 'the read position is remembered');
t_contains($waf, 'fseek($handle, $offset)', 'and the file is resumed from it');
t_contains($waf, 'if ($size < $offset) { $offset = 0; }',
    'a rotated or replaced log restarts from the top');

$ing = substr($waf, strpos($waf, 'public function ingestModSecLog'), 4000);
t_contains($ing, 'ftell($handle)', 'the new position is recorded after reading');

// -- An empty table must explain itself --------------------------------------
// "No attacks" and "we never looked" render identically as a blank table.
t_contains($waf, 'function ingestStatus', 'the ingest state is reportable');
foreach (['log_found', 'log_path', 'last_run', 'total_events'] as $k) {
    t_contains($waf, "'" . $k . "'", "status reports $k");
}

$api = t_code($repo . '/backend/api/index.php');
t_contains($api, "'ingest-status'", 'and is exposed over the API');

$js   = file_get_contents($repo . '/frontend/js/app.js');
$html = file_get_contents($repo . '/frontend/index.html');
t_contains($js, 'function loadWafIngestState', 'the WAF page reads that state');
t_contains($js, 'No ModSecurity audit log found',
    'and says so rather than showing an unexplained empty table');
t_contains($html, 'id="waf-ingest-banner"', 'there is somewhere to say it');
t_contains($js, 'function wafIngestNow', 'and the log can be read on demand');

// -- The busy overlay --------------------------------------------------------
$api_js = file_get_contents($repo . '/frontend/js/api.js');

t_contains($html, 'id="sg-busy"', 'the overlay exists');
t_contains($html, 'aria-live', 'and announces itself to assistive technology');
t_contains($html, 'prefers-reduced-motion',
    'with the spin slowed for reduced-motion users');

t_contains($api_js, 'function busyStart', 'requests raise the busy state');
t_contains($api_js, 'function busyEnd', 'and lower it');
t_contains($api_js, '_busy = Math.max(0, _busy - 1)',
    'the counter cannot go negative and strand the overlay');

// Counted, not boolean: several requests can be in flight and the overlay must
// survive until the last finishes.
t_contains($api_js, '_busy++', 'concurrent requests are counted');
t_contains($api_js, 'if (_busy === 1)', 'only the first raises it');
t_contains($api_js, 'if (_busy === 0)', 'only the last lowers it');

// Delayed, so a fast request does not produce a flash that reads as a glitch.
t_contains($api_js, 'setTimeout(() => busyShow', 'showing it is delayed');

// finally, not after the return: an early return or a thrown fetch would
// otherwise leave the overlay stuck on, locking the user out of the error.
$reqFn = substr($api_js, strpos($api_js, 'async function req('), 3000);
t_contains($reqFn, '} finally {', 'the busy state is released in a finally block');
t_contains($reqFn, 'if (block) busyEnd();', 'releasing exactly what it raised');

// Mutations block; reads do not. The monitor page polls every 15 seconds, and
// an overlay flashing on each poll would be worse than no overlay at all.
t_contains($reqFn, "method !== 'GET'", 'only state-changing requests block the UI');
t_contains($api_js, 'withBusy', 'with an opt-in for slow reads');
