<?php
/**
 * Three faults reported from one dashboard session.
 *
 *   1. The auto-quarantine toggle "is not working, because i cannot see that
 *      setting implemented on malware scanner dashboard".
 *   2. The dashboard's real-time monitor widget "does not give proper
 *      information if that service is turned on and if on i cannot turn it off".
 *   3. "firewall dashboard loading is still the worst and freezes entire screen".
 *
 * The first two share a shape: a control rendered from markup that nothing ever
 * corrected, so the page asserted a state it had not read.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

function dw_js(string $path): string
{
    $src = file_get_contents($path);
    $bs  = chr(92); $nl = chr(10);
    $out = ''; $n = strlen($src);
    for ($i = 0; $i < $n; $i++) {
        $c = $src[$i];
        if ($c === '"' || $c === "'" || $c === chr(96)) {
            $q = $c; $out .= $c;
            for ($i++; $i < $n; $i++) {
                $out .= $src[$i];
                if ($src[$i] === $bs) { $i++; if ($i < $n) { $out .= $src[$i]; } continue; }
                if ($src[$i] === $q) { break; }
            }
            continue;
        }
        if ($c === '/' && $i + 1 < $n && $src[$i + 1] === '/') {
            while ($i < $n && $src[$i] !== $nl) { $i++; }
            $out .= $nl; continue;
        }
        if ($c === '/' && $i + 1 < $n && $src[$i + 1] === '*') {
            $e = strpos($src, '*/', $i + 2); $i = $e === false ? $n : $e + 1; continue;
        }
        $out .= $c;
    }
    return $out;
}

$js   = dw_js($repo . '/frontend/js/app.js');
$html = file_get_contents($repo . '/frontend/index.html');
$fw   = t_code($repo . '/backend/lib/Firewall.php');

// ── 1. The scanner page must read the auto-quarantine setting ───────────────
// The state line was hard-coded in the markup and only ever corrected by
// loadSettings(), which runs on the Settings page. Opening the Scanner page
// directly showed the default regardless of the real value.
t_contains($js, 'function loadScannerQuarantineState',
    'the scanner page reads the auto-quarantine setting');
$lt = substr($js, strpos($js, 'async function loadThreats'), 400);
t_contains($lt, 'loadScannerQuarantineState()',
    'and does so whenever the scanner page loads');
t_contains($js, 'auto-quarantine state unknown',
    'a failed read says so rather than asserting "off"');

// The setting has to be honoured somewhere, or the toggle really is decorative.
$sc = t_code($repo . '/backend/lib/Scanner.php');
t_ok(substr_count($sc, "Database::setting('auto_quarantine')") >= 1,
    'the scanner consults auto_quarantine when acting on a threat');

// ── 2. The dashboard monitor widget ─────────────────────────────────────────
// It was populated ONLY by toggleMonitor(), so on a fresh dashboard it kept
// the markup's values and monitorRunning stayed false -- meaning the button,
// which reads "Stop" in the HTML, called START on the first click.
$rd = substr($js, strpos($js, 'async function refreshDashboard'), 600);
t_contains($rd, 'loadMonitorStats()',
    'the dashboard loads the monitor status when it refreshes');

// The markup must not assert a state it has not read.
t_ok(strpos($html, 'id="rt-status-badge" style="margin-left:8px">Active<') === false,
    'the widget no longer ships claiming the monitor is Active');
t_contains($html, 'id="rt-toggle-btn"', 'the toggle button exists');
$btn = substr($html, strpos($html, 'id="rt-toggle-btn"'), 200);
t_contains($btn, 'disabled', 'and starts disabled until the status is known');
t_ok(strpos($btn, '>Stop<') === false,
    'it does not ship labelled Stop before anything has been read');

// Acting on an unknown state is what produced "I cannot turn it off".
t_contains($js, "dataset.ready !== '1'",
    'toggleMonitor refuses to act before the first status load');

// ── 3. The monitor page badge must not claim protection it is not giving ────
$lm = substr($js, strpos($js, 'async function loadMonitor()'), 1200);
t_contains($lm, 'd.suspended', 'the monitor page reports a paused monitor');
t_contains($lm, 'd.stale', 'and one that is running but doing nothing');
$stopPos = strpos($lm, "'○ Stopped'");
$greenPos = strpos($lm, "'● Running'");
t_ok($stopPos !== false && $greenPos !== false && $stopPos < $greenPos,
    'the plain green Running is the last branch, not the first');

// ── 4. Firewall: nothing on this path may hang the request ──────────────────
// iptables -L takes the xtables lock. On a CSF box lfd rewrites rules
// constantly, so that call can wait on a lock somebody else holds -- and
// cpsrvd serialises requests, so one stuck call stops the whole dashboard.
t_contains($fw, 'function shBounded', 'shell commands on this path are bounded');
t_contains($fw, 'timeout ', 'with timeout(1), in case the binary ignores -w');
t_contains($fw, '-w 2', 'and iptables is given a bounded wait for the lock');
t_contains($fw, 'timed_out', 'a command that did not finish is distinguishable');

// Reporting 0 rules after a timeout would read as "no firewall".
t_contains($fw, 'iptables_unknown', 'an unavailable count is flagged, not reported as zero');
t_contains($js, 'iptables status unavailable',
    'and the UI says so rather than printing "iptables active" regardless');

// The probes are cached: the page asks on every visit and every refresh.
t_contains($fw, 'function cached', 'expensive probes are cached');
t_contains($fw, "self::cached('iptables_rules'", 'the iptables count is cached');
t_contains($fw, "self::cached('csf_status'", 'and the CSF status');

// The cheap database counts must not sit behind the shell commands.
$gs = substr($fw, strpos($fw, 'public function getStats'), 1400);
$dbPos  = strpos($gs, 'SELECT COUNT(*) as c FROM blocked_ips');
$shPos  = strpos($gs, 'self::cached');
t_ok($dbPos !== false && $shPos !== false && $dbPos < $shPos,
    'the counts the page leads with are read before anything forks a process');

// And one slow call must not hold the other two panels back.
$lf = substr($js, strpos($js, 'async function loadFirewall'), 900);
t_contains($lf, '.catch(() => null)',
    'a failing firewall call cannot reject the whole page load');
