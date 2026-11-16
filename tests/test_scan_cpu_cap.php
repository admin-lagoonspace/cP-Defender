<?php
/**
 * cpu_limit_percent has to be a CEILING, not a priority.
 *
 * Reported: ServerScrub is using more of the server than it needs. The
 * evidence from the production box:
 *
 *   PID 781423 root 39 19 1136888 983912 R 97.0 1.6 0:13.26 clamscan
 *
 * nice 19 -- the floor -- holding 97% of a core, with 44.8% of the machine
 * idle and scan_max_concurrent already 1. Both levers the product had were at
 * their stops. That is not a misconfiguration; it is what nice does. nice
 * decides who yields when processes COMPETE and caps nothing, so a scan on an
 * otherwise idle core correctly takes all of it.
 *
 * So cpu_limit_percent promised a limit it could not deliver. These tests
 * cover the mechanism that makes it one (a cgroup CPU quota via systemd-run),
 * and -- just as important -- that the panel never claims a ceiling on a host
 * where the kernel refused to provide one.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$scanner = t_code($repo . '/backend/lib/Scanner.php');
$js      = t_js($repo . '/frontend/js/app.js');
$html    = file_get_contents($repo . '/frontend/index.html');

// ── The cap is applied to the command that actually costs ──────────────────
//
// A prefix that exists but is not on the clamscan line is the bug this
// replaces: Scanner::nicePrefix() has been defined, and called from nowhere,
// the whole time.
preg_match('/private function scanBatch\(.*?^    }/ms', $scanner, $m);
$batch = $m[0] ?? '';
t_ok($batch !== '', 'scanBatch() is still where the clamscan command is built');
t_contains($batch, 'self::cpuCapPrefix()',
     'THE CAP REACHES THE COMMAND: scanBatch() prefixes the clamscan it runs '
   . '— a helper that is never called is exactly the defect being fixed here '
   . '(nicePrefix() has been dead code all along)');

// Order matters: timeout must be INSIDE the capped scope, or the 124 handling
// below it stops seeing clamscan's exit status.
t_ok(strpos($batch, '%stimeout %d nice -n%d ionice -c3') !== false,
     'and the quota wraps timeout, so timeout still owns clamscan and the '
   . '"batch abandoned" path keeps working');
t_contains($batch, 'nice -n%d ionice -c3',
     'nice and ionice are KEPT: the quota is the ceiling, nice is what makes '
   . 'a scan yield when the machine is genuinely contended, and dropping '
   . 'either answers only half the problem');

// ── A failed cap must not take the scan with it ────────────────────────────
preg_match('/public static function cpuCapPrefix\(\).*?^    }/ms', $scanner, $m2);
$prefix = $m2[0] ?? '';
t_ok($prefix !== '', 'cpuCapPrefix() exists');
t_contains($prefix, "return '';",
     'NO CAP IS A VALID ANSWER: it returns an empty prefix rather than a '
   . 'broken command — slower scans are a tradeoff, no scans is a regression');

preg_match('/private static function probeCpuCap\(\).*?^    }/ms', $scanner, $m3);
$probe = $m3[0] ?? '';
t_ok($probe !== '', 'probeCpuCap() exists');
t_contains($probe, '/bin/true',
     'PROVEN, NOT ASSUMED: the mechanism is tested by running something '
   . 'trivial under it. systemd-run exists on every systemd host and still '
   . 'fails without root or with a cgroup hierarchy that refuses CPUQuota, '
   . 'and a prefix that fails is a scan that does not run');
t_contains($probe, 'posix_geteuid',
     'and a non-root process does not even try — it cannot create a scope');
t_contains($probe, 'cpulimit',
     'with cpulimit as the fallback where systemd will not do it');
t_contains($prefix, "Database::setting('scan_cpu_cap_probe'",
     'the probe result is cached, so a scan does not re-run it per batch');

// ── 100% is not a cap worth paying for ────────────────────────────────────
t_contains($prefix, '$pct >= 100',
     'a 100% ceiling writes no scope: a full core is what an unrestricted '
   . 'scan already takes, so that would be cost with no effect');

// ── The quota keeps the yielding as well as adding the ceiling ────────────
t_contains($prefix, 'CPUQuota=%d%%',
     'the scope sets CPUQuota, which is the only thing the kernel enforces '
   . 'regardless of whether the box is busy');
t_contains($prefix, 'CPUWeight=10',
     'and CPUWeight, so a capped scan still loses to real work — the quota '
   . 'alone would let it hold its full share against a busy server');
t_contains($prefix, 'IOWeight=10',
     'and IOWeight, since a malware scan is as much disk as CPU');

// ── It can be switched off, and off must be honest ────────────────────────
t_contains($prefix, "Database::setting('scan_cpu_hard_cap', '1')",
     'the cap is a setting, defaulting ON — cpu_limit_percent already claimed '
   . 'to be a limit, so honouring it is the less surprising default');
t_contains($prefix, "Database::setSetting('scan_cpu_cap_mode', 'off')",
     'and switching it off records that, rather than leaving the panel '
   . 'reporting a stale mode');

$db = t_code($repo . '/backend/lib/Database.php');
t_contains($db, "('scan_cpu_hard_cap',       '1')",
     'the default is seeded, so an install does not depend on the setting '
   . 'being written before the first scan');
t_contains($db, "('scan_cpu_cap_mode',       'nice')",
     'and the reported mode starts as the truth — nice — not as a quota that '
   . 'has never been probed');

// ── THE HONESTY REQUIREMENT ───────────────────────────────────────────────
//
// This is the part that matters most. On a host where the quota is refused,
// the percentage is a priority and nothing more. A panel that renders "50%"
// without saying so is making a promise the kernel never agreed to, which is
// the same class of defect as a green badge over a daemon scanning nothing.
$rtm = t_code($repo . '/backend/lib/RealTimeMonitor.php');
t_contains($rtm, "'cpu_cap_mode'",
     'the status payload carries which mechanism is in force');
t_contains($rtm, "'cpu_cap_enabled'",
     'and whether the operator asked for one at all');

preg_match('/function renderCpuCapMode\(d\).*?^}/ms', $js, $m4);
$render = $m4[0] ?? '';
t_ok($render !== '', 'renderCpuCapMode() exists');
t_contains($render, 'NOT a ceiling on this host',
     'NO FALSE CEILING: when only nice is in force the card says so in those '
   . 'words, instead of showing a percentage that caps nothing');
t_contains($render, 'cgroup CPU quota at ',
     'and names the real mechanism when there is one');
t_contains($render, "mode === 'cpulimit'",
     'and distinguishes cpulimit, which is a ceiling but a userspace one');
t_contains($render, 'var(--amber)',
     'and the unenforced case is coloured as a caveat rather than reading as '
   . 'a healthy green');
t_contains($js, 'renderCpuCapMode(d);',
     'and the renderer is actually called from the monitor loader');

// The toggle must not be wired to the profile editor.
t_contains($html, 'id="mon-res-hardcap" onchange="monResCapToggled()"',
     'NOT A PROFILE LIMIT: the cap toggle has its own handler. Wiring it to '
   . 'monResEdited() would flip the resource profile to Custom as a side '
   . 'effect of ticking an unrelated box, discarding the preset the operator '
   . 'chose');
preg_match('/function monResCapToggled\(\).*?^}/ms', $js, $m5);
t_ok(strpos($m5[0] ?? '', 'selectMonResProfile') === false,
     'and that handler does not touch the profile at all');

// The saver has to send both the percentage and whether it is enforced.
preg_match('/async function saveMonitorResources\(\).*?^}/ms', $js, $m6);
$saver = $m6[0] ?? '';
t_contains($saver, 'scan_cpu_hard_cap:',
     'saving sends the enforcement flag, not just the percentage');
t_contains($saver, "scan_cpu_cap_probe:   ''",
     'and clears the cached probe, so turning the cap on re-tests the host '
   . 'rather than being answered from a "none" cached before systemd or '
   . 'cpulimit was available');

// ── nice is still mapped the way it always was ────────────────────────────
//
// The cap is an addition. Changing the nice mapping at the same time would
// alter behaviour on every host where the quota is refused, which is the one
// population that cannot afford a surprise.
t_contains($scanner, 'return (int) round(19 * (1.0 - $pct / 100.0));',
     'the existing CPU-percent-to-nice mapping is untouched, so hosts that '
   . 'cannot take a quota behave exactly as they did before');
