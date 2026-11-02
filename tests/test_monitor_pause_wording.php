<?php
/**
 * The monitor is paused and the service is running, and both cards say so.
 *
 * Reported from a live server, with a screenshot of one page showing both:
 *
 *     MONITOR STATUS            [ Paused — rsync ]
 *     SYSTEM SERVICE (SYSTEMD)  [ Active ]   PID 2463997   sub-state running
 *
 * Every word of that was true. They are answers to different questions --
 * systemd was asked whether the process is up, the daemon was asked whether it
 * is scanning -- and the page never said which was which, so side by side they
 * read as the product contradicting itself and were reported as a bug.
 *
 * The underlying behaviour is correct and must not change: during a backup the
 * daemon sets a flag on itself and keeps running. It does not exit, and it
 * must not. A process that exited would need restarting, would lose its
 * inotify watches, and would leave nothing running to notice the backup
 * finishing. That is precisely why systemd still reports it healthy.
 *
 * So this is about vocabulary, and about one renderer instead of three.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$js   = (string) file_get_contents($repo . '/frontend/js/app.js');
$html = (string) file_get_contents($repo . '/frontend/index.html');
$py   = (string) file_get_contents($repo . '/backend/daemon/monitor.py');

// ── The behaviour the wording describes is real ─────────────────────────────
//
// Asserted first, because if the daemon DID exit during a backup then the
// honest fix would be the opposite one: stop claiming the service is running.
t_contains($py, 'self.suspended = True',
     'THE PROCESS STAYS UP: suspending sets a flag on the running daemon');
t_contains($py, "db_set(conn, 'rt_suspended', '1')",
     'and records it for the interface to read');
$susp = t_fn_body($py, '_suspend', 'py');
t_ok(strpos($susp, 'sys.exit') === false && strpos($susp, 'os._exit') === false,
     'and does NOT exit — a process that exited would lose its inotify '
   . 'watches and leave nothing running to notice the backup finish');
t_contains($py, 'def _resume(self, conn, now, why):',
     'the same process resumes itself, which is only possible because it is '
   . 'still there');

// ── One function decides the scanning words ─────────────────────────────────
t_contains($js, 'function scanStateLabel(d) {',
     'THE TWO VOCABULARIES: the scanning state is rendered from one function');
t_contains($js, "return { text: '● Scanning', cls: 'badge-green' };",
     'which says "Scanning", not "Active" — "active" is the word that invites '
   . 'the service badge and this one to be compared as if they were the same '
   . 'claim');
t_contains($js, "text: '⏸ Scanning paused' + (d.suspend_reason ? ' — ' + d.suspend_reason : '')",
     'and "Scanning paused — rsync", which names what is paused');

// Both the dashboard card and the monitor page go through it. Two cards
// rendering one fact in two vocabularies is how this started.
t_ok(substr_count($js, 'scanStateLabel(') >= 3,
     'both the dashboard badge and the monitor page badge call it, rather '
   . 'than each spelling the states out again');
t_ok(strpos($js, "badge.textContent = 'Paused' + (d.suspend_reason") === false,
     'the dashboard card no longer has its own copy saying just "Paused"');
t_ok(!preg_match("/textContent = active \\? '● Active'/", $js),
     'and the service card no longer says a bare "Active"');

// ── The service badge is rendered where BOTH answers are known ──────────────
t_contains($js, 'function renderServiceBadge() {',
     'the service badge has one renderer');
t_contains($js, 'const mon       = State.lastMonitor;',
     'THE MISSING HALF: it reads the daemon\'s state as well as systemd\'s. '
   . 'Rendering from systemd alone is what produced a bare "Active" next to '
   . '"Paused"');
t_contains($js, "badge.textContent = '● Running · scanning paused';",
     'and says both things at once when both are true');
t_contains($js, "badge.className   = 'badge badge-green';
      badge.textContent = '● Running · scanning paused';",
     'STILL GREEN: the service is healthy, and that is the point being made. '
   . 'Amber would claim the process has a problem it does not have');

// Only when the daemon is both running AND suspended. A stopped daemon under a
// still-active unit must not be described as "scanning paused" -- that would
// claim a deliberate pause where there is a failure.
t_contains($js, 'const suspended = active && !!(mon && mon.running && mon.suspended);',
     'and only when the daemon is running and suspended, so a dead daemon '
   . 'under a live unit is not dressed up as a deliberate pause');

// ── Order must not matter ───────────────────────────────────────────────────
//
// On the monitor page loadMonitor() and loadServiceStatus() are started
// together by PAGE_LOADERS and either can land first.
t_contains($js, '  // Either loader may land first on this page; re-render from what is known.
  renderServiceBadge();',
     'THE RACE: loadMonitor() re-renders the service badge, so whichever of '
   . 'the two parallel loaders finishes last, the pair ends up consistent');
t_contains($js, 'State.lastService = d;',
     'and the service data is kept for the other direction');

// loadMonitor() never stored this. loadMonitorStats() did -- and that one does
// not run on the monitor page, which is the page the screenshot came from.
t_contains($js, '  monitorRunning = d.running;
  // Needed by renderServiceBadge() and by the dashboard alerts, and this
  // loader did not set it',
     'THE PAGE WITH NO DATA: loadMonitor() records the monitor state. Only '
   . 'loadMonitorStats() used to, and that does not run on the monitor page — '
   . 'so on the one page showing both cards, the service card had no way to '
   . 'know scanning was paused');

// ── The card explains itself ────────────────────────────────────────────────
t_contains($html, 'id="svc-pause-note"',
     'there is somewhere to say why one card says Running and the other says '
   . 'Paused');
t_contains($js, '<strong>The service is running.</strong> ',
     'and it leads with the answer to the question actually asked');
t_contains($js, 'It stays up during a backup on purpose',
     'saying the behaviour is deliberate');
t_contains($js, 'would lose its watches and leave nothing to notice when the ',
     'and why — stopping the process would be worse, which is the part that '
   . 'makes it believable rather than an excuse');
t_contains($js, 'Scanning resumes on its own.',
     'and that no action is needed');

// ── The dashboard alert uses the same words ─────────────────────────────────
t_contains($js, "push('amber', 'Real-time scanning is paused while '",
     'the dashboard alert names scanning, not monitoring');
t_contains($js, "+ ' runs — the service is still running', 'monitor');",
     'and says the service is up, so the alert does not read as an outage '
   . 'beside a Services panel reporting the unit healthy');
t_contains($js, "(State.lastMonitor.suspend_reason || 'a backup')",
     'naming what is holding it, as the badges do');
