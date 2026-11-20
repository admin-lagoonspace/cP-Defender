<?php
/**
 * Fixing the code path does nothing for the infection already on the server.
 *
 * Reported, after the containment fix shipped: "One infection which was found
 * is still active and not being quarantines. this fix should be retroactive
 * for all active infections".
 *
 * That is fair. Real-time detection used to record a threat and then, behind
 * a bare auto_quarantine flag, either move the file with no notion of
 * severity or do nothing whatsoever. Every finding it declined is still on
 * disk, still executable, still listed as Active. Changing what happens to
 * the NEXT detection leaves all of those exactly where they were -- and they
 * are the ones an operator is looking at.
 *
 * `serverscrub contain-active` walks them and applies the policy. It does not
 * reimplement it: every row goes through Scanner::applyThreatPolicy, the same
 * call a scan and the monitor make, so the mass-detection bound, report-only
 * feeds, the auto-quarantine switch and the severity mapping all apply
 * exactly as they would to a fresh finding.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$cli = t_code($repo . '/backend/cli/serverscrub.php');
$ins = file_get_contents($repo . '/install.sh');

// ── The command exists and targets exactly the stuck rows ─────────────────
t_contains($cli, "case 'contain-active': {",
     'the sweep is a first-class CLI command, so it can be re-run by hand');
t_contains($cli, "WHERE status = 'active'",
     'THE STUCK ROWS ARE THE TARGET: findings the old gate declined are the '
   . 'ones still running on the server');

// ── It calls the one policy, rather than deciding anything ────────────────
t_contains($cli, '$sc->applyThreatPolicy($path, $id,',
     'ONE POLICY: the sweep calls the same function a scan and the real-time '
   . 'monitor call, so the bound, the feeds and the severity mapping apply '
   . 'identically — a second implementation here would be a third copy');

// ── Critical first ────────────────────────────────────────────────────────
t_contains($cli, "WHEN 'critical' THEN 0 WHEN 'high' THEN 1",
     'CRITICAL FIRST: if a bound trips or the run is cut short, the most '
   . 'dangerous files have already been dealt with');

// ── A dry run must not touch anything ─────────────────────────────────────
preg_match('/case \'contain-active\': \{.*?\n    \}/s', $cli, $m);
$fn = $m[0] ?? '';
t_ok($fn !== '', 'the command body is readable');
t_contains($fn, "\$dry   = in_array('--dry-run', \$rest, true);",
     'there is a dry run');
$posDry   = strpos($fn, 'if ($dry) {');
$posApply = strpos($fn, '$r      = $sc->applyThreatPolicy(');
t_ok($posDry !== false && $posApply !== false && $posDry < $posApply,
     'A DRY RUN RETURNS BEFORE ACTING: the check sits ahead of the policy '
   . 'call, so --dry-run cannot delete anything — this command deletes '
   . 'criticals, so "show me first" has to be real');

// ── A file that is already gone is reported, not invented ─────────────────
t_contains($fn, "if (\$path === '' || !file_exists(\$path)) {",
     'a row whose file has gone is detected');
t_contains($fn, 'FILE GONE',
     'NOTHING IS CLAIMED THAT DID NOT HAPPEN: a missing file is reported as '
   . 'missing rather than flipped to "deleted", which would credit this run '
   . 'with removing something it never touched');

// ── Bounded ───────────────────────────────────────────────────────────────
t_contains($fn, '$limit = 500;',
     'the sweep is bounded by default — a server mid-incident can hold a '
   . 'great many of these');
t_contains($fn, "if (\$a === '--limit' && isset(\$rest[\$i + 1]))",
     'and the bound can be raised deliberately');

// ── A machine-readable last line ──────────────────────────────────────────
t_contains($fn, "echo json_encode(['scanned' => count(\$rows), 'acted' => \$acted,",
     'the last line is JSON, so the installer and the API can report a '
   . 'number without parsing the human output above it');

// ── It runs on upgrade, from the NEW copy ─────────────────────────────────
//
// This is the whole reason it is in install.sh. An update runs the INSTALLED
// (old) update.sh, so a step added there first runs one release after it is
// written -- which is exactly how a fix can ship and do nothing.
t_contains($ins, 'contain-active --limit 500',
     'THE SWEEP RUNS ON UPGRADE: the operator should not have to know this '
   . 'command exists to get the infection on their server contained');
t_contains($ins, "SELECT COUNT(*) FROM threats WHERE status='active';",
     'and only when there is something to do, so a clean server pays nothing');
t_contains($ins, 'timeout 900 php',
     'BOUNDED IN TIME TOO: an update must not hang because containment had '
   . 'more work than one run allows — the lesson from the permissions step');
t_contains($ins, 'warn "  Containment sweep did not finish — run by hand:"',
     'and an unfinished sweep names the command to finish it');

// The sweep must sit INSIDE the register-only path, not behind a
// `if ! $REGISTER_ONLY` gate -- the mistake that stops install.sh restarting
// the monitor on an upgrade.
$posGate  = strpos($ins, 'if ! $REGISTER_ONLY; then');
$posSweep = strpos($ins, 'contain-active --limit 500');
t_ok($posSweep !== false && $posGate !== false && $posSweep < $posGate,
     'AND IT IS NOT BEHIND THE INSTALL-ONLY GATE: the installs that need '
   . 'this sweep are precisely the ones being upgraded');
