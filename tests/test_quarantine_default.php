<?php
/**
 * Auto-quarantine ships OFF.
 *
 * Quarantine MOVES a detected file into /usr/local/sentinel-gate/quarantine,
 * which lives on the root partition. On a hosting box whose customer data sits
 * on a separate volume, an enthusiastic scan can fill / -- and a security tool
 * that takes the server down has done more harm than the malware it moved.
 *
 * Detection is unaffected: the threat is recorded either way. Acting on it is
 * something the operator opts into.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── A fresh install has it off ───────────────────────────────────────────────
// The sandbox database was created by migrate() in this run, so this is the
// real seeded value rather than an assertion about the source.
t_eq('0', Database::setting('auto_quarantine'),
    'a fresh install seeds auto_quarantine off');

// ── Existing installs are NOT flipped ────────────────────────────────────────
// The seed is INSERT OR IGNORE, so an operator who deliberately turned it on
// keeps it. Silently disabling a protective action during an update would be a
// change nobody asked for and nobody would see.
$src = t_code($repo . '/backend/lib/Database.php');
t_contains($src, 'INSERT OR IGNORE INTO settings',
    'settings are seeded, not overwritten, on upgrade');

// migrate() is private, so the guarantee is asserted from the SQL it runs:
// INSERT OR IGNORE cannot overwrite a row that already exists. An operator who
// turned quarantine on keeps it through every future upgrade.
t_ok(strpos($src, "INSERT INTO settings (key, value) VALUES
") === false,
    'the seed is never a plain INSERT that could overwrite');

Database::setSetting('auto_quarantine', '1');
t_eq('1', Database::setting('auto_quarantine'), 'the setting can be turned on');
Database::setSetting('auto_quarantine', '0');
t_eq('0', Database::setting('auto_quarantine'), 'and back off again');

// ── The readers agree on what "on" means ─────────────────────────────────────
// Every consumer compares against the string '1', so any other value is off.
// A mismatch here would mean quarantine ran when the UI said it would not.
$scanner = t_code($repo . '/backend/lib/Scanner.php');
t_eq(3, substr_count($scanner, "Database::setting('auto_quarantine') === '1'"),
    'the scanner gates all three quarantine sites on the same test');

$daemon = file_get_contents($repo . '/backend/daemon/monitor.py');
t_contains($daemon, "db_get(conn,'auto_quarantine') == '1'",
    'the real-time monitor uses the same test');

// ── The UI must not claim otherwise ──────────────────────────────────────────
$html = file_get_contents($repo . '/frontend/index.html');
t_ok(strpos($html, 'auto-quarantine enabled</div>') === false,
    'the scanner page no longer states "enabled" as static text');
t_contains($html, 'id="scanner-quar-state"',
    'the scanner page reports the live setting');
// Collapse whitespace first: the sentence is wrapped across source lines, and
// an assertion that only passes while the markup stays on one line would push
// formatting decisions around to suit the test.
$flat = preg_replace('/\s+/', ' ', $html);
t_contains($flat, 'on the root partition',
    'the toggle explains what enabling it costs');
t_contains($flat, 'recorded either way',
    'the toggle says detection still happens with it off');

$app = file_get_contents($repo . '/frontend/js/app.js');
t_contains($app, "auto_quarantine: '0'",
    'the client-side fallback agrees with the seeded default');
t_contains($app, "'auto-quarantine on' : 'auto-quarantine off'",
    'the scanner subtitle is driven by the setting');
