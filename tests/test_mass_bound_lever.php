<?php
/**
 * FLAG-AND-WAIT WITH NO VISIBLE LEVER IS A DEAD END.
 *
 * `scan_mass_signature_max` governs whether one signature may go on
 * quarantining customer files, and it existed only as a row in the settings
 * table: no CLI command, no field, no label, no help text. `grep -rn` across
 * backend/, frontend/, cpanel/ and whm/ found the default row and the constant
 * name, and nothing else.
 *
 * That matters because of what the bound does past its limit. The findings are
 * flagged and left in place — correct, and the right conservative default —
 * and the ways on from there are: suppress the signature (wrong when the
 * detection is real, which on 30 Apr it was), issue a per-file verdict on
 * 153,800 files (not a thing a person can do), or raise the bound. The spec
 * required the lever to be operator-visible precisely so the chosen design has
 * an exit. Without it, the next real incident is handled by somebody guessing
 * a settings key at 03:00.
 *
 * This asserts the lever exists, that it is discoverable from `--help`, and
 * that it reports the last trip WITH its evidence — because "the bound tripped"
 * and "the bound tripped on 154,323 matches that are one distinct file" lead
 * to opposite next steps.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

require_once $repo . '/backend/lib/MassDetection.php';

$cli = t_code($repo . '/backend/cli/serverscrub.php');

// ── The lever ──────────────────────────────────────────────────────────────

t_contains($cli, "'mass-bound'",
     'THERE IS A COMMAND. `serverscrub scan mass-bound [N]` shows and sets the '
   . 'bound on destructive action at scale, which was previously reachable '
   . 'only by an authenticated admin who already knew the settings key');
t_contains($cli, 'MassDetection::SETTING_MAX',
     'and it writes the same setting the scanner reads, rather than a second '
   . 'key that looks like it');
t_contains($cli, "require_once \$BASE . '/lib/MassDetection.php'",
     'with the class required AT THE TOP of the CLI, next to QuarantineRestore '
   . 'and for the same reason: a require_once buried in a switch arm is how a '
   . 'recovery tool dies with "Class not found" the first time somebody '
   . 'reaches for it');

t_contains($cli, 'MassDetection::lastTrip()',
     'AND THE RECORDED TRIP IS NOW READ BY SOMETHING. lastTrip() and '
   . 'clearLastTrip() were dead outside the test suite: the product wrote the '
   . 'evidence down and then nothing in the CLI or the panel ever showed it');

$help = t_fn_body($cli, 'usage', 'php');
$helpText = $help !== '' ? $help : $cli;
t_contains($helpText, 'scan mass-bound',
     'and it is listed in --help, which is the only place an operator who does '
   . 'not already know the command can find it');

// ── What it must not hand over ─────────────────────────────────────────────

t_ok(strpos($cli, "'serverscrub signatures suppress add ' . \$signature") === false,
     'THE CLI DOES NOT PRE-COMPOSE A SUPPRESSION FOR A VERDICT IT CANNOT '
   . 'REACH. A ready-to-paste `signatures suppress add` beside a detection the '
   . 'product has just said it cannot judge is one keystroke from blinding the '
   . 'scanner to a live ransomware run');

$next = t_fn_body($cli, 'self_mass_next', 'php');
t_contains($next, 'do NOT suppress the signature',
     'for a mass-identical verdict it says the opposite outright');
t_contains($next, 'signatures suppress add \' . $signature',
     'and the command is written out for exactly one verdict — varied-content, '
   . 'where every matched file differs and a noisy rule is the likely reading');
t_contains($next, 'could not tell',
     'while the undetermined case says so, and asks for a file to be read '
   . 'before either command is run');

// ── The same rule in the alarm the operator is paged with ──────────────────
//
// The CLI is where an operator looks when they already know something is
// wrong. The alarm is what tells them. Both have to hold the line.

$SIG = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';
$job = (int) Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running', 'started_at' => time() - 600,
    'files_scanned' => 100000, 'threats_found' => 0, 'scan_path' => '/home',
    'requested_by' => '@schedule',
]);
$note = hash('sha256', t_inert_payload('stands in for a qTox ransom note'));
Database::setSetting(MassDetection::SETTING_MAX, '10');
MassDetection::reset();
$pdo = Database::get();
$pdo->beginTransaction();
$st = $pdo->prepare(
    'INSERT INTO threats (scan_job_id, file_path, threat_name, threat_type, '
  . 'severity, status, hash, size, detected_at, cpanel_user) VALUES (?,?,?,?,?,?,?,?,?,?)');
for ($i = 1; $i <= 12; $i++) {
    $st->execute([$job, '/home/acct' . $i . '/README.md', $SIG, 'malware',
                  'critical', 'active', $note, 1400, time(), 'acct' . $i]);
}
$pdo->commit();

$r = MassDetection::allow($job, $SIG);
t_eq('mass-identical', $r['verdict'], 'the fixture trips as a real mass event');

$ev = (string) Database::fetchOne("SELECT description FROM security_events "
    . "WHERE type='mass_detection' ORDER BY id DESC LIMIT 1")['description'];
t_contains($ev, 'scan mass-bound',
     'AND THE ALARM NAMES THE LEVER. Past the bound an operator with a real '
   . 'mass event has flagged findings they cannot act on in bulk; being told '
   . 'the bound exists, by name, in the alarm, is the difference between a '
   . 'conservative default and a dead end');
t_ok(strpos($ev, 'suppress add ' . $SIG) === false,
     'and still does not hand them the command that would switch off '
   . 'detection of it');

$trip = MassDetection::lastTrip();
t_eq('mass-identical', (string) $trip['verdict'],
     'the verdict is in the record the CLI reads, not only in the prose');
t_eq(12, (int) $trip['samples_conclusive'],
     'with the number of samples it rests on, so "mass-identical" from twelve '
   . 'files and from two thousand cannot be read as the same claim');
Database::setSetting(MassDetection::SETTING_MAX, '500');
