<?php
/**
 * 154,323 customer files, one signature, 59 hours, in silence.
 *
 * Scan job 12457 on the production server quarantined 154,323 files from a
 * single third-party ClamAV signature, across at least twelve unrelated
 * accounts. 154,252 of them were `.md` — README.md and CHANGELOG.md inside
 * node_modules and vendor trees — matched by a rule that hunts long hex
 * strings, which is what a changelog full of git SHAs looks like. Not one
 * .php, .js or .html. There is no reading of that evidence in which it is
 * malware.
 *
 * Nothing stopped it and nothing said so. The job's own threats_found column
 * recorded 32,003 — the first account's share — so the one number an operator
 * would have looked at understated it five-fold.
 *
 * The verdict gate exists so the product cannot CLAIM what it has not
 * verified. This is the same rule applied to what it DOES: one signature
 * accounting for an implausible share of a run is evidence about the
 * signature, not about the customer's files. Above the bound, the product
 * flags instead of quarantining, halts the scan, and tells somebody — the same
 * standing rule as "flag WordPress databases and we will decide".
 *
 * Fixtures here are inert: see t_inert_payload() in tests/assert.php. The
 * bound counts findings, and a finding is a row.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

require_once $repo . '/backend/lib/MassDetection.php';

$SIG   = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';
$OTHER = '{HEX}php.cmdshell.gifheader.400.UNOFFICIAL';

$job = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running', 'started_at' => time() - 212400,
    'files_scanned' => 500000, 'threats_found' => 0,
    'scan_path' => '/home/kbroadlines/public_html,/home/inditdel/public_html',
    'requested_by' => '@schedule',
]);

/** One finding, the way the scan records it. */
$finding = function (string $path, string $sig, string $user) use ($job): int {
    return (int) Database::insert('threats', [
        'scan_job_id' => $job, 'file_path' => $path, 'threat_name' => $sig,
        'threat_type' => 'malware', 'severity' => 'high', 'status' => 'active',
        'hash' => hash('sha256', $path), 'size' => 1400,
        'detected_at' => time(), 'cpanel_user' => $user,
    ]);
};

// ── The default, and the reasoning being a setting ─────────────────────────

t_eq(500, MassDetection::limit(),
     'the bound defaults to 500 files from one signature in one scan. An '
   . 'ordinary infection is dozens to low hundreds — a defaced WordPress, a '
   . 'tree of injected index.php — and those complete untouched; 154,323 does '
   . 'not');

Database::setSetting('scan_mass_signature_max', '3');
t_eq(3, MassDetection::limit(), 'and it is a setting, because a server with a '
   . 'genuinely large infection may need it raised by someone who has looked');

// ── Below the bound, nothing changes ───────────────────────────────────────

MassDetection::reset();
$finding('/home/kbroadlines/public_html/a.md', $SIG, 'kbroadlines');
$r = MassDetection::allow($job, $SIG);
t_ok($r['act'] === true,
     'ONE detection is just a detection: the bound must not change what the '
   . 'product does about ordinary findings, or it is a worse product');
t_eq(1, $r['count'], 'and it reports what it counted');

$finding('/home/kbroadlines/public_html/b.md', $SIG, 'kbroadlines');
t_ok(MassDetection::allow($job, $SIG)['act'] === true, 'two is still fine');

// ── At the bound: flag, halt, alarm ────────────────────────────────────────

$finding('/home/inditdel/vendor/c.md', $SIG, 'inditdel');
$r = MassDetection::allow($job, $SIG);
t_ok($r['act'] === false,
     'AT THE BOUND THE PRODUCT STOPS ACTING: the third file is flagged, not '
   . 'quarantined. Customer files are not moved on the strength of a signature '
   . 'that is matching everything');
t_contains($r['reason'], 'evidence about the signature',
     'and the reason says what the evidence is about, because that is the '
   . 'judgement an operator has to make');
t_contains($r['reason'], 'An operator has to decide',
     'which is theirs to make, not the product\'s');

$jobRow = Database::fetchOne('SELECT status, stop_reason FROM scan_jobs WHERE id=?', [$job]);
t_eq('halted', $jobRow['status'],
     'THE SCAN HALTS. It ran for 59 hours past this point on the real server. '
   . 'If one signature is wrong about this many files, every other conclusion '
   . 'in the run is suspect too — and stopping is what gets a human to look');
t_contains((string) $jobRow['stop_reason'], 'mass-detection bound',
     'with a reason that is not "cancelled": nobody cancelled it, and an '
   . 'operator must be able to tell a scan they stopped from a scan that '
   . 'stopped itself');

$trip = MassDetection::lastTrip();
t_ok(is_array($trip), 'the trip is recorded where the CLI and the panel can read it');
t_eq($SIG, $trip['signature'] ?? '', 'with the signature named');
t_eq(3, (int) ($trip['count'] ?? 0), 'the count that tripped it');
t_ok((int) ($trip['accounts'] ?? 0) >= 2,
     'and how many ACCOUNTS it spans — twelve unrelated accounts is the fact '
   . 'that makes this a signature problem rather than a customer problem');
t_contains((string) ($trip['extensions'] ?? ''), 'md',
     'and the extensions, because "154,252 of them are .md" is a sentence an '
   . 'operator can act on and "154,323 threats found" is not');

$ev = Database::fetchOne(
    "SELECT type, severity, description FROM security_events "
  . "WHERE type='mass_detection' ORDER BY id DESC LIMIT 1");
t_ok(is_array($ev), 'AN ALARM IS RAISED: it is a security event, not a log line');
t_eq('critical', $ev['severity'] ?? '', 'at critical severity');
t_contains((string) $ev['description'], 'quarantine restore --job=',
     'and the alarm carries the command that undoes what has already been '
   . 'taken, because the operator reading it at 3am should not have to go '
   . 'looking for it');
t_contains((string) $ev['description'], 'signatures suppress add',
     'and the command that stops it happening again');
t_contains((string) $ev['description'], 'still in place',
     'and says the flagged files have NOT been touched, which is the thing '
   . 'they need to know first');

// ── A different signature in the same scan is unaffected ───────────────────

$finding('/home/kbroadlines/public_html/shell.php', $OTHER, 'kbroadlines');
t_ok(MassDetection::allow($job, $OTHER)['act'] === true,
     'the bound is PER SIGNATURE: the one finding in that run that might be '
   . 'real is still acted on. A bound that disarmed the whole scanner would '
   . 'trade one silent failure for another');

// ── Switching it off is possible, and is the state that caused the incident ─

Database::setSetting('scan_mass_signature_max', '0');
MassDetection::reset();
t_eq(0, MassDetection::limit(), '0 disables the bound');
t_ok(MassDetection::allow($job, $SIG)['act'] === true,
     'and with it disabled the product behaves exactly as it did on 10 Nov — '
   . 'which is why the default is not 0 and why the setting documents what it '
   . 'is for');
Database::setSetting('scan_mass_signature_max', '500');

// ── The counter the bound does NOT trust ───────────────────────────────────

$sc = t_code($repo . '/backend/lib/Scanner.php');
$md = t_code($repo . '/backend/lib/MassDetection.php');

t_contains($md, 'FROM threats WHERE scan_job_id = ? AND threat_name = ?',
     'the bound counts ROWS IN THE THREATS TABLE, which is the trustworthy '
   . 'figure');
t_ok(strpos(t_fn_body($md, 'allow', 'php'), 'threats_found') === false,
     'and never scan_jobs.threats_found, which was reading 32,003 while the '
   . 'table held 154,323 rows for the same job');

t_contains($sc, '$baseFiles   = (int) ($base[\'files_scanned\'] ?? 0);',
     'AND THE COUNTER ITSELF IS FIXED RATHER THAN WORKED AROUND: a sweep calls '
   . 'the scan once per account web root — about 120 of them — and both '
   . 'progress counters were local to one call, so each path overwrote the '
   . 'previous path\'s totals');
t_ok(substr_count($sc, '$baseThreats + count($threats)') >= 4,
     'every progress write is cumulative now, so threats_found rises across '
   . 'the whole sweep instead of restarting at each account');

$cron = t_code($repo . '/backend/cron/scan.php');
t_contains($cron, 'SELECT COUNT(*) AS c FROM threats WHERE scan_job_id=?',
     'and the final figure a finished job records is counted from the rows, '
   . 'not from whatever this worker happened to hold in memory');
t_contains($cron, "'cancelling', 'cancelled', 'halted'",
     'a halted job keeps its status: writing "done" over it would erase the '
   . 'record that the scan refused to continue');

// ── Where it sits in the policy chain ──────────────────────────────────────

$policy = t_fn_body($sc, 'applyThreatPolicy', 'php');
$boundPos = strpos($policy, 'MassDetection::allow(');
$quarPos  = strpos($policy, '$this->quarantine(');
$delPos   = strpos($policy, '$this->deleteInfected(');
t_ok($boundPos !== false && $quarPos !== false && $boundPos < $quarPos,
     'the bound is consulted BEFORE anything is quarantined');
t_ok($delPos !== false && $boundPos < $delPos,
     'and before anything is deleted, which is the action there is no undo for');
t_contains($policy, "'action' => 'flagged'",
     'past the bound the action is "flagged" — the finding is still recorded '
   . 'and still visible, which is what lets the operator judge the signature '
   . 'on the evidence');
t_contains($policy, 'flagged: mass detection bound',
     'and the row says why it was not acted on, so the UI is not showing an '
   . 'active threat with no explanation');
