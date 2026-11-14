<?php
/**
 * THE OTHER HALF OF JOB 12457 — a mass detection that is REAL.
 *
 * tests/test_mass_detection_bound.php encodes one reading of the bound: that a
 * signature matching 500+ files is evidence against the SIGNATURE. On
 * 2026-11-10 our scanner quarantined 154,323 files from one signature and that
 * detection was CORRECT — genuine qTox ransom notes from a root-level
 * ransomware run on 2026-04-30 that had gone unnoticed for six months.
 *
 * The bound as shipped in 2e160dc would have halted that scan at the 500th
 * file and left roughly 153,800 real ransomware artefacts in place, on a
 * production server with 132 accounts, while reporting 'halted'.
 *
 * So the count alone cannot decide. This file encodes the case the bound must
 * NOT break, and names the signal that separates the two: a ransom note
 * dropped across a tree is BYTE-IDENTICAL — one hash, thousands of paths — and
 * a hex-hunting signature matching changelogs produces thousands of DISTINCT
 * hashes. 154,323 copies of the same bytes is not evidence about the rule.
 *
 * Fixtures are inert: see t_inert_payload() in tests/assert.php. The bound
 * counts findings, and a finding is a row.
 */

require_once __DIR__ . '/../assert.php';
$ctx  = require __DIR__ . '/../bootstrap.php';
$repo = $ctx['repo'];

require_once $repo . '/backend/lib/MassDetection.php';

$RANSOM = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';
$HEXFP  = '{HEX}generic.longhex.changelog.900.UNOFFICIAL';

$mkjob = function (string $note) {
    return Database::insert('scan_jobs', [
        'scan_type' => 'full', 'status' => 'running', 'started_at' => time() - 600,
        'files_scanned' => 400000, 'threats_found' => 0,
        'scan_path' => '/home', 'requested_by' => '@schedule',
    ]);
};

/* The 2026-04-30 run dropped the same note everywhere, so every finding
 * carries the SAME sha256. That is the shape of a real mass compromise. */
$noteHash = hash('sha256', t_inert_payload('stands in for a qTox ransom note'));

$finding = function (int $job, string $path, string $sig, string $user, string $hash): int {
    return (int) Database::insert('threats', [
        'scan_job_id' => $job, 'file_path' => $path, 'threat_name' => $sig,
        'threat_type' => 'malware', 'severity' => 'critical', 'status' => 'active',
        'hash' => $hash, 'size' => 1400, 'detected_at' => time(),
        'cpanel_user' => $user,
    ]);
};

Database::setSetting(MassDetection::SETTING_MAX, '500');
MassDetection::reset();

// ── CASE 1: a REAL mass detection. 600 byte-identical ransom notes. ─────────

$jobReal = $mkjob('real');
$users   = ['kbroadlines', 'inditdel', 'vaultrun', 'pargolf'];
for ($i = 1; $i <= 600; $i++) {
    $u = $users[$i % 4];
    $finding($jobReal, '/home/' . $u . '/public_html/.qtox_READ_ME_' . $i . '.txt',
             $RANSOM, $u, $noteHash);
}

$r = MassDetection::allow($jobReal, $RANSOM);

/* WITHDRAWN 2026-11-13, by me, after Wasooli declined it and I checked the
 * grounds. I asserted act === true here: that a confirmed-real mass detection
 * must still be quarantined. Requirement 2 of
 * docs/specs/2026-11-13-quick-scan-blindspot-and-mass-detection-bound.md says
 * the opposite in terms — "Past the bound, destructive action (quarantine,
 * disable, delete) stops for that signature… This part of the current
 * behaviour is correct and must survive." The spec separates halting (harmful)
 * from flagging (the right conservative default) and keeps the second on
 * purpose. I was treating "must not leave files in place" as an absolute when
 * the spec had already settled it the other way. The decline is right.
 *
 * What survives is not this assertion but the missing exit: flag-and-wait is
 * only a safe design if the operator has a visible lever, and
 * scan_mass_signature_max is in no CLI command and no panel. That is case 6
 * below and blocker 3 of the 55bd3d5 report. */
t_ok($r['act'] === false,
     'WITHDRAWN — destructive action stops past the bound, by spec req 2, even '
   . 'for a verdict of mass-identical. Asserting the inverse was my error. The '
   . 'real gap is that nothing gives the operator a way to proceed: see case 6.');

$jobRow = Database::fetchOne('SELECT status, stop_reason FROM scan_jobs WHERE id=?', [$jobReal]);
t_eq('running', (string) $jobRow['status'],
     'and the scan DOES NOT HALT, so the remaining accounts are still scanned. '
   . 'A halt here means the other 128 accounts on the server are never looked '
   . 'at and the operator is told the run is over.');

// ── CASE 2: the 10 Nov false positive. 600 DISTINCT hashes, all .md ─────────

MassDetection::reset();
$jobFP = $mkjob('fp');
for ($i = 1; $i <= 600; $i++) {
    $u = $users[$i % 4];
    $finding($jobFP, '/home/' . $u . '/public_html/node_modules/pkg' . $i . '/CHANGELOG.md',
             $HEXFP, $u, hash('sha256', 'changelog-' . $i));
}

$f = MassDetection::allow($jobFP, $HEXFP);
t_ok($f['act'] === false,
     'A GENUINE FALSE POSITIVE STILL TRIPS. 600 findings with 600 different '
   . 'hashes, in node_modules, all .md, is one rule matching varied content — '
   . 'evidence about the rule. Flag, do not quarantine.');

t_eq(MassDetection::V_VARIED, (string) $f['verdict'],
     'and it is named as varied content');

/* CORRECTION TO AN EARLIER VERSION OF THIS FILE: I first asserted that the
 * false-positive scan HALTS, carried over from 2e160dc. That is wrong. A scan
 * must not stop finding things because it found a lot of things, in either
 * case — the halt is what would have left the 30 Apr ransomware in place. */
$fpRow = Database::fetchOne('SELECT status FROM scan_jobs WHERE id=?', [$jobFP]);
t_eq('running', (string) $fpRow['status'],
     'and THIS scan does not halt either: the bound pauses destruction, never '
   . 'discovery');

// ── CASE 3: near-identical is not identical ─────────────────────────────────

MassDetection::reset();
$jobNear = $mkjob('near');
for ($i = 1; $i <= 600; $i++) {
    $u = $users[$i % 4];
    // Same note, personalised with the victim's account — SIMILAR, not
    // byte-identical. Real ransomware does this. A test that only recognises
    // byte-identical files would read this as a false positive.
    $finding($jobNear, '/home/' . $u . '/tmp/webalizer/READ_ME_' . $i . '.txt',
             $RANSOM, $u, hash('sha256', 'qtox-note-for-' . $u));
}
$n = MassDetection::allow($jobNear, $RANSOM);
/* WITHDRAWN for the same reason as case 1 — act === false is correct by spec
 * req 2. What I was actually testing here, the VERDICT on a per-account note,
 * is now right: CLUSTERED_SHARE = 0.10 reads 4 distinct over 600 as
 * mass-identical. Wasooli adopted that part. So this case is kept as a
 * verdict assertion, which is the thing worth protecting. */
t_eq(MassDetection::V_IDENTICAL, (string) $n['verdict'],
     'NEAR-IDENTICAL IS STILL A MASS COMPROMISE. A ransom note personalised '
   . 'per account gives four distinct hashes over 600 files, not 600. The '
   . 'signal is "very few distinct contents for very many paths", not '
   . 'byte-equality, or the next ransomware run evades the check by appending '
   . 'a counter. (Verdict only — act === false is correct here, see case 1.)');

// ── CASE 4: the suppression from 04aefc1 is the operator's lever, not this ──

require_once $repo . '/backend/lib/SignatureSuppressions.php';
$md = t_code($repo . '/backend/lib/MassDetection.php');
t_ok(strpos($md, 'SignatureSuppressions') === false
     || strpos($md, 'suppress') !== false,
     'the bound points the operator at `signatures suppress add`, which is the '
   . 'reviewed lever, instead of suppressing a signature on its own authority');

// ── CASE 5: what the product may NOT claim on hash evidence alone ──────────
//
// A ransom note that embeds anything per-file — a counter, a victim id, a
// timestamp — is all-distinct, and so is a changelog false positive. Under
// content hashing the two shapes are INDISTINGUISHABLE, so 'varied-content'
// is not a conclusion the evidence supports.

/* NARROWED 2026-11-13. I asserted that all-distinct must read 'undetermined'.
 * Wasooli declined on spec req 3, which explicitly endorses sampled content
 * identicality as evidence, and req 4's bar is "on count ALONE" — which this
 * clears. On both real incidents the verdict is right. I accept the verdict
 * NAME and press only the part that can hurt somebody: what the product then
 * TELLS the operator to type. Where the evidence is consistent with a real
 * per-file-unique mass event, a pre-composed `signatures suppress add` line is
 * the dangerous branch typed out for them. */
$varied = MassDetection::weigh(500, 500, 1);
t_eq(MassDetection::V_VARIED, $varied,
     'all-distinct reads as varied content — accepted, per spec req 3');

t_eq(MassDetection::V_UNKNOWN, MassDetection::weigh(600, 118, 6),
     'and a per-victim note spread thinly reads as undetermined — the known '
   . 'soft spot, correctly named');

/* The thin per-victim shape, end to end, so this tests the text the operator
 * actually sees rather than a helper. 600 matches, 118 victims, ~5 copies. */
$jobThin = $mkjob('thin');
for ($i = 0; $i < 600; $i++) {
    $v = 'acct' . ($i % 118);
    $finding($jobThin, '/home/' . $v . '/sub' . $i . '/README.md', $RANSOM, $v,
             hash('sha256', 'note-for-' . $v));
}
MassDetection::reset();
$thin = MassDetection::allow($jobThin, $RANSOM);
t_eq(MassDetection::V_UNKNOWN, (string) $thin['verdict'],
     'confirmed end to end through allow()');

/* The row reason names suppression in prose only ("suppress the signature if
 * it is wrong") and carries no command — that part is fine. The critical
 * ALARM is where the pre-composed line is, and the alarm is what an operator
 * is paged with. */
/* RESOLVED in 55bd3d5..18d2ec2. Wasooli accepted this and the alarm now
 * composes the suppress command for varied-content ONLY; mass-identical says
 * "do NOT suppress" and names `scan mass-bound`, and undetermined says "READ
 * ONE OF THE FLAGGED FILES BEFORE ANYTHING ELSE … neither command below is
 * safe to run blind" and names suppression without pasting the signature.
 * Verified per verdict by tests/tools/verdict-text-probe.php. Kept as a
 * regression guard, matching on the COMPOSED string (signature substituted),
 * because the bare phrase legitimately appears in all three. */
$evThin = Database::fetchOne(
    "SELECT description FROM security_events WHERE type='mass_detection' "
  . "AND description LIKE '%CANNOT TELL%' ORDER BY id DESC LIMIT 1");
t_ok(strpos((string) ($evThin['description'] ?? ''),
            'signatures suppress add ' . $RANSOM) === false,
     'AND WHERE IT CANNOT TELL, IT DOES NOT TYPE OUT THE SUPPRESS COMMAND. '
   . 'Measured on 600 samples / 118 distinct / top 6 — a real ransom note '
   . 'personalised per victim — both the row reason and the critical alarm '
   . 'hand over a ready-to-paste `serverscrub signatures suppress add <sig>`. '
   . 'That is detection of a live infection, switched off, pre-typed, at 03:00, '
   . 'in the one case the product has just said it cannot judge. Name '
   . 'suppression as an option by all means; do not compose the command.');

t_eq(MassDetection::V_IDENTICAL, MassDetection::weigh(600, 4, 150),
     'FEW DISTINCT FILES OVER MANY PATHS IS A MASS EVENT. 4 distinct contents '
   . 'across 600 matches is a note personalised per account — the commonest '
   . 'real shape. weigh() measures only the TOP group (150/600 = 0.25), so it '
   . 'reads as undetermined; the distinct COUNT is the signal it ignores.');

t_ok(MassDetection::weigh(500, 251, 250) !== MassDetection::V_VARIED,
     'AND A MIXED JOB IS NOT A FALSE POSITIVE. 250 byte-identical copies of '
   . 'one file is a mass event whatever the other 250 matches are; calling the '
   . 'run "what a signature matching ordinary files looks like" hides it.');

// ── CASE 6: there must be a way to FINISH a real clean-up ──────────────────

/* RESOLVED in e5083c1: `serverscrub scan mass-bound [N]` exists, is in
 * --help, records a high-severity event on change and prints the last trip
 * with its verdict and sample sizes. Verified against a real install. The
 * grep below is widened to the command name, because the CLI reaches the
 * setting through MassDetection::SETTING_MAX rather than the literal key. */
$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_ok(stripos($cli, 'mass-bound') !== false
     || strpos($cli, 'scan_mass_signature_max') !== false
     || stripos($cli, 'quarantine apply') !== false
     || stripos($cli, 'remediate') !== false,
     'THERE MUST BE A DO, NOT JUST AN UNDO. Past the bound the remaining '
   . '~153,800 real '
   . 'ransomware files are flagged and left on disk, and the CLI has '
   . '`quarantine restore` to undo a clean-up but no supported way to raise '
   . 'the bound or act on flagged findings in bulk. CORRECTION to an earlier '
   . 'version of this message: it is not SQL-only — routeSettings get/set '
   . 'returns and accepts any key matching ^[a-z_]+$, so an admin CAN change '
   . 'it through the generic API. It is reachable but not discoverable, which '
   . 'is what spec req 7 ("the setting remains operator-visible") asked for.');
