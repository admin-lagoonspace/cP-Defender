<?php
/**
 * A SCAN MUST NOT STOP FINDING THINGS BECAUSE IT FOUND A LOT OF THINGS.
 *
 * 2026-04-30, host.lws-s1.com, 132 accounts. Something with root privilege
 * wrote a qTox ransom note named README.md into effectively every directory of
 * every account, and renamed every database-shaped file (.sql, .db, .sqlite,
 * .bak) to *.sorry. It never touched /var/lib/mysql, never touched site
 * content and never touched PHP, so all 118 sites kept serving and NOBODY
 * NOTICED FOR SIX AND A HALF MONTHS. CPGuard was installed and running
 * throughout and reported none of it.
 *
 * Our scan found it: 154,323 matches of ONE signature,
 * {HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL, on 10 Nov. That
 * detection was 100% CORRECT — verified by reading the files and matching the
 * attacker's qTox TOX ID. 58,597 notes were still live on disk when it was
 * investigated on 11-13 Nov and 1,864 .sorry stubs remained.
 *
 * Commit 2e160dc read that same event as proof the SIGNATURE was wrong, and
 * halted any scan past 500 files from one signature. Had it been in place on
 * 10 Nov it would have ended the scan at the 500th ransom note, left roughly
 * 153,800 real ransomware files on 132 live accounts, and shown the operator a
 * message reading "evidence about the signature rather than about these
 * files". A bound that stops detection fails safe in the WRONG DIRECTION: it
 * fails toward leaving malware in place.
 *
 * So this file encodes the incident. The bound may stop DESTROYING. It may not
 * stop FINDING. And because count alone cannot tell 30 Apr from a bad rule —
 * both are ~154,000 matches of one signature, and both are almost all `.md`,
 * since README.md is the name of a changelog in node_modules AND the name the
 * attacker gave the note — the product weighs the one piece of evidence that
 * does separate them: how many DISTINCT files those matches are.
 *
 * Fixtures are inert: see t_inert_payload() in tests/assert.php. A finding is
 * a row; the bound counts rows.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

require_once $repo . '/backend/lib/MassDetection.php';

/** The real signature, from the real event. */
$RANSOM = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';
/** A plausible bad rule of the kind 10 Nov was first mistaken for. */
$HEXFP  = '{HEX}generic.longhex.changelog.900.UNOFFICIAL';

$mkjob = function (string $type = 'full'): int {
    return (int) Database::insert('scan_jobs', [
        'scan_type' => $type, 'status' => 'running', 'started_at' => time() - 600,
        'files_scanned' => 400000, 'threats_found' => 0,
        'scan_path' => '/home', 'requested_by' => '@schedule',
    ]);
};

/**
 * Bulk findings, the shape the scan records them in.
 *
 * One prepared statement in one transaction: the 30 Apr replay below inserts
 * 154,323 rows, and Database::insert() re-prepares per row, which turns this
 * file into a two-minute test for no gain in fidelity.
 */
$findings = function (int $job, string $sig, int $n, callable $pathFn,
                      callable $hashFn, callable $userFn): void {
    $pdo = Database::get();
    $pdo->beginTransaction();
    $st = $pdo->prepare(
        'INSERT INTO threats (scan_job_id, file_path, threat_name, threat_type, '
      . 'severity, status, hash, size, detected_at, cpanel_user) '
      . 'VALUES (?,?,?,?,?,?,?,?,?,?)'
    );
    for ($i = 1; $i <= $n; $i++) {
        $st->execute([$job, $pathFn($i), $sig, 'malware', 'critical', 'active',
                      $hashFn($i), 1400, time(), $userFn($i)]);
    }
    $pdo->commit();
};

/* 118 accounts served sites on that server; 132 existed. The notes were in
 * $HOME, .cpanel/caches/config/, tmp/webalizer/, .cphorde/, .subaccounts/ and
 * ssl/ — every one of them outside public_html. */
$users = [];
for ($i = 0; $i < 118; $i++) { $users[] = 'acct' . $i; }
$where = ['', '/.cpanel/caches/config', '/tmp/webalizer', '/.cphorde',
          '/.subaccounts', '/ssl', '/public_html/wp-content'];

Database::setSetting(MassDetection::SETTING_MAX, '500');

// ═══ THE 30 APR REPLAY. 154,323 matches, one file, repeated. ════════════════

MassDetection::reset();
$jobReal = $mkjob();
$note    = hash('sha256', t_inert_payload('stands in for the qTox ransom note'));
$findings($jobReal, $RANSOM, 154323,
    function (int $i) use ($users, $where): string {
        return '/home/' . $users[$i % 118] . $where[$i % 7] . '/README.md';
    },
    function (int $i) use ($note): string { return $note; },
    function (int $i) use ($users): string { return $users[$i % 118]; }
);

$r = MassDetection::allow($jobReal, $RANSOM);

$jobRow = Database::fetchOne(
    'SELECT status, stop_reason FROM scan_jobs WHERE id=?', [$jobReal]);
t_eq('running', (string) $jobRow['status'],
     'THE SCAN IS NOT HALTED BY 154,323 MATCHES OF ONE SIGNATURE. This is the '
   . 'regression that blocked the release: with the halt in place this scan '
   . 'ends at its 500th finding, 128 of the 132 accounts are never walked, and '
   . '~153,800 real ransom notes stay on disk with the operator told the run '
   . 'is over');
t_eq('', (string) ($jobRow['stop_reason'] ?? ''),
     'and no stop reason is written, because nothing stopped the scan');

t_eq(154323, (int) (Database::fetchOne(
        'SELECT COUNT(*) AS c FROM threats WHERE scan_job_id=? AND threat_name=?',
        [$jobReal, $RANSOM])['c'] ?? 0),
     'EVERY ONE OF THE 154,323 FINDINGS IS STILL RECORDED. The operator cannot '
   . 'clean what the product declined to list; 58,597 of these were still live '
   . 'on disk six and a half months in');

t_eq('mass-identical', $r['verdict'],
     'AND THE PRODUCT READS IT CORRECTLY: 154,323 matches that are ONE distinct '
   . 'file repeated is a mass event, not a noisy rule. A ransom note dropped '
   . 'across a tree is the same bytes everywhere; a hex-hunting rule matching '
   . 'changelogs matches files that all differ');
t_ok($r['act'] === false,
     'destructive action still stops at the bound even though the detection is '
   . 'real. 154,000 files is a decision about SCOPE and a human makes it once — '
   . 'the product does not mass-quarantine a customer server unattended');

t_contains($r['reason'], 'real mass event',
     'the operator is told to treat it as a real mass event, in those words');
t_contains($r['reason'], 'do NOT suppress the signature',
     'and told NOT to suppress the signature, which is the exact wrong move '
   . 'here and the one the old message steered them toward');
t_ok(strpos($r['reason'], 'evidence about the signature') === false,
     'and nowhere is this described as evidence about the signature. That '
   . 'sentence was shown for a detection that was 100% correct');

$ev = Database::fetchOne("SELECT severity, description FROM security_events "
    . "WHERE type='mass_detection' ORDER BY id DESC LIMIT 1");
t_ok(is_array($ev), 'an alarm is raised for a real mass event too');
t_eq('critical', (string) $ev['severity'],
     'at critical severity and immediately: the 10 Nov failure was 59 hours of '
   . 'silence and this one was six and a half MONTHS of it');
t_contains((string) $ev['description'], 'THE SCAN IS STILL RUNNING',
     'and the alarm says the scan has not stopped, so nobody reads a bound trip '
   . 'as a finished run');
t_contains((string) $ev['description'], 'SAME FEW FILES REPEATED',
     'and names the evidence that makes this a compromise rather than a bad '
   . 'rule');
t_contains((string) $ev['description'], 'Of 2000 of 2000 sampled matches',
     'with the sample size stated — 2,000 rows is the bounded ceiling, and a '
   . 'verdict is only as good as the sample it names');

// ═══ THE 10 NOV FALSE-POSITIVE SHAPE. Many matches, all different. ══════════

MassDetection::reset();
$jobFP = $mkjob();
$findings($jobFP, $HEXFP, 154323,
    function (int $i) use ($users): string {
        return '/home/' . $users[$i % 118] . '/public_html/node_modules/p' . $i
             . '/CHANGELOG.md';
    },
    function (int $i): string { return hash('sha256', 'changelog-' . $i); },
    function (int $i) use ($users): string { return $users[$i % 118]; }
);

$f = MassDetection::allow($jobFP, $HEXFP);
t_eq('varied-content', $f['verdict'],
     'THE SAME COUNT ON DIFFERENT FILES READS THE OTHER WAY. 154,323 matches '
   . 'that are 154,323 distinct files is a rule hunting hex strings through '
   . 'changelogs full of git SHAs. Count could not tell these two cases apart; '
   . 'distinct contents can');
t_ok($f['act'] === false, 'destructive action stops here too');
t_contains($f['reason'], 'signatures suppress add',
     'and THIS is where the operator is pointed at suppression — the reviewed, '
   . 'operator-driven lever from 04aefc1, named only for the case it fits');
t_eq('running', (string) Database::fetchOne(
        'SELECT status FROM scan_jobs WHERE id=?', [$jobFP])['status'],
     'and even a genuinely bad signature does not stop the scan: the rest of '
   . 'the run may hold the finding that is real');

// ═══ A HANDFUL OF DISTINCT FILES IS STILL ONE EVENT ════════════════════════

MassDetection::reset();
$jobNear = $mkjob();
// 20 notes per account across all 118 accounts: the 30 Apr shape if the
// attacker had personalised the note per victim, which real ransomware does.
$findings($jobNear, $RANSOM, 2360,
    function (int $i) use ($users, $where): string {
        return '/home/' . $users[$i % 118] . $where[$i % 7] . '/README.md';
    },
    function (int $i) use ($users): string {
        return hash('sha256', 'note-for-' . $users[$i % 118]);
    },
    function (int $i) use ($users): string { return $users[$i % 118]; }
);
t_eq('mass-identical', MassDetection::allow($jobNear, $RANSOM)['verdict'],
     'NEAR-IDENTICAL IS STILL A MASS EVENT. 118 distinct notes over 2,360 paths '
   . 'is one event with a per-victim note, not 2,360 unrelated files. A test '
   . 'that demanded byte-equality would be evaded by appending a counter and '
   . 'would read the next ransomware run as a false positive');

/* The thresholds, stated directly rather than inferred from a fixture, so the
 * boundary this product declines to guess at is visible and reviewable. */
t_eq('mass-identical', MassDetection::weigh(2000, 118, 20),
     '118 distinct files in 2,000 samples — 17 copies each — reads as one event');
t_eq('varied-content', MassDetection::weigh(2000, 2000, 1),
     '2,000 distinct files in 2,000 samples reads as a rule matching ordinary '
   . 'files, which is the only case that points at suppression');
t_eq('undetermined', MassDetection::weigh(2000, 600, 8),
     'AND 600 DISTINCT FILES IN 2,000 SAMPLES IS NEITHER. It does not guess. '
   . 'Guessing "bad signature" here is the 30 Apr failure and guessing '
   . '"infection" is the 10 Nov one');
t_eq('undetermined', MassDetection::weigh(500, 251, 250),
     'AND A MIXED MATCH SET IS NOT A FALSE POSITIVE EITHER. 250 identical '
   . 'copies of one file alongside 250 unrelated ones is a mass event sitting '
   . 'inside a noisy rule — both are true at once. Calling that '
   . '"varied-content" and pointing at suppression would bury the infection in '
   . 'the false positive, which is the 30 Apr failure in miniature');
t_eq('undetermined', MassDetection::weigh(7, 1, 7),
     'nor does it rule on seven samples, however identical they are: eight is '
   . 'the floor, and a verdict from a handful of files out of 154,323 is not a '
   . 'verdict');

// ═══ WHERE IT CANNOT TELL, IT SAYS SO ══════════════════════════════════════

MassDetection::reset();
$jobBlind = $mkjob();
$findings($jobBlind, $RANSOM, 600,
    function (int $i) use ($users): string {
        return '/home/' . $users[$i % 118] . '/.cache/README.md';
    },
    // No hash: the file vanished between the match and the record. That is an
    // INCONCLUSIVE sample and must not be scored either way -- counted as a
    // distinct file it would have read as "all different", i.e. as a false
    // positive, which is the failure this whole file is about.
    function (int $i): string { return ''; },
    function (int $i) use ($users): string { return $users[$i % 118]; }
);
$b = null;
t_no_throw(function () use (&$b, $jobBlind, $RANSOM) {
    $b = MassDetection::allow($jobBlind, $RANSOM);
}, 'an unusable content sample throws nothing into the scan worker, which is '
 . 'detached and unwatched');
t_eq('undetermined', $b['verdict'],
     'AND THE ANSWER IS "WE DO NOT KNOW". With no readable content the product '
   . 'will not call 600 matches a false positive and will not call them an '
   . 'infection. It records unknown, as it does for a WAF event it could not '
   . 'confirm was blocked');
t_contains($b['reason'], 'No file content hash was available',
     'and says why it does not know, with the count of samples that failed');
t_ok($b['act'] === false,
     'destructive action still stops: not knowing is a reason to be careful '
   . 'with customer files, not a reason to proceed');
t_eq('running', (string) Database::fetchOne(
        'SELECT status FROM scan_jobs WHERE id=?', [$jobBlind])['status'],
     'and not knowing is not a reason to stop scanning either');

// ═══ TWO SIGNATURES IN ONE JOB, INDEPENDENTLY ══════════════════════════════

MassDetection::reset();
$jobTwo = $mkjob();
$findings($jobTwo, $RANSOM, 600,
    function (int $i) use ($users): string {
        return '/home/' . $users[$i % 118] . '/ssl/README.md';
    },
    function (int $i) use ($note): string { return $note; },
    function (int $i) use ($users): string { return $users[$i % 118]; }
);
$findings($jobTwo, $HEXFP, 600,
    function (int $i) use ($users): string {
        return '/home/' . $users[$i % 118] . '/vendor/v' . $i . '/README.md';
    },
    function (int $i): string { return hash('sha256', 'vendor-' . $i); },
    function (int $i) use ($users): string { return $users[$i % 118]; }
);
t_eq('mass-identical', MassDetection::allow($jobTwo, $RANSOM)['verdict'],
     'two signatures tripping in one job are weighed separately: the ransomware '
   . 'one reads as a mass event');
t_eq('varied-content', MassDetection::allow($jobTwo, $HEXFP)['verdict'],
     'and the noisy one reads as a noisy rule, in the same job, from the same '
   . 'evidence applied to its own rows');
t_eq('running', (string) Database::fetchOne(
        'SELECT status FROM scan_jobs WHERE id=?', [$jobTwo])['status'],
     'and neither stops the scan, so a run with one bad rule and one real '
   . 'infection still finds the infection');

// ═══ SWITCHED OFF IS SWITCHED OFF ══════════════════════════════════════════

Database::setSetting(MassDetection::SETTING_MAX, '0');
MassDetection::reset();
$evBefore = (int) (Database::fetchOne(
    "SELECT COUNT(*) AS c FROM security_events WHERE type='mass_detection'")['c'] ?? 0);
$off = MassDetection::allow($jobReal, $RANSOM);
t_ok($off['act'] === true, 'with the bound at 0 there is no bound');
t_eq('', $off['verdict'], 'no verdict, because nothing was sampled');
t_eq($evBefore, (int) (Database::fetchOne(
        "SELECT COUNT(*) AS c FROM security_events WHERE type='mass_detection'")['c'] ?? 0),
     'and no alarm. 0 is the state the product shipped in on 10 Nov, and it is '
   . 'off only because an operator turned it off');
Database::setSetting(MassDetection::SETTING_MAX, '500');

// ═══ THE QUARANTINE DIRECTORY, COUNTED ═════════════════════════════════════
//
// The bound's whole job is that files stop MOVING. Asserted on the directory
// rather than on the return value, because 154,323 files moved out of
// customers' accounts is what actually happened and a row saying 'flagged'
// while the file is gone would be the same failure wearing a label.

MassDetection::reset();
/* 10, with 15 findings: nine move and six do not. The bound trips AT its
 * limit -- the tenth finding is the one that asks and is refused -- and ten
 * samples is also the floor for a verdict, so this exercises the whole path
 * the real event takes rather than a corner of it. */
Database::setSetting(MassDetection::SETTING_MAX, '10');
Database::setSetting('auto_quarantine', '1');
Database::setSetting('policy_medium_days', '5');

$live = $sandbox . '/live';
@mkdir($live, 0700, true);
$scanner = new Scanner();
$jobQ    = $mkjob();
$actions = [];
for ($i = 1; $i <= 15; $i++) {
    $path = $live . '/README' . $i . '.md';
    file_put_contents($path, t_inert_payload('stands in for a ransom note'));
    $tid = (int) Database::insert('threats', [
        'scan_job_id' => $jobQ, 'file_path' => $path, 'threat_name' => $RANSOM,
        'threat_type' => 'malware', 'severity' => 'medium', 'status' => 'active',
        'hash' => $note, 'size' => 1400, 'detected_at' => time(),
        'cpanel_user' => 'acct0',
    ]);
    $actions[] = (string) $scanner->applyThreatPolicy(
        $path, $tid, 'medium', $RANSOM, $jobQ)['action'];
}

$quarantined = 0;
$it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(QUARANTINE_DIR, FilesystemIterator::SKIP_DOTS));
foreach ($it as $fsi) { if ($fsi->isFile()) { $quarantined++; } }

t_eq(9, $quarantined,
     'NINE FILES MOVED, AND THEN NO MORE, at a bound of 10 over 15 findings. '
   . 'This is the half of 2e160dc that was right and has to survive: one '
   . 'third-party rule does not get to empty a customer account unattended, '
   . 'and 154,323 files did move on 10 Nov');
t_eq('flagged', $actions[14],
     'the findings past the bound come back "flagged" rather than acted on');
t_eq(6, count(Database::fetchAll(
        "SELECT id FROM threats WHERE scan_job_id=? "
      . "AND action_taken LIKE 'flagged: mass detection bound%'", [$jobQ])),
     'with the reason written on the row, so the UI shows an unactioned threat '
   . 'WITH an explanation instead of a bare active threat');
t_eq(6, count(Database::fetchAll(
        "SELECT id FROM threats WHERE scan_job_id=? "
      . "AND action_taken LIKE '%mass-identical%'", [$jobQ])),
     'and the VERDICT on the row too, because an operator triaging 58,597 '
   . 'flagged files needs to know the product thinks they are real rather than '
   . 'reading "bound exceeded" as "ignore these"');
t_eq(6, count(glob($live . '/README*.md')),
     'and the six past the bound are still on disk where the customer left '
   . 'them: flag, do not destroy');

// ═══ THE HALT, BY NAME, SO IT CANNOT COME BACK ═════════════════════════════

$md = t_code($repo . '/backend/lib/MassDetection.php');
t_ok(strpos($md, 'halt') === false,
     'NOTHING IN THE CLASS HALTS ANYTHING, asserted on the source by name. '
   . 'MassDetection::halt() set scan_jobs.status to "halted", which '
   . 'Scanner::isCancelled() treats as a stop, so the worker left at the next '
   . 'batch boundary. A future reader who finds the old reasoning persuasive '
   . 'has to delete this assertion to reinstate it');
t_ok(strpos($md, 'scan_jobs') === false,
     'and it does not write to scan_jobs at all — the table through which a '
   . 'scan is stopped. It has no business there');
t_ok(strpos($md, 'LIMIT 2000') !== false || strpos($md, 'SAMPLE_ROWS') !== false,
     'the evidence sample stays bounded at 2,000 rows: this runs mid-batch on a '
   . 'server with 132 live accounts');
t_contains(t_fn_body($md, 'trip', 'php'), 'ORDER BY id LIMIT',
     'in ONE query per tripped signature, which is also where the extensions '
   . 'and the account spread come from. One query per FILE on a 154,323-file '
   . 'run is a second incident');
t_ok(strpos(t_fn_body($md, 'trip', 'php'), 'hash_file') === false
     && strpos(t_fn_body($md, 'trip', 'php'), 'file_get_contents') === false,
     'and it reads no files. threats.hash is recorded at detection, BEFORE the '
   . 'policy runs, so it survives the quarantining of the first 500 matches — '
   . 'a disk read here would find exactly those files missing and would call '
   . 'every real mass event undetermined');
