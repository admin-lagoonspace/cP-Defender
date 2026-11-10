<?php
/**
 * Putting 154,323 customer files back.
 *
 * On 10 Nov scan job 12457 quarantined 154,323 files from one third-party
 * ClamAV signature:
 *
 *     {HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL   154,323
 *     {HEX}php.cmdshell.gifheader.400.UNOFFICIAL                        1
 *
 * across at least twelve unrelated accounts — 32,003 in one, 26,721 in
 * another, and a long tail. By extension: 154,252 `.md`, 34 `.tar`, 34 `.gz`,
 * 4 `.zip`. The markdown is README.md and CHANGELOG.md inside node_modules and
 * vendor trees, matched by a signature that looks for long hex strings;
 * changelogs are full of git SHAs. Not one .php, .js or .html. 204 MB in
 * total, averaging 1.4 KB a file.
 *
 * And the product had no way to put any of it back. `quarantine` had status,
 * sweep, prune and move. `restoreFromQuarantine()` took one id, was reachable
 * only from an API route, guessed the quarantine directory from a date instead
 * of reading the path it had recorded, verified nothing, restored no
 * ownership, and returned a bare bool.
 *
 * ── A NOTE ON THE FIXTURES ───────────────────────────────────────────────────
 *
 * Nothing written to disk here contains a pattern a scanner matches, and that
 * is deliberate. An earlier draft of this file used a real webshell string for
 * the one "could be genuine" finding, and the developer's own antivirus
 * reported two Severe, Active backdoors against it and held the file open --
 * which surfaced as a hash mismatch in the restore code and cost an hour. See
 * t_inert_payload() in tests/assert.php, and tests/test_integrity.php, which
 * hit this first and wrote it down.
 *
 * What this file pins is the behaviour an operator at 2am depends on: that a
 * dry run moves nothing, that a scope cannot be omitted, that the 72 archives
 * can be handed back without touching the other 154,251 files, that a file
 * already back at its path is never overwritten, that bytes are verified
 * before anything moves, and that the report says what happened to every file
 * rather than counting the ones that worked.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

require_once $repo . '/backend/lib/QuarantineRestore.php';

// ── A sandbox that looks like the incident ─────────────────────────────────

$home = $sandbox . '/home';

/* Quarantine is pointed INTO THE SANDBOX, which it otherwise is not.
 *
 * QUARANTINE_DIR is /var/.serverscrub/quarantine and storagePath() falls back
 * to it, so every test file in the suite — and every previous run on the same
 * machine — shares one real directory outside its sandbox. This file found
 * that the hard way: a quarantined copy left behind by an earlier run of
 * itself, at the same id and the same name, made the hash check fail against
 * bytes from a different run. The product reads the setting first, so saying
 * so here is enough; the harness hole is worth a look of its own. */
Database::setSetting('quarantine_dir', $sandbox . '/quarantine-store');
$qdir = Database::storagePath('quarantine') . '/' . date('Y-m-d');
@mkdir($qdir, 0700, true);
@mkdir($home . '/kbroadlines/public_html/node_modules/left-pad', 0755, true);
@mkdir($home . '/inditdel/backups', 0755, true);

$SIG = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';

// The real job id, so the fixture reads like the incident it is about.
Database::query(
    'INSERT INTO scan_jobs (id, scan_type, status, started_at, finished_at, '
  . 'files_scanned, threats_found, scan_path, requested_by) '
  . 'VALUES (?,?,?,?,?,?,?,?,?)',
    [12457, 'quick', 'running', time() - 212400, null, 1200000, 32003,
     '/home/kbroadlines/public_html,/home/inditdel/public_html', '@schedule']
);
$JOB = 12457;

/**
 * Quarantine a file the way Scanner::quarantine() leaves things: the content
 * in the quarantine directory, a row pointing at it, and a placeholder where
 * the file used to be.
 */
$plant = function (string $path, string $content, ?string $sig = null,
                   array $over = []) use ($qdir, $JOB, $SIG): array {
    $sig = $sig ?? $SIG;
    @mkdir(dirname($path), 0755, true);
    $id = Database::insert('threats', array_merge([
        'scan_job_id'  => $JOB,
        'file_path'    => $path,
        'threat_name'  => $sig,
        'threat_type'  => 'malware',
        'severity'     => 'high',
        'status'       => 'quarantined',
        'action_taken' => 'quarantine',
        'hash'         => hash('sha256', $content),
        'size'         => strlen($content),
        'detected_at'  => time() - 3600,
        'resolved_at'  => time() - 3500,
        'cpanel_user'  => explode('/', trim(str_replace($GLOBALS['sgHome'] ?? '', '', $path), '/'))[0] ?? '',
    ], $over));

    $dest = $qdir . '/' . basename($path) . '_' . $id . '.quarantine';
    file_put_contents($dest, $content);
    Database::query('UPDATE threats SET quarantine_path=? WHERE id=?', [$dest, $id]);
    file_put_contents($path . '.serverscrub_removed', "quarantined\n");
    return ['id' => $id, 'dest' => $dest, 'path' => $path];
};
$GLOBALS['sgHome'] = $home;

$md1 = $plant($home . '/kbroadlines/public_html/node_modules/left-pad/README.md',
              "# left-pad\n\nsha 4f8c3d1e9b7a2c5f8e1d0a3b6c9f2e5d8a1b4c7e\n");
$md2 = $plant($home . '/kbroadlines/public_html/node_modules/left-pad/CHANGELOG.md',
              "## 1.3.0\n\ncommit 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b\n");
$tar = $plant($home . '/inditdel/backups/site-2026-11-01.tar',
              str_repeat("TARDATA", 400));
$gz  = $plant($home . '/inditdel/backups/db-2026-11-01.sql.gz',
              str_repeat("GZDATA", 300));
/* The other signature from job 12457 -- the one finding in the run that looks
 * like it could be genuine. What matters here is only that it carries a
 * DIFFERENT signature NAME, so a scope aimed at the false positive can be
 * shown not to drag it back; the bytes are inert (see the note above). */
$php = $plant($home . '/kbroadlines/public_html/shell.php',
              t_inert_payload('stands in for the one finding that may be real'),
              '{HEX}php.cmdshell.gifheader.400.UNOFFICIAL');

// ── A scope is not optional ────────────────────────────────────────────────

$r = QuarantineRestore::run([], ['apply' => true]);
t_ok(empty($r['success']),
     'THERE IS NO "RESTORE EVERYTHING": an unscoped restore is refused, '
   . 'because it would put real detections back alongside the false ones — '
   . 'the mirror image of the fault it exists to fix');
t_contains((string) $r['error'], '--job=',
     'and the refusal names the scopes that are available, since an operator '
   . 'reading it is mid-incident');

// ── Dry run is the default, and it moves nothing ───────────────────────────

$r = QuarantineRestore::run(['job' => $JOB]);
t_ok(!empty($r['dry_run']), 'without --apply the run is a dry run');
t_eq(5, $r['matched'], 'the whole job is five findings in this fixture');
t_eq(5, $r['restored'], 'and all five would be restored');
t_ok(is_file($md1['dest']),
     'NOTHING MOVED: the quarantined copy is still in quarantine');
t_ok(!is_file($md1['path']), 'and the original is still absent');

// ── The 72 archives, without the 154,251 markdown files ────────────────────

$r = QuarantineRestore::run(['job' => $JOB, 'ext' => 'tar,gz,zip']);
t_eq(2, $r['matched'],
     'THE NARROW CASE IS EASY: an extension scope picks out the archives — the '
   . 'files with real customer value — and leaves the documentation alone. On '
   . 'the server this is 72 files out of 154,323');
t_contains($r['scope'], 'extension tar/gz/zip', 'and the scope says what it is');

$r = QuarantineRestore::run(['job' => $JOB, 'ext' => 'tar,gz,zip'], ['apply' => true]);
t_eq(2, $r['restored'], 'both archives are restored');
t_ok(is_file($tar['path']) && is_file($gz['path']), 'and are back on disk');
t_eq(str_repeat('TARDATA', 400), (string) file_get_contents($tar['path']),
     'byte-for-byte what was taken');
t_ok(!is_file($tar['dest']), 'the quarantined copy is gone, not duplicated');
t_ok(!is_file($tar['path'] . '.serverscrub_removed'),
     'and the "this file was removed" placeholder goes with it, or the account '
   . 'owner is left with a note next to the file it is about');
t_ok(!is_file($md1['path']),
     'THE MARKDOWN WAS NOT TOUCHED: the scope was the archives, and a scope '
   . 'that quietly did more than it said would be unusable for this');

$row = Database::fetchOne('SELECT status, action_taken FROM threats WHERE id=?', [$tar['id']]);
t_eq('restored', $row['status'], 'the finding records that it was restored');
t_contains((string) $row['action_taken'], 'restored from quarantine by',
     'with who did it, because this is the audit trail for undoing a detection');

// Re-running must not do the work twice.
$again = QuarantineRestore::run(['job' => $JOB, 'ext' => 'tar,gz,zip'], ['apply' => true]);
t_eq(0, $again['matched'],
     'RESUMABLE: a restored finding leaves the selection, so an interrupted '
   . 'run of 154,323 files can simply be run again');
t_eq(0, $again['restored'], 'and nothing is restored a second time');

// ── By signature, which is how the incident is described ───────────────────

$r = QuarantineRestore::run(['job' => $JOB, 'signature' => $SIG]);
t_eq(2, $r['matched'],
     'the two remaining markdown files match the bad signature by name');
t_ok(strpos($r['scope'], 'signature "' . $SIG . '"') !== false,
     'and the scope quotes the signature exactly');

$r = QuarantineRestore::run(['job' => $JOB, 'signature' => '{HEX}linux.ransom.*']);
t_eq(2, $r['matched'],
     'a trailing * is the one wildcard, so a family of signatures can be named');

$r = QuarantineRestore::run(['signature' => '{HEX}php.cmdshell.gifheader.400.UNOFFICIAL']);
t_eq(1, $r['matched'],
     'and the OTHER signature in that job — the one real-looking finding — is '
   . 'a different scope entirely. Restoring the false positive must not drag '
   . 'the webshell back with it');

// ── Never overwrite what is there now ──────────────────────────────────────

file_put_contents($md1['path'], "# left-pad\n\nreplaced by the customer\n");
$r = QuarantineRestore::run(['id' => (string) $md1['id']], ['apply' => true]);
t_eq(0, $r['restored'], 'a file that exists again is NOT restored over');
t_eq(1, $r['skipped']['a file already exists at the original path'] ?? 0,
     'it is skipped, with the reason named: the customer or their deployment '
   . 'has put something there since, and overwriting it would be a second '
   . 'data loss caused by fixing the first');
t_eq("# left-pad\n\nreplaced by the customer\n", (string) file_get_contents($md1['path']),
     'and what they put there is untouched');
@unlink($md1['path']);

// ── Verify before moving ───────────────────────────────────────────────────

file_put_contents($md2['dest'], "not what was taken\n");
$r = QuarantineRestore::run(['id' => (string) $md2['id']], ['apply' => true]);
t_eq(0, $r['restored'], 'a quarantined copy that does not match its hash is not restored');
t_eq(1, $r['failed']['the quarantined copy does not match the hash recorded when it '
                   . 'was taken'] ?? 0,
     'and it is reported as a FAILURE rather than a skip: the bytes in '
   . 'quarantine are not the bytes that were taken, and writing them over a '
   . 'customer\'s path would be worse than leaving them where they are');
t_ok(!is_file($md2['path']), 'nothing was written');

// ── A missing copy says where it looked ────────────────────────────────────

$lost = $plant($home . '/kbroadlines/public_html/node_modules/left-pad/LICENSE.md', "MIT\n");
@unlink($lost['dest']);
$r = QuarantineRestore::run(['id' => (string) $lost['id']], ['apply' => true]);
t_eq(1, $r['skipped']['the quarantined copy is not on disk any more'] ?? 0,
     'a finding whose quarantined copy has gone is reported, not silently '
   . 'counted as done');
t_ok(count(QuarantineRestore::searchedDirs()) >= 1,
     'and the directories it looked in are available to print — '
   . '`quarantine status` reports a legacy /home/.sentinel-gate/quarantine, '
   . 'and "not on disk" has to mean "not in any of these"');

// ── Ownership and mode ─────────────────────────────────────────────────────

$own = $plant($home . '/inditdel/backups/owned.tar', str_repeat('X', 100), null,
              ['prev_mode' => 0640]);
$r = QuarantineRestore::run(['id' => (string) $own['id']], ['apply' => true]);
t_eq(1, $r['restored'], 'a finding with a recorded mode is restored');
if (DIRECTORY_SEPARATOR === '/') {
    t_eq('0640', substr(sprintf('%o', fileperms($own['path'])), -4),
         'with the mode it had when it was taken, not 0644 — these are files '
       . 'in a customer\'s home and the mode is part of the file');
} else {
    t_ok(true, 'NOT EXERCISED ON WINDOWS: file modes are not POSIX here; the '
             . 'mode assertion runs in the container');
}
t_eq(1, (int) ($r['ownership']['from_record'] + $r['ownership']['not_changed']),
     'and the report says whether the owner came from the record or was '
   . 'inferred from the directory, because "restored" with the wrong owner is '
   . 'a different kind of broken and the operator has to know which files to '
   . 'look at');

$src = t_code($repo . '/backend/lib/QuarantineRestore.php');
$fn  = t_fn_body($src, 'applyOwnership', 'php');
t_contains($fn, '@stat(dirname($dest))',
     'with no record, the owner is taken from the directory the file goes back '
   . 'into — which in a customer home is the account that owns the site. None '
   . 'of the 154,323 files from 10 Nov has a recorded owner, so this is the '
   . 'path that will actually run');
t_contains($fn, 'FALLBACK_MODE',
     'and the mode falls back to a documented constant rather than whatever '
   . 'the quarantine copy happens to carry (0600, set by quarantine itself)');

$qr = t_fn_body($src, 'one', 'php');
$hashPos = strpos($qr, 'hash_file');
$movePos = strpos($qr, 'self::move(');
t_ok($hashPos !== false && $movePos !== false && $hashPos < $movePos,
     'the hash is checked BEFORE the move, not after: afterwards is too late '
   . 'to decide not to');

// ── Batching, and the limit ────────────────────────────────────────────────

$r = QuarantineRestore::run(['job' => $JOB], ['limit' => 1]);
t_eq(1, $r['considered'],
     'a limit bounds one invocation, so 154,323 files can be done in pieces '
   . 'by somebody watching');
t_ok($r['matched'] > 1, 'while still reporting the full size of the scope');

$runFn = t_fn_body($src, 'run', 'php');
t_contains($runFn, 'AND id > ?',
     'paged by id rather than OFFSET: a row that cannot be restored stays '
   . 'quarantined, and an OFFSET-free query would select it again for ever');
t_contains($runFn, 'Logger::info(',
     'and progress is logged per batch, because a run over 154,323 files that '
   . 'says nothing for an hour is indistinguishable from a hung one');

// ── The report shape ───────────────────────────────────────────────────────

$r = QuarantineRestore::run(['job' => $JOB]);
foreach (['matched', 'considered', 'restored', 'skipped', 'failed', 'examples',
          'remaining'] as $k) {
    t_ok(array_key_exists($k, $r), 'the report carries ' . $k);
}
t_ok(is_array($r['skipped']) && is_array($r['failed']),
     'NEVER A BARE SUCCESS COUNT: skipped and failed are reasons with counts, '
   . 'and the examples let an operator go and look at one');

// ── The CLI ────────────────────────────────────────────────────────────────

$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, "case 'restore': {",
     'the command exists — there was no supported way to put a file back at '
   . 'all, which is why I could not give the user one');
t_contains($cli, "require_once \$BASE . '/lib/QuarantineRestore.php';",
     'and the class is required at the TOP of the CLI, not inside the switch '
   . 'arm: a recovery tool that dies with "class not found" the first time it '
   . 'is used is worse than no tool');
t_contains($cli, 'DRY RUN - nothing will be moved. Add --apply to restore.',
     'a dry run says so before it says anything else');
t_contains($cli, 'Suppress the signature:',
     'and after a real restore it says what it has NOT done: these files are '
   . 'back and the next scan will match them again. Choosing silently between '
   . 'a verdict per file and suppressing the signature would hide a hole in '
   . 'the defence');
t_contains($cli, 'need_root();', 'restoring needs root, like every other write path');
