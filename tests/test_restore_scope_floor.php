<?php
/**
 * `quarantine restore --signature='*' --apply` PUT A WEBSHELL BACK ON A LIVE
 * DOCROOT AND EXITED 0.
 *
 * `QuarantineRestore::selector()` refuses a restore with NO scope — "Refusing
 * to restore without a scope… 'Everything' would put real detections back as
 * well as false ones" — but it never checked that the scope given was narrow.
 * `--signature='*'` became `threat_name LIKE '%'`: every quarantined row, in
 * every job, for every account, under every signature. `--ext=md` alone is the
 * same hole by another route, and on job 12457 that is 154,252 files — which
 * are the 30 Apr qTox ransom notes.
 *
 * The context is what makes this urgent rather than theoretical. Restore
 * exists for the operator who has just had 154,323 of their customers' files
 * quarantined. The operator who reaches for it is, by definition, mid-incident
 * — and on this server the same event involved real ransomware. One wildcard
 * and they hand the attacker's files back.
 *
 * `04aefc1` already applies an eight-character floor to a suppression prefix,
 * which only switches detection off. The path that writes attacker code onto a
 * customer's disk had no floor at all.
 *
 * Fixtures are inert: see t_inert_payload() in tests/assert.php.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

require_once $repo . '/backend/lib/QuarantineRestore.php';

$SHELL  = '{HEX}php.cmdshell.gifheader.400.UNOFFICIAL';
$RANSOM = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';

$job = (int) Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'done', 'started_at' => time() - 7200,
    'files_scanned' => 500000, 'threats_found' => 2, 'scan_path' => '/home',
    'requested_by' => '@schedule',
]);
foreach ([[ '/home/victim/public_html/evil.php', $SHELL, 'victim'],
          [ '/home/victim/README.md',            $RANSOM, 'victim']] as $f) {
    Database::insert('threats', [
        'scan_job_id' => $job, 'file_path' => $f[0], 'threat_name' => $f[1],
        'threat_type' => 'malware', 'severity' => 'critical',
        'status' => 'quarantined', 'action_taken' => 'quarantine',
        'hash' => hash('sha256', $f[0]), 'size' => 1400,
        'detected_at' => time(), 'cpanel_user' => $f[2],
    ]);
}

// ── The wildcard that matched everything ───────────────────────────────────

$sel = QuarantineRestore::selector(['signature' => '*']);
t_ok(isset($sel['error']),
     'A BARE `--signature=*` IS REFUSED. It became `threat_name LIKE \'%\'` — '
   . 'every quarantined file on the server — and restored a '
   . 'php.cmdshell webshell to /home/victim/public_html/evil.php with exit 0');
t_contains((string) $sel['error'], '8',
     'with the same eight-character floor a suppression prefix has had since '
   . '04aefc1. That one only switches detection off; this one writes attacker '
   . 'code back onto a customer\'s disk');

t_ok(isset(QuarantineRestore::selector(['signature' => '{HEX}*'])['error']),
     'and six characters of "{HEX}" is refused too, which would have reached '
   . 'every hex signature in the database');

$ok = QuarantineRestore::selector(['signature' => '{HEX}php.cmdshell.gifheader*']);
t_ok(!isset($ok['error']),
     'A SPECIFIC PREFIX STILL WORKS. The floor is on how little an operator '
   . 'may say, not on their ability to name a family of signatures — undoing '
   . 'one bad feed\'s work is what the wildcard is for');
t_contains((string) $ok['desc'], 'php.cmdshell.gifheader',
     'and the description names what it will match, because that is what the '
   . 'dry run shows before anything moves');

// ── The extension that matched everything ──────────────────────────────────

$sel = QuarantineRestore::selector(['ext' => 'md']);
t_ok(isset($sel['error']),
     '`--ext=md` ALONE IS REFUSED. On job 12457 that is 154,252 files, and '
   . 'those files are the ransom notes a root-level intruder left in nearly '
   . 'every directory of nearly every account');
t_contains((string) $sel['error'], '--job=',
     'and the refusal names what to add, because an operator mid-incident '
   . 'needs the next command and not a lecture');

$scoped = QuarantineRestore::selector(['job' => $job, 'ext' => 'tar,gz,zip']);
t_ok(!isset($scoped['error']),
     'THE DOCUMENTED USE STILL WORKS: `--job=N --ext=tar,gz,zip` is how the 72 '
   . 'archives in that job — plausibly a customer\'s own backups — are handed '
   . 'back first. An extension may NARROW a restore; it may not define one');

$acct = QuarantineRestore::selector(['account' => 'victim', 'ext' => 'md']);
t_ok(!isset($acct['error']),
     'and an account is narrow enough to carry an extension too: "every .md we '
   . 'took from this one customer" is a scope somebody can be accountable for');

// ── Still refused with nothing at all ──────────────────────────────────────

t_ok(isset(QuarantineRestore::selector([])['error']),
     'and an empty scope is still refused, which is the check that already '
   . 'existed and is not weakened by any of the above');

// ── The counting and listing paths honour it too ───────────────────────────

$c = QuarantineRestore::count(['signature' => '*']);
t_ok(isset($c['error']),
     'count() refuses it as well, so the dry run cannot report "154,323 files '
   . 'would be restored" as though it were an available option');

$run = QuarantineRestore::run(['signature' => '*'], ['apply' => true]);
t_ok(empty($run['success']),
     'AND --apply CANNOT GET PAST IT. This is the call that ran on the test '
   . 'server: one command, no dry run, exit 0, a webshell back under a live '
   . 'docroot');
t_eq('quarantined', (string) Database::fetchOne(
        'SELECT status FROM threats WHERE file_path=?',
        ['/home/victim/public_html/evil.php'])['status'],
     'and the webshell is still in quarantine where it belongs');

// ── Where the floor lives ──────────────────────────────────────────────────

$sel = t_fn_body(t_code($repo . '/backend/lib/QuarantineRestore.php'),
                 'selector', 'php');
t_contains($sel, '$narrow',
     'the floor is applied in selector(), which is the single place every '
   . 'caller — count(), breakdown(), run() and the CLI — gets its WHERE clause '
   . 'from. Applied in the CLI instead, the API would still have the hole');
