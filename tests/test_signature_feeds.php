<?php
/**
 * Third-party rules arrive, and cannot touch anything until promoted.
 *
 * The product ran on the ClamAV database, weekly, plus twenty hand-written
 * regexes. ClamAV is weak on exactly what matters here -- PHP webshells in a
 * customer's docroot -- so two feeds are pulled alongside it: Linux Malware
 * Detect, written by a hosting operator for shared hosting, and
 * PHP-malware-finder, YARA aimed at webshells.
 *
 * ClamAV loads .ndb/.hdb/.yara from its own database directory, so nothing
 * needs patching. Forking it would mean owning a C codebase and losing
 * upstream security fixes for a feature it already has.
 *
 * THE SAFETY PROPERTY
 *
 * These rules were written by other people for other environments. One that
 * is merely noisy on a workstation takes a working website down here, across
 * every account at once, and the first anyone hears of it is the customer.
 * So a feed arrives in report mode: recorded, displayed, nothing touched.
 *
 * NOTE ON THE FIXTURE
 *
 * The file this creates is deliberately inert. The first version wrote a real
 * one-line webshell and Windows Defender quarantined the test file itself --
 * correctly. applyThreatPolicy() acts on a path and a recorded detection and
 * never reads the contents, so a live sample bought nothing and cost the
 * ability to read the test at all.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// -- Report-only is the default, and not merely documented ------------------
foreach (array_keys(SignatureFeeds::catalogue()) as $feed) {
    t_eq('report', SignatureFeeds::action($feed),
         'THE LOADED GUN: feed "' . $feed . '" defaults to report-only. A feed '
       . 'that promoted itself to deleting files would be the worst possible '
       . 'reading of "keep the signatures up to date"');
}

// -- A detection is traced back to the feed that made it --------------------
t_eq('lmd', SignatureFeeds::feedFor('rfxn.PHP.Shell'),
     'an LMD detection is recognised by its name');
t_eq('pmf', SignatureFeeds::feedFor('YARA.php_malware_finder_eval'),
     'and a php-malware-finder one');
t_eq(null, SignatureFeeds::feedFor('SG.PHP.eval_base64'),
     'OUR OWN RULES ARE NOT A FEED: they keep the behaviour they already '
   . 'had, or this change would quietly stop the scanner acting on anything');
t_eq(null, SignatureFeeds::feedFor('Unix.Trojan.Generic'),
     'and neither is the ClamAV set');

// -- The gate, exercised against a real file --------------------------------
//
// Asserting the branch exists proves nothing: what matters is whether a file
// on disk is still executable afterwards.
$dir = sys_get_temp_dir() . '/sg-feedact-' . getmypid();
@mkdir($dir, 0777, true);
$file = $dir . '/fixture.php';

$make = static function () use ($file) {
    file_put_contents($file, '<?php /* inert fixture */ return 1;');
    @chmod($file, 0644);
};
$modeOf = static function () use ($file): int {
    clearstatcache(true, $file);
    return (int) (@fileperms($file) & 0777);
};

Database::setSetting('auto_quarantine', '1');
$sc = new Scanner();

$make();
$id = Database::insert('threats', [
    'file_path' => $file, 'threat_name' => 'rfxn.PHP.Shell',
    'severity'  => 'critical', 'status' => 'active', 'detected_at' => time(),
]);
$modeBefore = $modeOf();
$r = $sc->applyThreatPolicy($file, $id, 'critical', 'rfxn.PHP.Shell');

t_eq('none', $r['action'],
     'A FEED IN REPORT MODE TOUCHES NOTHING, even with auto-quarantine ON '
   . 'and a critical severity');
t_ok(is_file($file), 'the file is still there');

// Can this filesystem actually take permissions away?
//
// On Windows chmod only toggles a read-only bit, so 0000 is not achievable.
// That is not a reason to skip the test: it is the case disableInfected()
// must refuse rather than report success on, and the first run of this file
// on Windows is what proved the guard works.
@chmod($file, 0000);
clearstatcache(true, $file);
$chmodWorks = ((int) (@fileperms($file) & 0777)) === 0;
@chmod($file, 0644);

// Not asserted as a literal: on a filesystem without POSIX modes the file
// comes back 0666 whatever it was created with. What matters is that the
// report-only path did not CHANGE it.
t_eq($modeBefore, $modeOf(),
     'and the permissions are exactly as the report-only path found them');

// -- Promoted to disable ----------------------------------------------------
t_ok(SignatureFeeds::setAction('lmd', 'disable'), 'a feed can be promoted');

$make();
$id2 = Database::insert('threats', [
    'file_path' => $file, 'threat_name' => 'rfxn.PHP.Shell',
    'severity'  => 'critical', 'status' => 'active', 'detected_at' => time(),
]);
$r2 = $sc->applyThreatPolicy($file, $id2, 'critical', 'rfxn.PHP.Shell');

if ($chmodWorks) {
    t_eq('disabled', $r2['action'], 'it disables rather than deletes');
    t_ok(is_file($file),
         'THE REVERSIBLE ANSWER: the file is still on disk. A false positive '
       . 'costs one chmod to undo instead of a restore from backup');
    t_eq(0, $modeOf(), 'but nothing can execute it');

    $row = Database::fetchOne('SELECT status, prev_mode FROM threats WHERE id=?', [$id2]);
    t_eq('disabled', $row['status'], 'the threat row says so');
    t_eq(0644, (int) $row['prev_mode'],
         'and remembers the mode that was taken away -- without that, '
       . 'disabling is a one-way door and nobody can put a false positive back');

    $back = Scanner::reEnable($id2);
    t_ok(!empty($back['success']), 'a disabled file can be re-enabled');
    t_eq(0644, $modeOf(), 'restored to exactly the mode it had, not a guess');
    $row2 = Database::fetchOne('SELECT status FROM threats WHERE id=?', [$id2]);
    t_eq('active', $row2['status'],
         'and it goes back to being an open finding, because the file is '
       . 'executable again and still flagged');
} else {
    // THE LIE THAT WOULD MATTER MOST. Reporting a file as neutralised when
    // its permissions never changed leaves a live webshell marked handled,
    // and nobody looks at it again.
    t_eq('failed', $r2['action'],
         'A FILESYSTEM THAT CANNOT TAKE PERMISSIONS AWAY gets an honest '
       . 'failure, not a claim that the file was neutralised');
    t_contains((string) ($r2['error'] ?? ''), 'could not remove permissions',
         'and the reason names the filesystem rather than blaming the file');

    $row = Database::fetchOne('SELECT status FROM threats WHERE id=?', [$id2]);
    t_eq('active', $row['status'],
         'the threat stays open, because nothing was actually done to it');
    t_ok(is_file($file), 'and the file is left exactly as it was found');
}

// -- Our own detections are unaffected by any of this -----------------------
$make();
$id3 = Database::insert('threats', [
    'file_path' => $file, 'threat_name' => 'SG.PHP.eval_base64',
    'severity'  => 'critical', 'status' => 'active', 'detected_at' => time(),
]);
$r3 = $sc->applyThreatPolicy($file, $id3, 'critical', 'SG.PHP.eval_base64');
t_ok($r3['action'] !== 'none',
     'OUR RULES STILL ACT: the feed gate does not disarm the scanner for '
   . 'detections that never came from a feed');

@unlink($file);
@rmdir($dir);
Database::setSetting('auto_quarantine', '0');
SignatureFeeds::setAction('lmd', 'report');

// -- The download is bounded and checked ------------------------------------
$src = t_code($repo . '/backend/lib/SignatureFeeds.php');
t_contains($src, 'private const MAX_BYTES = 33554432;',
     'BOUNDED: a feed that grows without limit must not fill the disk every '
   . 'account on this server shares');
t_contains($src, 'stripos($head, ',
     'THE CAPTIVE PORTAL: an HTML error page written into the ClamAV database '
   . 'directory stops clamscan starting at all -- worse than being out of date');
t_contains($src, '$tmp = $dest . ',
     'and each file is written aside and renamed in, so a half-finished '
   . 'download never becomes a database ClamAV tries to load');
t_contains($src, 'CURLOPT_SSL_VERIFYPEER => true',
     'fetched over verified TLS -- these become executable detection logic '
   . 'on every account');

// A feed being unreachable must not fail the whole signature update: the
// ClamAV database still updated, and reporting failure would hide that.
$sc2 = t_code($repo . '/backend/lib/Scanner.php');
t_contains($sc2, '$feeds = SignatureFeeds::update();',
     'the weekly signature task pulls the feeds');
t_contains($sc2, 'Signature feeds: ',
     'and an unreachable feed is logged, not thrown -- freshclam still ran');
