<?php
/**
 * The ROLLBACK ITSELF must not be a false claim.
 *
 * 7f397eb fixed the 7 Nov outage: setMode() now snapshots both config files
 * and restores them when apachectl rejects the result. test_waf_config_rollback
 * covers the happy path of that fix.
 *
 * This file covers the part that is still wrong. restoreConfig() is:
 *
 *     foreach ($snap as $p => $contents) {
 *         if ($contents === null) { @unlink($p); continue; }
 *         @file_put_contents($p, $contents);
 *         @chmod($p, 0644);
 *     }
 *
 * Nothing looks at what @file_put_contents or @unlink returned. setMode() then
 * returns 'rolled_back' => true unconditionally. So when the restore fails the
 * product reports a rollback that did not happen, and the config Apache
 * rejected is still on disk -- which is precisely the state that took
 * host.lws-s1.com down for 132 accounts:
 *
 *     AH00526: Syntax error on line 56 of .../REQUEST-913-SCANNER-DETECTION.conf
 *     ModSecurity: Found another rule with the same id
 *     [RESTART FAILURE] httpd.conf rebuild exited 25 during forced restart
 *
 * The fix closed the window where the file is left behind BY CHOICE and left
 * open the window where it is left behind BY ACCIDENT. Both end with Apache
 * refusing to start hours later, and the second one is worse, because the
 * operator has been told in writing that it was rolled back.
 *
 * ── WHY THE RESTORE CAN FAIL ON A REAL SERVER ────────────────────────────────
 *
 * The runner callback below fires from inside validateApache(), which is
 * exactly between the write and the restore. Everything that can happen in
 * that window on a live server lands there, and `apachectl -t` against a full
 * CRS on a 132-account box is not instant:
 *
 *   - the filesystem holding /etc fills up (ENOSPC; note that
 *     file_put_contents returns a SHORT COUNT, not false, so a truncated
 *     config is written and reported as a successful restore)
 *   - a config-management agent re-asserts ownership or mode
 *   - chattr +i, which some hardening guides apply to /etc/httpd/conf.d
 *   - the filesystem is remounted read-only after an I/O error
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

$cdir = $sandbox . '/wafconf';
$idir = $sandbox . '/wafinc';
@mkdir($cdir, 0700, true);
@mkdir($idir, 0700, true);
WAFInstaller::setConfDir($cdir);
WAFInstaller::setIncludeDir($idir);

$conf = $cdir . '/serverscrub-waf.conf';
$inc  = WAFInstaller::includePath();

// A known-good config to roll back TO.
WAFInstaller::setRunner(fn(string $cmd) => ['out' => 'Syntax OK', 'code' => 0]);
WAFInstaller::setMode('detectiononly');
$good = (string) @file_get_contents($conf);
t_contains($good, 'SecRuleEngine DetectionOnly', 'baseline: a working config is in place');

// ── 1. A restore that fails must not be reported as a rollback ──────────────

// Making the file read-only is enough on Windows, and NOT enough on Linux:
// the product runs as root there, and root ignores the permission bits. The
// suite passed these assertions in the container for that reason alone while
// the defect was fully present -- confirmed by hand, as root, inside the
// container, by replacing the file with a directory.
//
// So do that here: a directory at the config path defeats file_put_contents
// for root too (EISDIR), on every platform. Same failure the real cases
// produce -- ENOSPC, a read-only remount, chattr +i -- reached portably.
$locked = false;
WAFInstaller::setRunner(function (string $cmd) use (&$locked, $conf) {
    if (!$locked) {
        $locked = true;
        @chmod($conf, 0444);
        @unlink($conf);
        @mkdir($conf, 0755, true);   // the restore target is now un-writable
    }
    return ['out' => "AH00526: Syntax error on line 56 of REQUEST-913-SCANNER-DETECTION.conf"
                   . "\nModSecurity: Found another rule with the same id",
            'code' => 1];
});
$bad = WAFInstaller::setMode('on');

// Undo the trap before asserting, so a failure here leaves a usable sandbox.
if (is_dir($conf)) { @rmdir($conf); }
@chmod($conf, 0666);

$onDisk = is_file($conf) ? (string) @file_get_contents($conf) : '';
$restoreWorked = ($onDisk === $good);

t_ok(empty($bad['success']), 'a rejected config is still reported as a failure');

// This is the assertion that matters. Either the restore succeeded, or the
// product must NOT claim it did.
t_ok($restoreWorked || empty($bad['rolled_back']),
     'THE CLAIM MUST MATCH THE DISK: setMode() must not return '
   . "rolled_back => true when restoreConfig() could not write the file back. "
   . 'restoreConfig() ignores the return of @file_put_contents and @unlink, so '
   . 'it cannot tell. The operator reads "rolled back" and stops looking, and '
   . 'the config Apache refuses is still there for the next restart');

t_ok($restoreWorked || strpos($bad['error'], 'rolled back') === false,
     'and the error text must not say "rolled back" when nothing was put back');

t_ok($restoreWorked || strpos($onDisk, 'SecRuleEngine On') === false,
     'THE OUTAGE STATE: the rejected mode must not be the one left on disk. '
   . 'Apache keeps serving what it parsed at its last start, so this is '
   . 'invisible until a kernel update, a cPanel upgrade or a 3am reboot');

t_ok($restoreWorked || WAFInstaller::currentMode() !== 'on',
     'and currentMode() must not report the mode that was rejected and '
   . 'supposedly rolled back -- the dashboard reads this');

// ── 2. "The restore does not validate either" must not be the only signal ───
//
// setMode() does re-validate after restoring and sets restored_ok. But a
// FAILED RESTORE and a CONFIG THAT WAS ALREADY BROKEN produce an identical
// result shape, and the message blames the second one:
//
//   "WARNING: the restored config does not validate either, so Apache may
//    already have been unable to restart before this change"
//
// That sentence points the operator at a pre-existing fault when the real
// cause is that this call just failed to clean up after itself.
t_ok($restoreWorked || strpos($bad['error'], 'already have been unable') === false,
     'a failed restore must not be reported as a pre-existing fault. The '
   . 'operator is told Apache "may already have been unable to restart before '
   . 'this change" when in fact this change is what left the file there');

// ── 3. No apachectl is not "Apache rejected the change" ─────────────────────
//
// validateApache() returns ok=false with 'Could not run an Apache syntax
// check' when it finds no validator, and setMode() feeds that straight into
// "Apache rejected the change". Apache rejected nothing; there was no Apache
// to ask. On this very container there is no httpd, and on a Debian host
// /usr/sbin/apachectl does not exist at all.
WAFInstaller::setRunner(fn(string $cmd) => ['out' => '', 'code' => 127]);
$v = WAFInstaller::validateApache();
t_ok(empty($v['ok']), 'with no validator present, validateApache() does not claim success');
t_contains($v['output'], 'Could not run an Apache syntax check',
           'and says so in its own words');

$none = WAFInstaller::setMode('on');
t_ok(empty($none['success']), 'and the mode change does not claim success either');
t_ok(strpos((string) ($none['error'] ?? ''), 'Apache rejected') === false,
     'but it must NOT say "Apache rejected the change" when no Apache was '
   . 'consulted. That is a false statement about what happened, and it sends '
   . 'the operator looking for a syntax error that does not exist');

// ── 4. A missing FIRST candidate must not end the search ────────────────────
//
// validateApache() loops over four binaries and returns on the first whose
// output is non-empty. sh() captures stderr, so a binary that is absent
// produces "No such file or directory" -- non-empty -- and the loop returns
// ok=false without ever trying apache2ctl. Every candidate after the first
// is unreachable on any host where /usr/sbin/apachectl is missing, which is
// every Debian/Ubuntu host; includePath() claims to support those.
WAFInstaller::setRunner(function (string $cmd) {
    if (strpos($cmd, '/usr/sbin/apachectl') !== false
        || strpos($cmd, '/usr/sbin/httpd') !== false) {
        return ['out' => 'sh: line 1: ' . trim(explode(' ', $cmd)[0], "'")
                       . ': No such file or directory', 'code' => 127];
    }
    return ['out' => 'Syntax OK', 'code' => 0];   // apache2ctl is present and happy
});
$v2 = WAFInstaller::validateApache();
t_ok(!empty($v2['ok']),
     'a working validator later in the list must still be found. The absent '
   . 'first candidate writes to stderr, sh() folds stderr into out, and the '
   . 'non-empty output makes the loop return "rejected" without trying '
   . 'apache2ctl -- so a mode can never be set on a host whose apachectl is '
   . 'not at /usr/sbin/apachectl');

// ── 5. The mode shown must mean the WAF is actually loaded ──────────────────
//
// currentMode() parses SecRuleEngine out of our own config file and never
// checks that the Apache include which makes Apache read that file exists.
// install() on a validation failure calls disableConfig(), which unlinks the
// include and LEAVES the config -- so the panel reports a blocking WAF that
// Apache is not loading at all.
WAFInstaller::setRunner(fn(string $cmd) => ['out' => 'Syntax OK', 'code' => 0]);
WAFInstaller::setMode('on');
@unlink($inc);
$st = WAFInstaller::status();
t_ok(!is_file($inc), 'with the Apache include removed');
t_ok(($st['mode'] ?? '') !== 'on' || ($st['include_present'] ?? null) === false,
     'status() must not report mode "on" without saying the include is gone. '
   . 'Nothing of ours is loaded by Apache, no request is being filtered, and '
   . 'the dashboard shows a WAF in blocking mode -- protection the product '
   . 'cannot deliver');

// ── 6. Structure: the restore result has to be checked at all ──────────────

$src = t_code($repo . '/backend/lib/WAFInstaller.php');
t_ok(strpos($src, '@file_put_contents($p, $contents);') === false,
     'restoreConfig() must not discard the result of its write. Every other '
   . 'write in this class is checked -- writeConfig() tests both of its '
   . 'file_put_contents calls -- and the one write whose failure recreates the '
   . 'outage is the one that is not');
