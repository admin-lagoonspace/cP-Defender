<?php
/**
 * A rollback is only a rollback if the bytes are back on the disk.
 *
 * 7 Nov: WAFInstaller::setMode() wrote a ModSecurity config, `apachectl -t`
 * rejected it, and the rejected file was LEFT ON DISK. Apache went on serving
 * the configuration it had already parsed, so nothing looked wrong. Ten hours
 * later the first restart failed:
 *
 *     AH00526: Syntax error on line 56 of REQUEST-913-SCANNER-DETECTION.conf
 *     ModSecurity: Found another rule with the same id
 *
 * cPanel retried three times, rebuilt httpd.conf, and gave up. nginx returned
 * 502 for all 132 accounts. The fix (7f397eb) added a snapshot and a restore —
 * and then discarded the result of both of the restore's writes:
 *
 *     foreach ($snap as $p => $contents) {
 *         if ($contents === null) { @unlink($p); continue; }
 *         @file_put_contents($p, $contents);
 *         @chmod($p, 0644);
 *     }
 *
 * while setMode() returned 'rolled_back' => true unconditionally. So the
 * window where the rejected file is left behind BY CHOICE was closed and the
 * window where it is left behind BY ACCIDENT was left open — and the second is
 * worse, because the operator has a sentence in writing telling them it was
 * put back, so they stop looking.
 *
 * This file is about the things that must be true of the restore itself.
 * tests/test_waf_rollback_honesty.php asserts the product does not CLAIM more
 * than it did; this one asserts what it does.
 *
 * WHY A RESTORE FAILS ON A REAL SERVER, all inside the window `apachectl -t`
 * occupies (seconds, against the full CRS, on a 132-account box): /etc fills
 * up; a config-management agent re-asserts the file; `chattr +i`, which
 * several hardening guides apply to the Apache conf.d; the filesystem
 * remounts read-only after an I/O error.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

$cdir = $sandbox . '/rv-conf';
$idir = $sandbox . '/rv-inc';
@mkdir($cdir, 0700, true);
@mkdir($idir, 0700, true);
WAFInstaller::setConfDir($cdir);
WAFInstaller::setIncludeDir($idir);

$conf = $cdir . '/serverscrub-waf.conf';
$inc  = WAFInstaller::includePath();

$okRunner  = function (string $cmd) { return ['out' => 'Syntax OK', 'code' => 0]; };
$apacheNo  = "AH00526: Syntax error on line 56 of REQUEST-913-SCANNER-DETECTION.conf"
           . "\nModSecurity: Found another rule with the same id";

// ── 1. restoreConfig() reports per path, and verifies by reading back ───────

$probe = $sandbox . '/rv-probe.conf';
file_put_contents($probe, "original bytes\n");

$r = WAFInstaller::restoreConfig([$probe => "original bytes\n"]);
t_ok($r['ok'], 'restoring a writable file succeeds');
t_eq([], $r['failed'], 'and reports nothing failed');
t_eq("original bytes\n", (string) file_get_contents($probe),
     'with the snapshot bytes on disk');

// A directory at the target defeats file_put_contents for root too (EISDIR),
// which is the portable stand-in for ENOSPC, chattr +i and a read-only
// remount: all of them are "the write did not happen".
@unlink($probe);
@mkdir($probe, 0755, true);
$r = WAFInstaller::restoreConfig([$probe => "original bytes\n"]);
t_ok(empty($r['ok']),
     'A RESTORE THAT DID NOT HAPPEN IS REPORTED AS A FAILURE. The version this '
   . 'replaces discarded the return of file_put_contents entirely, so it could '
   . 'not tell, and setMode() said "rolled back" either way');
t_eq(1, count($r['failed']), 'one path failed');
t_eq($probe, $r['failed'][0]['path'] ?? null,
     'and the result NAMES it — an operator who has to move a file aside by '
   . 'hand needs the path, not a boolean');
@rmdir($probe);

// A file that did not exist before must come back as absent, not as an empty
// file: an empty SecRuleEngine config and no config are different to Apache.
file_put_contents($probe, "written since the snapshot\n");
$r = WAFInstaller::restoreConfig([$probe => null]);
t_ok($r['ok'], 'a file that did not exist before is removed');
t_ok(!is_file($probe), 'and is actually gone');

// ...and a removal that fails is a failure. Read-only is enough on Windows;
// on Linux as root it is not, so the directory stands in there.
$blocked = $sandbox . '/rv-blocked';
@mkdir($blocked, 0755, true);
file_put_contents($blocked . '/keeper', 'x');   // a non-empty dir cannot rmdir
$r = WAFInstaller::restoreConfig([$blocked => null]);
t_ok(empty($r['ok']),
     'a file that cannot be removed is reported as a failed restore, not '
   . 'assumed gone — @unlink\'s return was thrown away before');

// ── 2. A short write is a failed restore, not a successful one ──────────────
//
// file_put_contents() on a full filesystem returns a SHORT BYTE COUNT, not
// false. Testing `=== false` would accept a truncated ModSecurity config as a
// restored one, and a truncated config is a config Apache refuses. ENOSPC
// cannot be produced in a sandbox, so this one is asserted on the source.

$src     = t_code($repo . '/backend/lib/WAFInstaller.php');
$restore = t_fn_body($src, 'restoreConfig', 'php');
t_contains($restore, 'strlen($want)',
     'the bytes WRITTEN are compared against the bytes to write: a full disk '
   . 'returns a count, not an error, and === false would miss it');
t_contains($restore, 'file_get_contents($p)',
     'and the file is read back and compared, because the count says what the '
   . 'call believes it wrote and not what the filesystem holds');
t_ok(strpos($restore, '@unlink($p);') !== false
     && strpos($restore, 'file_exists($p)') !== false,
     'the removal is checked by looking for the file afterwards');

// ── 3. setMode(): a failed rollback is an emergency, and is said so ─────────

WAFInstaller::setRunner($okRunner);
WAFInstaller::setMode('detectiononly');
$good = (string) file_get_contents($conf);
t_contains($good, 'SecRuleEngine DetectionOnly', 'baseline: a working config is in place');

// The trap fires from inside validateApache(), which is exactly the window
// between the write and the restore.
$trapped = false;
WAFInstaller::setRunner(function (string $cmd) use (&$trapped, $conf, $apacheNo) {
    if (strpos($cmd, '-t') !== false && !$trapped) {
        $trapped = true;
        @chmod($conf, 0444);
        @unlink($conf);
        @mkdir($conf, 0755, true);      // the restore target is now unwritable
    }
    return ['out' => $apacheNo, 'code' => 1];
});
$bad = WAFInstaller::setMode('on');
if (is_dir($conf)) { @rmdir($conf); }

t_ok($trapped, 'the trap fired inside the validation window');
t_ok(empty($bad['success']), 'the rejected config is reported as a failure');
t_ok(isset($bad['rolled_back']) && $bad['rolled_back'] === false,
     'THE CLAIM MATCHES THE DISK: rolled_back is false, because the previous '
   . 'config could not be written back');
t_contains((string) $bad['error'], 'could NOT be put back',
     'and the operator is told that in those words');
t_ok(strpos((string) $bad['error'], 'rolled back') === false,
     'the words "rolled back" do not appear anywhere in a failure that did not '
   . 'roll anything back');
t_ok(strpos((string) $bad['error'], 'already have been unable') === false,
     'and a failed restore is not blamed on a pre-existing fault: this call is '
   . 'what left the file there, and sending the operator after an older '
   . 'problem costs the only thing they do not have');

// The escalation: if the previous config cannot be put back, the rejected one
// must not be left for Apache to read. No WAF config is a server with no WAF;
// a config Apache refuses is a server that will not start.
$onDisk = is_file($conf) ? (string) file_get_contents($conf) : '';
t_ok(strpos($onDisk, 'SecRuleEngine On') === false,
     'THE OUTAGE STATE IS NOT REACHED: the config Apache has already refused '
   . 'is not what is left on the disk for the next restart');
t_ok(!is_file((string) $inc),
     'and the Apache include is removed too, so Apache reads nothing of ours '
   . 'at all — the include and the config are in different directories, so a '
   . 'filesystem fault under one does not necessarily stop the other');
t_ok(WAFInstaller::currentMode() !== 'on',
     'and the mode the panel reads is not the rejected one');

// ── 4. No syntax checker is not a verdict from Apache ──────────────────────

@mkdir($cdir, 0700, true);
WAFInstaller::setRunner($okRunner);
WAFInstaller::setMode('detectiononly');
$good = (string) file_get_contents($conf);

WAFInstaller::setRunner(function (string $cmd) { return ['out' => '', 'code' => 127]; });
$none = WAFInstaller::setMode('on');
t_ok(empty($none['success']), 'with nothing to check with, the mode is not applied');
t_ok(strpos((string) $none['error'], 'Apache rejected') === false,
     '"could not check" is not "checked and rejected". Apache was never asked, '
   . 'and attributing a rejection to it sends the operator looking for a '
   . 'syntax error that no program has ever reported');
t_eq($good, (string) @file_get_contents($conf),
     'and the config on disk is byte-for-byte the one that was working');

// ── 5. validateApache() has three outcomes, not two ────────────────────────

WAFInstaller::setRunner($okRunner);
$v = WAFInstaller::validateApache();
t_ok($v['ran'] && $v['ok'], 'a validator that accepts: ran and ok');

WAFInstaller::setRunner(function (string $cmd) use ($apacheNo) {
    return ['out' => $apacheNo, 'code' => 1];
});
$v = WAFInstaller::validateApache();
t_ok($v['ran'] && empty($v['ok']), 'a validator that refuses: ran, not ok');
t_contains($v['output'], 'same id',
     "and Apache's own words are passed through — the reason is the only thing "
   . 'that tells an operator what to fix');

WAFInstaller::setRunner(function (string $cmd) {
    return ['out' => 'sh: apachectl: No such file or directory', 'code' => 127];
});
$v = WAFInstaller::validateApache();
t_ok(empty($v['ran']) && empty($v['ok']),
     'and no validator at all: NOT ran, so nothing may be claimed on Apache\'s '
   . 'behalf, including failure');

// Every candidate is tried. sh() folds stderr into out, so the old loop
// returned "rejected" on the first binary that was merely absent, and
// apache2ctl — the Debian name — was unreachable. includePath() claims to
// support Debian.
WAFInstaller::setRunner(function (string $cmd) {
    if (strpos($cmd, 'apache2ctl') !== false) { return ['out' => 'Syntax OK', 'code' => 0]; }
    return ['out' => 'sh: line 1: No such file or directory', 'code' => 127];
});
$v = WAFInstaller::validateApache();
t_ok(!empty($v['ran']) && !empty($v['ok']),
     'a working validator later in the list is still found');
t_contains((string) $v['binary'], 'apache2ctl', 'and the one that answered is named');

// ── 6. Structure: the decision cannot drift back ───────────────────────────

$setMode = t_fn_body($src, 'setMode', 'php');
t_contains($setMode, 'NO_CHECKER_ERR',
     'setMode() refuses the change outright when the host has no syntax '
   . 'checker, BEFORE writing anything: writing an unvalidated ModSecurity '
   . 'config to a server that cannot be asked about it is the 7 Nov outage, '
   . 'and it stays invisible until the next restart');
// Stronger than it looks: a literal `true` here is exactly how the product
// came to report a rollback it had not performed, and the only safe rule is
// that the value is always read off the restore result -- in every branch,
// including the ones where it is already known.
$waf = t_code($repo . '/backend/lib/WAF.php');
t_ok(strpos($src, "'rolled_back' => true") === false
     && strpos($waf, "'rolled_back' => true") === false,
     'rolled_back is never a literal true anywhere: it is derived from what '
   . 'restoreConfig() reported, in WAFInstaller and in WAF::addCustomRule '
   . 'alike. The outage was reported to the operator as a completed rollback');

// ── 7. The two subtlest checks, each pinned on its own ─────────────────────
//
// Shakaal mutation-tested the restore and found that deleting EITHER the
// short-write check or the byte-readback left the whole suite green. Those two
// checks are the fix, and nothing guarded them.
//
// ENOSPC cannot be produced in a sandbox, so the filesystem is replaced by one
// that misbehaves in each of the ways that matter. Each case below asserts the
// EXACT reason reported, because the three failure branches all end in
// ok => false: only the reason distinguishes them, so only the reason can tell
// you that the branch you think is doing the work is the one that did.
//
// The wrapper is not a realistic filesystem. It asks one question per case:
// "was the path openable?", "was the byte count looked at?", "was the file
// read back?"

class SgRestoreProbe
{
    /** 'short'  — accepts half the data and then refuses: a full filesystem. */
    /** 'lying'  — reports every byte written and keeps half: a cache that
     *             loses the tail, or anything that rewrites the file after us. */
    /** 'honest' — behaves. */
    public static $mode = 'short';
    public static $stored = '';
    public static $pos = 0;
    public static $calls = 0;
    public $context;

    public function stream_open($path, $mode, $options, &$opened)
    {
        if (strpos($mode, 'r') === 0) { self::$pos = 0; return true; }
        self::$stored = '';
        self::$calls  = 0;
        return true;
    }

    public function stream_write($data)
    {
        self::$calls++;
        if (self::$mode === 'short') {
            // Half, once, and nothing after that. fwrite() reports the count
            // it managed; file_put_contents() would report false and lose it.
            if (self::$calls > 1) { return 0; }
            $n = (int) floor(strlen($data) / 2);
            self::$stored .= substr($data, 0, $n);
            return $n;
        }
        if (self::$mode === 'lying') {
            self::$stored .= substr($data, 0, (int) floor(strlen($data) / 2));
            return strlen($data);
        }
        self::$stored .= $data;
        return strlen($data);
    }

    public function stream_read($count)
    {
        $chunk = substr(self::$stored, self::$pos, $count);
        self::$pos += strlen($chunk);
        return $chunk;
    }

    public function stream_eof() { return self::$pos >= strlen(self::$stored); }
    public function stream_stat() { return $this->url_stat('', 0); }
    public function stream_close() { return true; }
    public function stream_flush() { return true; }

    public function url_stat($path, $flags)
    {
        return ['dev' => 0, 'ino' => 0, 'mode' => 0100644, 'nlink' => 1, 'uid' => 0,
                'gid' => 0, 'rdev' => 0, 'size' => strlen(self::$stored), 'atime' => 0,
                'mtime' => 0, 'ctime' => 0, 'blksize' => -1, 'blocks' => -1];
    }
}

stream_wrapper_register('sgprobe', 'SgRestoreProbe');
$probePath = 'sgprobe://restore-target.conf';
$snapshot  = str_repeat("SecRuleEngine DetectionOnly\n", 40);   // 1,080 bytes
$half      = (int) floor(strlen($snapshot) / 2);

$reasonOf = static function (array $r) {
    return (string) ($r['failed'][0]['reason'] ?? '');
};

// (a) The honest case first, so a failure below cannot be the harness.
SgRestoreProbe::$mode = 'honest';
$r = WAFInstaller::restoreConfig([$probePath => $snapshot]);
t_ok(!empty($r['ok']), 'a filesystem that behaves restores cleanly through the probe');
t_eq($snapshot, SgRestoreProbe::$stored, 'with every byte of the snapshot written');

// (b) A FULL FILESYSTEM: half the config written, and the count says so.
//     This is the case the whole check exists for. If the byte comparison is
//     removed, the readback catches it instead and the reason changes — which
//     is why the reason is what is asserted.
SgRestoreProbe::$mode = 'short';
$r = WAFInstaller::restoreConfig([$probePath => $snapshot]);
t_ok(empty($r['ok']),
     'A SHORT WRITE IS A FAILED RESTORE: half a ModSecurity config is still a '
   . 'config Apache will refuse, and the operator must not be told the '
   . 'previous one was put back');
t_eq($half, strlen(SgRestoreProbe::$stored),
     'sanity: half of it really is on disk');
t_contains($reasonOf($r), 'only ' . $half . ' of its ' . strlen($snapshot) . ' bytes',
     'AND THE COUNT IS WHAT CAUGHT IT: the reason names how much was written, '
   . 'which is both the proof that the byte comparison ran and the one thing '
   . 'that tells an operator the file on disk is now truncated and /etc is '
   . 'full. A "could not be written" message here would mean the comparison '
   . 'was gone and something else had noticed');

// (c) A filesystem that reports success and did not keep it. Only reading the
//     file back can see this.
SgRestoreProbe::$mode = 'lying';
$r = WAFInstaller::restoreConfig([$probePath => $snapshot]);
t_ok(empty($r['ok']),
     'THE FILE IS READ BACK AND COMPARED: the byte count is what the call '
   . 'believes it wrote, not what the filesystem holds');
t_contains($reasonOf($r), 'reads back',
     'and the reason says the readback is what failed, so removing that check '
   . 'cannot pass unnoticed');

// (d) A path that cannot be opened at all — a different branch, a different
//     reason, and the one a directory in the way produces.
SgRestoreProbe::$mode = 'honest';
$r = WAFInstaller::restoreConfig(['sgprobe-missing://nope' => $snapshot]);
t_ok(empty($r['ok']), 'a path that cannot be opened is a failed restore');
t_contains($reasonOf($r), 'could not be opened',
     'with its own reason: three failure branches all end in ok => false, so '
   . 'the reason is the only way to know which of them did the work');
