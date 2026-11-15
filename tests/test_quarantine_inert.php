<?php
/**
 * Quarantine makes the file inert, and records whose file it was, BEFORE it
 * moves anything — on every path, not just the automatic one.
 *
 * Both halves of this used to live in handleByPolicy() only, so a scan acted
 * correctly and the Quarantine button in the UI did not:
 *
 *   1. THE EXECUTION WINDOW. Between detection and the move the file is still
 *      executable by the web server, and a webshell's best moment is the one
 *      where it knows it is being removed. rename() closes that window in
 *      microseconds -- but rename() is not what runs when quarantine lives on
 *      another filesystem, and install.sh deliberately relocates quarantine to
 *      /home for exactly that reason. So on a hosting server the copy path is
 *      the NORMAL path, and the window was as long as the copy took.
 *
 *   2. THE OWNER. orig_uid/orig_gid/prev_mode are what let a restore put the
 *      file back as the customer's file instead of root's. Without them
 *      QuarantineRestore infers the owner from the destination directory and
 *      falls back to 0644 -- which is how the 154,323 files from job 12457 came
 *      back, and the reason those columns were added. A file quarantined by
 *      hand deserves the same record as one quarantined by policy.
 *
 * These assert on ORDER, not merely on presence: "calls disableFile somewhere
 * in the function" was true of the broken version too, because the order is the
 * entire property. And they read comment-stripped source, because an assertion
 * that a comment can satisfy is how this suite has been fooled before.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$sc   = t_code($repo . '/backend/lib/Scanner.php');
$body = t_fn_body($sc, 'quarantine', 'php');

t_ok($body !== '', 'Scanner::quarantine() is still a findable function');

// ── The order inside quarantine() ────────────────────────────────────────────
$atStat    = strpos($body, 'orig_uid');
$atDisable = strpos($body, 'self::disableFile(');
$atRename  = strpos($body, 'rename($filePath, $dest)');
$atCopy    = strpos($body, 'copy($filePath, $dest)');

t_ok($atStat    !== false, 'quarantine() records orig_uid itself, not only its callers');
t_ok($atDisable !== false, 'quarantine() makes the file inert itself, not only its callers');
t_ok($atRename  !== false, 'quarantine() still moves the file with rename()');

t_ok($atStat !== false && $atDisable !== false && $atStat < $atDisable,
    'the owner and mode are recorded BEFORE the file is disabled — after the '
  . 'chmod its mode is 0000 and the real one is gone');

t_ok($atDisable !== false && $atRename !== false && $atDisable < $atRename,
    'the file is made inert BEFORE rename() — that is the execution window');

t_ok($atDisable !== false && $atCopy !== false && $atDisable < $atCopy,
    'the file is made inert BEFORE the cross-device copy — the long window, '
  . 'and the one a hosting server actually takes');

// ── What is written, and what is not ─────────────────────────────────────────
t_contains($body, 'prev_mode=COALESCE(prev_mode,?)',
    'prev_mode does not clobber a mode a caller captured earlier: handleByPolicy '
  . 'disables the file before calling this, so by here the real mode is already gone');

t_contains($body, '$recMode !== 0 ? $recMode : null',
    '0000 is never recorded as prev_mode — it is this scanner\'s own doing, and '
  . 'restoring a file to it hands the customer back something unreadable');

// ── A failed move puts the mode back ─────────────────────────────────────────
//
// Three ways the copy path can fail after the chmod: the copy, the size check,
// and unlinking the original. Each must undo the chmod. An unreadable file that
// is still infected is the worst of both outcomes, and it is what the customer
// is left with otherwise.
t_eq(3, substr_count($body, 'self::restoreMode($filePath, $prevMode);'),
    'every failure after the chmod restores the mode (copy, short copy, unlink)');

// ── The quarantined copy's own bits, verified not trusted ────────────────────
t_contains($body, 'chmod($dest, 0600)',
    'the quarantined file is 0600 — no execute bit for anyone, root included');

$atChmod  = strpos($body, 'chmod($dest, 0600)');
$atVerify = strpos($body, 'fileperms($dest)');
t_ok($atVerify !== false && $atChmod !== false && $atChmod < $atVerify,
    'the mode is read back after being set: a filesystem mounted without '
  . 'permission support reports success and changes nothing');

// ── The callers that had neither ─────────────────────────────────────────────
//
// Both go straight into quarantine() with no preparation of their own, which is
// correct now and was the bug before. Pinned so a future caller cannot be added
// that reimplements the move instead.
$api = t_code($repo . '/backend/api/index.php');
t_contains($api, '$scanner->quarantine($threat[\'file_path\'], (int)$id)',
    'the API quarantine action goes through Scanner::quarantine()');
// Not "the API contains no rename()" -- it rotates the monitor log with one,
// which is unrelated and was the first version of this assertion being wrong
// rather than the code. What matters is that it never moves or re-modes a
// THREAT's file itself.
foreach (['rename($threat', 'copy($threat', 'chmod($threat',
          'rename((string) $threat', 'unlink($threat'] as $own) {
    t_ok(strpos($api, $own) === false,
        'the API does not handle a threat file itself: no ' . $own . ')');
}

t_contains($sc, '$this->quarantine((string) $threat[\'file_path\'], $id)',
    'the bulk action goes through Scanner::quarantine() too');

// ── Then the same thing, actually executed ───────────────────────────────────
//
// The assertions above read source, which is how this suite usually pins
// ordering -- but ordering in source is only a proxy for ordering at runtime,
// and the record is a database write that either happens or does not. So run a
// real quarantine against a real file in the sandbox and look at the row.
//
// Mode bits are asserted only on POSIX. Windows has no owner/group/other
// triad, chmod there sets little more than the read-only flag, and this suite
// runs on the machine releases are cut from.

require_once $repo . '/backend/lib/Scanner.php';

$sandbox = $ctx['sandbox'];
Database::setSetting('quarantine_dir', $sandbox . '/quarantine-inert');

$victimDir = $sandbox . '/home/acct/public_html';
@mkdir($victimDir, 0755, true);
$victim = $victimDir . '/upload.php';
file_put_contents($victim, t_inert_payload('stands in for a quarantined shell'));
@chmod($victim, 0644);

$posix = DIRECTORY_SEPARATOR === '/';
$modeBefore = @fileperms($victim) & 0777;

$qid = Database::insert('threats', [
    'file_path'   => $victim,
    'threat_type' => 'test',
    'severity'    => 'high',
    'status'      => 'active',
    'detected_at' => time(),
]);

$res = (new Scanner())->quarantine($victim, (int) $qid);

t_eq(true, !empty($res['success']),
    'the quarantine succeeded: ' . ($res['error'] ?? 'no error reported'));
t_eq(false, file_exists($victim), 'the original file is gone from the account');
t_eq(true, isset($res['dest']) && is_file($res['dest']),
    'the quarantined copy exists where the result says it does');

$row = Database::fetchOne(
    'SELECT orig_uid, orig_gid, prev_mode FROM threats WHERE id=?', [(int) $qid]);

t_eq(true, $row !== false && $row['orig_uid'] !== null,
    'orig_uid was recorded by quarantine() itself — this is the column whose '
  . 'absence left 154,323 files with no way back to their owner');
t_eq(true, $row !== false && $row['orig_gid'] !== null, 'orig_gid was recorded');
t_eq(true, $row !== false && $row['prev_mode'] !== null, 'prev_mode was recorded');
t_ok($row !== false && (int) $row['prev_mode'] !== 0,
    'prev_mode is not 0000 — recording the mode this scanner just imposed would '
  . 'restore the file unreadable');

if ($posix) {
    t_eq($modeBefore, ((int) $row['prev_mode']) & 0777,
        'prev_mode is the mode the file actually had before quarantine');
    t_eq(0600, @fileperms($res['dest']) & 0777,
        'the quarantined copy is 0600 on disk — verified by reading it back, '
      . 'not by trusting chmod');
    t_eq(0, @fileperms($res['dest']) & 0111,
        'no execute bit is set for anyone, so not even root can exec it');
} else {
    echo "prev_mode/0600 bit checks are POSIX-only; skipped on this platform\n";
}

// The placeholder the site owner finds in place of their file.
t_eq(true, is_file($victim . '.serverscrub_removed'),
    'a note is left at the original path saying where the file went');
