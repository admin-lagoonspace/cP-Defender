<?php
/**
 * An update must not be impossible on a server that needs it.
 *
 * Reported: unable to update on production, immediately after quarantine had
 * filled the root partition.
 *
 * update.sh copied ${INSTALL_DIR}/quarantine and logs into /var/backups on
 * EVERY update -- doubling the very thing that had filled the disk, on the same
 * partition. Nothing pruned those backups either, so each update left another
 * full copy behind. The fix for the disk problem was therefore un-installable
 * because of the disk problem.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$up = file_get_contents($repo . '/update.sh');

// ── Only back up what the update can destroy ─────────────────────────────────
//
// The point is that the snapshot copies CODE and not the two directories that
// grow without bound -- quarantine, which holds whole infected files, and
// logs. Both the snapshot and the rollback iterate UPDATE_DIRS, so the test is
// that UPDATE_DIRS contains no bulk data directory.
//
// This assertion used to pin the literal string
// 'UPDATE_DIRS=( backend frontend whm )'. That made a necessary fix look like
// a regression: the list was MISSING cpanel/, so updates never delivered the
// page every cPanel user opens, and adding it failed this test. Pinning a
// literal list in two places is how the lists drifted apart to begin with --
// assert the property, not the spelling.
t_ok(preg_match('/^UPDATE_DIRS=\(([^)]*)\)/m', $up, $m) === 1,
    'update.sh declares UPDATE_DIRS');
$dirs = preg_split('/\s+/', trim($m[1]), -1, PREG_SPLIT_NO_EMPTY);

foreach (['quarantine', 'logs', 'database'] as $bulk) {
    t_ok(!in_array($bulk, $dirs, true),
        "$bulk/ is not in UPDATE_DIRS — the update never replaces it, so the "
      . "snapshot must not copy it either");
}
t_contains($up, 'backend', 'the code directories are what gets replaced');
t_ok(count($dirs) > 0 && count($dirs) < 8,
    'UPDATE_DIRS stays a short list of code directories');

$preserveStart = strpos($up, 'PRESERVE=(');
$preserveEnd   = strpos($up, ')', $preserveStart);
$preserve      = substr($up, $preserveStart, $preserveEnd - $preserveStart);

t_ok(strpos($preserve, 'quarantine') === false,
    'quarantine is NOT copied into the backup (the update never touches it)');
t_ok(strpos($preserve, '/logs') === false,
    'logs are NOT copied into the backup either');
t_contains($preserve, 'database', 'the database IS preserved');
t_contains($preserve, 'mode.php', 'mode.php IS preserved — it holds the licensing secret');
t_contains($preserve, 'custom.sig', 'custom signatures are preserved');

// ── Old backups must be pruned ───────────────────────────────────────────────
t_contains($up, 'SG_KEEP_BACKUPS', 'the number of backups kept is configurable');
t_contains($up, 'Pruned ', 'old backups are removed and the removal is reported');
t_contains($up, 'tail -n +$((_SG_KEEP + 1))',
    'everything past the retained count is pruned');

// ── Refuse to start without room ─────────────────────────────────────────────
t_contains($up, 'Not enough free space to update safely',
    'the update refuses rather than failing halfway');
t_contains($up, 'df -Pk', 'free space is measured on the install volume');

// The check must come BEFORE anything is written, or it is pointless.
$checkPos  = strpos($up, '_SG_FREE_KB=');
$backupPos = strpos($up, 'state "backup"');
t_ok($checkPos !== false && $backupPos !== false && $checkPos < $backupPos,
    'the space check runs before the backup starts');

// And it must say how to recover, since the operator is stuck at that moment.
$msgStart = $checkPos;
$msg      = substr($up, $msgStart, 1600);
t_contains($msg, 'serverscrub quarantine prune', 'it names the command that frees quarantine');
t_contains($msg, 'scan_*.log', 'it names the log files that accumulate');
t_contains($msg, 'BACKUP_ROOT', 'it names the backup directory');

// ── The updater must not claim success on a half-applied update ────────────
//
// FROM A LIVE SERVER. VERSION read 4.13.1 while backend/config/config.php
// still defined 4.10.0: the top-level files were copied by `cp` and the
// backend was not delivered by the `rsync`. The panel reported 4.10.0, because
// the API reads SG_VERSION -- and the updater had already printed
// "Update complete".
//
// An updater that can leave those out of step and still claim success is worse
// than one that fails outright: the operator believes they are patched.

$upd = (string)file_get_contents($repo . '/update.sh');

t_contains($upd, 'PARTIAL UPDATE',
     'the updater checks that the code actually landed');
t_contains($upd, "SG_VERSION',\s*'",
     'by reading SG_VERSION out of the installed config.php');
t_contains($upd, 'state_failed',
     'and records the run as failed, so the panel does not show success');

// The check must come BEFORE the success banner, or it reports both.
$posCheck  = strpos($upd, 'PARTIAL UPDATE');
$posBanner = strpos($upd, 'Update complete!');
t_ok($posCheck !== false && $posBanner !== false && $posCheck < $posBanner,
     'and it runs before the "Update complete" banner, not after it');

// ── rsync must compare CONTENT, not timestamps ─────────────────────────────
//
// THE ROOT CAUSE OF FIVE FAILED UPDATES ON A LIVE SERVER.
//
// rsync's default quick check is SIZE + MTIME. make-release.sh pinned every
// entry in the archive to the ZIP epoch (1980-01-01), so after extraction
// every file carried the same timestamp. Any file whose SIZE had not changed
// was therefore judged identical to the one already installed and never
// transferred.
//
// backend/config/config.php sat at 4.10.0 through five consecutive updates,
// because '4.10.0' and '4.13.3' are both six characters and the file size
// never moved. frontend/index.html was stuck the same way. The rsync reported
// success every time -- it had genuinely finished, having decided there was
// nothing to do -- so the updater printed "Update complete" while the panel
// correctly reported 4.10.0.
//
// Three separate symptoms, one cause: the stale sidebar version, the stale
// SG_VERSION, and every feature shipped since 4.10.0 being absent.

$up2 = (string)file_get_contents($repo . '/update.sh');

preg_match_all('/^\s*rsync\s+(.*)$/m', $up2, $rs);
t_ok(count($rs[1]) >= 2, 'update.sh uses rsync to apply and to roll back');
foreach ($rs[1] as $args) {
    t_contains($args, '--checksum',
         'every rsync compares checksums, not size+mtime: ' . trim(substr($args, 0, 44)));
}

// The archive must not pin every file to a fixed timestamp either. update.sh
// no longer depends on it, but a timestamp that is a lie breaks any other tool
// that compares files.
$mk = (string)file_get_contents($repo . '/scripts/make-release.sh');
t_ok(strpos($mk, 'date_time=(1980, 1, 1, 0, 0, 0)') === false,
     'the archive no longer pins every file to the ZIP epoch');
t_contains($mk, 'st.st_mtime',
     "and carries each file's real modification time");
