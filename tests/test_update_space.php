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
