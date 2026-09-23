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
// UPDATE_DIRS is backend/frontend/whm; nothing else is touched, so nothing else
// needs copying.
t_contains($up, 'UPDATE_DIRS=( backend frontend whm )',
    'the update only replaces the code directories');

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
t_contains($msg, 'sentinel quarantine prune', 'it names the command that frees quarantine');
t_contains($msg, 'scan_*.log', 'it names the log files that accumulate');
t_contains($msg, 'BACKUP_ROOT', 'it names the backup directory');
