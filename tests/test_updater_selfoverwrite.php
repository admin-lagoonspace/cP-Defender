<?php
/**
 * The updater must not be the file it is overwriting.
 *
 * FROM A LIVE SERVER, 31 Oct 2026. An update applied every file cleanly and
 * then died:
 *
 *     ✔  Updated: update.sh
 *     /usr/local/serverscrub/update.sh: line 642: ater: command not found
 *     ⚠  Update failed — rolling back to v4.22.5
 *
 * "ater" appears in no file in this repository. update.sh is in UPDATE_FILES,
 * so the updater copies the new version over ITSELF while bash is still
 * reading it. Bash does not read a script in one go; it reads incrementally
 * and remembers a byte offset. Replace the file underneath it and execution
 * resumes at that offset in different content -- landing mid-word and running
 * the tail of one as a command.
 *
 * It had always been there and had always been luck: it only fires when a
 * release changes the length of update.sh enough to move the offset somewhere
 * harmful. 4.23.0 added ten lines and moved it.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$upd = (string) file_get_contents($repo . '/update.sh');

// ── The script still replaces itself; that is not the thing to fix ──────────
t_contains($upd, 'UPDATE_FILES=( VERSION install.sh uninstall.sh update.sh',
     'update.sh is still among the files an update replaces — a server must be '
   . 'able to receive a fix to its own updater');

// ── ...so it must not be reading that file when it does ─────────────────────
t_contains($upd, 'SG_UPDATE_REEXEC',
     'THE FIX: the updater re-execs before doing any work');
t_contains($upd, 'exec bash "$_tmp"',
     'from a private copy, so the file bash is reading is never the file being '
   . 'overwritten');
t_contains($upd, 'mktemp /tmp/sg-updater.XXXXXX.sh', 'staged under /tmp');

// Order is the whole point: the guard has to run before anything copies.
$guardAt = strpos($upd, 'SG_UPDATE_REEXEC');
$copyAt  = strpos($upd, 'cp "$src" "${INSTALL_DIR}/${file}"');
t_ok($guardAt !== false && $copyAt !== false && $guardAt < $copyAt,
     'and does so BEFORE the copy loop that would overwrite it');

// It must only apply to the installed copy. upgrade.sh fetches update.sh into
// /tmp and runs it from there; re-execing that would be a pointless extra
// process, and a checkout is not the file the run replaces either.
t_contains($upd, '"$_self" == "$_inst"',
     'only the INSTALLED copy re-execs — upgrade.sh already runs a fetched one '
   . 'from /tmp, which nothing overwrites');

// Failure to stage a copy must not block updating altogether.
t_contains($upd, 'could not stage a private copy',
     'and a server that cannot make a temp copy still updates, the way every '
   . 'previous release did, rather than refusing outright');

// ── The safe path that existed all along ────────────────────────────────────
$upg = (string) file_get_contents($repo . '/upgrade.sh');
t_contains($upg, 'UPDATER="${TMP}/update.sh"',
     'upgrade.sh runs a fetched updater out of /tmp, which is why it was never '
   . 'affected and is the way out of a broken update.sh');

// ── The same shape elsewhere, which turned out to be noise, not a bug ───────
//
// install.sh copies install.sh/update.sh/uninstall.sh into INSTALL_DIR, and
// --register-only runs it FROM INSTALL_DIR -- so source and destination were
// the same file. A first version of this test banned the pattern outright and
// failed on it, which was too blunt: install.sh sets pipefail but NOT errexit,
// so the failed copy printed to stderr and the script carried on. It never
// broke an install.
//
// It did print three "are the same file" errors during every single update,
// which is how an operator learns to ignore an updater's output -- so it is
// guarded rather than banned.
$ins = (string) file_get_contents($repo . '/install.sh');
t_contains($ins, 'readlink -f "${SCRIPT_DIR}" 2>/dev/null)" != "$(readlink -f "${INSTALL_DIR}"',
     'install.sh skips the copy when it is already running from the install '
   . 'directory, instead of failing three copies and continuing');
t_contains($ins, 'files are already in place, not copying',
     'and says so, rather than silently doing nothing');

t_ok(strpos($ins, 'set -e') === false || strpos($ins, 'set -euo') === false,
     'install.sh does not use errexit — which is WHY the same-file copies were '
   . 'survivable rather than fatal; worth knowing before anyone adds it');

// upgrade.sh never copies itself anywhere.
$upgSrc = (string) file_get_contents($repo . '/upgrade.sh');
t_ok(strpos($upgSrc, 'cp "${SCRIPT_DIR}/upgrade.sh"') === false,
     'upgrade.sh does not copy over itself while running');
