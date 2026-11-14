<?php
/**
 * What the release zip is allowed to contain.
 *
 * scripts/ was not packaged at all until 4.36.2. That is why the nginx cache
 * fix for latest.json could not deploy itself: the fix lived in
 * scripts/cdn-sync.sh, nothing shipped scripts/cdn-sync.sh, and the only route
 * onto a server was a human copying a raw GitHub URL. A fix that cannot reach
 * the machine it fixes is not shipped.
 *
 * The answer was NOT to package the directory. scripts/ also holds publish.sh,
 * make-release.sh, preflight.py, build.py, the check-* gates and webhook.php --
 * release machinery and site infrastructure, none of which belongs in a
 * customer install. So three names ship and the rest do not, and the list
 * lives in three files that must agree: make-release.sh puts them in the zip,
 * install.sh copies them on a fresh install, update.sh refreshes them.
 *
 * These tests exist because that is three places to forget. A name added to
 * one and not the others gives a file that ships but is never updated, or is
 * updated but never installed -- and either reads as "the script is there" to
 * anyone checking by eye.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$mk  = t_shell($repo . '/scripts/make-release.sh');
$ins = t_shell($repo . '/install.sh');
$upd = t_shell($repo . '/update.sh');

function t_absent(string $haystack, string $needle, string $what): void
{
    $pass = strpos($haystack, $needle) === false;
    echo ($pass ? 'PASS ' : 'FAIL ') . $what
        . ($pass ? '' : " — found '{$needle}', which must not be there")
        . "\n";
}

// ── The three lists are the same three names ────────────────────────────────
//
// Derived, not pinned as a literal: a test that only greps for a string it was
// given cannot notice the OTHER file falling out of step, which is the whole
// failure being guarded against here.
preg_match('/OPS_SCRIPTS=\(\s*([^)]*)\)/', $mk, $m);
$pkg = preg_split('/\s+/', trim($m[1] ?? ''), -1, PREG_SPLIT_NO_EMPTY);
sort($pkg);

t_eq(['cdn-setup.sh', 'cdn-sync.sh', 'cdn-trigger-watch.sh'], $pkg,
     'make-release.sh packages exactly the CDN trio');

preg_match('/for _ops in ([^;]*); do/', $ins, $m2);
$installed = preg_split('/\s+/', trim($m2[1] ?? ''), -1, PREG_SPLIT_NO_EMPTY);
sort($installed);

t_eq($pkg, $installed,
     'install.sh copies exactly what make-release.sh packaged. A packaged '
   . 'script the installer does not copy is absent from every fresh install '
   . 'while being present in the zip, so it looks delivered and is not');

// ── and the update refreshes them ───────────────────────────────────────────
t_contains($upd, 'UPDATE_DIRS=( backend frontend whm cpanel scripts )',
     'scripts/ is in UPDATE_DIRS, so an update overlays it. Without this the '
   . 'copy placed at install time is frozen forever: the server would carry '
   . 'cdn-sync.sh from whichever release it first installed, and shipping a '
   . 'fix would change nothing on it');

// UPDATE_DIRS is also what the pre-update code snapshot and the rollback
// iterate, so adding scripts/ there covers it both ways. Pinned because a
// rollback that restores three of four directories leaves a mixed install.
t_contains($upd, 'for dir in "${UPDATE_DIRS[@]}"',
     'the snapshot and rollback iterate UPDATE_DIRS rather than their own '
   . 'hardcoded list, so scripts/ is snapshotted and restored with the rest');

// ── What must never ship ────────────────────────────────────────────────────
//
// Each of these is in scripts/ and would have been picked up by a `cp -r` of
// the directory.
t_absent($mk, 'cp -r "${REPO_DIR}/scripts"',
     'make-release.sh does NOT copy scripts/ wholesale');
t_absent($ins, 'cp -r "${SCRIPT_DIR}/scripts"',
     'install.sh does NOT copy scripts/ wholesale — it also runs from a git '
   . 'checkout, where that directory is the full release toolchain');

foreach (['publish.sh', 'make-release.sh', 'preflight.py', 'build.py',
          'webhook.php', 'deploy-site.sh', 'smoke.php', 'extract-notes.sh'] as $never) {
    t_eq(false, in_array($never, $pkg, true),
         "release tooling stays out of the payload: scripts/{$never}");
}

// ── The files the list names actually exist ─────────────────────────────────
//
// make-release.sh exits non-zero on a missing ops script rather than quietly
// shipping a zip without it, which is the same lesson as everything else here.
foreach ($pkg as $name) {
    t_eq(true, is_file($repo . '/scripts/' . $name),
         "scripts/{$name} exists in the tree");
}

t_contains($mk, 'ops script missing from the payload',
     'a named ops script that is absent fails the build instead of producing '
   . 'a release that silently lacks it');
