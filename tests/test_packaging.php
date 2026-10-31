<?php
/**
 * Packaging rules.
 *
 * Development tooling must never reach a customer's server. Tests describe how
 * to break the product, name every past defect, and execute arbitrary code from
 * a sandbox; scripts/ contains the release machinery. None of it belongs in a
 * security product installed as root.
 *
 * This asserts against the FINISHED zip rather than the build script's
 * intentions, because the two have diverged before: 3.19.2 shipped a zero-byte
 * config.php that the build was certain it had written correctly.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$version = trim(file_get_contents($repo . '/VERSION'));
$zipPath = $repo . '/dist/serverscrub-' . $version . '.zip';

if (!is_file($zipPath)) {
    echo "SKIP no zip for {$version} yet — run scripts/build.py first\n";
    return;
}

$zip = new ZipArchive();
$zip->open($zipPath);
$names = [];
for ($i = 0; $i < $zip->numFiles; $i++) {
    $names[] = $zip->getNameIndex($i);
}
$zip->close();

// ── Nothing developmental ships ──────────────────────────────────────────────
$leaked = array_values(array_filter($names, function ($n) {
    return strpos($n, '/tests/') !== false
        || strpos($n, '/scripts/') !== false
        || preg_match('#/(phpunit|\.github|\.git)/#', $n);
}));
t_eq(0, count($leaked), 'no tests/ or scripts/ in the package'
    . ($leaked ? ' — leaked: ' . implode(', ', array_slice($leaked, 0, 5)) : ''));

// Build leftovers from the maintainer's machine are not the product either.
// v3.27.3 shipped backend/daemon/__pycache__/monitor.cpython-{310,312}.pyc --
// bytecode for interpreters no target server runs (cPanel hosts are on 3.6).
// Python ignores a .pyc that does not match its own version, so nothing broke,
// but someone else's build output inside a security product is not something
// to discover from a customer.
$leftovers = array_values(array_filter($names, function ($n) {
    return strpos($n, '__pycache__') !== false
        || preg_match('/\.py[co]$/', $n)
        || substr($n, -10) === '.DS_Store';
}));
t_eq(0, count($leftovers), 'no build leftovers in the package'
    . ($leftovers ? ' — leaked: ' . implode(', ', array_slice($leftovers, 0, 5)) : ''));

// The bundled PHP interpreter used by the gates is 36MB of not-the-product.
$php = array_values(array_filter($names, fn($n) => strpos($n, '/php/') !== false));
t_eq(0, count($php), 'the bundled PHP interpreter is not packaged');

// test.sh is DIFFERENT: it is the post-install self-test the wiki documents,
// a product feature rather than development tooling. It must ship.
t_ok(in_array('serverscrub/test.sh', $names, true),
    'test.sh (the product self-test) IS packaged');

// ── Everything the product needs does ship ───────────────────────────────────
foreach ([
    'serverscrub/backend/api/index.php',
    'serverscrub/backend/config/config.php',
    'serverscrub/backend/lib/Database.php',
    'serverscrub/backend/lib/License.php',
    'serverscrub/frontend/index.html',
    'serverscrub/frontend/js/api.js',
    'serverscrub/install.sh',
    'serverscrub/uninstall.sh',
    'serverscrub/update.sh',
    // The upgrade bootstrap. It fetches the CURRENT update.sh before handing
    // over, which is the only way a server benefits from a fix to the updater
    // itself -- the copy on disk is always the one that shipped with the
    // version already installed. Dropping it from the archive would leave
    // every server upgrading with its own stale updater.
    'serverscrub/upgrade.sh',
    'serverscrub/VERSION',
    // The page every cPanel user opens. If this is missing from the archive the
    // installer has nothing to copy, and the Security menu entry leads to a
    // blank page for every customer on the server.
    'serverscrub/cpanel/serverscrub/index.live.php',
] as $required) {
    t_ok(in_array($required, $names, true), "packaged: " . basename($required));
}

// ── No packaged PHP file is empty ────────────────────────────────────────────
// php -l passes an empty file. 3.19.2 shipped config.php at zero bytes and every
// gate reported success.
$zip = new ZipArchive();
$zip->open($zipPath);
$empties = [];
for ($i = 0; $i < $zip->numFiles; $i++) {
    $st = $zip->statIndex($i);
    if (substr($st['name'], -4) === '.php' && $st['size'] === 0) {
        $empties[] = $st['name'];
    }
}
$zip->close();
t_eq(0, count($empties), 'no packaged PHP file is empty'
    . ($empties ? ' — ' . implode(', ', $empties) : ''));

// ── The package declares the version it claims to be ─────────────────────────
$zip = new ZipArchive();
$zip->open($zipPath);
$cfg = $zip->getFromName('serverscrub/backend/config/config.php');
$ver = $zip->getFromName('serverscrub/VERSION');
$zip->close();
t_eq($version, trim((string)$ver), 'packaged VERSION matches the filename');
t_ok(strpos((string)$cfg, "'" . $version . "'") !== false,
    'packaged config.php carries the same version');

// ── The two packagers must agree ────────────────────────────────────────────
//
// scripts/build.py and scripts/make-release.sh both produce
// dist/serverscrub-<version>.zip -- the same path -- from their own
// independent allowlists. So whichever ran last wins, and for a while they
// disagreed: build.py omitted "cpanel", the directory holding the page every
// cPanel user opens, and "upgrade.sh". Running build.py after publish.sh would
// have overwritten a correct release with an incomplete one while latest.json
// kept advertising the SHA-256 of the good zip.
//
// Compared as sets, because the order each script lists them in does not
// matter and should not make this test fail.
$buildPy = t_shell(dirname(__DIR__) . '/scripts/build.py');
$makeSh  = t_shell(dirname(__DIR__) . '/scripts/make-release.sh');

t_ok(preg_match('/^ITEMS\s*=\s*\[(.*?)\]/ms', $buildPy, $m) === 1,
     'build.py declares an ITEMS allowlist');
preg_match_all('/"([^"]+)"/', $m[1] ?? '', $bm);
$buildItems = $bm[1] ?? [];

t_ok(preg_match('/for item in ([^;]+?); do/', $makeSh, $m2) === 1,
     'make-release.sh declares an allowlist');
$shItems = preg_split('/\s+/', trim($m2[1] ?? ''), -1, PREG_SPLIT_NO_EMPTY);

sort($buildItems);
sort($shItems);
t_eq($shItems, $buildItems,
     'build.py and make-release.sh package exactly the same things — '
   . 'they write the same zip path, so a difference is a silent bad release');

// Both must carry the cPanel user page. Without it the installer has nothing
// to copy and the Security menu entry is a blank page for every customer.
t_ok(in_array('cpanel', $buildItems, true), 'build.py packages cpanel/');
t_ok(in_array('upgrade.sh', $buildItems, true), 'build.py packages upgrade.sh');

// ── All THREE lists must agree ──────────────────────────────────────────────
//
// Three independent places decide what this product consists of:
//
//   1. scripts/build.py          ITEMS                -- what the dev build packages
//   2. scripts/make-release.sh   its allowlist        -- what the release packages
//   3. update.sh                 UPDATE_DIRS + FILES  -- what an UPDATE delivers
//
// All three disagreed, and the third one was the expensive one. update.sh
// copied only backend/, frontend/, whm/ and four files, so:
//
//   - cpanel/ was never delivered by an update. That directory holds the page
//     every CUSTOMER opens from their own cPanel. A server updated at any
//     point after cpanel/ was introduced showed an empty menu entry to every
//     user on it, and said so only as two lines in an installer log.
//   - test.sh was never delivered, so every update finished with "test.sh not
//     found -- skipping verification". The post-install check silently had not
//     run in months.
//   - upgrade.sh was never delivered, so the script whose whole job is to
//     fetch a newer updater could not arrive by update.
//
// The zip was correct the whole time. Only the copy list was wrong, which is
// the hardest version of this bug to see: nothing is missing from the release,
// and a fresh install is perfect.
$updateSh = t_shell(dirname(__DIR__) . '/update.sh');

t_ok(preg_match('/^UPDATE_DIRS=\(([^)]*)\)/m', $updateSh, $m3) === 1,
     'update.sh declares UPDATE_DIRS');
$updDirs = preg_split('/\s+/', trim($m3[1] ?? ''), -1, PREG_SPLIT_NO_EMPTY);

t_ok(preg_match('/^UPDATE_FILES=\(([^)]*)\)/m', $updateSh, $m4) === 1,
     'update.sh declares UPDATE_FILES');
$updFiles = preg_split('/\s+/', trim($m4[1] ?? ''), -1, PREG_SPLIT_NO_EMPTY);

$delivered = array_merge($updDirs, $updFiles);
sort($delivered);

// $shItems is make-release.sh's allowlist, read above.
t_eq($shItems, $delivered,
     'update.sh delivers exactly what make-release.sh packages — anything '
   . 'packaged but not copied reaches fresh installs only, and never the '
   . 'servers that update');

// Named individually, because these three are the ones that were missing and
// each one has a distinct user-visible consequence.
t_ok(in_array('cpanel', $updDirs, true),
     'an update delivers cpanel/ — the page every cPanel user opens');
t_ok(in_array('test.sh', $updFiles, true),
     'an update delivers test.sh, so post-install verification actually runs');
t_ok(in_array('upgrade.sh', $updFiles, true),
     'an update delivers upgrade.sh, so the next manual upgrade has it');

// ── An optional directory must not be able to roll back a good update ───────
//
// update.sh ran `chmod -R 700 "${INSTALL_DIR}/quarantine"` unconditionally.
// Quarantine is configurable and commonly lives outside the install directory
// -- on the server this was found, /home/.serverscrub/quarantine, because
// /home is the big volume. So the path did not exist, chmod exited non-zero,
// `set -e` declared the update failed, and a server that had ALREADY applied
// the new version in full was rolled all the way back.
t_ok(!preg_match('/^\s*chmod -R 700 "\$\{INSTALL_DIR\}\/quarantine"\s*$/m', $updateSh),
     'update.sh no longer chmods the quarantine path unconditionally');
t_contains($updateSh, 'for _SG_D in database quarantine logs; do',
     'the optional directories are tightened only when present');
t_contains($updateSh, "Database::setting('quarantine_dir'",
     'and the real quarantine path is read from settings, not assumed');

// ── The release-notes link must point somewhere that exists ─────────────────
//
// The panel renders ONE "Release Notes" link and has no fallback. It pointed at
// the CDN -- https://defender.lws-s1.com/serverscrub/code/v<version>/CHANGELOG.md
// -- which 404s, because that CDN has never been populated. The download
// survives the same problem only because update.sh walks both channels.
//
// Both generators write this url and they must agree, for the same reason the
// file lists must: they produce the same manifest and whichever ran last wins.

$mkNotes = preg_match('/NOTES_URL="([^"]+)"/', $makeSh, $mn) ? $mn[1] : '';
$pyNotes = preg_match('/"notes":\s*"([^"]+)"/', $buildPy, $pn) ? $pn[1] : '';

t_ok($mkNotes !== '', 'make-release.sh defines a notes url');
t_ok($pyNotes !== '', 'build.py defines a notes url');

foreach (['make-release.sh' => $mkNotes, 'build.py' => $pyNotes] as $who => $u) {
    t_ok(strpos($u, 'defender.lws-s1.com') === false,
         "$who does not point the notes link at the CDN, which is not populated");
    t_ok(strpos($u, 'CDN') === false,
         "$who does not interpolate the CDN variable into it either");
    t_contains($u, 'notes-',
         "$who links THIS version's notes, not the whole changelog");
}

// build.py interpolates a variable, so the host is asserted where it is
// actually written rather than in the format string.
t_contains($buildPy, 'GH_REPO = "https://github.com/',
     'build.py resolves the notes host to GitHub');
t_contains($pyNotes, '%s/blob/',
     'and builds the notes url from it');
t_contains($mkNotes, 'github.com',
     'make-release.sh names GitHub directly');

// publish.sh has to commit the file that url names, or the link 404s one
// release later instead of immediately.
$pub = t_shell(dirname(__DIR__) . '/scripts/publish.sh');
t_contains($pub, 'dist/notes-',
     'publish.sh commits the per-version notes file the link points at');

// And the panel must not render a link with nowhere to go.
$appJs2 = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
t_contains($appJs2, "relLink.style.display = 'none'",
     'the Release Notes link is hidden when there is no url, rather than '
   . 'sitting there dead');
