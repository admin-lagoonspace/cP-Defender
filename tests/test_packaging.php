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
    'serverscrub/cpanel/serverscrub/index.php',
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
$buildPy = t_code(dirname(__DIR__) . '/scripts/build.py');
$makeSh  = t_code(dirname(__DIR__) . '/scripts/make-release.sh');

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
