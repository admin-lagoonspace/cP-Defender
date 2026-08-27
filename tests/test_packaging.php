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
$zipPath = $repo . '/dist/sentinel-gate-' . $version . '.zip';

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

// The bundled PHP interpreter used by the gates is 36MB of not-the-product.
$php = array_values(array_filter($names, fn($n) => strpos($n, '/php/') !== false));
t_eq(0, count($php), 'the bundled PHP interpreter is not packaged');

// test.sh is DIFFERENT: it is the post-install self-test the wiki documents,
// a product feature rather than development tooling. It must ship.
t_ok(in_array('sentinel-gate/test.sh', $names, true),
    'test.sh (the product self-test) IS packaged');

// ── Everything the product needs does ship ───────────────────────────────────
foreach ([
    'sentinel-gate/backend/api/index.php',
    'sentinel-gate/backend/config/config.php',
    'sentinel-gate/backend/lib/Database.php',
    'sentinel-gate/backend/lib/License.php',
    'sentinel-gate/frontend/index.html',
    'sentinel-gate/frontend/js/api.js',
    'sentinel-gate/install.sh',
    'sentinel-gate/uninstall.sh',
    'sentinel-gate/update.sh',
    'sentinel-gate/VERSION',
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
$cfg = $zip->getFromName('sentinel-gate/backend/config/config.php');
$ver = $zip->getFromName('sentinel-gate/VERSION');
$zip->close();
t_eq($version, trim((string)$ver), 'packaged VERSION matches the filename');
t_ok(strpos((string)$cfg, "'" . $version . "'") !== false,
    'packaged config.php carries the same version');
