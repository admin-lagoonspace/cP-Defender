<?php
/**
 * The reported version must be the version that is running.
 *
 * Reported symptom: "version displayed in the bottom left corner always shows
 * v3.18.2, it doesn't update after I run any update script".
 *
 * mode.php is written once, at install time, and recorded SG_VERSION. It is not
 * rewritten by updates -- `install.sh --register-only`, the path update.sh
 * takes, deliberately leaves it alone so the licensing secret survives. When
 * 3.19.6 reordered config.php to load mode.php FIRST (to silence a redefinition
 * warning), that frozen value started winning: an install first set up on
 * 3.18.2 reported 3.18.2 for ever, no matter how many updates were applied.
 *
 * The sidebar was the visible symptom. The update checker comparing against a
 * frozen version was the serious one.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The running version matches ./VERSION ────────────────────────────────────
$file = trim(file_get_contents($repo . '/VERSION'));
t_eq($file, SG_VERSION, 'SG_VERSION matches ./VERSION');

// ── A stale mode.php cannot override it ──────────────────────────────────────
// config.php defines SG_VERSION before including mode.php, so the constant is
// already set by the time a frozen value would be read. Assert the ORDER, since
// that is the property that broke.
$cfg = t_code($repo . '/backend/config/config.php');
$defPos  = strpos($cfg, "define('SG_VERSION'");
$modePos = strpos($cfg, "require_once __DIR__ . '/mode.php'");
t_ok($defPos !== false,  'config.php defines SG_VERSION');
t_ok($modePos !== false, 'config.php includes mode.php');
t_ok($defPos < $modePos,
    'SG_VERSION is defined BEFORE mode.php is included, so a frozen value cannot win');

// It must not be guarded: a guard would let mode.php win again if the include
// order were ever changed back.
t_ok(strpos($cfg, "if (!defined('SG_VERSION'))") === false,
    'SG_VERSION is defined unconditionally, not behind a guard');

// ── The installer must not write a version into mode.php ─────────────────────
$install = file_get_contents($repo . '/install.sh');
$modeTemplate = '';
if (preg_match('/cat > "\$\{INSTALL_DIR\}\/backend\/config\/mode\.php".*?MODEPHP/s', $install, $m)) {
    $modeTemplate = $m[0];
}
t_ok($modeTemplate !== '', 'the mode.php template was located in install.sh');
t_ok(strpos($modeTemplate, "define('SG_VERSION'") === false,
    'install.sh does NOT record SG_VERSION in mode.php');

// ── Existing installs are migrated ───────────────────────────────────────────
t_contains($install, "sed -i \"/define('SG_VERSION'/d\"",
    'install.sh strips a frozen SG_VERSION from an existing mode.php');

// The migration is worthless if it sits in the section --register-only skips,
// because the installs that need it are precisely the ones being updated.
$migratePos = strpos($install, 'Migrate an older mode.php');
$guardPos   = strpos($install, 'INSTALL-ONLY SECTIONS (skipped in --register-only');
t_ok($migratePos !== false && $guardPos !== false, 'both markers were found');
t_ok($migratePos < $guardPos,
    'the migration runs on --register-only, the path update.sh uses');

// It must preserve the rest of the file: the licensing secret lives there and
// clobbering it would break activation on every updated server.
t_contains($install, 'mode.php.bak', 'the migration backs mode.php up first');
// Slice the migration block precisely: a fixed-width window ran past it into
// the mode.php template, which legitimately mentions the secret, and the
// assertion failed on correct code.
$blockEnd   = strpos($install, 'INSTALL-ONLY SECTIONS (skipped', $migratePos);
$migration  = substr($install, $migratePos, $blockEnd - $migratePos);
// Strip shell comments before asserting: the block's own comment explains that
// the secret is preserved, and the first version of this check failed on that
// sentence. Assertions about what code does must not read prose about it -- the
// third time this exact trap has been hit in this suite.
$migrationCode = implode("
", array_filter(
    explode("
", $migration),
    static fn($l) => strpos(ltrim($l), '#') !== 0
));
t_ok(strpos($migrationCode, 'SG_LICENSE_SECRET') === false,
    'the migration does not touch the licensing secret');
t_ok(substr_count($migration, 'sed -i') === 1,
    'the migration makes exactly one edit to mode.php');

// ── The API reports the same version the UI shows ────────────────────────────
// The sidebar falls back to the version stamped into index.html, but the value
// it prefers comes from auth/status. Both must agree with the code.
$html = file_get_contents($repo . '/frontend/index.html');
t_contains($html, 'v' . $file . ' · cPanel Plugin',
    'index.html is stamped with the current version at build time');
