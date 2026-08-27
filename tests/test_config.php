<?php
/**
 * Regressions in backend/config/config.php.
 *
 * Every assertion here corresponds to a failure that reached a production
 * server:
 *
 *   3.19.2  config.php shipped ZERO BYTES. php -l passes an empty file, so the
 *           syntax gate called it green. Every request answered "Direct access
 *           denied" because the guards test constants it defines.
 *   3.11-ish config.php was truncated mid-string ('spamco) for at least eight
 *           releases, invisible because the API 501'd before PHP parsed it.
 *   3.19.4  config.php defined SG_ROOT/SG_VERSION and THEN included mode.php,
 *           which set them again: two warnings on every single request.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$path = $repo . '/backend/config/config.php';
$src  = file_get_contents($path);

t_ok(filesize($path) > 500, 'config.php is not empty or truncated');

// The truncation ended mid-array. A closing "]));" proves RBL_FEEDS terminates.
t_contains($src, ']));', 'RBL_FEEDS array is closed');
t_ok(substr(rtrim($src), -1) !== ',', 'file does not end mid-expression');

// The guards the runtime depends on. Missing any one of these is not a subtle
// degradation: it is "Direct access denied" on every endpoint.
foreach (['SG_ROOT', 'SG_VERSION', 'SG_DB', 'SG_LOGS', 'QUARANTINE_DIR', 'INSTALL_MODE'] as $c) {
    t_ok(defined($c), "constant {$c} is defined");
}

// The bootstrap defines SG_ROOT before including config.php. If config.php ever
// stops guarding its defines, this is where it shows up — and the guard is what
// lets update.sh leave an older mode.php in place without warnings.
t_eq($ctx['sandbox'], SG_ROOT, 'a pre-defined SG_ROOT is respected, not overwritten');

// SG_DB must live under SG_ROOT, or a test would write into a real install.
t_ok(strpos(SG_DB, SG_ROOT) === 0, 'SG_DB is derived from SG_ROOT');

// The version in config.php must match ./VERSION, or the UI reports one version
// while the updater compares another.
$version = trim(file_get_contents($repo . '/VERSION'));
t_eq($version, SG_VERSION, 'SG_VERSION matches ./VERSION');

// Including mode.php twice must not warn. mode.php is written by the installer
// and update.sh does NOT rewrite it, so config.php has to tolerate an old one.
$modePath = sys_get_temp_dir() . '/sg-mode-' . getmypid() . '.php';
file_put_contents($modePath, "<?php\n"
    . "if (!defined('SG_ROOT'))    { define('SG_ROOT', '/tmp/x'); }\n"
    . "if (!defined('SG_VERSION')) { define('SG_VERSION', '0.0.0'); }\n");
$warnings = [];
set_error_handler(function ($no, $str) use (&$warnings) { $warnings[] = $str; return true; });
require $modePath;
restore_error_handler();
@unlink($modePath);
t_eq(0, count($warnings), 'a mode.php that redefines constants raises no warning');
