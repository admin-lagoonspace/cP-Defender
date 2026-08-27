<?php
/**
 * Sentinel Gate — test bootstrap.
 *
 * DEVELOPMENT ONLY. Nothing in tests/ is packaged; scripts/build.py excludes it
 * and asserts its absence from the finished zip.
 *
 * Loads the product into a throwaway install so tests never touch a real one.
 * SG_ROOT is defined BEFORE config.php, which works because config.php guards
 * every define — a property worth relying on here and worth keeping.
 */

const SG_TEST = true;

$repo = dirname(__DIR__);

$sandbox = sys_get_temp_dir() . '/sg-test-' . getmypid() . '-' . mt_rand(1000, 9999);
foreach (['database', 'logs', 'quarantine', 'tmp'] as $d) {
    @mkdir($sandbox . '/' . $d, 0700, true);
}

define('SG_API', true);
define('SG_ROOT', $sandbox);
// The trial marker lives outside SG_ROOT by design. Redirect it into the
// sandbox, or the suite reads and writes real machine state — which it did,
// reporting an expired trial from a marker an earlier run had left behind.
define('SG_INSTALL_MARKER', $sandbox . '/installed-at');
define('INSTALL_MODE', 'cpanel');

require_once $repo . '/backend/config/config.php';

foreach ([
    'Database', 'Auth', 'Logger', 'Scanner', 'Firewall', 'WAF', 'IPReputation',
    'RealTimeMonitor', 'BotShield', 'CMSGuard', 'RootkitScanner', 'FileIntegrity',
    'PHPHardening', 'UpdateChecker', 'License', 'FirewallEngine', 'RootkitEngine',
    'BlocklistRegistry', 'WAFInstaller',
] as $lib) {
    require_once $repo . '/backend/lib/' . $lib . '.php';
}

register_shutdown_function(function () use ($sandbox) {
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sandbox, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    }
    @rmdir($sandbox);
});

return ['repo' => $repo, 'sandbox' => $sandbox];
