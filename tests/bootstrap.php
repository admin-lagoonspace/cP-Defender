<?php
/**
 * ServerScrub — test bootstrap.
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

/* ── NOTHING A TEST WRITES MAY LEAVE THE SANDBOX ─────────────────────────────
 *
 * QUARANTINE_DIR is not derived from SG_ROOT. config.php picks the first
 * writable volume out of /home and /var, so on a server it is
 * /home/.serverscrub/quarantine -- correct there, and on the developer's
 * Windows machine it resolved to C:ar\.serverscrub\quarantine, OUTSIDE the
 * sandbox, shared by every test file and surviving every run.
 *
 * Two things came out of that, and the second is the one that matters. A
 * fixture left behind by one run was found by the next -- same id, same name,
 * different bytes -- and presented as a hash mismatch in the code under test.
 * And the files accumulated on the user's own workstation until their
 * antivirus reported two Severe, Active backdoors in them, which is not an
 * acceptable thing for a test suite to do to somebody's machine.
 *
 * config.php guards every define, so defining it here wins. It is the fifth
 * time a test has depended on the machine it ran on; see tests/env.php for the
 * other half of the pattern. The product is unaffected: nothing defines this
 * but config.php and this file. */
define('QUARANTINE_DIR', $sandbox . '/quarantine');
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
    'BlocklistRegistry', 'WAFInstaller', 'WAFExclusions', 'UserReport', 'UserScanRequest', 'BruteForce', 'Schedule',
    'Heuristics', 'WPDatabaseScanner', 'Updater', 'Dependencies', 'NetworkGuard', 'MailGuard',
    'Verdicts', 'ThreatStore', 'ExternalDefence', 'MailQueue', 'ProxyRanges', 'GoodBots', 'HttpFlood',
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
