<?php
/**
 * The rename to ServerScrub, and the migration that protects an existing
 * Sentinel Gate install.
 *
 * The rename itself is mechanical. The part that can destroy something is the
 * migration: a live server has its database, several hundred quarantined files
 * and all its settings under /usr/local/sentinel-gate. Installing beside it
 * would orphan every one of them and leave two copies of the product fighting
 * over the same cron entries and systemd units.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$install   = file_get_contents($repo . '/install.sh');
$uninstall = file_get_contents($repo . '/uninstall.sh');

// ── Nothing still answers to the old name ───────────────────────────────────
// CHANGELOG is excluded on purpose: it records what the product was called at
// the time, and rewriting it would be a false history rather than a rename.
$stale = [];
$it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($repo, FilesystemIterator::SKIP_DOTS));
foreach ($it as $f) {
    $path = str_replace('\\', '/', $f->getPathname());
    if (preg_match('#/(\.git|dist|python|php|node_modules|__pycache__)/#', $path)) { continue; }
    if (!preg_match('/\.(php|js|html|sh|py|json|md|service|conf|css)$/i', $path)) { continue; }
    if (basename($path) === 'CHANGELOG.md') { continue; }
    // install.sh and the uninstaller must still know the old names: that is
    // what the migration is for.
    if (basename($path) === 'install.sh' || basename($path) === 'uninstall.sh') { continue; }
    if (strpos(basename($path), 'test_rebrand') === 0) { continue; }

    $c = @file_get_contents($path);
    if ($c !== false && preg_match('/sentinel[\s_-]?gate/i', $c)) {
        $stale[] = str_replace($repo, '', $path);
    }
}
t_eq(0, count($stale), 'no source file still refers to the old product name'
    . ($stale ? ' — ' . implode(', ', array_slice($stale, 0, 5)) : ''));

// ── The new names, where they have to be exact ──────────────────────────────
t_contains($install, 'INSTALL_DIR="/usr/local/serverscrub"', 'the install directory is renamed');
t_contains($install, 'serverscrub-monitor', 'and the monitor service');
t_contains($install, 'serverscrub-web', 'and the web service');
t_contains($install, '/usr/bin/serverscrub', 'and the command-line tool');
t_contains($install, 'cgi/serverscrub', 'and the WHM plugin directory');

// Registered under the new name with both cPanel and a plain Linux server.
t_contains($install, 'register_appconfig', 'the WHM plugin is registered');
t_contains($install, 'serverscrub.conf', 'under the new appconfig name');
t_contains($install, 'serverscrub-web.service', 'and the standalone service unit is named for it');

// ── The migration ───────────────────────────────────────────────────────────
t_contains($install, 'OLD_DIR="/usr/local/sentinel-gate"',
    'the installer knows where the old install lives');

// Order is the whole of this: services down, then processes, then the move.
$mig = substr($install, strpos($install, 'OLD_DIR="/usr/local/sentinel-gate"'), 6000);
$stopPos = strpos($mig, 'systemctl stop');
$killPos = strpos($mig, 'pkill -f');
$movePos = strpos($mig, 'mv "${OLD_DIR}" "${INSTALL_DIR}"');
t_ok($stopPos !== false && $movePos !== false && $stopPos < $movePos,
    'the old services are stopped before the directory moves');
t_ok($killPos !== false && $killPos < $movePos,
    'and detached scan workers killed, since they outlive the service');

// A move, not a copy: several hundred quarantined files half-copied would be
// worse than either outcome.
t_contains($mig, 'mv "${OLD_DIR}" "${INSTALL_DIR}"',
    'the data is moved, preserving database and quarantine');
t_ok(strpos($mig, 'cp -r "${OLD_DIR}"') === false, 'and never copied');

// Both present means an interrupted migration or a fresh install after the
// rename. Overwriting either would lose data.
t_contains($mig, 'pre-serverscrub',
    'an existing new-name install is not overwritten; the old one is set aside');

// The database is named after the product too, and SQLite keeps sidecar files.
t_contains($mig, 'database/sentinel.db', 'the old database file is found');
t_contains($mig, 'database/serverscrub.db', 'and renamed');
t_contains($mig, 'wal shm journal',
    'with its write-ahead log, so an uncheckpointed transaction is not stranded');

// The old registrations must go, or WHM keeps a menu entry pointing at a
// directory that no longer exists.
t_contains($mig, 'unregister_appconfig sentinel_gate', 'the old WHM plugin is deregistered');
t_contains($mig, 'frontend/${_th}/sentinel_gate', 'the old cPanel user plugin is removed');
t_contains($mig, 'rm -f /usr/bin/sentinel', 'and the old CLI');
t_contains($mig, '/etc/cron.d/sentinel-gate', 'old cron entries are removed before new ones are written');

// The WAF include is referenced by Apache. Deleting it without putting the new
// name in place would silently drop every rule.
t_contains($mig, 'sentinel-waf.conf', 'the old WAF include is handled');
t_contains($mig, 'serverscrub-waf.conf', 'by renaming it rather than deleting it');

// ── The logo ────────────────────────────────────────────────────────────────
foreach ([
    'frontend/images/logo.png',
    'frontend/images/icon-64.png',
    'frontend/images/icon-180.png',
    'whm/serverscrub.png',
] as $asset) {
    t_ok(is_file($repo . '/' . $asset), "ships {$asset}");
    t_ok(filesize($repo . '/' . $asset) > 500, "{$asset} is not a stub");
}
t_ok(!is_file($repo . '/whm/sentinel_gate.png'), 'the old icon is gone');

$html = file_get_contents($repo . '/frontend/index.html');
t_contains($html, 'images/logo.png', 'the login screen shows the logo');
t_contains($html, 'rel="icon"', 'the browser tab has an icon');
t_contains($html, 'images/icon-180.png', 'and there is an apple-touch icon');

// Two different shields in one interface is one too many.
t_ok(strpos($html, '<svg width="34" height="38"') === false,
    'the old hand-drawn shield mark is gone from the header');
t_ok(strpos($html, '<svg width="46" height="52"') === false,
    'and from the activation card');

// The icons are referenced by the plugin registrations.
t_contains($install, 'whm/serverscrub.png', 'the WHM plugin icon is installed');
t_contains($install, '"icon":     "serverscrub.png"', 'and the cPanel plugin names it');

// ── Uninstall removes what install creates ──────────────────────────────────
t_contains($uninstall, 'serverscrub-monitor', 'the uninstaller stops the renamed service');
t_contains($uninstall, '/usr/bin/serverscrub', 'and removes the renamed CLI');


// ── The WHM Driver module ───────────────────────────────────────────────────
// The installer copies these by name. The rename swept install.sh but the
// FILES are .pm, which the sweep did not cover — so the installer was left
// copying ServerScrub.pm from a tree that still held SentinelGate.pm, and the
// driver install would have failed on a real server.
t_ok(is_file($repo . '/whm/Driver/ServerScrub.pm'), 'the driver module is renamed');
t_ok(is_file($repo . '/whm/Driver/ServerScrub/META.pm'), 'and its META module');
t_ok(!is_file($repo . '/whm/Driver/SentinelGate.pm'), 'the old module is gone');

$drv = file_get_contents($repo . '/whm/Driver/ServerScrub.pm');
t_contains($drv, 'Driver::ServerScrub', 'the Perl package is renamed too');
t_ok(strpos($drv, 'SentinelGate') === false, 'with no stale package reference');

// What the installer copies must be what the tree actually holds.
foreach (['ServerScrub.pm', 'ServerScrub/META.pm'] as $f) {
    t_contains($install, '/' . $f, "the installer copies {$f}");
    t_ok(is_file($repo . '/whm/Driver/' . $f), "and {$f} exists to be copied");
}

// And the old one is cleaned up, or cPanel keeps loading a Perl package for a
// plugin that no longer exists.
t_contains($mig, 'Driver/SentinelGate.pm', 'the old driver module is removed on migration');
