#!/usr/bin/env php
<?php
/**
 * Sentinel Gate — Daily Update Check Cron
 * Installed by install.sh to run once per day.
 * Fetches latest GitHub release and caches the result.
 */

// ── Bootstrap ─────────────────────────────────────────────────────────────────
$root = getenv('SG_ROOT') ?: '/usr/local/sentinel-gate';
$cfg  = $root . '/backend/config/mode.php';

if (!file_exists($cfg)) {
    fwrite(STDERR, "[update-check] Config not found: $cfg\n");
    exit(1);
}

require_once $cfg;
require_once $root . '/backend/lib/Logger.php';
require_once $root . '/backend/lib/Database.php';
require_once $root . '/backend/lib/UpdateChecker.php';

// ── Suppress display errors (we write to log instead) ─────────────────────────
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// ── Run check ─────────────────────────────────────────────────────────────────
$result = UpdateChecker::checkForUpdates();

if ($result['update_available']) {
    echo "[update-check] New version available: v{$result['latest_version']} (current: v{$result['current_version']})\n";
    echo "[update-check] Release: {$result['release_url']}\n";
} else {
    echo "[update-check] Up to date — v{$result['current_version']}\n";
}
