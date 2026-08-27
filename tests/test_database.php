<?php
/**
 * Database regressions.
 *
 *   3.19.7  Database::getSetting() was called from 11 sites across four files.
 *           The method does not exist — it is setting(). License::status()
 *           fataled, and since every feature route consults the licence, one
 *           typo took down dashboard, scanner, firewall, WAF and IP reputation
 *           at once.
 *   3.19.6  Scheduled tasks died with "Undefined constant SG_DB" because cron
 *           entries load mode.php only, and update.sh never rewrites cron.
 */

require_once __DIR__ . '/assert.php';
require __DIR__ . '/bootstrap.php';

// ── The API is what callers actually use ─────────────────────────────────────
t_ok(method_exists('Database', 'setting'),    'Database::setting() exists');
t_ok(method_exists('Database', 'setSetting'), 'Database::setSetting() exists');
t_ok(!method_exists('Database', 'getSetting'),
    'Database::getSetting() does NOT exist — callers must use setting()');

// ── Settings round trip ──────────────────────────────────────────────────────
t_no_throw(function () {
    Database::setSetting('t_key', 'value-1');
}, 'setSetting() writes without throwing');

t_eq('value-1', Database::setting('t_key'), 'setting() reads back what was written');
t_eq('value-2', Database::setting('t_missing', 'value-2'), 'setting() returns the default when absent');
t_eq(null, Database::setting('t_missing'), 'setting() returns null with no default');

Database::setSetting('t_key', 'value-3');
t_eq('value-3', Database::setting('t_key'), 'setSetting() overwrites an existing key');

// The licence code passes an int default (installedAt uses 0). It must not blow
// up on the string type hint.
t_no_throw(function () {
    Database::setting('t_int_default', '0');
}, 'a scalar default is accepted');

// ── SG_DB fallback ───────────────────────────────────────────────────────────
// Database.php derives SG_DB from SG_ROOT when a stale cron entry omits it.
// Without this, existing installs stay broken until their cron is rewritten,
// which update.sh does not do.
$dbSrc = t_code(dirname(__DIR__) . '/backend/lib/Database.php');
t_contains($dbSrc, "!defined('SG_DB')", 'Database.php derives SG_DB when it is absent');

// ── The schema the product depends on ────────────────────────────────────────
t_no_throw(function () {
    Database::get();
}, 'the database opens');

$tables = array_column(
    Database::fetchAll("SELECT name FROM sqlite_master WHERE type='table'"),
    'name'
);
foreach (['settings', 'threats', 'firewall_rules', 'security_events',
          'scan_jobs', 'blocked_ips', 'waf_events'] as $t) {
    t_ok(in_array($t, $tables, true), "table {$t} is created by migrate()");
}
