<?php
/**
 * Sentinel Gate — Core Configuration
 * Adjust paths after installation via install.sh
 */

define('SG_VERSION',  '3.19.3');
define('SG_ROOT',     dirname(__DIR__, 2));
define('SG_DB',       SG_ROOT . '/database/sentinel.db');
define('SG_LOGS',     SG_ROOT . '/logs');
define('SG_TMP',      '/tmp/sentinel-gate');

// ── Install Mode ──────────────────────────────────────────────────────────────
// Written by install.sh into backend/config/mode.php
// Values: 'cpanel' | 'standalone'
if (file_exists(__DIR__ . '/mode.php')) {
    require_once __DIR__ . '/mode.php';
} else {
    define('INSTALL_MODE', 'cpanel');
}

// Standalone web server port
define('SG_PORT', 31150);

// ── cPanel / WHM ─────────────────────────────────────────────────────────────
define('CPANEL_USER',    getenv('REMOTE_USER') ?: 'root');
define('CPANEL_BASE',    '/usr/local/cpanel');
define('UAPI_BINARY',    CPANEL_BASE . '/bin/uapi');
define('WHMAPI_BINARY',  CPANEL_BASE . '/bin/whmapi1');

// ── ClamAV ───────────────────────────────────────────────────────────────────
define('CLAMSCAN_BIN',   '/usr/bin/clamscan');
define('FRESHCLAM_BIN',  '/usr/bin/freshclam');
define('CLAMD_SOCKET',   '/var/run/clamav/clamd.ctl');

// ── CSF / Firewall ────────────────────────────────────────────────────────────
define('CSF_BIN',        '/usr/sbin/csf');
define('CSF_CONF',       '/etc/csf/csf.conf');
define('CSF_DENY',       '/etc/csf/csf.deny');
define('CSF_ALLOW',      '/etc/csf/csf.allow');
define('IPTABLES_BIN',   '/sbin/iptables');

// ── ModSecurity ───────────────────────────────────────────────────────────────
define('MODSEC_CONF',    '/etc/apache2/conf.d/modsec_vendor_configs');
define('MODSEC_AUDIT',   '/var/log/modsec_audit.log');
define('MODSEC_LOG',     '/var/log/apache2/modsec.log');

// ── Scan Settings ─────────────────────────────────────────────────────────────
define('SCAN_MAX_SIZE',  52428800);   // 50MB per file
define('SCAN_THREADS',   4);
define('QUARANTINE_DIR', SG_ROOT . '/quarantine');

// ── API Auth ──────────────────────────────────────────────────────────────────
define('JWT_SECRET',     hash('sha256', gethostname() . 'sentinel_gate_secret_2024'));
define('JWT_EXPIRY',     3600 * 8);  // 8 hours

// ── Malware Signature patterns ───────────────────────────────────────────────
define('SIG_DIR', SG_ROOT . '/backend/signatures');

// ── RBL / IP Reputation feeds ────────────────────────────────────────────────
define('RBL_FEEDS', serialize([
    'spamhaus'    => 'zen.spamhaus.org',
    'barracuda'   => 'b.barracudacentral.org',
    'sorbs'       => 'dnsbl.sorbs.net',
    'abuseipdb'   => 'https://api.abuseipdb.com/api/v2/check',
    'spamcop'     => 'bl.spamcop.net',
    'uceprotect'  => 'dnsbl-1.uceprotect.net',
    'psbl'        => 'psbl.surriel.com',
    'spfbl'       => 'bl.spfbl.net',
]));

// NOTE: this map is the legacy feed list, consumed only by IPReputation as a
// name => host pair. BlocklistRegistry is the authoritative source (25 lists
// with categories, weights and return-code meanings); prefer it for new work.
