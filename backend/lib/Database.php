<?php
/**
 * Sentinel Gate — SQLite Database Layer
 */

class Database {
    private static ?PDO $pdo = null;

    public static function get(): PDO {
        if (self::$pdo === null) {
            $db_path = SG_DB;
            $dir = dirname($db_path);
            if (!is_dir($dir)) mkdir($dir, 0750, true);

            self::$pdo = new PDO("sqlite:$db_path");
            self::$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            self::$pdo->exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
            self::migrate(self::$pdo);
        }
        return self::$pdo;
    }

    private static function migrate(PDO $db): void {
        $db->exec("
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type   TEXT    NOT NULL DEFAULT 'quick',
                status      TEXT    NOT NULL DEFAULT 'pending',
                started_at  INTEGER,
                finished_at INTEGER,
                files_scanned  INTEGER DEFAULT 0,
                threats_found  INTEGER DEFAULT 0,
                scan_path   TEXT    DEFAULT '/',
                created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS threats (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_job_id  INTEGER REFERENCES scan_jobs(id),
                file_path    TEXT    NOT NULL,
                threat_name  TEXT,
                threat_type  TEXT,
                severity     TEXT    DEFAULT 'high',
                status       TEXT    DEFAULT 'active',
                hash         TEXT,
                size         INTEGER,
                detected_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                resolved_at  INTEGER,
                action_taken TEXT
            );

            CREATE TABLE IF NOT EXISTS firewall_rules (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                direction   TEXT    NOT NULL DEFAULT 'in',
                protocol    TEXT    DEFAULT 'tcp',
                port        TEXT,
                source_ip   TEXT,
                dest_ip     TEXT,
                action      TEXT    NOT NULL DEFAULT 'DROP',
                enabled     INTEGER NOT NULL DEFAULT 1,
                hits        INTEGER DEFAULT 0,
                priority    INTEGER DEFAULT 100,
                comment     TEXT,
                created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT    NOT NULL UNIQUE,
                reason      TEXT,
                country     TEXT,
                threat_score INTEGER DEFAULT 0,
                blocked_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                expires_at  INTEGER,
                permanent   INTEGER DEFAULT 0,
                source      TEXT    DEFAULT 'manual'
            );

            CREATE TABLE IF NOT EXISTS waf_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id     TEXT,
                rule_msg    TEXT,
                severity    TEXT,
                ip_address  TEXT,
                uri         TEXT,
                method      TEXT,
                host        TEXT,
                user_agent  TEXT,
                action      TEXT    DEFAULT 'block',
                timestamp   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                type        TEXT    NOT NULL,
                severity    TEXT    NOT NULL DEFAULT 'medium',
                source_ip   TEXT,
                target      TEXT,
                description TEXT,
                raw_data    TEXT,
                resolved    INTEGER DEFAULT 0,
                timestamp   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS file_integrity (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path   TEXT    NOT NULL UNIQUE,
                hash_sha256 TEXT    NOT NULL,
                size        INTEGER,
                permissions TEXT,
                owner       TEXT,
                baseline_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                last_check  INTEGER,
                status      TEXT    DEFAULT 'clean'
            );

            CREATE TABLE IF NOT EXISTS settings (
                key         TEXT    PRIMARY KEY,
                value       TEXT,
                updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS ip_reputation (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT    NOT NULL UNIQUE,
                score       INTEGER DEFAULT 0,
                country     TEXT,
                asn         TEXT,
                rbl_hits    TEXT,
                last_seen   INTEGER,
                cached_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS cron_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                job_name    TEXT,
                status      TEXT,
                message     TEXT,
                duration_ms INTEGER,
                ran_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            -- v3.3.1: add cpanel_user to threats (ALTER is idempotent via try/catch in PHP)

            -- Default settings
            INSERT OR IGNORE INTO settings (key, value) VALUES
                ('scan_schedule',           'daily'),
                ('scan_paths',              '/home'),
                ('email_alerts',            '1'),
                ('alert_email',             ''),
                ('auto_quarantine',         '1'),
                ('firewall_enabled',        '1'),
                ('waf_enabled',             '1'),
                ('bot_shield_enabled',      '1'),
                ('ip_rep_enabled',          '1'),
                ('geo_block_countries',     ''),
                ('rate_limit_ssh',          '5'),
                ('rate_limit_http',         '100'),
                ('php_disable_funcs',       'exec,passthru,shell_exec,system,proc_open,popen'),
                ('installed_at',            CAST(strftime('%s','now') AS TEXT)),
                ('last_scan',               '0'),
                ('clam_db_update',          '0'),
                -- Storage management
                ('quarantine_dir',          ''),
                ('log_dir',                 ''),
                ('log_retention_days',      '30'),
                ('quarantine_retention_days','90'),
                ('db_max_waf_events',       '100000'),
                ('db_max_security_events',  '50000'),
                ('db_max_cron_log',         '1000'),
                ('monitor_log_max_mb',      '50');

            -- Default firewall rules
            INSERT OR IGNORE INTO firewall_rules (name, direction, protocol, port, action, comment) VALUES
                ('ALLOW_SSH',          'in',   'tcp', '22',   'ACCEPT', 'Allow SSH access'),
                ('ALLOW_HTTP',         'in',   'tcp', '80',   'ACCEPT', 'Allow HTTP'),
                ('ALLOW_HTTPS',        'in',   'tcp', '443',  'ACCEPT', 'Allow HTTPS'),
                ('ALLOW_cPanel',       'in',   'tcp', '2082', 'ACCEPT', 'Allow cPanel'),
                ('ALLOW_WHM',          'in',   'tcp', '2086', 'ACCEPT', 'Allow WHM'),
                ('ALLOW_cPanelSSL',    'in',   'tcp', '2083', 'ACCEPT', 'Allow cPanel SSL'),
                ('ALLOW_WHMSSL',       'in',   'tcp', '2087', 'ACCEPT', 'Allow WHM SSL'),
                ('BLOCK_NULL_PACKETS', 'in',   'tcp', NULL,   'DROP',   'Block NULL packets'),
                ('BLOCK_XMAS',         'in',   'tcp', NULL,   'DROP',   'Block XMAS packets'),
                ('RATE_LIMIT_SSH',     'in',   'tcp', '22',   'LIMIT',  'Rate limit SSH brute force');
        ");

        // Incremental migrations — safe to run on every boot (IF NOT EXISTS / IGNORE)
        // Add cpanel_user column to threats if missing (SQLite ALTER TABLE is append-only)
        $cols = array_column($db->query("PRAGMA table_info(threats)")->fetchAll(PDO::FETCH_ASSOC), 'name');
        if (!in_array('cpanel_user', $cols)) {
            $db->exec("ALTER TABLE threats ADD COLUMN cpanel_user TEXT");
        }
    }

    public static function query(string $sql, array $params = []): PDOStatement {
        $stmt = self::get()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    public static function fetchAll(string $sql, array $params = []): array {
        return self::query($sql, $params)->fetchAll();
    }

    public static function fetchOne(string $sql, array $params = []): ?array {
        $row = self::query($sql, $params)->fetch();
        return $row ?: null;
    }

    public static function insert(string $table, array $data): int {
        $cols = implode(',', array_keys($data));
        $placeholders = implode(',', array_fill(0, count($data), '?'));
        self::query("INSERT INTO $table ($cols) VALUES ($placeholders)", array_values($data));
        return (int) self::get()->lastInsertId();
    }

    /**
     * Resolve a storage path — uses DB setting if configured, otherwise falls
     * back to the compile-time constant (QUARANTINE_DIR / SG_LOGS).
     * This lets admins relocate data via the GUI without touching config.php.
     */
    public static function storagePath(string $type): string {
        $key     = ($type === 'quarantine') ? 'quarantine_dir' : 'log_dir';
        $fallback= ($type === 'quarantine') ? QUARANTINE_DIR   : SG_LOGS;
        $val     = self::setting($key, '');
        $path    = ($val !== '') ? rtrim($val, '/') : rtrim($fallback, '/');
        if (!is_dir($path)) @mkdir($path, 0750, true);
        return $path;
    }

    /**
     * Prune old database rows to prevent unbounded growth.
     * Called by the nightly cron and by the GUI "Run Cleanup Now" button.
     */
    public static function pruneOldRecords(): array {
        $deleted = [];

        // WAF events — keep only the most recent N rows
        $maxWaf = (int) self::setting('db_max_waf_events', '100000');
        $total  = self::fetchOne("SELECT COUNT(*) as c FROM waf_events")['c'];
        if ($total > $maxWaf) {
            $keep = self::fetchOne(
                "SELECT id FROM waf_events ORDER BY id DESC LIMIT 1 OFFSET ?",
                [$maxWaf]
            );
            if ($keep) {
                $r = self::query("DELETE FROM waf_events WHERE id <= ?", [$keep['id']]);
                $deleted['waf_events'] = $r->rowCount();
            }
        }

        // Security events — keep only the most recent N rows
        $maxSec = (int) self::setting('db_max_security_events', '50000');
        $total  = self::fetchOne("SELECT COUNT(*) as c FROM security_events")['c'];
        if ($total > $maxSec) {
            $keep = self::fetchOne(
                "SELECT id FROM security_events ORDER BY id DESC LIMIT 1 OFFSET ?",
                [$maxSec]
            );
            if ($keep) {
                $r = self::query("DELETE FROM security_events WHERE id <= ?", [$keep['id']]);
                $deleted['security_events'] = $r->rowCount();
            }
        }

        // IP reputation cache — evict entries older than 24 hours
        $cutoff = time() - 86400;
        $r = self::query("DELETE FROM ip_reputation WHERE cached_at < ?", [$cutoff]);
        $deleted['ip_reputation'] = $r->rowCount();

        // Cron log — keep only last N rows
        $maxCron = (int) self::setting('db_max_cron_log', '1000');
        $total   = self::fetchOne("SELECT COUNT(*) as c FROM cron_log")['c'];
        if ($total > $maxCron) {
            $keep = self::fetchOne(
                "SELECT id FROM cron_log ORDER BY id DESC LIMIT 1 OFFSET ?",
                [$maxCron]
            );
            if ($keep) {
                $r = self::query("DELETE FROM cron_log WHERE id <= ?", [$keep['id']]);
                $deleted['cron_log'] = $r->rowCount();
            }
        }

        // Resolved threats older than quarantine_retention_days — mark as archived
        $retDays = (int) self::setting('quarantine_retention_days', '90');
        $cutoff  = time() - ($retDays * 86400);
        $r = self::query(
            "UPDATE threats SET status='archived' WHERE status='quarantined' AND detected_at < ?",
            [$cutoff]
        );
        $deleted['threats_archived'] = $r->rowCount();

        // Compact the DB after large deletes
        self::get()->exec('PRAGMA wal_checkpoint(PASSIVE); VACUUM;');

        return $deleted;
    }

    public static function setting(string $key, ?string $default = null): ?string {
        $row = self::fetchOne("SELECT value FROM settings WHERE key = ?", [$key]);
        return $row ? $row['value'] : $default;
    }

    public static function setSetting(string $key, string $value): void {
        self::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, strftime('%s','now'))
             ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            [$key, $value]
        );
    }
}
