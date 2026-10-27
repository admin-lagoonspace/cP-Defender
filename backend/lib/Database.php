<?php
/**
 * ServerScrub — SQLite Database Layer
 */

// The scheduled tasks installed before 3.19.4 load mode.php only, which records
// SG_ROOT but not SG_DB, so every cron run died with "Undefined constant SG_DB".
// update.sh does not rewrite those cron files, so a corrected installer is not
// enough on its own — derive the path when it is absent.
if (!defined('SG_DB') && defined('SG_ROOT')) {
    define('SG_DB', SG_ROOT . '/database/serverscrub.db');
}

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
                ('scan_time',               '02:00'),
                ('scan_day',                '0'),
                ('scan_type',               'full'),
                ('sig_update_schedule',     'weekly'),
                ('sig_update_time',         '01:00'),
                ('sig_update_day',          '0'),
                ('iprep_schedule',          'daily'),
                ('iprep_time',              '03:00'),
                ('iprep_day',               '0'),
                ('scan_paths',              '/home'),
                -- Stand down while a backup or bulk transfer is running.
                -- JetBackup walks every account and rsync streams the result
                -- off-box; a real-time scanner competing for the same disks at
                -- that moment is the worst time for it to be working hardest.
                ('rt_pause_on_backup',        '1'),
                -- Bring monitoring back up once the backups have finished.
                -- The daemon suspends its own scanning during a backup, but a
                -- daemon that is stopped cannot restart itself -- and a
                -- monitor that went down in a backup window otherwise stays
                -- down until somebody notices.
                ('rt_autostart_after_backup', '1'),
                -- 'every' means every scheduler tick, which cron fires at */15.
                ('rt_autostart_schedule',     'every'),
                -- Set when a person stops the monitor with no backup running,
                -- so auto-resume does not overrule a deliberate decision.
                ('rt_manual_stop',            '0'),
                ('rt_backup_procs',           'jetbackup,rsync'),
                -- Never treated as a running backup, however they match.
                -- JetBackup's daemon runs continuously whether or not a backup
                -- is happening; matching it suspended real-time monitoring
                -- permanently on every server with JetBackup installed.
                ('rt_backup_exclude',         'jetbackupd,jetbackup5d,jetbackupmysqld'),
                ('rt_backup_check_secs',      '20'),
                -- rsync is usually a series of short runs; resuming between
                -- them costs more than staying down for another minute.
                ('rt_backup_resume_secs',     '60'),
                -- A process merely NAMED rsync is enough to suspend scanning,
                -- so the pause has to end on its own eventually.
                ('rt_backup_max_suspend_secs','14400'),
                ('email_alerts',            '1'),
                ('alert_email',             ''),
                -- Off by default. Quarantine MOVES the file into
                -- /usr/local/serverscrub/quarantine, which is on the root
                -- partition, so an enthusiastic scan can fill / on a server
                -- whose customer data lives on a separate volume. Detection
                -- still records the threat; acting on it is a decision the
                -- operator opts into.
                ('auto_quarantine',         '0'),
                -- What happens to an infected file, by severity.
                -- high/critical: deleted outright, with no copy kept.
                -- medium: quarantined for 5 days, then deleted.
                -- low: quarantined for 7 days, then deleted.
                ('policy_high_action',      'delete'),
                ('policy_medium_days',      '5'),
                ('policy_low_days',         '7'),
                -- At most this many scans at once, and one is the intended
                -- number. Each clamscan loads the whole ClamAV signature
                -- database into its own memory (650MB to 1.3GB observed), so
                -- a second scan buys a second copy of that database and two
                -- processes queued on the same disks -- not half the runtime.
                -- Raising it is possible but is not a throughput control.
                ('scan_max_concurrent',     '1'),
                -- A single clamscan invocation that exceeds this is abandoned;
                -- one was found holding 13 minutes of CPU on one file.
                ('scan_batch_timeout',      '600'),
                -- Hold a scan while a backup is running. The real-time monitor
                -- has paused during backups since 3.30.0; the scanner did not,
                -- so clamscan competed with rsync for the same disks while the
                -- monitor sat idle.
                ('scan_pause_on_backup',    '1'),
                -- How long a dealt-with threat stays in the log. Active ones
                -- are kept regardless of age: an unresolved threat is exactly
                -- what the log is for.
                ('threat_retention_days',   '7'),
                -- Rootkit scanning runs nightly. It was unseeded, so it fell
                -- back to the code default of weekly; a rootkit that lands on
                -- Monday should not wait until Sunday to be noticed. 03:00 is
                -- after the usual backup window.
                ('rootkit_schedule',        'daily'),
                ('rootkit_time',            '03:00'),
                ('rootkit_day',             '0'),
                -- After this long waiting, the scan gives up and the next
                -- scheduled run picks it up rather than sleeping for ever.
                ('scan_backup_max_wait',    '14400'),
                -- Quarantine grew without limit until this existed. 0 disables
                -- pruning, for anyone who would rather keep everything.
                ('quarantine_retention_days', '7'),
                ('firewall_enabled',        '1'),
                ('waf_enabled',             '1'),
                ('bot_shield_enabled',      '1'),
                ('ip_rep_enabled',          '1'),
                ('geo_block_countries',     ''),
                ('rate_limit_ssh',          '5'),
                -- Brute-force detection. The dashboard has charted this since
                -- it was written and nothing ever produced the data.
                ('bf_enabled',              '1'),
                ('bf_threshold',            '5'),
                ('bf_ladder',               '10800,21600,86400,0'),
                ('bf_offence_memory_days',  '30'),
                ('bf_window',               '600'),
                ('bf_auto_block',           '1'),
                ('bf_retention_days',       '7'),
                ('bf_schedule',             'every'),
                ('bf_whitelist',            ''),
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
                ('monitor_log_max_mb',      '50'),
                -- Performance
                ('cpu_limit_percent',       '50'),
                ('rt_poll_interval',        '300'),
                -- Update checker
                ('update_available',        '0'),
                ('update_latest_ver',       ''),
                ('update_checked_at',       '0'),
                ('update_release_url',      ''),
                ('update_release_notes',    '');

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

        // Operator verdicts: "I looked at this file and it is not malware."
        //
        // Keyed on (file_path, sha256), NOT on path. This is the whole point:
        // an exclusion blinds the scanner to a path forever, while a verdict
        // only suppresses the REPORT for the exact bytes somebody read and
        // cleared. Change one byte and the hash no longer matches, so the file
        // is reported again at full severity. See Verdicts.php.
        //
        // UNIQUE(file_path, sha256) makes a double-click a no-op rather than a
        // duplicate row.
        $db->exec("
            CREATE TABLE IF NOT EXISTS file_verdicts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path   TEXT    NOT NULL,
                sha256      TEXT    NOT NULL,
                verdict     TEXT    NOT NULL DEFAULT 'not_malware',
                threat_name TEXT,
                size        INTEGER DEFAULT 0,
                note        TEXT,
                created_by  TEXT,
                created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE(file_path, sha256)
            );
            CREATE INDEX IF NOT EXISTS idx_verdict_lookup
                ON file_verdicts(file_path, sha256);
        ");

        // Firewall rules: the seeding INSERT above says OR IGNORE, and until now
        // there was nothing for it to ignore ON.
        //
        // FROM A LIVE SERVER. The Firewall page "took forever to load" and then
        // killed the browser tab. The cause was 343,000 rules in a table the
        // operator had added about a dozen entries to. firewall_rules has no
        // UNIQUE constraint, so "INSERT OR IGNORE" had no conflict to ignore and
        // the ten default rules were appended again on EVERY database open --
        // which is every API request. 343,000 / 10 is roughly 34,000 page loads.
        // The product was manufacturing its own rules, and paging the table only
        // hides that.
        //
        // Give the rule identity a unique index so OR IGNORE has something to
        // ignore, and collapse what has already piled up, keeping the earliest
        // row of each set. port, source_ip and dest_ip are nullable and SQLite
        // treats NULLs as distinct, so the index is on COALESCE'd expressions --
        // otherwise BLOCK_NULL_PACKETS, whose port IS NULL, would go on
        // duplicating straight past the index.
        $hasFwIdx = $db->query(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_fw_identity'"
        )->fetchColumn();
        if ($hasFwIdx === false) {
            $db->exec("DELETE FROM firewall_rules WHERE id NOT IN (
                           SELECT MIN(id) FROM firewall_rules
                            GROUP BY name, direction, COALESCE(protocol,''),
                                     COALESCE(port,''), COALESCE(source_ip,''),
                                     COALESCE(dest_ip,''), action)");
            $db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_fw_identity
                           ON firewall_rules (name, direction, COALESCE(protocol,''),
                                COALESCE(port,''), COALESCE(source_ip,''),
                                COALESCE(dest_ip,''), action)");
        }

        // Incremental migrations — safe to run on every boot (IF NOT EXISTS / IGNORE)
        // Add cpanel_user column to threats if missing (SQLite ALTER TABLE is append-only)
        $cols = array_column($db->query("PRAGMA table_info(threats)")->fetchAll(PDO::FETCH_ASSOC), 'name');
        if (!in_array('cpanel_user', $cols)) {
            $db->exec("ALTER TABLE threats ADD COLUMN cpanel_user TEXT");
        }

        // Which process is actually doing the scanning.
        //
        // A scan was launched detached with `&` and its PID was never recorded,
        // so nothing could stop it afterwards: once started, clamscan ran to
        // completion whatever the operator did. The process GROUP is the useful
        // thing to keep -- the worker forks clamscan for every batch, and
        // killing only the worker leaves the clamscan it is currently waiting
        // on running.
        $jobCols = array_column($db->query("PRAGMA table_info(scan_jobs)")->fetchAll(PDO::FETCH_ASSOC), 'name');
        if (!in_array('worker_pid', $jobCols)) {
            $db->exec("ALTER TABLE scan_jobs ADD COLUMN worker_pid INTEGER");
        }
        if (!in_array('worker_pgid', $jobCols)) {
            $db->exec("ALTER TABLE scan_jobs ADD COLUMN worker_pgid INTEGER");
        }

        // Where a quarantined file went, and when it may be deleted. The sweep
        // needs the exact path: guessing it from the threat's original name
        // would eventually delete the wrong thing.
        $thCols = array_column($db->query("PRAGMA table_info(threats)")->fetchAll(PDO::FETCH_ASSOC), 'name');
        if (!in_array('quarantine_path', $thCols)) {
            $db->exec("ALTER TABLE threats ADD COLUMN quarantine_path TEXT");
        }
        if (!in_array('quarantine_expires_at', $thCols)) {
            $db->exec("ALTER TABLE threats ADD COLUMN quarantine_expires_at INTEGER");
        }

        // One-time repair of mail_activity written before 4.11.1.
        //
        // collect() used to file every log line it read into the CURRENT hour,
        // so a first run -- which reads up to 8 MB of HISTORY -- recorded days
        // of mail as though it had all happened in the last sixty minutes. On
        // a live server that produced a CRITICAL finding of "5,036 messages in
        // the last hour" against an account whose real figure was 22 messages
        // across 300,000 log lines.
        //
        // Those rows cannot be corrected, only discarded: the hour they
        // belonged to was never recorded. The offset is reset too, so the log
        // is re-read and rebuilt with correct timestamps.
        $row = $db->query("SELECT value FROM settings WHERE key = 'mg_bucket_repair'")
                  ->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            // mail_activity is created lazily by MailGuard::ensureSchema(), so
            // it may not exist yet on a fresh install. Checked rather than
            // assumed: an exception here aborts every migration after it.
            $has = $db->query("SELECT name FROM sqlite_master
                                WHERE type='table' AND name='mail_activity'")
                      ->fetch(PDO::FETCH_ASSOC);
            if ($has) { $db->exec("DELETE FROM mail_activity"); }
            $db->exec("DELETE FROM settings WHERE key = 'mg_offset'");
            $db->exec("INSERT OR REPLACE INTO settings (key, value)
                       VALUES ('mg_bucket_repair', '1')");
        }

        // Outbound mail monitoring, on by default.
        //
        // OUTBOUND ONLY. Inbound filtering is MagicSpam's job on this server
        // and two tools fighting over inbound policy is worse than one. Nothing
        // here reads a message body or scores spam; it counts and attributes.
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('mg_enabled', '1')");
        // 500/hour per account. The relay that prompted this ran at ~1,690/hour
        // for a day, so this catches that shape inside the first hour while
        // staying well above what a busy shop or a small newsletter sends.
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('mg_hourly', '500')");
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('mg_queue', '2000')");
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('mg_frozen', '250')");
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('mg_retain_days', '60')");

        // Network-layer guards. Scan detection and flood limits are ON: both
        // only ever record, and the escalation they feed into is the
        // brute-force ladder that was already running.
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('ng_scan_enabled', '1')");
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('ng_scan_ports', '10')");
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('ng_flood_enabled', '1')");
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('ng_flood_limit', '150')");
        // 80 and 443 exempt by default. A browser opens six connections per
        // page, a corporate NAT or CDN presents hundreds of real users as one
        // address, and this product's own dashboard is served over 443 -- a
        // flood limit there blocks the operator out of the page they would
        // need to turn it off.
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('ng_flood_exempt_ports', '80,443')");
        // Egress filtering OFF, with no automatic enable anywhere. A wrong
        // inbound rule blocks visitors and you hear about it; a wrong OUTBOUND
        // rule breaks updates, DNS, mail, licensing and backups quietly.
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('ng_egress_enabled', '0')");

        // Unattended updating, on by default.
        //
        // Defaulting this ON is a real decision and not a neutral one: it
        // replaces the security software on a production server without anyone
        // watching. It is the right default anyway, because the alternative
        // observed in the field is a server running a version from months ago
        // with an "update available" badge nobody reads. The risk is bounded
        // instead by what Updater::shouldApply() refuses -- major versions, a
        // running scan, a running backup, and anything after three failures.
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('auto_update', '1')");
        // Major versions are NOT automatic. X is reserved in this product's
        // versioning for a breaking change.
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('auto_update_major', '0')");
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('autoupdate_schedule', 'daily')");
        // 04:30: after the 03:30 database sweep and the 04:00 CMS discovery,
        // so a restart does not land on top of either.
        $db->exec("INSERT OR IGNORE INTO settings (key, value)
                   VALUES ('autoupdate_time', '04:30')");

        // Why a heuristic fired, in a sentence.
        //
        // Added with the heuristic rule engine. The old flat signatures were
        // self-describing -- "eval_base64" says what it found -- but a rule
        // that fires on a CONJUNCTION cannot be read off its name. An operator
        // deciding whether to delete a customer's file needs to be told that
        // the file checks a 32-hex password with hash_equals() and then calls
        // move_uploaded_file(), not just that rule 'upload_backdoor_hashkey'
        // matched.
        if (!in_array('detail', $thCols)) {
            $db->exec("ALTER TABLE threats ADD COLUMN detail TEXT");
        }

        // Findings that are not files.
        //
        // Everything this product recorded until now was a path. During the
        // October 2026 incident most of what mattered was a database row: 148
        // administrator accounts inserted by SQL, a payload mirrored across
        // wp_options and a draft post, a login token in usermeta, and a
        // contact form whose autoresponder relayed 92,954 spam messages
        // without a single file being modified. None of those fit in `threats`
        // -- there is no file to quarantine and nothing to delete on disk --
        // so they get their own table, and the actions column says what a
        // human should do rather than implying the software already did it.
        $db->exec("
            CREATE TABLE IF NOT EXISTS wp_findings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_job_id  INTEGER REFERENCES scan_jobs(id),
                install_path TEXT    NOT NULL,
                db_name      TEXT,
                cpanel_user  TEXT,
                finding_type TEXT    NOT NULL,
                severity     TEXT    DEFAULT 'medium',
                what         TEXT,
                action       TEXT,
                status       TEXT    DEFAULT 'open',
                detected_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                resolved_at  INTEGER
            );
        ");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_wpf_open
                     ON wp_findings(status, severity)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_wpf_install
                     ON wp_findings(install_path)");

        // 3.30.4 shipped scan_max_concurrent defaulting to 2; the intended
        // number is 1. The seed above is INSERT OR IGNORE, so it cannot change
        // a row that already exists -- an upgrade would silently keep 2.
        //
        // Guarded by a marker so it runs exactly once: an operator who later
        // sets this to 2 deliberately keeps it, rather than having every
        // upgrade quietly overrule them.
        // Quarantine used to be kept for 30 days. The policy is that nothing
        // stays beyond 7, and the seed is INSERT OR IGNORE so it cannot change
        // a row that already exists -- an upgrade would otherwise keep 30 and
        // the backlog would never clear. Marked so it runs once: an operator
        // who deliberately sets a longer retention afterwards keeps it.
        $qmig = $db->query(
            "SELECT value FROM settings WHERE key='sg_mig_quarantine_7d'"
        )->fetchColumn();
        if ($qmig === false) {
            $db->exec("UPDATE settings SET value='7'
                        WHERE key='quarantine_retention_days'
                          AND CAST(value AS INTEGER) > 7");
            $db->exec("INSERT OR REPLACE INTO settings (key,value) "
                    . "VALUES ('sg_mig_quarantine_7d','1')");
        }

        // Brute force blocked at ten failures in ten minutes and, because
        // nothing ever lifted a block, blocked each address at most once ever.
        // The policy is five failures and an escalating term. Existing
        // installs hold the old threshold, which the seed cannot change.
        // Marked so an operator who afterwards chooses their own threshold
        // keeps it.
        $bfmig = $db->query(
            "SELECT value FROM settings WHERE key='sg_mig_bf_ladder'"
        )->fetchColumn();
        if ($bfmig === false) {
            $db->exec("UPDATE settings SET value='5'
                        WHERE key='bf_threshold' AND CAST(value AS INTEGER) > 5");
            // Auto-blocking off meant the ladder would never run at all. It
            // is turned back on once: watching an attack without acting on it
            // is what prompted this.
            $db->exec("UPDATE settings SET value='1' WHERE key='bf_auto_block'");
            $db->exec("INSERT OR REPLACE INTO settings (key,value) "
                    . "VALUES ('sg_mig_bf_ladder','1')");
        }

        $migrated = $db->query(
            "SELECT value FROM settings WHERE key='sg_mig_scan_concurrency_1'"
        )->fetchColumn();
        if ($migrated === false) {
            $db->exec("UPDATE settings SET value='1' WHERE key='scan_max_concurrent'");
            $db->exec("INSERT OR REPLACE INTO settings (key,value) "
                    . "VALUES ('sg_mig_scan_concurrency_1','1')");
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
