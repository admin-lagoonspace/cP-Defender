<?php
/**
 * Brute-force detection.
 *
 * The dashboard has charted a "Brute Force" series since it was written, and
 * it queries security_events for type='brute_force'. Nothing has ever written
 * one, so the line sat flat at zero on servers that were certainly being
 * hammered. `rate_limit_ssh` was seeded as a setting and read by nothing at
 * all. This is the detector both of those were waiting for.
 *
 * It reads authentication logs, groups failures by source address, and acts
 * when one crosses a threshold inside a window. Reading is incremental, with
 * the same offset handling the WAF ingester uses: an auth log on a server
 * under attack grows quickly, and re-reading it from the top every few minutes
 * is how a detector becomes the load problem it was meant to report on.
 *
 * cPanel ships cPHulk, which does something similar for cPanel's own services.
 * This is deliberately not a replacement: it covers SSH, mail and FTP in one
 * place alongside everything else this product reports, and it feeds the
 * firewall that is already here.
 */

class BruteForce
{
    /**
     * Where authentication failures are logged, and how to recognise one.
     *
     * Each source is tried in order and the first readable path wins. The
     * patterns capture the source address; the username, where the format
     * offers one, is useful for telling a targeted attack from a spray.
     */
    public static function sources(): array
    {
        return [
            'ssh' => [
                'label' => 'SSH',
                'paths' => ['/var/log/secure', '/var/log/auth.log'],
                'patterns' => [
                    // Failed password for [invalid user] NAME from IP port N
                    '/Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)/',
                    // Invalid user NAME from IP
                    '/Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)/',
                    // Connection closed by authenticating user NAME IP [preauth]
                    '/Connection closed by authenticating user (?P<user>\S+) (?P<ip>[0-9a-fA-F:.]+)/',
                ],
            ],
            'cpanel' => [
                'label' => 'cPanel / WHM',
                'paths' => ['/usr/local/cpanel/logs/login_log'],
                'patterns' => [
                    // IP - USER [date] "..." FAILED LOGIN service
                    '/^(?P<ip>[0-9a-fA-F:.]+)\s+-\s+(?P<user>\S+)\s+\[[^\]]*\].*FAILED LOGIN/i',
                ],
            ],
            'mail' => [
                'label' => 'Mail (Exim / Dovecot)',
                'paths' => ['/var/log/exim_mainlog', '/var/log/maillog'],
                'patterns' => [
                    // dovecot_login authenticator failed for (x) [IP]: 535 ...
                    '/authenticator failed for[^\[]*\[(?P<ip>[0-9a-fA-F:.]+)\][^\n]*535/i',
                    // dovecot: auth: ... rip=IP ... (auth failed)
                    '/auth failed[^\n]*rip=(?P<ip>[0-9a-fA-F:.]+)/i',
                ],
            ],
            'ftp' => [
                'label' => 'FTP',
                'paths' => ['/var/log/messages', '/var/log/syslog'],
                'patterns' => [
                    // pure-ftpd: (?@IP) [WARNING] Authentication failed for user [x]
                    '/pure-ftpd:\s*\(\?@(?P<ip>[0-9a-fA-F:.]+)\)[^\n]*Authentication failed/i',
                ],
            ],
        ];
    }

    /** Create the tables this needs. Called from the scan path, idempotent. */
    public static function ensureSchema(): void
    {
        Database::get()->exec("
            CREATE TABLE IF NOT EXISTS brute_force_attempts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT NOT NULL,
                service     TEXT NOT NULL,
                username    TEXT,
                attempted_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_bfa_ip   ON brute_force_attempts(ip_address);
            CREATE INDEX IF NOT EXISTS idx_bfa_time ON brute_force_attempts(attempted_at);

            CREATE TABLE IF NOT EXISTS brute_force_offenders (
                ip_address   TEXT PRIMARY KEY,
                service      TEXT,
                attempts     INTEGER NOT NULL DEFAULT 0,
                usernames    TEXT,
                first_seen   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                last_seen    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                blocked      INTEGER NOT NULL DEFAULT 0,
                blocked_at   INTEGER
            );
        ");
    }

    // ── Settings ─────────────────────────────────────────────────────────────

    public static function enabled(): bool
    {
        return (Database::setting('bf_enabled', '1') ?? '1') === '1';
    }

    /** Failures from one address within the window before it counts as an attack. */
    public static function threshold(): int
    {
        return max(3, min(1000, (int) (Database::setting('bf_threshold', '10') ?? 10)));
    }

    /** The window, in seconds. */
    public static function window(): int
    {
        return max(60, min(86400, (int) (Database::setting('bf_window', '600') ?? 600)));
    }

    public static function autoBlock(): bool
    {
        return (Database::setting('bf_auto_block', '1') ?? '1') === '1';
    }

    /** How long an automatic block lasts. 0 means permanent. */
    public static function blockDuration(): int
    {
        return max(0, min(2592000, (int) (Database::setting('bf_block_duration', '3600') ?? 3600)));
    }

    /** Addresses never blocked, however they behave. */
    public static function whitelist(): array
    {
        $raw = (string) (Database::setting('bf_whitelist', '') ?? '');
        $out = [];
        foreach (explode(',', $raw) as $ip) {
            $ip = trim($ip);
            if ($ip !== '') { $out[$ip] = true; }
        }
        return $out;
    }

    // ── Reading the logs ─────────────────────────────────────────────────────

    /** The readable path for a source, or null. */
    public static function sourcePath(string $key): ?string
    {
        $src = self::sources()[$key] ?? null;
        if ($src === null) { return null; }

        $override = (string) (Database::setting('bf_log_' . $key, '') ?? '');
        $paths    = $override !== '' ? array_merge([$override], $src['paths']) : $src['paths'];

        foreach ($paths as $p) {
            if (is_readable($p)) { return $p; }
        }
        return null;
    }

    /**
     * Read new failures from every source into brute_force_attempts.
     *
     * Returns the number of failures recorded.
     */
    public static function collect(): int
    {
        self::ensureSchema();
        $total = 0;

        foreach (array_keys(self::sources()) as $key) {
            $path = self::sourcePath($key);
            if ($path === null) { continue; }

            $size   = (int) @filesize($path);
            $offKey = 'bf_offset_' . $key;
            $offset = (int) (Database::setting($offKey, '0') ?? 0);

            // Rotated or replaced: start again rather than seeking past the end.
            if ($size < $offset) { $offset = 0; }
            if ($size === $offset) { continue; }

            $fh = @fopen($path, 'r');
            if ($fh === false) { continue; }
            if ($offset > 0) { @fseek($fh, $offset); }

            $patterns = self::sources()[$key]['patterns'];
            $rows     = [];

            while (($line = fgets($fh)) !== false) {
                foreach ($patterns as $re) {
                    if (preg_match($re, $line, $m) && !empty($m['ip'])) {
                        if (filter_var($m['ip'], FILTER_VALIDATE_IP) === false) { break; }
                        $rows[] = [$m['ip'], $key, $m['user'] ?? null];
                        break;
                    }
                }
                // A single pass must not be able to eat all the memory on a
                // server that has been under attack for hours.
                if (count($rows) >= 5000) { break; }
            }
            $newOffset = ftell($fh);
            fclose($fh);

            if ($rows) {
                $now = time();
                $db  = Database::get();
                $db->beginTransaction();
                $stmt = $db->prepare(
                    'INSERT INTO brute_force_attempts (ip_address, service, username, attempted_at)
                     VALUES (?,?,?,?)'
                );
                foreach ($rows as $r) { $stmt->execute([$r[0], $r[1], $r[2], $now]); }
                $db->commit();
                $total += count($rows);
            }

            Database::setSetting($offKey, (string) (int) $newOffset);
        }

        return $total;
    }

    /**
     * Find addresses over the threshold, record them, and block if configured.
     *
     * @return array{checked:int,offenders:int,blocked:int}
     */
    public static function evaluate(): array
    {
        self::ensureSchema();

        $since = time() - self::window();
        $min   = self::threshold();

        // CAST, because this comparison does not work without it.
        //
        // PDO's SQLite driver binds every parameter as TEXT, and SQLite orders
        // integers before text, so COUNT(*) >= '10' is false for any count.
        // The detector found nothing at all until this was tracked down -- it
        // collected failures correctly and then silently never crossed its own
        // threshold. Verified: execute([5]) and execute(['5']) both return
        // nothing here; a literal, a CAST, or bindValue with PARAM_INT work.
        $rows = Database::fetchAll(
            "SELECT ip_address,
                    COUNT(*)              AS attempts,
                    GROUP_CONCAT(DISTINCT service)  AS services,
                    GROUP_CONCAT(DISTINCT username) AS usernames,
                    MIN(attempted_at)     AS first_seen,
                    MAX(attempted_at)     AS last_seen
               FROM brute_force_attempts
              WHERE attempted_at >= CAST(? AS INTEGER)
           GROUP BY ip_address
             HAVING COUNT(*) >= CAST(? AS INTEGER)",
            [$since, $min]
        );

        $white   = self::whitelist();
        $blocked = 0;
        $acted   = 0;
        $skipped = 0;

        foreach ($rows as $r) {
            $ip = (string) $r['ip_address'];

            // Never act against the server's own addresses or anything the
            // operator has protected: locking the admin out of the box while
            // defending it is not a trade worth making.
            if (isset($white[$ip]) || self::isLocal($ip)) { $skipped++; continue; }

            $acted++;
            $existing = Database::fetchOne(
                'SELECT * FROM brute_force_offenders WHERE ip_address=?', [$ip]
            );

            Database::query(
                "INSERT INTO brute_force_offenders
                    (ip_address, service, attempts, usernames, first_seen, last_seen, blocked)
                 VALUES (?,?,?,?,?,?,?)
                 ON CONFLICT(ip_address) DO UPDATE SET
                    service   = excluded.service,
                    attempts  = excluded.attempts,
                    usernames = excluded.usernames,
                    last_seen = excluded.last_seen",
                [$ip, (string) $r['services'], (int) $r['attempts'],
                 mb_substr((string) $r['usernames'], 0, 400),
                 (int) $r['first_seen'], (int) $r['last_seen'],
                 (int) ($existing['blocked'] ?? 0)]
            );

            // One event per offender per window, not one per failed password:
            // a thousand events for one attack buries everything else on the
            // dashboard and tells the operator nothing extra.
            $recent = Database::fetchOne(
                "SELECT id FROM security_events
                  WHERE type='brute_force' AND source_ip=? AND timestamp >= CAST(? AS INTEGER)",
                [$ip, time() - self::window()]
            );
            if (!$recent) {
                Database::insert('security_events', [
                    'type'        => 'brute_force',
                    'severity'    => (int) $r['attempts'] >= ($min * 5) ? 'high' : 'medium',
                    'source_ip'   => $ip,
                    'target'      => (string) $r['services'],
                    'description' => $r['attempts'] . ' failed authentication attempt(s) from '
                                   . $ip . ' against ' . $r['services']
                                   . ' in the last ' . round(self::window() / 60) . ' minute(s)',
                ]);
            }

            if (self::autoBlock() && empty($existing['blocked'])) {
                $fw  = new Firewall();
                $ttl = self::blockDuration();
                $res = $fw->blockIP(
                    $ip,
                    'Brute force: ' . $r['attempts'] . ' failures against ' . $r['services'],
                    $ttl === 0,
                    $ttl === 0 ? 86400 : $ttl
                );
                if (!empty($res['success'])) {
                    Database::query(
                        'UPDATE brute_force_offenders SET blocked=1, blocked_at=? WHERE ip_address=?',
                        [time(), $ip]
                    );
                    $blocked++;
                    Logger::warn("Brute force: blocked {$ip} after {$r['attempts']} failures");
                }
            }
        }

        // 'offenders' counts addresses actually acted on, not every row over
        // the threshold: the two differ whenever something was skipped for
        // being loopback, private or whitelisted, and reporting the larger
        // number would claim action that was deliberately not taken.
        return [
            'checked'   => count($rows),
            'offenders' => $acted,
            'skipped'   => $skipped,
            'blocked'   => $blocked,
        ];
    }

    /** Loopback and private ranges, which must never be auto-blocked. */
    private static function isLocal(string $ip): bool
    {
        if ($ip === '127.0.0.1' || $ip === '::1') { return true; }
        // A private address reaching an auth log usually means a proxy or a
        // misconfiguration, and blocking it can take the whole network out.
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /** Collect then evaluate. This is what the scheduler calls. */
    public static function run(): array
    {
        if (!self::enabled()) {
            return ['enabled' => false, 'collected' => 0, 'offenders' => 0, 'blocked' => 0];
        }
        $collected = self::collect();
        $r         = self::evaluate();
        self::prune();

        Database::setSetting('bf_last_run', (string) time());
        return [
            'enabled'   => true,
            'collected' => $collected,
            'offenders' => $r['offenders'],
            'blocked'   => $r['blocked'],
        ];
    }

    /**
     * Drop attempts older than the retention period.
     *
     * Without this the attempts table grows without limit on a server under
     * sustained attack, which is exactly the server that can least afford it.
     */
    public static function prune(): int
    {
        $days = max(1, min(90, (int) (Database::setting('bf_retention_days', '7') ?? 7)));
        $cut  = time() - ($days * 86400);
        $n    = Database::query(
            'DELETE FROM brute_force_attempts WHERE attempted_at < CAST(? AS INTEGER)', [$cut]
        )->rowCount();
        Database::query(
            'DELETE FROM brute_force_offenders WHERE last_seen < CAST(? AS INTEGER) AND blocked = 0', [$cut]
        );
        return $n;
    }

    // ── Reporting ────────────────────────────────────────────────────────────

    public static function stats(): array
    {
        self::ensureSchema();
        $day  = time() - 86400;
        $week = time() - (7 * 86400);

        $sources = [];
        foreach (self::sources() as $key => $src) {
            $path = self::sourcePath($key);
            $sources[$key] = [
                'label'     => $src['label'],
                'log_found' => $path !== null,
                'log_path'  => $path,
                'attempts_24h' => (int) (Database::fetchOne(
                    'SELECT COUNT(*) c FROM brute_force_attempts WHERE service=? AND attempted_at >= ?',
                    [$key, $day])['c'] ?? 0),
            ];
        }

        return [
            'enabled'        => self::enabled(),
            'threshold'      => self::threshold(),
            'window'         => self::window(),
            'auto_block'     => self::autoBlock(),
            'block_duration' => self::blockDuration(),
            'last_run'       => (int) (Database::setting('bf_last_run', '0') ?? 0),
            'attempts_24h'   => (int) (Database::fetchOne(
                'SELECT COUNT(*) c FROM brute_force_attempts WHERE attempted_at >= ?',
                [$day])['c'] ?? 0),
            'attempts_7d'    => (int) (Database::fetchOne(
                'SELECT COUNT(*) c FROM brute_force_attempts WHERE attempted_at >= ?',
                [$week])['c'] ?? 0),
            'offenders'      => (int) (Database::fetchOne(
                'SELECT COUNT(*) c FROM brute_force_offenders')['c'] ?? 0),
            'blocked'        => (int) (Database::fetchOne(
                'SELECT COUNT(*) c FROM brute_force_offenders WHERE blocked=1')['c'] ?? 0),
            'sources'        => $sources,
        ];
    }

    /** Failures per day, for the chart. */
    public static function timeline(int $days = 14): array
    {
        self::ensureSchema();
        $out = [];
        for ($i = $days - 1; $i >= 0; $i--) {
            $start = strtotime('today -' . $i . ' days');
            $end   = $start + 86400;
            $out[] = [
                'date'     => date('Y-m-d', $start),
                'attempts' => (int) (Database::fetchOne(
                    'SELECT COUNT(*) c FROM brute_force_attempts WHERE attempted_at >= ? AND attempted_at < ?',
                    [$start, $end])['c'] ?? 0),
                'blocked'  => (int) (Database::fetchOne(
                    'SELECT COUNT(*) c FROM brute_force_offenders WHERE blocked_at >= ? AND blocked_at < ?',
                    [$start, $end])['c'] ?? 0),
            ];
        }
        return $out;
    }

    public static function offenders(int $limit = 100): array
    {
        self::ensureSchema();
        return Database::fetchAll(
            'SELECT * FROM brute_force_offenders ORDER BY last_seen DESC LIMIT ' . max(1, min(500, $limit))
        );
    }

    /** Which usernames are being tried — a spray looks different from a target. */
    public static function topTargets(int $limit = 10): array
    {
        self::ensureSchema();
        return Database::fetchAll(
            "SELECT username, COUNT(*) AS attempts
               FROM brute_force_attempts
              WHERE username IS NOT NULL AND username != '' AND attempted_at >= ?
           GROUP BY username ORDER BY attempts DESC LIMIT " . max(1, min(50, $limit)),
            [time() - 86400]
        );
    }

    /** Release an address: unblock it at the firewall and forget it. */
    public static function release(string $ip): array
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return ['success' => false, 'error' => 'Not a valid IP address', 'code' => 400];
        }
        $fw = new Firewall();
        $fw->unblockIP($ip);
        Database::query('DELETE FROM brute_force_offenders WHERE ip_address=?', [$ip]);
        Database::query('DELETE FROM brute_force_attempts  WHERE ip_address=?', [$ip]);
        Logger::info('Brute force: released ' . $ip);
        return ['success' => true, 'ip' => $ip];
    }
}
