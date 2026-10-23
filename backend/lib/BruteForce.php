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

        // Added in 4.2.0, so existing installs need them bolted on. SQLite has
        // no ADD COLUMN IF NOT EXISTS, and a failed ALTER inside exec() would
        // abort the rest of the batch, so each is checked first.
        $have = [];
        foreach (Database::fetchAll('PRAGMA table_info(brute_force_offenders)') as $c) {
            $have[(string) $c['name']] = true;
        }
        // How many times this address has earned a block. The ladder is keyed
        // on this, not on attempts: an address that comes back after its term
        // has expired is a repeat offender regardless of how hard it tried.
        if (!isset($have['offences'])) {
            Database::get()->exec(
                'ALTER TABLE brute_force_offenders ADD COLUMN offences INTEGER NOT NULL DEFAULT 0');
        }
        // Why an address that earned a block did not get one.
        //
        // Escalation only set blocked=1 when the firewall reported success. A
        // refusal -- no firewall backend, a rule that would not apply, auto
        // blocking switched off -- fell through silently, leaving the row at
        // blocked=0, which the panel rendered as "Watching". An operator
        // looking at an address with 398 port-scan hits marked "Watching" is
        // right to ask what the product is doing, and nothing on the page or
        // in the database could answer.
        if (!isset($have['block_error'])) {
            Database::get()->exec(
                'ALTER TABLE brute_force_offenders ADD COLUMN block_error TEXT');
        }
        if (!isset($have['block_tried_at'])) {
            Database::get()->exec(
                'ALTER TABLE brute_force_offenders ADD COLUMN block_tried_at INTEGER');
        }
        // When the current block lifts. NULL while blocked means permanent.
        if (!isset($have['blocked_until'])) {
            Database::get()->exec(
                'ALTER TABLE brute_force_offenders ADD COLUMN blocked_until INTEGER');
        }
        // When the last block was lifted. Attempts recorded before this are
        // evidence that has already been punished; counting them again would
        // re-block the address the moment its term ended.
        if (!isset($have['cleared_at'])) {
            Database::get()->exec(
                'ALTER TABLE brute_force_offenders ADD COLUMN cleared_at INTEGER');
        }

        // An address blocked before the ladder existed has served no recorded
        // strike, so its next offence would start again at three hours. One is
        // the honest count: it has been blocked once.
        Database::query(
            'UPDATE brute_force_offenders SET offences=1 WHERE blocked=1 AND offences=0');
    }

    /**
     * The escalation ladder, in seconds. 0 means permanent.
     *
     * Three hours, then six, then a day, then for good. Each term is served
     * for one offence; coming back after it expires earns the next rung. The
     * point of escalating rather than blocking permanently on the first
     * offence is that addresses are reassigned and people mistype passwords,
     * so a first offence should cost an afternoon, not a customer.
     */
    public static function ladder(): array
    {
        $raw = (string) (Database::setting('bf_ladder', '10800,21600,86400,0') ?? '');
        $out = [];
        foreach (explode(',', $raw) as $part) {
            $v = trim($part);
            if ($v === '') { continue; }
            $out[] = max(0, min(2592000, (int) $v));
            if ((int) $v === 0) { break; }    // permanent ends the ladder
        }
        return $out !== [] ? $out : [10800, 21600, 86400, 0];
    }

    /**
     * How long the Nth offence is blocked for. 0 means permanent.
     *
     * Past the end of the ladder the last rung repeats, so a ladder that does
     * not end in 0 never becomes permanent -- which is a legitimate choice for
     * an operator who does not want permanent blocks, and must not silently
     * turn into one.
     */
    public static function termFor(int $offence): int
    {
        $l = self::ladder();
        $i = max(1, $offence) - 1;
        return $l[min($i, count($l) - 1)];
    }

    // ── Settings ─────────────────────────────────────────────────────────────

    public static function enabled(): bool
    {
        return (Database::setting('bf_enabled', '1') ?? '1') === '1';
    }

    /** Failures from one address within the window before it counts as an attack. */
    public static function threshold(): int
    {
        return max(3, min(1000, (int) (Database::setting('bf_threshold', '5') ?? 5)));
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
     * End blocks whose term has been served.
     *
     * Two things happen, and both matter. The firewall rule goes, which is
     * what makes a three-hour block three hours rather than for ever. And the
     * address's recorded attempts are discarded, because they are evidence it
     * has already been punished for -- leaving them in place would push it
     * straight back over the threshold the instant it was released, which
     * would turn every first offence into a permanent block within minutes
     * and make the ladder meaningless.
     *
     * The strike count is deliberately NOT reset. That is the whole ladder:
     * an address that comes back is on its second offence.
     */
    public static function releaseExpired(): array
    {
        self::ensureSchema();
        $now = time();

        $due = Database::fetchAll(
            "SELECT ip_address FROM brute_force_offenders
              WHERE blocked = 1
                AND blocked_until IS NOT NULL
                AND blocked_until > 0
                AND blocked_until <= CAST(? AS INTEGER)",
            [$now]
        );

        $fw       = new Firewall();
        $released = 0;
        foreach ($due as $r) {
            $ip  = (string) $r['ip_address'];
            $res = $fw->unblockIP($ip);
            if (empty($res['success'])) {
                // Try again next run rather than record a release that did
                // not happen.
                continue;
            }
            Database::query(
                'UPDATE brute_force_offenders
                    SET blocked=0, blocked_until=NULL, cleared_at=?, attempts=0
                  WHERE ip_address=?',
                [$now, $ip]
            );
            Database::query('DELETE FROM brute_force_attempts WHERE ip_address=?', [$ip]);
            $released++;
            Logger::info("Brute force: {$ip} released, term served");
        }

        return ['released' => $released, 'due' => count($due)];
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

            // Escalate.
            //
            // Until 4.2.0 this blocked only when the address had never been
            // blocked before, and nothing ever lifted a block -- so in
            // practice an address was blocked once, for ever, or (far more
            // often, since nothing expired anything) watched indefinitely
            // while it kept trying. An operator looking at a list of addresses
            // marked "Watching" after two hundred failures is right to ask
            // what the product is for.
            // Auto blocking switched off is a DECISION, and the panel has to
            // show it as one. Left unrecorded it looked identical to a block
            // that failed and to an address still below its next rung: all
            // three rendered as "Watching".
            if (!self::autoBlock() && empty($existing['blocked'])) {
                Database::query(
                    'UPDATE brute_force_offenders
                        SET block_error = ?, block_tried_at = ?
                      WHERE ip_address = ?',
                    ['auto-block is switched off', time(), $ip]
                );
            }

            if (self::autoBlock() && empty($existing['blocked'])) {
                $offence = (int) ($existing['offences'] ?? 0) + 1;
                $ttl     = self::termFor($offence);
                $perm    = ($ttl === 0);

                $fw  = new Firewall();
                $res = $fw->blockIP(
                    $ip,
                    'Brute force: ' . $r['attempts'] . ' failures against ' . $r['services']
                        . ' (offence ' . $offence . ')',
                    $perm,
                    $perm ? 86400 : $ttl
                );
                if (!empty($res['success'])) {
                    Database::query(
                        'UPDATE brute_force_offenders
                            SET blocked=1, blocked_at=?, blocked_until=?, offences=?,
                                block_error=NULL, block_tried_at=?
                          WHERE ip_address=?',
                        [time(), $perm ? null : time() + $ttl, $offence, time(), $ip]
                    );
                    $blocked++;
                    Logger::warn("Brute force: blocked {$ip} after {$r['attempts']} failures"
                        . ' — offence ' . $offence . ', '
                        . ($perm ? 'permanent' : self::humanTerm($ttl)));
                } else {
                    // THE FAILURE THAT USED TO VANISH.
                    //
                    // Without this the row stayed at blocked=0 and the panel
                    // said "Watching" — which reads as a deliberate choice to
                    // observe rather than "we tried to block this and the
                    // firewall would not do it". The operator has no way to
                    // discover the difference, and the address keeps knocking.
                    $why = trim((string) ($res['error'] ?? '')) ?: 'the firewall refused the block';
                    Database::query(
                        'UPDATE brute_force_offenders
                            SET block_error = ?, block_tried_at = ?
                          WHERE ip_address = ?',
                        [mb_substr($why, 0, 200), time(), $ip]
                    );
                    Logger::error("Brute force: could NOT block {$ip} after "
                        . "{$r['attempts']} failures — {$why}");
                    Database::insert('security_events', [
                        'type'        => 'brute_force_block_failed',
                        'severity'    => 'high',
                        'source_ip'   => $ip,
                        'target'      => (string) $r['services'],
                        'description' => 'Wanted to block ' . $ip . ' after '
                                       . $r['attempts'] . ' failures but could not: ' . $why,
                    ]);
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

    /** A block term as an operator would say it. 0 is permanent. */
    public static function humanTerm(int $secs): string
    {
        if ($secs <= 0) { return 'permanent'; }
        // Days only past two of them: the policy is written in hours, and a
        // ladder rung shown as "1d" next to "3h" and "6h" reads as a different
        // kind of quantity rather than the next step up.
        if ($secs >= 172800 && $secs % 86400 === 0) { return ($secs / 86400) . 'd'; }
        if ($secs % 3600 === 0) { return ($secs / 3600) . 'h'; }
        if ($secs % 60 === 0)    { return ($secs / 60) . 'm'; }
        return $secs . 's';
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

        // Before evaluating, not after: an address whose term ended must be
        // out of the blocked state by the time evaluate() looks at it, or its
        // return visit is recorded against a block that has already been
        // served and it never climbs the ladder.
        $rel = self::releaseExpired();

        $r = self::evaluate();
        self::prune();

        Database::setSetting('bf_last_run', (string) time());
        return [
            'enabled'   => true,
            'collected' => $collected,
            'offenders' => $r['offenders'],
            'blocked'   => $r['blocked'],
            'released'  => $rel['released'],
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
        // An address that has served a term keeps its strike count for much
        // longer than its attempts are kept.
        //
        // Attempts are evidence and expire in a week. The strike count is
        // history, and pruning it on the same clock quietly reset the ladder:
        // an address released after a three-hour block goes to blocked=0, and
        // seven quiet days later its row was deleted along with the record
        // that it had ever offended. An attacker returning every eighth day
        // would have been blocked for three hours, for ever, which is the
        // behaviour the ladder exists to prevent.
        $memDays = max(1, min(365,
            (int) (Database::setting('bf_offence_memory_days', '30') ?? 30)));
        $memCut  = time() - ($memDays * 86400);

        Database::query(
            'DELETE FROM brute_force_offenders
              WHERE blocked = 0
                AND ((offences = 0 AND last_seen < CAST(? AS INTEGER))
                  OR (offences > 0 AND last_seen < CAST(? AS INTEGER)))',
            [$cut, $memCut]
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
            'ladder'         => array_map([self::class, 'humanTerm'], self::ladder()),
            'ladder_secs'    => self::ladder(),
            // Both of these were saved by the settings form and never sent
            // back to it, so the form could not populate them. The allow-list
            // box therefore always LOOKED empty -- its placeholder is a pair of
            // RFC 5737 documentation addresses, which reads like a configured
            // list -- and "Keep records for" always showed the markup's 7.
            //
            // Saving the form posts whatever is in the boxes, so changing the
            // threshold also silently emptied the allow list and reset the
            // retention. A settings page that quietly discards settings is
            // worse than one that has none.
            'whitelist'      => (string) (Database::setting('bf_whitelist', '') ?? ''),
            'retention_days' => max(1, min(90,
                                   (int) (Database::setting('bf_retention_days', '7') ?? 7))),
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
        $rows = Database::fetchAll(
            'SELECT * FROM brute_force_offenders ORDER BY last_seen DESC LIMIT ' . max(1, min(500, $limit))
        );

        // Derived here rather than in the front end so the list, the API and
        // the logs all describe a block the same way.
        $now   = time();
        $white = self::whitelist();
        foreach ($rows as &$r) {
            $off   = (int) ($r['offences'] ?? 0);
            $until = $r['blocked_until'] === null ? null : (int) $r['blocked_until'];
            $r['offences']      = $off;
            $r['blocked_until'] = $until;
            $r['permanent']     = (int) (!empty($r['blocked']) && $until === null);
            $r['expires_in']    = ($until !== null && !empty($r['blocked']))
                                    ? max(0, $until - $now) : null;
            // What the next offence will cost, which is the part that makes
            // the ladder visible instead of implied.
            $r['next_term']     = self::humanTerm(self::termFor($off + 1));

            // "Watching" used to mean four different things, and the operator
            // could not tell them apart: below the threshold, auto-block
            // switched off, a block the firewall refused, and an address on
            // the allow list. Three of those mean the product is NOT acting,
            // and one of them is a fault. Saying "Watching" for all four is
            // how an address with 398 port-scan hits sat there looking as
            // though that were the plan.
            $err = trim((string) ($r['block_error'] ?? ''));
            if (!empty($r['blocked'])) {
                $r['state'] = ($until === null) ? 'permanent' : 'blocked';
            } elseif (isset($white[(string) $r['ip_address']])) {
                $r['state'] = 'allowlisted';
            } elseif ($err !== '') {
                $r['state'] = (stripos($err, 'switched off') !== false)
                    ? 'monitor_only'
                    : 'block_failed';
            } else {
                $r['state'] = 'watching';
            }
            $r['state_reason'] = $err;
            // What it would take to act, so "watching" is a number rather
            // than a mood.
            $r['threshold']    = self::threshold();
            $r['window_mins']  = (int) round(self::window() / 60);
        }
        unset($r);
        return $rows;
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
        // The strike count goes too. A manual release is the operator saying
        // this address is not an attacker, so starting it back at the first
        // rung is the point rather than a side effect. An address that is
        // merely serving its term is released by releaseExpired(), which
        // deliberately keeps the count.
        Database::query('DELETE FROM brute_force_offenders WHERE ip_address=?', [$ip]);
        Database::query('DELETE FROM brute_force_attempts  WHERE ip_address=?', [$ip]);
        Logger::info('Brute force: released ' . $ip);
        return ['success' => true, 'ip' => $ip];
    }
}
