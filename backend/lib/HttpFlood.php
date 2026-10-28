<?php
/**
 * HTTP flood and scanner detection, from the web logs.
 *
 * WHY THIS EXISTS
 * ---------------
 * On 2026-10-27 a single address took all eight cores of a live server to
 * load 22 with 1.2% idle. Nothing in this product noticed.
 *
 *   185.177.72.49  — 1,963 of 2,000 requests on one vhost, brute-forcing
 *                    filenames across EVERY site on the box looking for
 *                    leaked secrets: /.env, /.git/config, /settings.py,
 *                    /stack.json, ~/.aws/credentials
 *
 * Every one of those requests was a 404. That is precisely why it was
 * invisible: no failed logins, no malware on disk, no 500s, nothing any
 * existing check watches. But WordPress handles 404s IN PHP, so each miss was
 * a full framework boot plus database queries. Thousands of them, across
 * seven pools, is the whole machine.
 *
 * A separate, smaller event the same day: ~10 addresses sending 509 of 2,000
 * requests to /xmlrpc.php on one vhost. XML-RPC is cheap to send and
 * expensive to serve — system.multicall attempts hundreds of password guesses
 * in a single request — so a handful of hosts can saturate a server.
 *
 * WHY BOT SHIELD MISSED BOTH
 * --------------------------
 *   1. it reads /var/log/nginx/access.log, which on a cPanel box carries
 *      almost nothing — per-vhost traffic goes to /var/log/nginx/domains/*
 *   2. it classifies by USER-AGENT, and neither attack had a distinctive one
 *
 * So this detector keys on shape rather than identity:
 *
 *   A. 404 STORM      one IP, many misses, several vhosts  -> scanner
 *   B. ENDPOINT FLOOD many IPs, one costly path            -> xmlrpc/wp-login
 *   C. RATE           one IP far above everyone else       -> brute hammer
 *
 * BOUNDS. This runs on a box that is, by definition, already in trouble when
 * it matters. It reads the N most recently written vhost logs, tails a fixed
 * number of lines from each, and considers only lines inside the window. It
 * never scans a log whole: /var/log/nginx/domains was 5.4 GB on the server
 * this was written for.
 */

declare(strict_types=1);

require_once __DIR__ . '/ProxyRanges.php';

class HttpFlood
{
    /** Per-vhost logs, which is where cPanel actually records traffic. */
    private const LOG_DIRS = ['/var/log/nginx/domains', '/usr/local/apache/domlogs'];

    /** Most recently written logs to look at. */
    private const MAX_LOGS = 25;

    /** Lines tailed from each. */
    private const MAX_LINES = 4000;

    /** Bytes read per log, so a single enormous line cannot blow memory. */
    private const MAX_BYTES = 4194304;   // 4 MB

    /** Paths worth counting on their own: cheap to request, costly to serve. */
    public const COSTLY_PATHS = [
        '/xmlrpc.php', '/wp-login.php', '/wp-cron.php', '/wp-comments-post.php',
        '/xmlrpc.php?rsd', '/wp-json/wp/v2/users',
    ];

    /** Paths that only ever mean somebody is hunting for secrets. */
    public const SECRET_PATHS = [
        '/.env', '/.git/config', '/.git/HEAD', '/settings.py', '/stack.json',
        '/config.json', '/credentials', '/.aws/credentials', '/server-status',
        '/.ssh/id_rsa', '/docker-compose.yml', '/wp-config.php.bak',
    ];

    // ── Settings ────────────────────────────────────────────────────────────

    public static function enabled(): bool
    {
        return (Database::setting('hf_enabled', '1') ?? '1') === '1';
    }

    /** Detect only, never block. The honest default for a new auto-blocker. */
    public static function monitorOnly(): bool
    {
        return (Database::setting('hf_monitor_only', '0') ?? '0') === '1';
    }

    public static function window(): int
    {
        return max(60, min(3600, (int) (Database::setting('hf_window', '300') ?? 300)));
    }

    /** 404s from one address, within the window, before it is a scanner. */
    public static function missThreshold(): int
    {
        return max(10, min(10000, (int) (Database::setting('hf_miss_threshold', '100') ?? 100)));
    }

    /** Requests from one address, within the window, before it is a hammer. */
    public static function rateThreshold(): int
    {
        return max(20, min(100000, (int) (Database::setting('hf_rate_threshold', '600') ?? 600)));
    }

    /** Hits on one costly endpoint, within the window, before it is a flood. */
    public static function endpointThreshold(): int
    {
        return max(20, min(100000, (int) (Database::setting('hf_endpoint_threshold', '200') ?? 200)));
    }

    /** How long a block lasts. */
    public static function blockSeconds(): int
    {
        return max(300, min(2592000, (int) (Database::setting('hf_block_secs', '3600') ?? 3600)));
    }

    // ── Safety rails ────────────────────────────────────────────────────────

    /**
     * Addresses this must never block, whatever they do.
     *
     * An automatic blocker that locks the administrator out of the server it
     * is defending has done more damage than the attack. On the day this was
     * written the operator's own address appeared in the logs with 261
     * requests in a 2,000-line sample — comfortably inside some of these
     * thresholds.
     *
     * Three sources, all of them deliberate:
     *   - the Brute Force allow list, so one list governs both
     *   - this server's own addresses, read from the interfaces
     *   - any address with a live authenticated panel session
     */
    public static function neverBlock(): array
    {
        $out = [];

        foreach (BruteForce::whitelist() as $ip => $_) { $out[$ip] = 'allow list'; }

        foreach (self::serverIPs() as $ip) { $out[$ip] = 'this server'; }

        // Whoever has used the panel recently. Blocking them would end the
        // session that could undo the block.
        //
        // Recorded explicitly rather than read from a sessions table: this
        // product authenticates against cPanel and keeps no session table of
        // its own, so the first version of this queried a table that does not
        // exist — a safety rail that would have thrown on every run.
        foreach (self::recentAdminIPs() as $ip => $when) {
            $out[$ip] = 'used the panel ' . max(0, (int) round((time() - $when) / 60))
                      . ' minute(s) ago';
        }

        return $out;
    }

    /** How long a panel visit protects an address. */
    private const ADMIN_IP_TTL = 86400;

    /** @return array<string,int> ip => last seen */
    public static function recentAdminIPs(): array
    {
        $raw = (string) (Database::setting('hf_admin_ips', '') ?? '');
        $out = [];
        $now = time();
        foreach (explode(',', $raw) as $pair) {
            $pair = trim($pair);
            if ($pair === '' || strpos($pair, '|') === false) { continue; }
            [$ip, $ts] = explode('|', $pair, 2);
            $ip = trim($ip); $ts = (int) $ts;
            if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) { continue; }
            if ($now - $ts > self::ADMIN_IP_TTL) { continue; }
            $out[$ip] = $ts;
        }
        return $out;
    }

    /**
     * Note that an administrator reached the panel from this address.
     *
     * Called on every authenticated API request. Cheap: it writes only when
     * the address is new or the record is more than an hour stale, so a busy
     * panel does not turn into a settings write per request.
     */
    public static function rememberAdminIp(string $ip): void
    {
        $ip = trim($ip);
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) { return; }
        if (self::isLocal($ip)) { return; }

        $known = self::recentAdminIPs();
        if (isset($known[$ip]) && (time() - $known[$ip]) < 3600) { return; }

        $known[$ip] = time();
        // Newest first, bounded, so one roaming admin cannot grow this setting
        // without limit.
        arsort($known);
        $known = array_slice($known, 0, 20, true);

        $parts = [];
        foreach ($known as $k => $t) { $parts[] = $k . '|' . $t; }
        Database::setSetting('hf_admin_ips', implode(',', $parts));
    }

    /** This machine's own addresses. */
    public static function serverIPs(): array
    {
        static $ips = null;
        if ($ips !== null) { return $ips; }
        $ips = ['127.0.0.1' => true, '::1' => true];
        $out = (string) @shell_exec("ip -o addr show 2>/dev/null | awk '{print \$4}'");
        foreach (explode("\n", $out) as $line) {
            $ip = trim(explode('/', trim($line))[0] ?? '');
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) { $ips[$ip] = true; }
        }
        $ips = array_keys($ips);
        return $ips;
    }

    /** Loopback and private ranges are never an external attacker. */
    public static function isLocal(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) { return true; }
        return filter_var($ip, FILTER_VALIDATE_IP,
                          FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    // ── Reading the logs ────────────────────────────────────────────────────

    /**
     * The vhost logs most likely to contain current traffic.
     *
     * Most recently MODIFIED, not largest. Sorting by size picks logs that
     * were huge months ago: on the server this was written for, the biggest
     * files were autodiscover logs eleven days stale, and sampling those
     * showed nothing while the live attack was in a smaller file.
     *
     * Byte logs and the internal 127.0.0.1 / cpanel logs are excluded: they
     * are not request logs and would only add noise.
     */
    public static function logFiles(int $max = self::MAX_LOGS): array
    {
        foreach (self::LOG_DIRS as $dir) {
            if (!@is_dir($dir)) { continue; }
            $files = @glob($dir . '/*');
            if (!$files) { continue; }

            $keep = [];
            foreach ($files as $f) {
                $base = basename($f);
                if (!@is_file($f) || !@is_readable($f)) { continue; }
                if (strpos($base, 'bytes_log') !== false)   { continue; }
                if (strpos($base, '127.0.0.1') === 0)        { continue; }
                if (strpos($base, 'cpanel') === 0)           { continue; }
                $keep[$f] = (int) (@filemtime($f) ?: 0);
            }
            if (!$keep) { continue; }
            arsort($keep);
            return array_slice(array_keys($keep), 0, max(1, $max));
        }
        return [];
    }

    /** Last N lines of a file, capped in bytes. Never reads a log whole. */
    public static function tail(string $file, int $lines, int $maxBytes): array
    {
        $fh = @fopen($file, 'rb');
        if ($fh === false) { return []; }
        $size = @filesize($file);
        if ($size === false) { @fclose($fh); return []; }
        $read = (int) min($size, $maxBytes);
        if ($size > $read) { @fseek($fh, $size - $read); }
        $buf = (string) @stream_get_contents($fh);
        @fclose($fh);
        if ($buf === '') { return []; }
        $all = explode("\n", $buf);
        // The first line is probably a fragment, since we seeked mid-file.
        if (count($all) > 1 && $size > $read) { array_shift($all); }
        return array_slice($all, -$lines);
    }

    /**
     * Parse one combined-log line.
     *
     * @return array{ip:string,ts:int,method:string,path:string,status:int}|null
     */
    public static function parseLine(string $line): ?array
    {
        if (!preg_match(
                '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})/',
                $line, $m)) {
            return null;
        }
        $ts = strtotime(str_replace(':', ' ', substr($m[2], 0, 11)) . substr($m[2], 11));
        if ($ts === false) { $ts = 0; }

        // Who actually sent this request.
        //
        // When a site is behind a CDN the first field is the CDN's edge, not a
        // visitor, and counting requests by that field merges thousands of
        // unrelated people into one apparent attacker. On a live server that
        // put two Cloudflare edges into csf.deny.
        //
        // If the proxy recorded the originating address in the line, act on
        // that. If it did not, keep the edge: the block gate declines proxy
        // addresses and says why, which tells the operator their logs need
        // real-client addresses — far more useful than discarding the line and
        // showing nothing at all.
        $ip    = $m[1];
        $proxy = ProxyRanges::nameFor($ip);
        if ($proxy !== null) {
            $real = ProxyRanges::clientFromLine($line);
            if ($real !== null) { $ip = $real; }
        }

        return ['ip' => $ip, 'ts' => $ts, 'method' => $m[3],
                'path' => $m[4], 'status' => (int) $m[5],
                'via' => $proxy];
    }

    // ── Detection ───────────────────────────────────────────────────────────

    /**
     * Look for the three shapes.
     *
     * Read-only. Returns what it WOULD act on; enforce() does the acting, so
     * the panel can show findings without anything being blocked.
     */
    public static function analyse(): array
    {
        $window  = static::window();
        $cutoff  = time() - $window;
        // static::, not self:: — late static binding, so the log source can be
        // overridden by a subclass. Without it the replay test that proves
        // this detector catches the real 2026-10-27 attack silently read the
        // production log directories instead of its fixtures, found nothing,
        // and would have "passed" against a detector that did not work.
        $logs    = static::logFiles();
        $never   = static::neverBlock();

        $byIp    = [];   // ip => counters
        $byPath  = [];   // costly path => [ip => n]
        $scanned = 0;

        foreach ($logs as $file) {
            $vhost = basename($file);
            foreach (static::tail($file, self::MAX_LINES, self::MAX_BYTES) as $line) {
                if ($line === '') { continue; }
                $r = static::parseLine($line);
                if ($r === null) { continue; }
                // A line with no usable timestamp is counted: refusing it
                // would silently drop whole logs whose format differs
                // slightly, and under-counting an attack is the failure that
                // matters here.
                if ($r['ts'] > 0 && $r['ts'] < $cutoff) { continue; }
                $scanned++;

                $ip = $r['ip'];
                if (!isset($byIp[$ip])) {
                    $byIp[$ip] = ['total' => 0, 'misses' => 0, 'secrets' => 0,
                                  'vhosts' => [], 'paths' => []];
                }
                $byIp[$ip]['total']++;
                $byIp[$ip]['vhosts'][$vhost] = true;

                if ($r['status'] === 404 || $r['status'] === 403) {
                    $byIp[$ip]['misses']++;
                }

                $bare = strtok($r['path'], '?');
                if ($bare === false) { $bare = $r['path']; }

                foreach (self::SECRET_PATHS as $s) {
                    if (stripos($bare, $s) !== false) {
                        $byIp[$ip]['secrets']++;
                        $byIp[$ip]['paths'][$bare] = true;
                        break;
                    }
                }
                foreach (self::COSTLY_PATHS as $c) {
                    if (strcasecmp($bare, strtok($c, '?') ?: $c) === 0) {
                        if (!isset($byPath[$c])) { $byPath[$c] = []; }
                        $byPath[$c][$ip] = ($byPath[$c][$ip] ?? 0) + 1;
                        break;
                    }
                }
            }
        }

        $findings = [];

        // A + C: per-address shapes.
        foreach ($byIp as $ip => $c) {
            if (self::isLocal($ip) || isset($never[$ip])) { continue; }

            $vhosts = count($c['vhosts']);

            // A. 404 storm. The one that took the server down, and the one
            // nothing else watches: thousands of misses leave no trace in any
            // error count, yet each is a full PHP boot on WordPress.
            if ($c['misses'] >= self::missThreshold()) {
                $findings[] = self::finding($ip, 'scanner',
                    $c['misses'] . ' not-found responses across ' . $vhosts
                  . ' site(s) in ' . round($window / 60) . ' minute(s)'
                  . ($c['secrets'] > 0
                      ? ' — including ' . $c['secrets'] . ' request(s) for secrets '
                        . 'such as ' . implode(', ', array_slice(array_keys($c['paths']), 0, 3))
                      : ''),
                    $c, $vhosts);
                continue;
            }

            // C. Sheer rate.
            if ($c['total'] >= self::rateThreshold()) {
                $findings[] = self::finding($ip, 'rate',
                    $c['total'] . ' requests across ' . $vhosts . ' site(s) in '
                  . round($window / 60) . ' minute(s)', $c, $vhosts);
            }
        }

        // B. Endpoint floods: many addresses onto one costly path. Each sender
        // may be modest on its own, which is exactly why a per-IP rate rule
        // never catches this.
        $endpoints = [];
        foreach ($byPath as $path => $ips) {
            $total = array_sum($ips);
            if ($total < self::endpointThreshold()) { continue; }
            arsort($ips);
            $endpoints[] = [
                'path'    => $path,
                'total'   => $total,
                'sources' => count($ips),
                'top'     => array_slice($ips, 0, 10, true),
            ];
        }

        return [
            'scanned'   => $scanned,
            'logs'      => count($logs),
            'window'    => $window,
            'findings'  => $findings,
            'endpoints' => $endpoints,
            'monitor_only' => self::monitorOnly(),
            'protected' => count($never),
        ];
    }

    private static function finding(string $ip, string $kind, string $why,
                                    array $c, int $vhosts): array
    {
        return [
            'ip'      => $ip,
            'kind'    => $kind,
            'reason'  => $why,
            'total'   => $c['total'],
            'misses'  => $c['misses'],
            'secrets' => $c['secrets'],
            'vhosts'  => $vhosts,
        ];
    }

    // ── Acting on it ────────────────────────────────────────────────────────

    /**
     * Block what analyse() found.
     *
     * Every refusal is recorded with its reason. A block that fails silently
     * is how this product spent a week reporting "Watching" against addresses
     * it had never managed to block.
     */
    public static function enforce(): array
    {
        self::ensureSchema();

        if (!self::enabled()) {
            return ['success' => true, 'skipped' => 'detection is switched off',
                    'blocked' => 0, 'findings' => 0];
        }

        $res      = self::analyse();
        $blocked  = 0;
        $failed   = [];
        $monitor  = self::monitorOnly();

        foreach ($res['findings'] as $f) {
            $ip = (string) $f['ip'];

            // Already dealt with, by us or by anything else on the box.
            if (self::recentlyActioned($ip)) { continue; }

            self::record($ip, $f, $monitor);

            if ($monitor) { continue; }

            $fw  = new Firewall();
            $out = $fw->blockIP($ip, 'HTTP ' . $f['kind'] . ': ' . $f['reason'],
                                false, self::blockSeconds());
            if (!empty($out['success'])) {
                $blocked++;
                Logger::warn('HttpFlood: blocked ' . $ip . ' — ' . $f['reason']);
                Logger::event('http_flood_blocked', 'high', $ip, '',
                              'Blocked ' . $ip . ': ' . $f['reason']);
                Database::query(
                    'UPDATE http_flood_offenders SET blocked = 1, block_error = NULL
                      WHERE ip_address = ?', [$ip]);
            } else {
                $why = trim((string) ($out['error'] ?? '')) ?: 'the firewall refused it';
                $failed[] = ['ip' => $ip, 'error' => $why];
                Logger::error('HttpFlood: could NOT block ' . $ip . ' — ' . $why);
                Database::query(
                    'UPDATE http_flood_offenders SET block_error = ? WHERE ip_address = ?',
                    [mb_substr($why, 0, 200), $ip]);
            }
        }

        Database::setSetting('hf_last_run', (string) time());

        return ['success' => true, 'blocked' => $blocked,
                'findings' => count($res['findings']),
                'endpoints' => count($res['endpoints']),
                'scanned' => $res['scanned'], 'logs' => $res['logs'],
                'monitor_only' => $monitor, 'failed' => $failed];
    }

    /** Acted on in the last window already. */
    private static function recentlyActioned(string $ip): bool
    {
        $row = Database::fetchOne(
            'SELECT last_seen FROM http_flood_offenders
              WHERE ip_address = ? AND blocked = 1', [$ip]);
        if (!$row) { return false; }
        return (time() - (int) $row['last_seen']) < self::blockSeconds();
    }

    private static function record(string $ip, array $f, bool $monitor): void
    {
        Database::query(
            "INSERT INTO http_flood_offenders
                 (ip_address, kind, reason, requests, misses, secrets, vhosts,
                  first_seen, last_seen, blocked)
             VALUES (?,?,?,?,?,?,?,strftime('%s','now'),strftime('%s','now'),0)
             ON CONFLICT(ip_address) DO UPDATE SET
                 kind = excluded.kind, reason = excluded.reason,
                 requests = excluded.requests, misses = excluded.misses,
                 secrets = excluded.secrets, vhosts = excluded.vhosts,
                 last_seen = excluded.last_seen",
            [$ip, (string) $f['kind'], mb_substr((string) $f['reason'], 0, 400),
             (int) $f['total'], (int) $f['misses'], (int) $f['secrets'],
             (int) $f['vhosts']]);

        if ($monitor) {
            Logger::info('HttpFlood: would block ' . $ip . ' — ' . $f['reason']
                       . ' (monitor only)');
        }
    }

    public static function offenders(int $limit = 100): array
    {
        self::ensureSchema();
        return Database::fetchAll(
            'SELECT * FROM http_flood_offenders ORDER BY last_seen DESC LIMIT '
            . max(1, min(500, $limit))) ?: [];
    }

    public static function release(string $ip): array
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return ['success' => false, 'error' => 'Not a valid IP address'];
        }
        (new Firewall())->unblockIP($ip);
        Database::query('DELETE FROM http_flood_offenders WHERE ip_address = ?', [$ip]);
        Logger::info('HttpFlood: released ' . $ip);
        return ['success' => true, 'ip' => $ip];
    }

    public static function ensureSchema(): void
    {
        Database::get()->exec("
            CREATE TABLE IF NOT EXISTS http_flood_offenders (
                ip_address  TEXT PRIMARY KEY,
                kind        TEXT NOT NULL DEFAULT '',
                reason      TEXT NOT NULL DEFAULT '',
                requests    INTEGER NOT NULL DEFAULT 0,
                misses      INTEGER NOT NULL DEFAULT 0,
                secrets     INTEGER NOT NULL DEFAULT 0,
                vhosts      INTEGER NOT NULL DEFAULT 0,
                first_seen  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                last_seen   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                blocked     INTEGER NOT NULL DEFAULT 0,
                block_error TEXT
            )");
        Database::get()->exec("CREATE INDEX IF NOT EXISTS idx_hf_seen
                                 ON http_flood_offenders(last_seen DESC)");
    }

    public static function status(): array
    {
        self::ensureSchema();
        return [
            'enabled'            => self::enabled(),
            'monitor_only'       => self::monitorOnly(),
            'window'             => self::window(),
            'miss_threshold'     => self::missThreshold(),
            'rate_threshold'     => self::rateThreshold(),
            'endpoint_threshold' => self::endpointThreshold(),
            'block_secs'         => self::blockSeconds(),
            'last_run'           => (int) (Database::setting('hf_last_run', '0') ?? 0),
            'logs_found'         => count(self::logFiles()),
            'protected'          => self::neverBlock(),
        ];
    }
}
