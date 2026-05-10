<?php
/**
 * Sentinel Gate — Bot Shield Module
 * Detects and blocks malicious bots via access log analysis and UA pattern matching
 */

class BotShield {

    /** UA pattern groups that indicate bad bots */
    private array $badBotPatterns = [
        'scanner' => '/masscan|zgrab|nuclei|nmap|nikto|sqlmap|dirbuster|gobuster|wfuzz|hydra|acunetix|nessus|qualys/i',
        'scraper' => '/AhrefsBot|SemrushBot|DotBot|MJ12bot|BLEXBot|DataForSeoBot|PetalBot/i',
        'exploit' => '/(?:python-requests|curl\/)[^\s]+ .+(?:wp-login|xmlrpc)|Go-http-client.+(?:wp-admin|wp-login|xmlrpc)/i',
    ];

    /** UA patterns for legitimate crawlers — never block these */
    private array $goodBotPatterns = [
        '/Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|facebot|ia_archiver|Twitterbot/i',
    ];

    /** Access log locations to try, in order */
    private array $logPaths = [
        '/var/log/apache2/access.log',
        '/usr/local/apache/logs/access_log',
        '/var/log/nginx/access.log',
    ];

    public function __construct() {
        $this->ensureSchema();
    }

    private function ensureSchema(): void {
        Database::get()->exec("
            CREATE TABLE IF NOT EXISTS bot_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT NOT NULL,
                user_agent  TEXT,
                uri         TEXT,
                method      TEXT,
                country     TEXT,
                threat_type TEXT,
                action      TEXT NOT NULL DEFAULT 'block',
                hits        INTEGER NOT NULL DEFAULT 1,
                timestamp   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS bot_whitelist (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern  TEXT NOT NULL UNIQUE,
                note     TEXT,
                added_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
        ");
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    public function getStats(): array {
        $today         = mktime(0, 0, 0);
        $blockedToday  = Database::fetchOne(
            "SELECT COUNT(*) as c FROM bot_events WHERE action='block' AND timestamp >= ?", [$today]
        )['c'];
        $totalBlocked  = Database::fetchOne(
            "SELECT COUNT(*) as c FROM bot_events WHERE action='block'"
        )['c'];
        $whitelisted   = Database::fetchOne("SELECT COUNT(*) as c FROM bot_whitelist")['c'];
        $lastParse     = Database::setting('bot_last_requests_analyzed', '0');

        return [
            'bots_blocked_today'  => (int) $blockedToday,
            'total_blocked'       => (int) $totalBlocked,
            'whitelisted'         => (int) $whitelisted,
            'requests_analyzed'   => (int) $lastParse,
        ];
    }

    // ── Event Fetching ────────────────────────────────────────────────────────

    public function getBotEvents(int $limit = 100): array {
        return Database::fetchAll(
            "SELECT * FROM bot_events ORDER BY timestamp DESC LIMIT ?", [$limit]
        );
    }

    public function getBlockedBots(): array {
        return Database::fetchAll(
            "SELECT ip_address, user_agent, SUM(hits) as hits, country,
                    MAX(timestamp) as last_seen
             FROM bot_events
             WHERE action = 'block'
             GROUP BY ip_address
             ORDER BY last_seen DESC"
        );
    }

    public function getWhitelistedBots(): array {
        return Database::fetchAll("SELECT * FROM bot_whitelist ORDER BY added_at DESC");
    }

    // ── Log Analysis ──────────────────────────────────────────────────────────

    public function analyzeLogs(): array {
        $logFile = null;
        foreach ($this->logPaths as $path) {
            if (file_exists($path) && is_readable($path)) {
                $logFile = $path;
                break;
            }
        }

        if ($logFile === null) {
            Logger::error('BotShield: no accessible access log found');
            return ['error' => 'No access log found', 'findings' => []];
        }

        $findings        = [];
        $requestsRead    = 0;
        $whitelistPats   = $this->getWhitelistedBots();

        // Read last 50 000 lines to avoid memory exhaustion on large logs
        $lines = $this->tailFile($logFile, 50000);

        foreach ($lines as $line) {
            $requestsRead++;

            // Combined Log Format:
            // 1.2.3.4 - - [date] "METHOD /uri HTTP/1.1" status size "ref" "ua"
            if (!preg_match(
                '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d+)\s+\S+(?:\s+"[^"]*")?\s+"([^"]*)"/',
                $line, $m
            )) {
                continue;
            }

            [, $ip, , $method, $uri, , $ua] = $m;

            // Skip good bots
            if ($this->isGoodBot($ua)) continue;

            // Skip whitelisted patterns
            if ($this->isWhitelisted($ua, $whitelistPats)) continue;

            $threat = $this->detectThreatType($ua, $uri);
            if ($threat === null) continue;

            $findings[] = [
                'ip'         => $ip,
                'user_agent' => $ua,
                'uri'        => $uri,
                'method'     => $method,
                'threat_type'=> $threat,
            ];
        }

        Database::setSetting('bot_last_requests_analyzed', (string) $requestsRead);
        Logger::info("BotShield: analyzed $requestsRead log lines, found " . count($findings) . " bot hits");

        return [
            'log_file'          => $logFile,
            'requests_analyzed' => $requestsRead,
            'findings'          => $findings,
        ];
    }

    // ── Block / Unblock ───────────────────────────────────────────────────────

    public function blockBot(string $ip, string $ua, string $reason): bool {
        try {
            // Upsert bot_events — increment hits if already present
            $existing = Database::fetchOne(
                "SELECT id, hits FROM bot_events WHERE ip_address = ? AND action = 'block'", [$ip]
            );
            if ($existing) {
                Database::query(
                    "UPDATE bot_events SET hits = hits + 1, timestamp = strftime('%s','now'),
                     user_agent = ?, threat_type = ? WHERE id = ?",
                    [$ua, $reason, $existing['id']]
                );
            } else {
                Database::insert('bot_events', [
                    'ip_address'  => $ip,
                    'user_agent'  => $ua,
                    'threat_type' => $reason,
                    'action'      => 'block',
                ]);
            }

            // Enforce at the network level
            if (file_exists(CSF_BIN)) {
                exec(CSF_BIN . " -d " . escapeshellarg($ip) . " 2>/dev/null", $out, $code);
            } else {
                exec(IPTABLES_BIN . " -I INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null", $out, $code);
            }

            Logger::info("BotShield: blocked bot IP $ip — $reason");
            return true;
        } catch (Exception $e) {
            Logger::error('BotShield::blockBot — ' . $e->getMessage());
            return false;
        }
    }

    public function unblockBot(string $ip): bool {
        try {
            Database::query(
                "UPDATE bot_events SET action = 'unblocked' WHERE ip_address = ?", [$ip]
            );

            if (file_exists(CSF_BIN)) {
                exec(CSF_BIN . " -dr " . escapeshellarg($ip) . " 2>/dev/null");
            } else {
                exec(IPTABLES_BIN . " -D INPUT -s " . escapeshellarg($ip) . " -j DROP 2>/dev/null");
            }

            Logger::info("BotShield: unblocked IP $ip");
            return true;
        } catch (Exception $e) {
            Logger::error('BotShield::unblockBot — ' . $e->getMessage());
            return false;
        }
    }

    // ── Whitelist ─────────────────────────────────────────────────────────────

    public function addWhitelist(string $pattern, string $note = ''): bool {
        try {
            Database::insert('bot_whitelist', ['pattern' => $pattern, 'note' => $note]);
            Logger::info("BotShield: whitelisted pattern '$pattern'");
            return true;
        } catch (Exception $e) {
            Logger::error('BotShield::addWhitelist — ' . $e->getMessage());
            return false;
        }
    }

    public function removeWhitelist(int $id): bool {
        try {
            Database::query("DELETE FROM bot_whitelist WHERE id = ?", [$id]);
            return true;
        } catch (Exception $e) {
            Logger::error('BotShield::removeWhitelist — ' . $e->getMessage());
            return false;
        }
    }

    // ── Run Analysis ──────────────────────────────────────────────────────────

    public function runAnalysis(): array {
        $result      = $this->analyzeLogs();
        $blocked     = 0;
        $skipped     = 0;
        $alreadyBlocked = [];

        // Pre-load already-blocked IPs for fast lookup
        $rows = Database::fetchAll("SELECT ip_address FROM bot_events WHERE action = 'block'");
        foreach ($rows as $r) {
            $alreadyBlocked[$r['ip_address']] = true;
        }

        foreach ($result['findings'] ?? [] as $finding) {
            $ip = $finding['ip'];

            if (isset($alreadyBlocked[$ip])) {
                $skipped++;
                continue;
            }

            if ($this->blockBot($ip, $finding['user_agent'], $finding['threat_type'])) {
                $alreadyBlocked[$ip] = true;
                $blocked++;
            }
        }

        return [
            'requests_analyzed' => $result['requests_analyzed'] ?? 0,
            'findings'          => count($result['findings'] ?? []),
            'newly_blocked'     => $blocked,
            'already_blocked'   => $skipped,
            'log_file'          => $result['log_file'] ?? null,
        ];
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function isGoodBot(string $ua): bool {
        foreach ($this->goodBotPatterns as $pattern) {
            if (preg_match($pattern, $ua)) return true;
        }
        return false;
    }

    private function isWhitelisted(string $ua, array $whitelistRows): bool {
        foreach ($whitelistRows as $row) {
            $pat = $row['pattern'];
            // Support plain substring or /regex/ patterns
            if (str_starts_with($pat, '/')) {
                if (@preg_match($pat, $ua)) return true;
            } else {
                if (stripos($ua, $pat) !== false) return true;
            }
        }
        return false;
    }

    private function detectThreatType(string $ua, string $uri): ?string {
        foreach ($this->badBotPatterns as $type => $pattern) {
            if ($type === 'exploit') {
                // Exploit bots: combine UA + URI for context
                if (preg_match('/python-requests|curl\//i', $ua) &&
                    preg_match('/wp-login|xmlrpc/i', $uri)) {
                    return 'exploit';
                }
                if (preg_match('/Go-http-client/i', $ua) &&
                    preg_match('/wp-admin|wp-login|xmlrpc/i', $uri)) {
                    return 'exploit';
                }
            } else {
                if (preg_match($pattern, $ua)) return $type;
            }
        }
        return null;
    }

    /**
     * Return the last $n lines of a file without loading the whole file into memory.
     */
    private function tailFile(string $path, int $lines): array {
        $out = [];
        exec("tail -n $lines " . escapeshellarg($path) . " 2>/dev/null", $out);
        return $out;
    }
}
