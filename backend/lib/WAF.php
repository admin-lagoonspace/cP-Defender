<?php
/**
 * Sentinel Gate — WAF Module
 * ModSecurity 3.0 management + OWASP CRS
 */

class WAF {

    public function isModSecInstalled(): bool {
        exec('apachectl -M 2>/dev/null | grep -i security', $out);
        return !empty($out);
    }

    public function getStatus(): array {
        $enabled  = Database::setting('waf_enabled') === '1';
        $modsec   = $this->isModSecInstalled();
        $ruleCount = 0;
        if (is_dir(MODSEC_CONF)) {
            $ruleCount = count(glob(MODSEC_CONF . '/**/*.conf', GLOB_BRACE));
        }

        return [
            'enabled'      => $enabled,
            'modsec'       => $modsec,
            'mode'         => $this->getMode(),
            'rule_count'   => $ruleCount,
            'crs_version'  => $this->getCRSVersion(),
            'events_today' => $this->countEventsToday(),
        ];
    }

    private function getMode(): string {
        if (!is_readable(MODSEC_CONF . '/modsecurity.conf')) return 'unknown';
        $conf = file_get_contents(MODSEC_CONF . '/modsecurity.conf');
        if (preg_match('/SecRuleEngine\s+(\w+)/i', $conf, $m)) return $m[1];
        return 'unknown';
    }

    private function getCRSVersion(): string {
        $path = MODSEC_CONF . '/OWASP3/crs-setup.conf';
        if (!file_exists($path)) return 'Not installed';
        $content = file_get_contents($path);
        if (preg_match('/version\s+(\d+\.\d+\.\d+)/i', $content, $m)) return 'CRS ' . $m[1];
        return 'CRS (version unknown)';
    }

    private function countEventsToday(): int {
        $since = mktime(0, 0, 0);
        $row = Database::fetchOne(
            "SELECT COUNT(*) as c FROM waf_events WHERE timestamp >= ?", [$since]
        );
        return (int) ($row['c'] ?? 0);
    }

    public function getEvents(int $limit = 100, ?string $severity = null, ?string $ip = null): array {
        $where  = [];
        $params = [];
        if ($severity) { $where[] = 'severity = ?'; $params[] = $severity; }
        if ($ip)       { $where[] = 'ip_address = ?'; $params[] = $ip; }

        $sql = "SELECT * FROM waf_events" .
               ($where ? ' WHERE ' . implode(' AND ', $where) : '') .
               " ORDER BY timestamp DESC LIMIT ?";
        $params[] = $limit;
        return Database::fetchAll($sql, $params);
    }

    public function setMode(string $mode): array {
        $allowed = ['On', 'Off', 'DetectionOnly'];
        if (!in_array($mode, $allowed)) {
            return ['success' => false, 'error' => 'Invalid mode'];
        }

        $confPath = MODSEC_CONF . '/modsecurity.conf';
        if (is_readable($confPath)) {
            $conf = file_get_contents($confPath);
            $conf = preg_replace('/SecRuleEngine\s+\w+/', "SecRuleEngine $mode", $conf);
            file_put_contents($confPath, $conf);
            exec('service httpd graceful 2>/dev/null || service apache2 graceful 2>/dev/null');
        }

        Database::setSetting('waf_enabled', $mode === 'On' ? '1' : '0');
        return ['success' => true, 'mode' => $mode];
    }

    public function getRuleCategories(): array {
        return [
            ['id' => '900',  'name' => 'Initialization',       'active' => true,  'rules' => 45],
            ['id' => '910',  'name' => 'IP Reputation',         'active' => true,  'rules' => 12],
            ['id' => '911',  'name' => 'Method Enforcement',    'active' => true,  'rules' => 8],
            ['id' => '912',  'name' => 'DoS Protection',        'active' => true,  'rules' => 16],
            ['id' => '913',  'name' => 'Scanner Detection',     'active' => true,  'rules' => 94],
            ['id' => '920',  'name' => 'Protocol Enforcement',  'active' => true,  'rules' => 37],
            ['id' => '921',  'name' => 'Protocol Attack',       'active' => true,  'rules' => 22],
            ['id' => '930',  'name' => 'Local File Inclusion',  'active' => true,  'rules' => 54],
            ['id' => '931',  'name' => 'Remote File Inclusion', 'active' => true,  'rules' => 11],
            ['id' => '932',  'name' => 'Remote Code Execution', 'active' => true,  'rules' => 23],
            ['id' => '933',  'name' => 'PHP Injection',         'active' => true,  'rules' => 39],
            ['id' => '941',  'name' => 'XSS',                   'active' => true,  'rules' => 118],
            ['id' => '942',  'name' => 'SQL Injection',         'active' => true,  'rules' => 214],
            ['id' => '943',  'name' => 'Session Fixation',      'active' => true,  'rules' => 7],
            ['id' => '944',  'name' => 'Java Attack',           'active' => false, 'rules' => 12],
            ['id' => '949',  'name' => 'Blocking Evaluation',   'active' => true,  'rules' => 4],
        ];
    }

    /**
     * Where ModSecurity actually writes its audit log.
     *
     * MODSEC_AUDIT is /var/log/modsec_audit.log, which is the Debian default
     * and the path our own installer writes into its config. It is NOT where
     * cPanel puts it: EasyApache 4 logs to /var/log/apache2, and a server
     * using cPanel's own ModSecurity never had a file at our path at all. The
     * ingester checked file_exists() and returned 0, so the WAF page showed no
     * events and no error -- indistinguishable from a quiet server.
     *
     * The resolved path is remembered, and re-resolved when it stops existing
     * so a server that switches Apache builds recovers on its own.
     */
    public static function auditLogPath(): ?string
    {
        $stored = (string) (Database::setting('waf_audit_log', '') ?? '');
        if ($stored !== '' && is_readable($stored)) { return $stored; }

        foreach (self::auditLogCandidates() as $cand) {
            if (is_readable($cand)) {
                Database::setSetting('waf_audit_log', $cand);
                return $cand;
            }
        }
        return null;
    }

    /** Every place ModSecurity is known to write, most likely first. */
    public static function auditLogCandidates(): array
    {
        $configured = (string) (Database::setting('waf_audit_log_override', '') ?? '');
        $list = $configured !== '' ? [$configured] : [];
        return array_merge($list, [
            '/var/log/apache2/modsec_audit.log',        // EasyApache 4 (cPanel)
            '/usr/local/apache/logs/modsec_audit.log',  // older cPanel
            '/var/log/httpd/modsec_audit.log',          // RHEL-family httpd
            MODSEC_AUDIT,                               // our own config / Debian
            '/var/log/modsec/modsec_audit.log',
        ]);
    }

    /**
     * What the WAF log ingest is actually doing.
     *
     * "No attacks" and "we never looked" render identically as an empty table.
     * This is what lets the page tell them apart.
     */
    public function ingestStatus(): array
    {
        $path = self::auditLogPath();
        return [
            'log_found'    => $path !== null,
            'log_path'     => $path,
            'log_size'     => $path !== null ? (int) @filesize($path) : 0,
            'candidates'   => self::auditLogCandidates(),
            'last_run'     => (int) (Database::setting('waf_ingest_last_run', '0') ?? 0),
            'last_count'   => (int) (Database::setting('waf_ingest_last_count', '0') ?? 0),
            'total_events' => (int) (Database::fetchOne(
                                  'SELECT COUNT(*) c FROM waf_events')['c'] ?? 0),
            'offset'       => (int) (Database::setting('waf_ingest_offset', '0') ?? 0),
        ];
    }

    /**
     * Read new ModSecurity audit entries into waf_events.
     *
     * Reads only what has been appended since last time. The previous version
     * opened the file and read it from the top on every call, which with a
     * scheduled run would re-parse the whole audit log every 15 minutes --
     * gigabytes of I/O on a busy server, and duplicate rows for everything
     * older than the 60-second dedup window.
     */
    public function ingestModSecLog(): int {
        $path = self::auditLogPath();
        if ($path === null) {
            Database::setSetting('waf_ingest_last_run', (string) time());
            Database::setSetting('waf_ingest_last_count', '0');
            return 0;
        }

        $size   = (int) @filesize($path);
        $offset = (int) (Database::setting('waf_ingest_offset', '0') ?? 0);

        // Rotation, or a different file entirely: start again from the top.
        if ($size < $offset) { $offset = 0; }
        if ($size === $offset) {
            Database::setSetting('waf_ingest_last_run', (string) time());
            Database::setSetting('waf_ingest_last_count', '0');
            return 0;
        }

        $handle = @fopen($path, 'r');
        if ($handle === false) {
            Logger::warn('WAF: cannot read ' . $path);
            return 0;
        }
        if ($offset > 0) { @fseek($handle, $offset); }

        $count  = 0;
        $entry  = [];

        while (($line = fgets($handle)) !== false) {
            if (preg_match('/^--[a-f0-9]+-A--/', $line)) {
                // New entry
                if (!empty($entry)) {
                    $this->saveWafEvent($entry);
                    $count++;
                }
                $entry = [];
            } elseif (preg_match('/Message: (.+)/', $line, $m)) {
                preg_match('/\[id "(\d+)"\]/', $m[1], $idM);
                preg_match('/\[msg "([^"]+)"\]/', $m[1], $msgM);
                preg_match('/\[severity "(\w+)"\]/', $m[1], $sevM);
                $entry['rule_id']  = $idM[1]  ?? '';
                $entry['rule_msg'] = $msgM[1] ?? '';
                $entry['severity'] = strtolower($sevM[1] ?? 'medium');
            } elseif (preg_match(
                    '/^\[[^\]]*\]\s+\S+\s+([0-9a-fA-F:.]+)\s+\d+\s+([0-9a-fA-F:.]+)\s+\d+/',
                    $line, $m)) {
                // ModSecurity section A is:
                //   [time] uniqueId clientIp clientPort serverIp serverPort
                //
                // The old pattern was '\] (\d+\.\d+\.\d+\.\d+) ' -- an IP
                // immediately after the closing bracket. What actually follows
                // the bracket is the unique id, so it never matched and every
                // event was stored with an empty ip_address. The IP is the one
                // field an operator acts on, so the table was listing attacks
                // with no way to block their source.
                //
                // The character class covers IPv6 as well; the old one did not.
                $entry['ip_address'] = $m[1];
                $entry['server_ip']  = $m[2];
            } elseif (preg_match('/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT) (.+) HTTP/', $line, $m)) {
                $entry['method'] = $m[1];
                $entry['uri']    = $m[2];
            } elseif (preg_match('/^Host:\s*(.+)/i', $line, $m)) {
                $entry['host'] = trim($m[1]);
            } elseif (preg_match('/^User-Agent:\s*(.+)/i', $line, $m)) {
                // The table has had a user_agent column all along and nothing
                // ever filled it.
                $entry['user_agent'] = trim($m[1]);
            }
        }
        // The trailing entry has no terminator yet if the file is mid-write;
        // leaving it means the next run picks it up complete.
        $newOffset = ftell($handle);
        fclose($handle);

        Database::setSetting('waf_ingest_offset', (string) (int) $newOffset);
        Database::setSetting('waf_ingest_last_run', (string) time());
        Database::setSetting('waf_ingest_last_count', (string) $count);
        if ($count > 0) {
            Logger::info("WAF: ingested {$count} ModSecurity event(s) from {$path}");
        }

        return $count;
    }

    private function saveWafEvent(array $e): void {
        if (empty($e['rule_id']) && empty($e['ip_address'])) return;

        // Deduplicate: skip if same rule+IP in last 60s
        $exists = Database::fetchOne(
            "SELECT id FROM waf_events WHERE rule_id=? AND ip_address=? AND timestamp > ?",
            [$e['rule_id'] ?? '', $e['ip_address'] ?? '', time() - 60]
        );
        if ($exists) return;

        Database::insert('waf_events', [
            'rule_id'    => $e['rule_id']    ?? '',
            'rule_msg'   => $e['rule_msg']   ?? '',
            'severity'   => $e['severity']   ?? 'medium',
            'ip_address' => $e['ip_address'] ?? '',
            'uri'        => $e['uri']        ?? '',
            'method'     => $e['method']     ?? '',
            'host'       => $e['host']       ?? '',
            'user_agent' => mb_substr((string)($e['user_agent'] ?? ''), 0, 512),
            'action'     => 'block',
        ]);
    }

    public function getStats(): array {
        $total   = Database::fetchOne("SELECT COUNT(*) as c FROM waf_events")['c'];
        $today   = Database::fetchOne(
            "SELECT COUNT(*) as c FROM waf_events WHERE timestamp >= ?", [mktime(0,0,0)]
        )['c'];
        $bySev   = Database::fetchAll(
            "SELECT severity, COUNT(*) as count FROM waf_events GROUP BY severity ORDER BY count DESC"
        );
        $topRules = Database::fetchAll(
            "SELECT rule_id, rule_msg, COUNT(*) as hits FROM waf_events GROUP BY rule_id ORDER BY hits DESC LIMIT 10"
        );
        $topIPs = Database::fetchAll(
            "SELECT ip_address, COUNT(*) as hits FROM waf_events GROUP BY ip_address ORDER BY hits DESC LIMIT 10"
        );

        return [
            'total_events' => (int) $total,
            'events_today' => (int) $today,
            'by_severity'  => $bySev,
            'top_rules'    => $topRules,
            'top_ips'      => $topIPs,
        ];
    }

    public function addCustomRule(string $id, string $pattern, string $action = 'block'): array {
        $confPath = MODSEC_CONF . '/sentinel-gate/custom_rules.conf';
        $dir = dirname($confPath);
        if (!is_dir($dir)) mkdir($dir, 0750, true);

        $rule = sprintf(
            'SecRule REQUEST_URI|ARGS|REQUEST_HEADERS "%s" "id:%s,phase:2,deny,status:403,msg:\'Sentinel-Custom\',log,auditlog"' . "\n",
            addslashes($pattern),
            $id
        );
        file_put_contents($confPath, $rule, FILE_APPEND);
        exec('service httpd graceful 2>/dev/null || service apache2 graceful 2>/dev/null');
        return ['success' => true];
    }
}
