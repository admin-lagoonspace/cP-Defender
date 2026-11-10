<?php

/* Pulls in what it calls, rather than trusting the caller to have done it.
 * UserReport did not, and `serverscrub user-reports` died with
 * Class "UserScanRequest" not found on all 132 accounts -- silently,
 * because writeAll() catches Throwable per account. require_once is
 * idempotent and safe across the cycles these classes form. */
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';
// setMode() delegates to it and getMode() reads the mode it records. No
// cycle: WAFInstaller requires only Database and Logger.
require_once __DIR__ . '/WAFInstaller.php';

/**
 * ServerScrub — WAF Module
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

    /**
     * The mode Apache is actually running in.
     *
     * Our own config is read FIRST, because it is included after the vendor's
     * and therefore wins. Reading only the vendor file reported a mode that
     * had been overridden -- the status said one thing and the engine card,
     * reading the right file, said another.
     *
     * 'unknown' when neither can be read. Not 'On': a status that assumes it
     * is protecting you is the one assumption this must never make.
     */
    private function getMode(): string {
        $ours = WAFInstaller::currentMode();          // on | detectiononly | off | unknown
        if ($ours !== 'unknown') {
            return ['on' => 'On', 'detectiononly' => 'DetectionOnly',
                    'off' => 'Off'][$ours] ?? $ours;
        }

        if (!is_readable(MODSEC_CONF . '/modsecurity.conf')) return 'unknown';
        $conf = (string) @file_get_contents(MODSEC_CONF . '/modsecurity.conf');
        if (preg_match('/^\s*SecRuleEngine\s+(\w+)/mi', $conf, $m)) return $m[1];
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

    public const EVENTS_MIN_PAGE = 25;
    public const EVENTS_MAX_PAGE = 500;

    /**
     * One page of events, WITH the total.
     *
     * This returned a bare list capped at 100 and nothing else, so the panel
     * showed the most recent hundred of 148,551 events and gave no way to
     * reach the rest -- or even to know there WAS a rest. An attack from last
     * Tuesday was in the database and unreachable from the product.
     *
     * The total is counted under the same filter as the rows. Counting the
     * whole table while listing a filtered page would put "Showing 1-50 of
     * 148,551" under fifty critical events, which is worse than no count.
     *
     * @return array{items:array,total:int,limit:int,offset:int}
     */
    public function getEvents(int $limit = 100, ?string $severity = null,
                              ?string $ip = null, int $offset = 0): array {
        $limit  = max(self::EVENTS_MIN_PAGE, min(self::EVENTS_MAX_PAGE, $limit));
        $offset = max(0, $offset);

        $where  = [];
        $params = [];
        if ($severity) { $where[] = 'severity = ?'; $params[] = $severity; }
        if ($ip)       { $where[] = 'ip_address = ?'; $params[] = $ip; }
        $clause = $where ? ' WHERE ' . implode(' AND ', $where) : '';

        $total = (int) (Database::fetchOne(
            "SELECT COUNT(*) AS c FROM waf_events" . $clause, $params)['c'] ?? 0);

        $rows = Database::fetchAll(
            "SELECT * FROM waf_events" . $clause .
            " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
            array_merge($params, [$limit, $offset]));

        return ['items' => $rows, 'total' => $total,
                'limit' => $limit, 'offset' => $offset];
    }

    /**
     * Set the rule engine mode.
     *
     * THIS USED TO BE A SECOND, DIFFERENT IMPLEMENTATION, and the two
     * disagreed. The page header's "Apply Mode" came here; the WAF Engine
     * card's selector went to WAFInstaller::setMode(). They wrote DIFFERENT
     * FILES:
     *
     *   here                 the VENDOR config, modsec_vendor_configs/modsecurity.conf
     *   WAFInstaller         serverscrub-waf.conf, the file we own and Apache loads
     *
     * Ours is included after the vendor's and sets SecRuleEngine itself, so
     * it is the one that decides. Editing the vendor file changed nothing a
     * request would ever notice.
     *
     * And it could not fail. `is_readable` guarded the edit, so on a server
     * where that path does not exist -- which is most of them; cPanel keeps
     * ModSecurity's config elsewhere -- the whole block was skipped and the
     * method still returned success. No write check, no `apachectl -t`, no
     * check that the reload worked. The operator pressed Apply Mode, was told
     * it had worked, and the engine below carried on saying "detectiononly",
     * because it was reading the file that actually governs.
     *
     * So this delegates. One implementation, which writes the file that
     * counts, validates the config before reloading, and reports a failure as
     * a failure.
     */
    public function setMode(string $mode): array {
        $allowed = ['On', 'Off', 'DetectionOnly'];
        if (!in_array($mode, $allowed, true)) {
            return ['success' => false, 'error' => 'Invalid mode'];
        }

        $r = WAFInstaller::setMode(strtolower($mode));
        if (empty($r['success'])) { return $r; }

        // Kept in step rather than set independently. waf_enabled drove a
        // "Mode: On" tile while the engine sat in DetectionOnly; two settings
        // for one fact is how that happens.
        Database::setSetting('waf_enabled', $mode === 'On' ? '1' : '0');
        return ['success' => true, 'mode' => $mode];
    }

    /**
     * The OWASP CRS categories actually installed on this server.
     *
     * -- WHY THIS READS FILES -------------------------------------------------
     *
     * It used to return a literal array: sixteen categories, exact rule
     * counts, and an Active/Disabled flag on each. It rendered identically on
     * a server with CRS 4.7.0, with CRS 3.x, and with no CRS installed at all,
     * and the panel presented every figure as fact. One of those literals was
     *
     *     ['id' => '944', 'name' => 'Java Attack', 'active' => false, 'rules' => 12]
     *
     * -- a specific, actionable claim about a customer's security posture that
     * was a hardcoded `false` in PHP source. An operator reading it either
     * believes the Java rules are off and goes looking for why, or believes
     * the other fifteen are on and stops looking. This is the same defect as
     * action = 'block' on 148,551 rows.
     *
     * Everything below is derived from the files WAFInstaller::crsPath()
     * locates, and when they cannot be read the answer is
     * available => false with a reason, for the panel to say so. A number this
     * product cannot derive is not displayed as one.
     *
     * -- WHAT "LOADED" MEANS AND DOES NOT ------------------------------------
     *
     * `loaded` is whether OUR config includes the CRS rules directory, which
     * is as far as reading files can establish. It is NOT "ModSecurity has
     * these rules in memory": only a running Apache knows that, and the mode
     * tile and `include_present` are what qualify it. `excluded` is the number
     * of rule exclusions the operator has recorded against ids in that
     * category -- rules the product itself has switched off, which the panel
     * otherwise shows no trace of.
     *
     * -- BOUNDS ---------------------------------------------------------------
     *
     * rules/*.conf one level down, at most $maxFiles of them, nothing over
     * 4 MB read. CRS 4.7.0 is ~35 files of ~40 KB. This is a panel load on a
     * 132-account server, not a scan.
     *
     * @return array{available:bool,reason:?string,crs_path:?string,
     *               crs_version:?string,loaded:bool,categories:array<int,array>}
     */
    public function getRuleCategories(int $maxFiles = 400): array {
        $dir = WAFInstaller::crsPath();
        if ($dir === null) {
            return $this->noCategories(
                'No OWASP CRS rule files were found on this server, so there are no '
                . 'categories to report. Install the WAF from this page and they will appear.');
        }

        $files = glob($dir . '/rules/*.conf') ?: [];
        if (!$files) {
            return $this->noCategories(
                'The OWASP CRS directory ' . $dir . ' holds no rule files that could be read, '
                . 'so no category counts can be shown.', $dir);
        }
        sort($files);
        $files = array_slice($files, 0, $maxFiles);

        // Which rules has the operator switched off? Recorded by us, so it is
        // knowable -- and the panel showed no sign of it at all.
        $excluded = [];
        try {
            foreach (WAFExclusions::all() as $row) {
                $excluded[substr((string) $row['rule_id'], 0, 3)]
                    = ($excluded[substr((string) $row['rule_id'], 0, 3)] ?? 0) + 1;
            }
        } catch (Throwable $e) {
            // A missing table must not take the panel down; the counts simply
            // stay at zero and nothing claims otherwise.
            Logger::warn('Could not read WAF exclusions for the category panel: ' . $e->getMessage());
        }

        $byId = [];
        foreach ($files as $f) {
            $base = basename($f);
            if (!preg_match('/^(?:REQUEST|RESPONSE)-(\d{3})-(.+)\.conf$/', $base, $m)) { continue; }
            $size = @filesize($f);
            if ($size === false || $size > 4194304) { continue; }

            // Comment lines first: CRS ships example rules commented out, and
            // counting those would inflate every figure on the panel.
            $body = (string) preg_replace('/^[ \t]*#.*$/m', '',
                                          (string) @file_get_contents($f));
            $n = preg_match_all('/(?:^|[,"\s])id:[\'"]?\d+/m', $body);

            $id = $m[1];
            if (!isset($byId[$id])) {
                $byId[$id] = ['id' => $id, 'name' => $this->prettyCategory($m[2]),
                              'rules' => 0, 'files' => [], 'excluded' => (int) ($excluded[$id] ?? 0)];
            }
            $byId[$id]['rules'] += (int) $n;
            $byId[$id]['files'][] = $base;
        }

        if (!$byId) {
            return $this->noCategories(
                'The files in ' . $dir . '/rules are not named the way OWASP CRS names them, so '
                . 'no categories could be identified from them.', $dir);
        }

        ksort($byId);
        $ourConf = (string) @file_get_contents(
            WAFInstaller::confDir() . '/serverscrub-waf.conf');
        $loaded  = strpos($ourConf, $dir . '/rules/') !== false;

        $cats = [];
        foreach ($byId as $c) {
            $c['loaded'] = $loaded;
            $cats[] = $c;
        }

        return ['available'   => true,
                'reason'      => null,
                'crs_path'    => $dir,
                // From the SAME tree the counts were read from, not from a
                // second path that may hold a different ruleset.
                'crs_version' => WAFInstaller::crsVersion($dir),
                'loaded'      => $loaded,
                'categories'  => $cats];
    }

    /** One shape for every "we cannot tell you" answer, with the reason in it. */
    private function noCategories(string $reason, ?string $dir = null): array {
        return ['available'   => false,
                'reason'      => $reason,
                'crs_path'    => $dir,
                'crs_version' => null,
                'loaded'      => false,
                'categories'  => []];
    }

    /**
     * REQUEST-942-APPLICATION-ATTACK-SQLI -> "SQL Injection".
     *
     * Derived from the file name, which is also returned in `files` so the
     * operator can check the derivation rather than trust it.
     */
    private function prettyCategory(string $raw): string {
        $raw = (string) preg_replace('/^APPLICATION-ATTACK-/', '', $raw);
        $known = [
            'SQLI' => 'SQL Injection', 'XSS' => 'XSS', 'RCE' => 'Remote Code Execution',
            'LFI' => 'Local File Inclusion', 'RFI' => 'Remote File Inclusion',
            'PHP' => 'PHP', 'NODEJS' => 'Node.js', 'JAVA' => 'Java', 'DOS' => 'DoS',
            'IP' => 'IP', 'CRS' => 'CRS', 'HTTP' => 'HTTP', 'MSSQL' => 'MSSQL',
        ];
        $out = [];
        foreach (explode('-', $raw) as $w) {
            if ($w === '') { continue; }
            $out[] = $known[strtoupper($w)] ?? ucfirst(strtolower($w));
        }
        return implode(' ', $out);
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
     * Show what the parser makes of the log on THIS server.
     *
     * The address parsing has now been wrong twice, each time because the
     * audit log on the target server was not laid out the way the code
     * assumed. Guessing again is not a plan: this reads the real file and
     * reports, side by side, the raw section-A lines and what was extracted
     * from them.
     *
     * @param int $limit how many entries to sample
     */
    public function parseTest(int $limit = 5): array
    {
        $path = self::auditLogPath();
        if ($path === null) {
            return ['ok' => false, 'error' => 'No ModSecurity audit log found',
                    'candidates' => self::auditLogCandidates()];
        }

        $handle = @fopen($path, 'r');
        if ($handle === false) {
            return ['ok' => false, 'error' => 'Cannot read ' . $path];
        }

        // Sample from the END: the beginning of a long-lived log is the least
        // interesting part and may predate the current configuration.
        $size = (int) @filesize($path);
        $tail = 256 * 1024;
        if ($size > $tail) { @fseek($handle, $size - $tail); @fgets($handle); }

        $samples = [];
        $pending = null;

        while (($line = fgets($handle)) !== false && count($samples) < $limit) {
            $line = rtrim($line, "\r\n");

            // The line after an -A-- boundary is the one carrying addresses.
            if (preg_match('/^--\S+-A--/', $line)) { $pending = true; continue; }
            if ($pending !== true) { continue; }
            $pending = null;

            $ips = [];
            if (preg_match('/^\[[^\]]+\]\s+(.*)$/', $line, $m)) {
                foreach (preg_split('/\s+/', trim($m[1])) as $tok) {
                    if (filter_var($tok, FILTER_VALIDATE_IP) !== false) { $ips[] = $tok; }
                }
            }
            $samples[] = [
                'raw'        => mb_substr($line, 0, 300),
                'client_ip'  => $ips[0] ?? null,
                'server_ip'  => $ips[1] ?? null,
                'matched'    => !empty($ips),
            ];
        }
        fclose($handle);

        $withIp = 0;
        foreach ($samples as $x) { if ($x['matched']) { $withIp++; } }

        return [
            'ok'          => true,
            'log_path'    => $path,
            'log_size'    => $size,
            'sampled'     => count($samples),
            'with_ip'     => $withIp,
            'samples'     => $samples,
            'stored_blank'=> (int) (Database::fetchOne(
                "SELECT COUNT(*) c FROM waf_events WHERE ip_address IS NULL OR ip_address=''"
            )['c'] ?? 0),
            'stored_total'=> (int) (Database::fetchOne(
                'SELECT COUNT(*) c FROM waf_events')['c'] ?? 0),
        ];
    }

    /**
     * Read the log again from the beginning.
     *
     * Events already stored keep whatever was parsed when they were ingested,
     * so a parser fix does nothing for them -- the offset has long since moved
     * past. This rewinds it. Clearing first is offered because re-reading
     * without it produces a second copy of everything older than the 60-second
     * dedup window.
     */
    public function reingest(bool $clearExisting = false): array
    {
        if ($clearExisting) {
            Database::query('DELETE FROM waf_events');
        }
        Database::setSetting('waf_ingest_offset', '0');
        $n = $this->ingestModSecLog();
        Logger::info('WAF: re-ingested from the start, ' . $n . ' event(s)'
                   . ($clearExisting ? ' (existing cleared)' : ''));
        return ['success' => true, 'ingested' => $n, 'cleared' => $clearExisting];
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

        // Same reason as BruteForce::collect(): a cached size equals the
        // stored offset and the ingest decides the log has not grown.
        clearstatcache(true, $path);
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

        // Offset of the end of the last COMPLETE entry. Only that is committed,
        // so an entry still being written is read again next time rather than
        // half-parsed and then skipped for ever.
        $safeOffset = $offset;

        while (($line = fgets($handle)) !== false) {
            // -Z-- terminates a transaction. Saving here, rather than when the
            // NEXT entry begins, is what makes the most recent event appear:
            // the old code only ever flushed an entry upon meeting the one
            // after it, so the newest was never stored -- and because the read
            // offset still advanced to the end of the file, it was never seen
            // again either. On a quiet server that is every event.
            if (preg_match('/^--\S+-Z--/', $line)) {
                if (!empty($entry)) {
                    $this->saveWafEvent($entry);
                    $count++;
                }
                $entry = [];
                $safeOffset = ftell($handle);
                continue;
            }

            if (preg_match('/^--\S+-A--/', $line)) {
                // A new entry beginning without a -Z-- before it means the
                // previous one was truncated. Keep what was parsed: a partial
                // event is still a recorded attack, and dropping it silently
                // would be worse.
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

                // The disruptive action is in the Message line's own preamble:
                // "Access denied with code 403", "Warning." and so on. One
                // transaction can carry several Message lines, and what the
                // operator needs is the strongest -- a request denied by rule
                // two was denied, whatever rule one merely warned about.
                $entry['action'] = self::strongerAction(
                    $entry['action'] ?? null, self::actionFromMessage($m[1]));
            } elseif (preg_match('/^Action:\s*Intercepted/i', $line)) {
                // Section H states it outright when present.
                $entry['action'] = 'blocked';
            } elseif (preg_match('/^Engine-Mode:\s*"?DETECTION_ONLY/i', $line)) {
                // Decisive in the other direction: in DetectionOnly nothing is
                // blocked, whatever an individual rule's message claims.
                $entry['action'] = 'detected';
            } elseif (preg_match('/^\[[^\]]+\]\s+(.*)$/', $line, $m)) {
                // ModSecurity section A, which carries the addresses.
                //
                // Parsed by looking for IP-shaped tokens rather than by
                // counting fields, because the number of fields varies. With
                // mod_unique_id the line is
                //     [time] uniqueId clientIp clientPort serverIp serverPort
                // and without it the id is simply absent. The previous two
                // attempts here were both positional: the first looked for an
                // address straight after the bracket (where the id is, when
                // there is one) and matched nothing at all; the second assumed
                // the id was always present and missed every server that does
                // not load mod_unique_id. Taking the first token that actually
                // validates as an IP is true for both layouts, and for IPv6.
                $ips = [];
                foreach (preg_split('/\s+/', trim($m[1])) as $tok) {
                    if (filter_var($tok, FILTER_VALIDATE_IP) !== false) {
                        $ips[] = $tok;
                    }
                }
                if ($ips) {
                    $entry['ip_address'] = $ips[0];
                    if (isset($ips[1])) { $entry['server_ip'] = $ips[1]; }
                }
            } elseif (preg_match('/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT) (.+) HTTP/', $line, $m)) {
                $entry['method'] = $m[1];
                $entry['uri']    = $m[2];
            } elseif (preg_match('/^Host:\s*(.+)/i', $line, $m)) {
                $entry['host'] = trim($m[1]);
            } elseif (preg_match('/^User-Agent:\s*(.+)/i', $line, $m)) {
                // The table has had a user_agent column all along and nothing
                // ever filled it.
                $entry['user_agent'] = trim($m[1]);
            } elseif (preg_match('/^X-Forwarded-For:\s*(.+)/i', $line, $m)) {
                // WHERE THE CLIENT ACTUALLY IS.
                //
                // Section A carries the CONNECTION address, and on an account
                // with cPanel's nginx caching enabled the connection comes
                // from nginx -- so the attacker was recorded as 127.0.0.1 or
                // as the server's own address. On a live server that put the
                // machine itself at the top of its own attacker list with
                // 1,780 hits, and loopback fourth with 848, every one of them
                // a real .env and proc/self/environ probe with no source.
                //
                // mod_remoteip is configured correctly and is not at fault:
                // cPanel points it at a secret-suffixed header name, nginx
                // sends the plain one, and it rightly ignores an unsigned
                // X-Forwarded-For. But ModSecurity's section A is written from
                // the connection either way, so the header is the only place
                // the address survives into the audit log.
                $entry['xff'] = trim($m[1]);
            } elseif (preg_match('/^CF-Connecting-IP:\s*(.+)/i', $line, $m)) {
                $entry['cf_ip'] = trim($m[1]);
            }
        }
        // Commit only as far as the last terminated entry. Anything after it
        // is still being written, and will be read in full next time.
        $newOffset = $safeOffset;
        fclose($handle);

        Database::setSetting('waf_ingest_offset', (string) (int) $newOffset);
        Database::setSetting('waf_ingest_last_run', (string) time());
        Database::setSetting('waf_ingest_last_count', (string) $count);
        if ($count > 0) {
            Logger::info("WAF: ingested {$count} ModSecurity event(s) from {$path}");
        }

        return $count;
    }

    /**
     * The disruptive action named in a ModSecurity Message line.
     *
     * 'blocked'  the request did not reach the site;
     * 'detected' the rule matched and the request was served anyway;
     * 'unknown'  the line says nothing either way, which is NOT 'blocked'.
     *
     * The third is the point. Guessing "blocked" from silence is how a column
     * that is supposed to say whether you were protected comes to say so
     * regardless.
     */
    public static function actionFromMessage(string $msg): string
    {
        if (preg_match('/\bAccess denied\b|\bIntercepted\b/i', $msg))  { return 'blocked'; }
        if (preg_match('/\bAccess dropped\b|\baction: drop\b/i', $msg)) { return 'dropped'; }
        if (preg_match('/\bredirect(ed)?\s+to\b/i', $msg))              { return 'redirected'; }
        // "Warning." is ModSecurity's word for "matched, allowed through".
        if (preg_match('/\bWarning\b|\bPattern match\b|\bMatched\b/i', $msg)) { return 'detected'; }
        return 'unknown';
    }

    /** Rank of certainty that the request was stopped. */
    private const ACTION_RANK = [
        'unknown'    => 0,
        'detected'   => 1,
        'redirected' => 2,
        'dropped'    => 3,
        'blocked'    => 4,
    ];

    /**
     * The more consequential of two actions for one transaction.
     *
     * A transaction with five Message lines, four warnings and one denial, was
     * blocked. Taking the last one seen would report it by whichever rule
     * happened to be written last.
     */
    public static function strongerAction(?string $a, ?string $b): string
    {
        $a = $a ?: 'unknown';
        $b = $b ?: 'unknown';
        $ra = self::ACTION_RANK[$a] ?? 0;
        $rb = self::ACTION_RANK[$b] ?? 0;
        return $rb > $ra ? $b : $a;
    }

    /**
     * Cloudflare's published edge ranges, as cPanel already writes them into
     * /etc/apache2/conf.d/includes/cloudflare.conf. Used only to decide
     * whether a CF-Connecting-IP header arrived from Cloudflare and can
     * therefore be believed.
     */
    private const CF_RANGES = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
        '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
        '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
        '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    /** A routable address: not loopback, not RFC1918, not link-local. */
    public static function isPublicIp(string $ip): bool
    {
        return $ip !== '' && filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    /** Is $ip inside $cidr? Handles v4 and v6 by comparing packed bits. */
    public static function cidrMatch(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) { return false; }
        $net  = @inet_pton($parts[0]);
        $addr = @inet_pton($ip);
        if ($net === false || $addr === false) { return false; }
        if (strlen($net) !== strlen($addr)) { return false; }  // v4 vs v6

        $bits  = (int) $parts[1];
        $whole = intdiv($bits, 8);
        $rest  = $bits % 8;

        if ($whole > 0 && strncmp($net, $addr, $whole) !== 0) { return false; }
        if ($rest === 0) { return true; }
        $mask = 0xFF << (8 - $rest) & 0xFF;
        return (ord($net[$whole]) & $mask) === (ord($addr[$whole]) & $mask);
    }

    private static function isCloudflare(string $ip): bool
    {
        foreach (self::CF_RANGES as $r) {
            if (self::cidrMatch($ip, $r)) { return true; }
        }
        return false;
    }

    /**
     * Is this address a proxy standing in front of us, rather than a client?
     *
     * Loopback and RFC1918 are obvious. The server's OWN address is the one
     * that caught us out: nginx on this server proxies to Apache over the
     * public interface for some vhosts, so the connection address was
     * 51.68.163.24 -- the machine itself -- and it was duly filed as the
     * busiest attacker on the server.
     *
     * Section A gives us the server address for that very connection, so the
     * comparison needs no configuration to read and no list to maintain.
     */
    public static function isProxyAddress(string $ip, string $serverIp = ''): bool
    {
        if ($ip === '') { return true; }
        if (!self::isPublicIp($ip)) { return true; }
        return $serverIp !== '' && $ip === $serverIp;
    }

    /** X-Forwarded-For as a list, left (furthest) to right (nearest). */
    public static function forwardedChain(string $header): array
    {
        if (trim($header) === '') { return []; }
        $out = [];
        foreach (explode(',', $header) as $tok) {
            $tok = trim($tok);
            // Strip a :port or [v6]:port suffix if one is present.
            if (preg_match('/^\[(.+)\](?::\d+)?$/', $tok, $m)) { $tok = $m[1]; }
            elseif (substr_count($tok, ':') === 1) { $tok = explode(':', $tok)[0]; }
            if (filter_var($tok, FILTER_VALIDATE_IP) !== false) { $out[] = $tok; }
        }
        return $out;
    }

    /**
     * Who actually made the request.
     *
     * @return array{ip:string,source:string,chain:string}
     *
     * THE RIGHTMOST hop in X-Forwarded-For, not the leftmost. nginx builds the
     * header with $proxy_add_x_forwarded_for, which APPENDS the address it saw
     * to whatever the client sent -- so the left of the chain is attacker
     * controlled and the right-hand entry is the one our own proxy wrote. A
     * scanner that sends "X-Forwarded-For: 8.8.8.8" would otherwise have us
     * record, report and potentially firewall Google.
     *
     * Only consulted when section A gave a proxy address. A request that
     * reached Apache directly already has a trustworthy source, and a header
     * on that request is purely the client's claim.
     */
    public static function resolveClientIp(array $e): array
    {
        $a     = trim((string) ($e['ip_address'] ?? ''));
        $chain = self::forwardedChain((string) ($e['xff'] ?? ''));
        $cf    = trim((string) ($e['cf_ip'] ?? ''));
        $joined = implode(', ', $chain);

        if (!self::isProxyAddress($a, (string) ($e['server_ip'] ?? ''))) {
            return ['ip' => $a, 'source' => 'direct', 'chain' => $joined];
        }

        $hop = '';
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            if (self::isPublicIp($chain[$i])) { $hop = $chain[$i]; break; }
        }

        // Cloudflare overwrites CF-Connecting-IP with the visitor address, so
        // for a site behind Cloudflare it is better than the chain -- whose
        // nearest hop is a Cloudflare edge, not the visitor. Believed when the
        // nearest hop IS Cloudflare, which corroborates it. Accepted without
        // that corroboration only when there is no chain at all, and labelled
        // so an operator can see which rows rest on it.
        if ($cf !== '' && self::isPublicIp($cf) && ($hop === '' || self::isCloudflare($hop))) {
            return [
                'ip'     => $cf,
                'source' => $hop === '' ? 'cf-connecting-ip-uncorroborated' : 'cf-connecting-ip',
                'chain'  => $joined,
            ];
        }

        if ($hop !== '') {
            return ['ip' => $hop, 'source' => 'x-forwarded-for', 'chain' => $joined];
        }

        // A proxy address and nothing to replace it with. Kept as it is and
        // named, rather than guessed at: an unattributable event is a fact
        // about the log, and inventing a source would be worse than saying so.
        return ['ip' => $a, 'source' => 'proxy-unresolved', 'chain' => $joined];
    }

    private function saveWafEvent(array $e): void {
        if (empty($e['rule_id']) && empty($e['ip_address'])) return;

        // Resolved BEFORE the duplicate check, or the 60-second window groups
        // by proxy address and collapses unrelated attackers arriving through
        // the same nginx into one another.
        $who = self::resolveClientIp($e);

        // Deduplicate: skip if same rule+IP in last 60s
        $exists = Database::fetchOne(
            "SELECT id FROM waf_events WHERE rule_id=? AND ip_address=? AND timestamp > ?",
            [$e['rule_id'] ?? '', $who['ip'], time() - 60]
        );
        if ($exists) return;

        Database::insert('waf_events', [
            'rule_id'    => $e['rule_id']    ?? '',
            'rule_msg'   => $e['rule_msg']   ?? '',
            'severity'   => $e['severity']   ?? 'medium',
            'ip_address' => $who['ip'],
            'uri'        => $e['uri']        ?? '',
            'method'     => $e['method']     ?? '',
            'host'       => $e['host']       ?? '',
            'user_agent' => mb_substr((string)($e['user_agent'] ?? ''), 0, 512),
            // WHAT HAPPENED, not what we assume happened. This was the literal
            // string 'block' for every row ever written, while the detail
            // dialog displayed it as fact. On a server running the engine in
            // DetectionOnly -- a mode this product offers and sets -- every
            // one of those rows claimed a request had been blocked when it had
            // been waved through. A security product inventing the one field
            // that says whether it protected you is the worst row it can hold.
            'action'     => (string) ($e['action'] ?? 'unknown'),
            // Kept so the attribution can be audited rather than trusted. An
            // operator about to firewall an address can see whether it came
            // from the connection, from a header, or not at all.
            'ip_source'  => $who['source'],
            'forwarded_for' => mb_substr($who['chain'], 0, 256),
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

    /**
     * Where the custom rules Apache loads are written.
     *
     * Overridable so this write path can be exercised without writing into
     * /etc on a developer's machine. It had never been run anywhere: the
     * method appended an unvalidated rule to a file Apache loads and then
     * restarted Apache, which is the 7 Nov outage in a path the rollback fix
     * never touched.
     */
    private static $customRulesPath = null;

    public static function setCustomRulesPath(?string $p): void { self::$customRulesPath = $p; }

    public static function customRulesPath(): string
    {
        return self::$customRulesPath ?? MODSEC_CONF . '/serverscrub/custom_rules.conf';
    }

    /**
     * Is this rule id already defined by something the product writes?
     *
     * Bands keep the two generators apart (see the id map in WAFExclusions),
     * and this is the check that holds anyway. A duplicate id is not a
     * warning: Apache answers "ModSecurity: Found another rule with the same
     * id" and refuses the WHOLE configuration, which on 7 Nov was 132
     * accounts at 502 for ten hours. It was reproduced by planting a custom
     * rule at id:15001 -- the id the exclusion generator had already used.
     *
     * CRS itself is not scanned: it owns 900,000+ and the custom band is
     * 20,000-29,999, so there is nothing there to collide with, and reading
     * ~35 rule files on every add would not be free.
     *
     * @return string|null a description of where it is already used
     */
    public function ruleIdInUse(int $id): ?string
    {
        if (in_array($id, WAFExclusions::generatedIds(), true)) {
            return 'a generated WAF rule exclusion';
        }
        $files = [
            self::customRulesPath() => 'the custom rules file',
            WAFInstaller::confDir() . '/serverscrub-waf.conf' => 'our own WAF config',
        ];
        foreach ($files as $f => $what) {
            if (!is_file($f)) { continue; }
            $body = (string) preg_replace('/^[ \t]*#.*$/m', '', (string) @file_get_contents($f));
            if (preg_match('/(?:^|[,"\s])id:[\'"]?' . $id . '\b/m', $body)) {
                return $what . ' (' . $f . ')';
            }
        }
        return null;
    }

    /**
     * Add one custom ModSecurity rule.
     *
     * -- WHAT THIS USED TO DO -------------------------------------------------
     *
     * It appended the rule to a file Apache loads, ran `service httpd
     * graceful`, and returned ['success' => true] unconditionally. No syntax
     * check, the return of neither the write nor the restart examined, and any
     * string accepted as the id -- while the API defaults the id to
     * uniqid('SG'), so the ordinary call wrote `id:SG6910abc12def3`, which is
     * a ModSecurity syntax error, into a live config and then restarted
     * Apache. One API call could take every site on the server down at the
     * next restart and report that it had worked.
     *
     * So, in order: the id must be digits and inside the band reserved for
     * custom rules; it must not already be in use; the pattern must be
     * something that can be rendered into a quoted directive at all; the file
     * is snapshotted before it is touched; `apachectl -t` runs BEFORE any
     * reload; a rejection is rolled back and the rollback is verified; and the
     * result says what happened rather than that it succeeded.
     *
     * @param string $id      numeric, WAFExclusions::CUSTOM_ID_MIN..CUSTOM_ID_MAX
     * @param string $pattern a regex for @rx
     * @param string $action  'block' (deny 403) or 'log' (log only)
     */
    public function addCustomRule(string $id, string $pattern, string $action = 'block'): array {
        $id      = trim($id);
        $pattern = trim($pattern);
        $action  = strtolower(trim($action));

        // -- The id ----------------------------------------------------------
        if (!preg_match('/^[0-9]{1,9}$/', $id)) {
            return ['success' => false,
                    'error'   => 'A ModSecurity rule id must be digits only, and "' . $id
                               . '" is not. ModSecurity rejects a non-numeric id as a syntax '
                               . 'error, which stops Apache starting.'];
        }
        $n = (int) $id;
        if ($n < WAFExclusions::CUSTOM_ID_MIN || $n > WAFExclusions::CUSTOM_ID_MAX) {
            return ['success' => false,
                    'error'   => 'Custom rule ids must be between ' . WAFExclusions::CUSTOM_ID_MIN
                               . ' and ' . WAFExclusions::CUSTOM_ID_MAX . '. '
                               . WAFExclusions::ID_BASE . '-' . WAFExclusions::ID_CEIL
                               . ' is reserved for generated rule exclusions and 900000+ for '
                               . 'OWASP CRS; reusing an id from either is the duplicate-id '
                               . 'failure that stops Apache starting.'];
        }
        $clash = $this->ruleIdInUse($n);
        if ($clash !== null) {
            return ['success' => false,
                    'error'   => 'Rule id ' . $n . ' is already used by ' . $clash
                               . '. Apache refuses the whole configuration when one id is '
                               . 'defined twice ("Found another rule with the same id").'];
        }

        // -- The pattern -----------------------------------------------------
        if ($pattern === '') {
            return ['success' => false, 'error' => 'A rule needs a pattern to match'];
        }
        if (strlen($pattern) > 512) {
            return ['success' => false, 'error' => 'The pattern is longer than 512 characters'];
        }
        /* Rejected rather than escaped. addslashes() was all that stood
         * between a pattern and the quoted directive it is interpolated into,
         * and a double quote or a newline in it ends that directive and starts
         * something Apache cannot parse. */
        if (strpbrk($pattern, "\"\\\r\n") !== false) {
            return ['success' => false,
                    'error'   => 'The pattern contains a quote, backslash or newline. Those end '
                               . 'the quoted ModSecurity directive, so the rule cannot be '
                               . 'written safely.'];
        }
        if (@preg_match('/' . str_replace('/', '\\/', $pattern) . '/', '') === false) {
            return ['success' => false,
                    'error'   => 'The pattern is not a valid regular expression, so ModSecurity '
                               . 'would reject the rule'];
        }

        // -- The action ------------------------------------------------------
        /* $action was accepted and then ignored: every rule was `deny`,
         * whatever the caller asked for. An operator who asked to log and got
         * blocking hears about it from their customers. */
        $actions = ['block' => 'deny,status:403', 'log' => 'pass,log'];
        if (!isset($actions[$action])) {
            return ['success' => false,
                    'error'   => 'Unknown action "' . $action . '". Use block or log.'];
        }

        $confPath = self::customRulesPath();
        $dir      = dirname($confPath);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            return ['success' => false, 'error' => 'Could not create ' . $dir];
        }

        $rule = sprintf(
            'SecRule REQUEST_URI|ARGS|REQUEST_HEADERS "@rx %s" '
            . '"id:%d,phase:2,%s,msg:\'ServerScrub-Custom\',log,auditlog"' . "\n",
            $pattern, $n, $actions[$action]
        );

        // Snapshotted BEFORE the write, and null means "there was no file" --
        // restoring that to an empty file is not the same thing to Apache.
        $snap = [$confPath => is_file($confPath) ? (string) @file_get_contents($confPath) : null];
        $want = ($snap[$confPath] === null ? '' : $snap[$confPath]) . $rule;

        /* Written whole rather than appended, so a short write -- what a full
         * filesystem gives you instead of an error -- is detectable, and so
         * the rollback is an exact byte-for-byte restore. */
        $wrote = @file_put_contents($confPath, $want);
        if ($wrote === false || $wrote !== strlen($want)) {
            $rb = WAFInstaller::restoreConfig($snap);
            return ['success' => false, 'rolled_back' => $rb['ok'],
                    'error'   => 'Could not write ' . $confPath
                               . ($wrote === false
                                    ? ' at all'
                                    : ' completely: ' . $wrote . ' of ' . strlen($want)
                                      . ' bytes, which is what a full filesystem does instead '
                                      . 'of reporting an error')
                               . ($rb['ok'] ? '. The file was put back as it was.'
                                            : '. ' . $this->restoreFailed($confPath))];
        }
        @chmod($confPath, 0644);

        // -- Validate BEFORE anything reloads --------------------------------
        $v = WAFInstaller::validateApache();
        if (!$v['ok']) {
            $rb   = WAFInstaller::restoreConfig($snap);
            $why  = $v['ran']
                ? 'Apache rejected the rule: ' . $v['output']
                : 'No Apache syntax check could be run on this server, so the rule was not '
                  . 'applied -- Apache has said nothing about it either way: ' . $v['output'];
            $note = $rb['ok']
                ? ' The file was put back exactly as it was and nothing was reloaded.'
                : ' ' . $this->restoreFailed($confPath);
            Logger::warn('Custom WAF rule ' . $n . ' not applied: ' . $why);
            return ['success' => false, 'rolled_back' => $rb['ok'], 'error' => $why . $note];
        }

        $reloaded = WAFInstaller::reloadApache();
        Logger::info('Custom WAF rule ' . $n . ' added (' . $action . ') and validated with '
                     . (string) $v['binary']);

        return ['success'      => true,
                'id'           => $n,
                'action'       => $action,
                'path'         => $confPath,
                'validated_by' => $v['binary'],
                // A rule on disk that Apache has not re-read is not filtering
                // anything yet, and saying "added" without saying that is the
                // same class of claim as the rest of this method's history.
                'live'         => $reloaded,
                'note'         => $reloaded
                    ? null
                    : 'The rule is valid and saved, but Apache could not be reloaded, so it is '
                      . 'not filtering requests yet. It will take effect at the next reload.'];
    }

    /**
     * Make a custom-rules file that could not be put back harmless, and say so.
     *
     * A rule Apache has already refused, in a file Apache loads, that we
     * cannot remove, is the outage waiting for the next restart. Older
     * installs registered this file with `Include` rather than
     * `IncludeOptional` (install.sh now writes IncludeOptional), so deleting
     * it could itself stop Apache -- it is emptied down to a comment instead,
     * which satisfies either form of include and contains no rules.
     */
    private function restoreFailed(string $confPath): string
    {
        $blank = "# ServerScrub custom rules - emptied after a rollback that failed.\n";
        @chmod($confPath, 0644);
        $n = @file_put_contents($confPath, $blank);
        clearstatcache(true, $confPath);
        $emptied = $n === strlen($blank) && (string) @file_get_contents($confPath) === $blank;

        if ($emptied) {
            Logger::error('Custom WAF rules file could not be restored and was emptied: ' . $confPath);
            return 'The previous contents could NOT be put back, so the file was emptied instead: '
                 . 'any custom rules it held are gone, but Apache will still start. Re-add them '
                 . 'once the cause is fixed.';
        }

        Logger::error('EMERGENCY: invalid custom WAF rule left on disk at ' . $confPath);
        return 'EMERGENCY: the previous contents could not be put back and the file could not be '
             . 'emptied either, so a rule Apache has already refused is STILL ON DISK at '
             . $confPath . '. Apache is running on the configuration it parsed at its last start, '
             . 'so nothing will look wrong until it is next restarted -- and then it will refuse '
             . 'to start and take every site on this server with it. Move that file aside BY '
             . 'HAND, now.';
    }

}
