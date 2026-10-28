<?php
/**
 * ServerScrub — Firewall Module
 * Wraps CSF (ConfigServer Firewall) and iptables
 */

class Firewall {

    public function isCSFInstalled(): bool {
        return file_exists(CSF_BIN);
    }

    // ── IP Management ─────────────────────────────────────────────────────────

    public function blockIP(string $ip, string $reason = '', bool $permanent = false,
                           int $ttl = 86400, bool $force = false): array {
        $this->validateIP($ip);

        // A shared proxy is not a visitor.
        //
        // Two Cloudflare edge addresses reached csf.deny on a live server
        // because a site behind Cloudflare logs the EDGE as its client, so a
        // few hundred failed logins through one edge looked like one attacker.
        // Blocking it stops nothing -- the attacker returns through another of
        // thousands of edges -- and drops every genuine visitor routed that
        // way, invisibly, because those requests never reach this server.
        //
        // This sits in blockIP() rather than in each detector because every
        // block in the product comes through here: brute force, HTTP flood,
        // the API and the CLI. A guard that each caller has to remember is a
        // guard that the next caller will not have.
        require_once __DIR__ . '/ProxyRanges.php';
        $proxy = ProxyRanges::nameFor($ip);
        if ($proxy !== null && !$force) {
            // Kept under 200 characters on purpose: brute_force_offenders
            // truncates block_error to that, and a remedy cut off mid-sentence
            // is not a remedy.
            $why = $ip . ' is a ' . $proxy . ' proxy address, not a visitor. '
                 . 'Blocking it drops real visitors and stops nothing. Log the '
                 . 'real client (mod_remoteip / CF-Connecting-IP) to identify '
                 . 'the attacker.';
            Logger::warn('Firewall: declined to block ' . $ip . ' — ' . $proxy . ' proxy address');
            return ['success' => false, 'error' => $why, 'proxy' => $proxy,
                    'backend' => FirewallEngine::detect()];
        }

        // Delegate to the built-in engine. It picks the right backend
        // (CSF / firewalld / nftables / iptables), keeps our rules inside a
        // namespaced table so nothing else is disturbed, and persists them so a
        // reboot does not silently discard every block while the database keeps
        // reporting them as active.
        require_once __DIR__ . '/FirewallEngine.php';
        $res  = FirewallEngine::block($ip);
        $out  = [$res['output'] ?? ''];
        $code = ($res['success'] ?? false) ? 0 : 1;

        // Checked BEFORE the database is written.
        //
        // The row used to be inserted regardless, so a block the firewall
        // refused still appeared in the Firewall page's blocked list. The
        // panel then showed an address as blocked while packets from it were
        // arriving normally, which is the most expensive kind of wrong a
        // security tool can be.
        if ($code !== 0) {
            $why = trim((string) ($res['error'] ?? '')) ?: trim(implode("\n", $out));
            $why = $why !== '' ? $why : 'the firewall backend rejected it';
            Logger::error("Firewall: could not block {$ip} — {$why}");
            return ['success' => false, 'error' => $why,
                    'output' => implode("\n", $out),
                    'backend' => FirewallEngine::detect()];
        }

        // Record in DB
        $existing = Database::fetchOne("SELECT id FROM blocked_ips WHERE ip_address = ?", [$ip]);
        if ($existing) {
            Database::query(
                "UPDATE blocked_ips SET reason=?, permanent=?, blocked_at=?, expires_at=? WHERE ip_address=?",
                [$reason, (int)$permanent, time(), $permanent ? null : time() + $ttl, $ip]
            );
        } else {
            Database::insert('blocked_ips', [
                'ip_address' => $ip,
                'reason'     => $reason,
                'permanent'  => (int) $permanent,
                'blocked_at' => time(),
                'expires_at' => $permanent ? null : time() + $ttl,
                'source'     => 'manual',
            ]);
        }


        $this->logEvent('block_ip', "Blocked IP $ip — $reason");
        return ['success' => true, 'output' => implode("\n", $out),
                'backend' => FirewallEngine::detect()];
    }

    /**
     * Lift blocks whose term has ended.
     *
     * blockIP has always written expires_at, and until 4.2.0 nothing ever read
     * it: every "temporary" block was permanent at the firewall while the
     * database cheerfully reported a deadline. That is the worse of the two
     * failure modes -- an operator who believes a block is temporary does not
     * go looking for the customer it is silently holding out -- and it also
     * made escalation impossible, since an address that is never released can
     * never re-offend.
     *
     * Permanent blocks (expires_at NULL) are never touched.
     */
    public static function expireBlocks(): array
    {
        $now  = time();
        $due  = Database::fetchAll(
            "SELECT ip_address FROM blocked_ips
              WHERE permanent = 0
                AND expires_at IS NOT NULL
                AND expires_at > 0
                AND expires_at <= CAST(? AS INTEGER)",
            [$now]
        );

        $fw       = new self();
        $released = 0;
        $failed   = 0;
        foreach ($due as $r) {
            $ip = (string) $r['ip_address'];
            $res = $fw->unblockIP($ip);
            if (!empty($res['success'])) {
                $released++;
            } else {
                // Left in place deliberately: the row still says blocked, so
                // the next run tries again rather than the database claiming a
                // release the firewall never performed.
                $failed++;
            }
        }

        if ($released > 0) {
            Logger::info("Firewall: released {$released} expired block(s)");
        }
        return ['released' => $released, 'failed' => $failed, 'due' => count($due)];
    }

    public function unblockIP(string $ip): array {
        $this->validateIP($ip);

        require_once __DIR__ . '/FirewallEngine.php';
        $res  = FirewallEngine::unblock($ip);
        $out  = [$res['output'] ?? ''];
        $code = ($res['success'] ?? false) ? 0 : 1;

        Database::query("DELETE FROM blocked_ips WHERE ip_address = ?", [$ip]);
        $this->logEvent('unblock_ip', "Unblocked IP $ip");
        return ['success' => true, 'output' => implode("\n", $out)];
    }

    public function allowIP(string $ip, string $comment = ''): array {
        $this->validateIP($ip);

        require_once __DIR__ . '/FirewallEngine.php';
        $res  = FirewallEngine::allow($ip);
        $out  = [$res['output'] ?? ''];
        $code = ($res['success'] ?? false) ? 0 : 1;

        return ['success' => $code === 0, 'output' => implode("\n", $out)];
    }

    public function getBlockedIPs(int $limit = 100, int $offset = 0): array {
        return Database::fetchAll(
            "SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT ? OFFSET ?",
            [$limit, $offset]
        );
    }

    // ── Rule Management ───────────────────────────────────────────────────────

    /** 100 per page by default; 500 is as far as a browser should be pushed. */
    public const RULES_MIN_PAGE = 25;
    public const RULES_MAX_PAGE = 500;

    /**
     * One page of rules, WITH the total.
     *
     * This returned every row. On a live server that was 343,000 rules, and
     * the panel turned all of them into table markup in one assignment — which
     * is not slow, it is fatal: the tab stops responding long before the
     * request finishes.
     *
     * Nothing needs all of them at once. An operator wants the rule they are
     * looking for, which is what the search is for, or the first page.
     *
     * @return array{items:array,total:int,limit:int,offset:int,search:string}
     */
    public function getRules(int $limit = 100, int $offset = 0, string $search = ''): array {
        $limit  = max(self::RULES_MIN_PAGE, min(self::RULES_MAX_PAGE, $limit));
        $offset = max(0, $offset);
        $search = trim($search);

        $where  = '';
        $params = [];
        if ($search !== '') {
            // Name, port and address are what somebody actually searches a
            // firewall by.
            $where = "WHERE name LIKE ? OR port LIKE ? OR source_ip LIKE ?
                         OR dest_ip LIKE ? OR protocol LIKE ?";
            $like  = '%' . $search . '%';
            $params = [$like, $like, $like, $like, $like];
        }

        $total = (int) (Database::fetchOne(
            "SELECT COUNT(*) AS c FROM firewall_rules $where", $params)['c'] ?? 0);

        $rows = Database::fetchAll(
            "SELECT * FROM firewall_rules $where
              ORDER BY priority ASC, id ASC
              LIMIT ? OFFSET ?",
            array_merge($params, [$limit, $offset])
        ) ?: [];

        return ['items' => $rows, 'total' => $total, 'limit' => $limit,
                'offset' => $offset, 'search' => $search];
    }

    public function addRule(array $data): array {
        $required = ['name', 'direction', 'action'];
        foreach ($required as $f) {
            if (empty($data[$f])) return ['success' => false, 'error' => "Missing field: $f"];
        }

        // firewall_rules now carries a unique index on the rule identity, so a
        // plain insert of a rule that already exists raises a constraint error
        // rather than silently adding a second copy. Adding the same rule twice
        // is a no-op from the operator's side, so say so and hand back the rule
        // they already have instead of a 500.
        $existing = Database::fetchOne(
            "SELECT id FROM firewall_rules
              WHERE name = ? AND direction = ? AND COALESCE(protocol,'') = ?
                AND COALESCE(port,'') = ? AND COALESCE(source_ip,'') = ?
                AND COALESCE(dest_ip,'') = ? AND action = ?",
            [
                $data['name'],
                $data['direction'],
                (string)($data['protocol'] ?? 'tcp'),
                (string)($data['port'] ?? ''),
                (string)($data['source_ip'] ?? ''),
                (string)($data['dest_ip'] ?? ''),
                strtoupper($data['action']),
            ]
        );
        if ($existing) {
            return ['success' => true, 'id' => (int)$existing['id'],
                    'duplicate' => true,
                    'message' => 'That rule already exists.'];
        }

        $id = Database::insert('firewall_rules', [
            'name'      => $data['name'],
            'direction' => $data['direction'],
            'protocol'  => $data['protocol'] ?? 'tcp',
            'port'      => $data['port'] ?? null,
            'source_ip' => $data['source_ip'] ?? null,
            'dest_ip'   => $data['dest_ip'] ?? null,
            'action'    => strtoupper($data['action']),
            'enabled'   => 1,
            'priority'  => $data['priority'] ?? 100,
            'comment'   => $data['comment'] ?? '',
        ]);

        $this->applyRule(Database::fetchOne("SELECT * FROM firewall_rules WHERE id = ?", [$id]));
        return ['success' => true, 'id' => $id];
    }

    public function toggleRule(int $id, bool $enabled): array {
        Database::query("UPDATE firewall_rules SET enabled = ? WHERE id = ?", [(int)$enabled, $id]);
        $rule = Database::fetchOne("SELECT * FROM firewall_rules WHERE id = ?", [$id]);
        if ($rule) {
            $enabled ? $this->applyRule($rule) : $this->removeRule($rule);
        }
        return ['success' => true];
    }

    public function deleteRule(int $id): array {
        $rule = Database::fetchOne("SELECT * FROM firewall_rules WHERE id = ?", [$id]);
        if ($rule) $this->removeRule($rule);
        Database::query("DELETE FROM firewall_rules WHERE id = ?", [$id]);
        return ['success' => true];
    }

    private function applyRule(array $rule): void {
        if (!$rule['enabled']) return;
        $cmd = $this->buildIptablesCmd($rule, '-A');
        if ($cmd) exec($cmd . ' 2>/dev/null');
    }

    private function removeRule(array $rule): void {
        $cmd = $this->buildIptablesCmd($rule, '-D');
        if ($cmd) exec($cmd . ' 2>/dev/null');
    }

    private function buildIptablesCmd(array $rule, string $op): ?string {
        $chain = match(strtolower($rule['direction'])) {
            'in'    => 'INPUT',
            'out'   => 'OUTPUT',
            'both'  => 'FORWARD',
            default => 'INPUT',
        };
        $proto = $rule['protocol'] ? "-p {$rule['protocol']}" : '';
        $port  = $rule['port']     ? "--dport {$rule['port']}" : '';
        $src   = $rule['source_ip'] ? "-s {$rule['source_ip']}" : '';

        $action = match(strtoupper($rule['action'])) {
            'ACCEPT' => 'ACCEPT',
            'DROP'   => 'DROP',
            'REJECT' => 'REJECT --reject-with icmp-host-prohibited',
            'LIMIT'  => 'ACCEPT',
            default  => 'DROP',
        };

        $limit = '';
        if ($rule['action'] === 'LIMIT') {
            $limit = '-m state --state NEW -m recent --set --name SG_RATE';
        }

        return trim(IPTABLES_BIN . " $op $chain $src $proto $port $limit -j $action");
    }

    // ── Port Scanner Detection ────────────────────────────────────────────────

    public function enablePortScanProtection(): array {
        $rules = [
            IPTABLES_BIN . " -N PORT_SCAN 2>/dev/null",
            IPTABLES_BIN . " -A PORT_SCAN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j RETURN",
            IPTABLES_BIN . " -A PORT_SCAN -j DROP",
            IPTABLES_BIN . " -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j PORT_SCAN",
            // NULL packets
            IPTABLES_BIN . " -A INPUT -p tcp --tcp-flags ALL NONE -j DROP",
            // XMAS packets
            IPTABLES_BIN . " -A INPUT -p tcp --tcp-flags ALL ALL -j DROP",
        ];
        foreach ($rules as $cmd) exec($cmd . ' 2>/dev/null');
        return ['success' => true];
    }

    // ── CSF Integration ───────────────────────────────────────────────────────

    public function getCSFStatus(): array {
        // Reads what the scheduler measured. Spawning pgrep and csf --version
        // here put two process launches on a page load.
        $csf = self::cachedOnly('csf_status', null);
        if ($csf !== null) { return $csf; }
        return ['installed' => file_exists(CSF_BIN), 'running' => null, 'version' => ''];
    }

    private function getCSFVersion(): string {
        // Cached for the request: the firewall page asks for stats more than
        // once, and forking csf to read a static version string each time is
        // pure latency.
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }
        $r = self::shBounded(escapeshellarg(CSF_BIN) . ' --version', 5);
        return $cached = ($r['out'][0] ?? 'unknown');
    }

    public function reloadFirewall(): array {
        if ($this->isCSFInstalled()) {
            exec(CSF_BIN . ' -r 2>&1', $out, $code);
        } else {
            exec('service iptables restart 2>&1', $out, $code);
        }
        return ['success' => $code === 0, 'output' => implode("\n", $out)];
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    /**
     * Run a command that must never hang the request.
     *
     * `iptables -L` takes the xtables lock. On a CSF server lfd rewrites rules
     * continuously, so that call can sit waiting for a lock somebody else
     * holds -- and cpsrvd serialises requests, so ONE stuck call stops the
     * whole dashboard responding, not just the firewall page. That is what
     * "the firewall page freezes the entire screen" was.
     *
     * Two belts: -w gives iptables a bounded wait for the lock instead of an
     * unbounded one, and timeout(1) bounds the whole command in case the
     * binary ignores -w or blocks somewhere else entirely.
     */
    private static function shBounded(string $cmd, int $seconds = 5): array
    {
        $out  = [];
        $code = 0;
        $wrapped = 'timeout ' . $seconds . ' ' . $cmd;
        @exec($wrapped . ' 2>/dev/null', $out, $code);
        // 124 is timeout(1)'s "it did not finish".
        return ['out' => $out, 'code' => $code, 'timed_out' => $code === 124];
    }

    /**
     * A value that costs a fork to obtain, remembered for a while.
     *
     * The firewall page asks for stats on every visit and every refresh. None
     * of these numbers change meaningfully within a minute, and paying several
     * process spawns -- one of which can block on a kernel lock -- for each
     * one is the difference between a page that loads and a page that hangs.
     */
    /**
     * A value produced by shelling out, read from cache and NEVER produced
     * here.
     *
     * This used to run $produce on a miss. That bounded the damage but did not
     * remove it: one request a minute still paid for an iptables call that can
     * sit on the xtables lock, and because cpsrvd serialises requests, that one
     * request stalls every other page too. "The firewall page is slow" survived
     * two attempts at fixing it for exactly this reason -- the work was still
     * on the path that has to be fast.
     *
     * The probing now happens in the scheduler, off the request entirely. A
     * missing value is reported as unknown rather than being fetched, because
     * a page that says "not measured yet" immediately is worth more than one
     * that is correct in nine seconds.
     */
    private static function cachedOnly(string $key, $default = null)
    {
        $raw = Database::setting('fwcache_' . $key, '');
        if ($raw === '' || $raw === null) { return $default; }
        $decoded = json_decode((string) $raw, true);
        return $decoded === null ? $default : $decoded;
    }

    /** How old the cached probes are, in seconds, or null if never taken. */
    public static function probeAge(): ?int
    {
        $at = (int) (Database::setting('fwcache_taken_at', '0') ?? 0);
        return $at > 0 ? max(0, time() - $at) : null;
    }

    /**
     * Take the measurements that cost a process spawn.
     *
     * Called from the scheduler, and once at install so the first page load
     * has something to show. Everything here is bounded twice over: -w gives
     * iptables a limited wait for the xtables lock instead of an unlimited
     * one, and timeout(1) bounds the command in case the binary ignores it.
     */
    public static function refreshProbes(): array
    {
        $r = self::shBounded(IPTABLES_BIN . ' -L INPUT -n -w 2 --line-numbers | wc -l');
        $ipt = $r['timed_out'] ? -1 : max(0, (int) ($r['out'][0] ?? 0) - 2);

        $csf = ['installed' => file_exists(CSF_BIN), 'running' => false, 'version' => ''];
        if ($csf['installed']) {
            $lfd = self::shBounded('pgrep lfd', 3);
            $csf['running'] = $lfd['code'] === 0;
            $v = self::shBounded(escapeshellarg(CSF_BIN) . ' --version', 5);
            $csf['version'] = $v['out'][0] ?? 'unknown';
        }

        Database::setSetting('fwcache_iptables_rules', (string) json_encode($ipt));
        Database::setSetting('fwcache_csf_status',     (string) json_encode($csf));
        Database::setSetting('fwcache_taken_at',       (string) time());

        return ['iptables_rules' => $ipt, 'csf_status' => $csf];
    }

    public function getStats(): array {
        // Three indexed counts. Nothing on this path spawns a process, opens a
        // socket or waits on a kernel lock, so the page cannot be slow because
        // of something else on the server.
        $blocked  = Database::fetchOne("SELECT COUNT(*) as c FROM blocked_ips")['c'];
        $rules    = Database::fetchOne("SELECT COUNT(*) as c FROM firewall_rules WHERE enabled=1")['c'];
        $today    = mktime(0, 0, 0);
        $todayBlk = Database::fetchOne(
            "SELECT COUNT(*) as c FROM blocked_ips WHERE blocked_at >= ?", [$today]
        )['c'];

        $ipt = self::cachedOnly('iptables_rules', null);
        $csf = self::cachedOnly('csf_status', null);

        return [
            'blocked_ips'   => (int) $blocked,
            'active_rules'  => (int) $rules,
            'blocked_today' => (int) $todayBlk,

            // -1 means the count timed out when it was taken; null means it has
            // not been taken yet. Reporting either as 0 would read as "no
            // firewall rules", which is a very different claim.
            'iptables_rules'   => $ipt === null ? 0 : (int) $ipt,
            'iptables_unknown' => $ipt === null || (int) $ipt < 0,
            'csf_status'       => $csf ?? ['installed' => file_exists(CSF_BIN),
                                           'running' => null, 'version' => ''],
            'probe_age'        => self::probeAge(),
            'probe_pending'    => $ipt === null,
        ];
    }

    // ── Geo Blocking ──────────────────────────────────────────────────────────

    public function setGeoBlock(array $countryCodes): array {
        Database::setSetting('geo_block_countries', implode(',', $countryCodes));

        if ($this->isCSFInstalled()) {
            // Write to CSF config CC_DENY
            $conf = file_get_contents(CSF_CONF);
            $cc   = implode(',', $countryCodes);
            $conf = preg_replace('/^CC_DENY\s*=.*/m', "CC_DENY = \"$cc\"", $conf);
            file_put_contents(CSF_CONF, $conf);
            exec(CSF_BIN . ' -r 2>/dev/null');
        }

        return ['success' => true, 'countries' => $countryCodes];
    }

    /**
     * A library must not end the request.
     *
     * This printed its own JSON and called exit(), which bypasses the router's
     * error envelope, skips its headers, and makes the method impossible to
     * test or to call from cron -- a validation failure would silently kill a
     * scheduled task mid-run. Throwing lets the router decide the status code
     * and keeps every caller's control flow intact.
     */
    private function validateIP(string $ip): void {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException('Invalid IP address');
        }
    }

    private function logEvent(string $type, string $msg): void {
        Database::insert('security_events', [
            'type'        => $type,
            'severity'    => 'info',
            'description' => $msg,
        ]);
    }
}
