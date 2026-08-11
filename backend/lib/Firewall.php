<?php
/**
 * Sentinel Gate — Firewall Module
 * Wraps CSF (ConfigServer Firewall) and iptables
 */

class Firewall {

    public function isCSFInstalled(): bool {
        return file_exists(CSF_BIN);
    }

    // ── IP Management ─────────────────────────────────────────────────────────

    public function blockIP(string $ip, string $reason = '', bool $permanent = false, int $ttl = 86400): array {
        $this->validateIP($ip);

        // Delegate to the built-in engine. It picks the right backend
        // (CSF / firewalld / nftables / iptables), keeps our rules inside a
        // namespaced table so nothing else is disturbed, and persists them so a
        // reboot does not silently discard every block while the database keeps
        // reporting them as active.
        require_once __DIR__ . '/FirewallEngine.php';
        $res  = FirewallEngine::block($ip);
        $out  = [$res['output'] ?? ''];
        $code = ($res['success'] ?? false) ? 0 : 1;

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
        return ['success' => $code === 0, 'output' => implode("\n", $out)];
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

    public function getRules(): array {
        return Database::fetchAll("SELECT * FROM firewall_rules ORDER BY priority ASC, id ASC");
    }

    public function addRule(array $data): array {
        $required = ['name', 'direction', 'action'];
        foreach ($required as $f) {
            if (empty($data[$f])) return ['success' => false, 'error' => "Missing field: $f"];
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
        if (!$this->isCSFInstalled()) {
            return ['installed' => false, 'running' => false];
        }
        exec(CSF_BIN . ' -l 2>&1 | head -5', $out, $code);
        exec('pgrep lfd', $lfd_out, $lfd_code);
        return [
            'installed' => true,
            'running'   => $lfd_code === 0,
            'version'   => $this->getCSFVersion(),
        ];
    }

    private function getCSFVersion(): string {
        exec(CSF_BIN . ' --version 2>&1', $out);
        return $out[0] ?? 'unknown';
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

    public function getStats(): array {
        $blocked  = Database::fetchOne("SELECT COUNT(*) as c FROM blocked_ips")['c'];
        $rules    = Database::fetchOne("SELECT COUNT(*) as c FROM firewall_rules WHERE enabled=1")['c'];
        $today    = mktime(0, 0, 0);
        $todayBlk = Database::fetchOne(
            "SELECT COUNT(*) as c FROM blocked_ips WHERE blocked_at >= ?", [$today]
        )['c'];

        // Get iptables rule count
        exec(IPTABLES_BIN . ' -L INPUT --line-numbers 2>/dev/null | wc -l', $iptOut);
        $iptCount = max(0, (int)($iptOut[0] ?? 0) - 2);

        return [
            'blocked_ips'   => (int) $blocked,
            'active_rules'  => (int) $rules,
            'blocked_today' => (int) $todayBlk,
            'iptables_rules'=> $iptCount,
            'csf_status'    => $this->getCSFStatus(),
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

    private function validateIP(string $ip): void {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid IP address']);
            exit;
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
