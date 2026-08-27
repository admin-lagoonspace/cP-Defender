<?php
/**
 * Sentinel Gate — built-in firewall engine
 *
 * A self-contained packet-filter manager, so the product does not require the
 * operator to install and learn a separate firewall first.
 *
 * ── PROVENANCE ───────────────────────────────────────────────────────────────
 * This is a clean-room implementation. It is NOT derived from CSF or CPGuard.
 *
 * That distinction is a licensing requirement, not a stylistic one. CSF was
 * discontinued on 2025-08-31 and released as-is under GPLv3 (cPanel now
 * maintains a fork for security fixes). GPLv3 is strong copyleft: code derived
 * from it makes the whole work a derivative, obliging us to publish Sentinel
 * Gate's source under GPLv3 — which would be incompatible with licensing it
 * commercially. CPGuard is proprietary, so copying from it is simply
 * infringement. Behaviour and features are not copyrightable; code is. So this
 * implements the same CAPABILITIES from first principles using the kernel's own
 * interfaces, and no CSF/CPGuard source was consulted.
 *
 * ── DESIGN ───────────────────────────────────────────────────────────────────
 * Everything lives in a DEDICATED table/chain that carries our name:
 *
 *   nftables : table inet sentinel_gate  { set sg_deny / sg_allow }
 *   iptables : chain SENTINEL_GATE, jumped to from INPUT
 *
 * Nothing outside that namespace is ever touched. The alternative — writing
 * loose rules into INPUT, which the previous implementation did — means we
 * cannot tell our rules from anyone else's, cannot remove them cleanly, and
 * fight whatever else manages the firewall.
 *
 * Rules are written to disk and restored by a boot unit. Without that, blocks
 * silently vanish on reboot while the database still reports them as active —
 * a security product claiming protection it is not providing.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class FirewallEngine
{
    const TABLE = 'sentinel_gate';     // nftables table
    const CHAIN = 'SENTINEL_GATE';     // iptables chain
    const SET_DENY  = 'sg_deny';
    const SET_ALLOW = 'sg_allow';

    /** Persisted rule state, restored at boot. */
    const STATE_DIR = '/etc/sentinel-gate';

    private static $backend = null;

    // ── Backend detection ────────────────────────────────────────────────────

    /**
     * Which subsystem is actually in charge.
     *
     * Order matters and is not arbitrary: we must defer to whatever is ALREADY
     * managing the firewall, or our rules get flushed the next time that tool
     * reloads. Detecting "iptables exists" first would be wrong on every modern
     * RHEL box, where iptables is present but firewalld owns the ruleset.
     */
    public static function detect(): string
    {
        if (self::$backend !== null) { return self::$backend; }

        if (self::has('csf') && file_exists('/usr/sbin/csf')) {
            self::$backend = 'csf';           // respect an existing CSF install
        } elseif (self::serviceActive('firewalld')) {
            self::$backend = 'firewalld';
        } elseif (self::has('nft')) {
            self::$backend = 'nftables';
        } elseif (self::has('iptables')) {
            self::$backend = 'iptables';
        } else {
            self::$backend = 'none';
        }
        return self::$backend;
    }

    public static function backendInfo(): array
    {
        $b = self::detect();
        return [
            'backend'     => $b,
            'name'        => [
                'csf'       => 'CSF (existing installation)',
                'firewalld' => 'firewalld',
                'nftables'  => 'nftables (built-in)',
                'iptables'  => 'iptables (built-in)',
                'none'      => 'No firewall available',
            ][$b] ?? $b,
            'builtin'     => in_array($b, ['nftables', 'iptables'], true),
            'installed'   => $b !== 'none',
            'initialised' => self::isInitialised(),
            'persistent'  => self::isPersistent(),
            'rule_count'  => self::countRules(),
        ];
    }

    // ── Initialisation ───────────────────────────────────────────────────────

    /**
     * Create our table/chain. Idempotent — safe to call on every boot and from
     * the UI, which matters because the installer, the boot unit and an admin
     * clicking "Enable" can all reach it.
     */
    public static function initialise(): array
    {
        $b = self::detect();
        if ($b === 'csf') {
            return ['success' => true, 'backend' => 'csf',
                    'message' => 'Using the existing CSF installation.'];
        }
        if ($b === 'none') {
            return ['success' => false, 'backend' => 'none',
                    'error' => 'No usable packet filter found (need nft or iptables).'];
        }

        @mkdir(self::STATE_DIR, 0750, true);

        if ($b === 'nftables') {
            // A named set gives O(1) matching regardless of how many addresses
            // are blocked. One rule per IP degrades badly past a few thousand.
            self::sh('nft add table inet ' . self::TABLE);
            self::sh('nft add set inet ' . self::TABLE . ' ' . self::SET_DENY .
                     ' { type ipv4_addr\; flags interval\; }');
            self::sh('nft add set inet ' . self::TABLE . ' ' . self::SET_ALLOW .
                     ' { type ipv4_addr\; flags interval\; }');
            self::sh('nft add chain inet ' . self::TABLE . ' input ' .
                     '{ type filter hook input priority -10\; policy accept\; }');
            // Allow is evaluated first so an allow entry always wins over a deny.
            self::sh('nft add rule inet ' . self::TABLE . ' input ip saddr @' .
                     self::SET_ALLOW . ' accept');
            self::sh('nft add rule inet ' . self::TABLE . ' input ip saddr @' .
                     self::SET_DENY . ' drop');

        } elseif ($b === 'firewalld') {
            // Work through firewalld's own ipset so it survives its reloads.
            self::sh('firewall-cmd --permanent --new-ipset=' . self::SET_DENY .
                     ' --type=hash:ip 2>/dev/null');
            self::sh('firewall-cmd --permanent --add-rich-rule=' .
                     escapeshellarg('rule source ipset="' . self::SET_DENY . '" drop'));
            self::sh('firewall-cmd --reload');

        } else { // iptables
            self::sh('iptables -N ' . self::CHAIN . ' 2>/dev/null');
            // -C tests for an existing jump; without it every call appends
            // another jump and INPUT grows without bound.
            if (self::sh('iptables -C INPUT -j ' . self::CHAIN . ' 2>/dev/null')['code'] !== 0) {
                self::sh('iptables -I INPUT 1 -j ' . self::CHAIN);
            }
        }

        Database::setSetting('fw_engine_initialised', '1');
        Database::setSetting('fw_engine_backend', $b);
        self::persist();
        return ['success' => true, 'backend' => $b,
                'message' => 'Built-in firewall active (' . $b . ').'];
    }

    public static function isInitialised(): bool
    {
        switch (self::detect()) {
            case 'nftables':
                return self::sh('nft list table inet ' . self::TABLE . ' >/dev/null 2>&1')['code'] === 0;
            case 'iptables':
                return self::sh('iptables -n -L ' . self::CHAIN . ' >/dev/null 2>&1')['code'] === 0;
            case 'firewalld':
                return strpos(self::sh('firewall-cmd --permanent --get-ipsets')['out'], self::SET_DENY) !== false;
            case 'csf':
                return true;
        }
        return false;
    }

    // ── Rules ────────────────────────────────────────────────────────────────

    public static function block(string $ip): array
    {
        if (!self::validIp($ip)) { return ['success' => false, 'error' => 'Invalid IP']; }
        switch (self::detect()) {
            case 'csf':
                $r = self::sh('csf -d ' . escapeshellarg($ip) . ' "Sentinel Gate"'); break;
            case 'nftables':
                $r = self::sh('nft add element inet ' . self::TABLE . ' ' .
                              self::SET_DENY . ' { ' . escapeshellarg($ip) . ' }'); break;
            case 'firewalld':
                $r = self::sh('firewall-cmd --permanent --ipset=' . self::SET_DENY .
                              ' --add-entry=' . escapeshellarg($ip));
                self::sh('firewall-cmd --reload');
                break;
            case 'iptables':
                if (self::sh('iptables -C ' . self::CHAIN . ' -s ' . escapeshellarg($ip) .
                             ' -j DROP 2>/dev/null')['code'] === 0) {
                    return ['success' => true, 'already' => true];
                }
                $r = self::sh('iptables -I ' . self::CHAIN . ' 1 -s ' .
                              escapeshellarg($ip) . ' -j DROP'); break;
            default:
                return ['success' => false, 'error' => 'No firewall backend available'];
        }
        self::persist();
        return ['success' => $r['code'] === 0, 'output' => $r['out']];
    }

    public static function unblock(string $ip): array
    {
        if (!self::validIp($ip)) { return ['success' => false, 'error' => 'Invalid IP']; }
        switch (self::detect()) {
            case 'csf':
                $r = self::sh('csf -dr ' . escapeshellarg($ip)); break;
            case 'nftables':
                $r = self::sh('nft delete element inet ' . self::TABLE . ' ' .
                              self::SET_DENY . ' { ' . escapeshellarg($ip) . ' }'); break;
            case 'firewalld':
                $r = self::sh('firewall-cmd --permanent --ipset=' . self::SET_DENY .
                              ' --remove-entry=' . escapeshellarg($ip));
                self::sh('firewall-cmd --reload');
                break;
            case 'iptables':
                $r = self::sh('iptables -D ' . self::CHAIN . ' -s ' .
                              escapeshellarg($ip) . ' -j DROP'); break;
            default:
                return ['success' => false, 'error' => 'No firewall backend available'];
        }
        self::persist();
        return ['success' => $r['code'] === 0, 'output' => $r['out']];
    }

    public static function allow(string $ip): array
    {
        if (!self::validIp($ip)) { return ['success' => false, 'error' => 'Invalid IP']; }
        switch (self::detect()) {
            case 'csf':
                $r = self::sh('csf -a ' . escapeshellarg($ip) . ' "Sentinel Gate"'); break;
            case 'nftables':
                $r = self::sh('nft add element inet ' . self::TABLE . ' ' .
                              self::SET_ALLOW . ' { ' . escapeshellarg($ip) . ' }'); break;
            case 'iptables':
                // Insert at position 1 so the accept precedes any drop below it.
                $r = self::sh('iptables -I ' . self::CHAIN . ' 1 -s ' .
                              escapeshellarg($ip) . ' -j ACCEPT'); break;
            case 'firewalld':
                $r = self::sh('firewall-cmd --permanent --add-rich-rule=' .
                      escapeshellarg('rule family=ipv4 source address="' . $ip . '" accept'));
                self::sh('firewall-cmd --reload');
                break;
            default:
                return ['success' => false, 'error' => 'No firewall backend available'];
        }
        self::persist();
        return ['success' => $r['code'] === 0, 'output' => $r['out']];
    }

    public static function listBlocked(): array
    {
        switch (self::detect()) {
            case 'nftables':
                $o = self::sh('nft -j list set inet ' . self::TABLE . ' ' . self::SET_DENY)['out'];
                $j = json_decode($o, true);
                $out = [];
                foreach (($j['nftables'] ?? []) as $n) {
                    foreach (($n['set']['elem'] ?? []) as $e) {
                        $out[] = is_array($e) ? ($e['prefix']['addr'] ?? '') : (string)$e;
                    }
                }
                return array_values(array_filter($out));
            case 'iptables':
                $o = self::sh('iptables -S ' . self::CHAIN)['out'];
                preg_match_all('/-s (\S+?)(?:\/32)? -j DROP/', $o, $m);
                return $m[1] ?? [];
            case 'firewalld':
                $o = self::sh('firewall-cmd --permanent --ipset=' . self::SET_DENY . ' --get-entries')['out'];
                return array_values(array_filter(array_map('trim', explode("\n", $o))));
            case 'csf':
                $o = @file_get_contents('/etc/csf/csf.deny') ?: '';
                preg_match_all('/^([0-9.]+)/m', $o, $m);
                return $m[1] ?? [];
        }
        return [];
    }

    private static function countRules(): int { return count(self::listBlocked()); }

    // ── Persistence ──────────────────────────────────────────────────────────

    /**
     * Save the live ruleset so a reboot does not silently drop every block.
     *
     * firewalld and CSF persist natively (--permanent / csf.deny), so they are
     * skipped. nftables and iptables do NOT: their rules are kernel state only,
     * and without this the database keeps reporting addresses as blocked while
     * the kernel has long since forgotten them.
     */
    public static function persist(): bool
    {
        @mkdir(self::STATE_DIR, 0750, true);
        switch (self::detect()) {
            case 'nftables':
                $r = self::sh('nft list table inet ' . self::TABLE .
                              ' > ' . self::STATE_DIR . '/nftables.rules 2>/dev/null');
                return $r['code'] === 0;
            case 'iptables':
                $r = self::sh('iptables-save > ' . self::STATE_DIR . '/iptables.rules 2>/dev/null');
                return $r['code'] === 0;
        }
        return true;   // csf / firewalld handle their own persistence
    }

    /** Re-apply saved rules. Invoked by the boot unit. */
    public static function restore(): array
    {
        $b = self::detect();
        if ($b === 'nftables') {
            $f = self::STATE_DIR . '/nftables.rules';
            if (!is_readable($f)) { return self::initialise(); }
            self::sh('nft delete table inet ' . self::TABLE . ' 2>/dev/null');
            $r = self::sh('nft -f ' . escapeshellarg($f));
            return ['success' => $r['code'] === 0, 'backend' => $b];
        }
        if ($b === 'iptables') {
            $f = self::STATE_DIR . '/iptables.rules';
            if (!is_readable($f)) { return self::initialise(); }
            $r = self::sh('iptables-restore < ' . escapeshellarg($f));
            return ['success' => $r['code'] === 0, 'backend' => $b];
        }
        return ['success' => true, 'backend' => $b, 'message' => 'Backend persists natively'];
    }

    public static function isPersistent(): bool
    {
        switch (self::detect()) {
            case 'csf': case 'firewalld': return true;
            case 'nftables': return is_readable(self::STATE_DIR . '/nftables.rules');
            case 'iptables': return is_readable(self::STATE_DIR . '/iptables.rules');
        }
        return false;
    }

    /** Remove everything we created. Used by the uninstaller. */
    public static function teardown(): void
    {
        switch (self::detect()) {
            case 'nftables':
                self::sh('nft delete table inet ' . self::TABLE . ' 2>/dev/null'); break;
            case 'iptables':
                self::sh('iptables -D INPUT -j ' . self::CHAIN . ' 2>/dev/null');
                self::sh('iptables -F ' . self::CHAIN . ' 2>/dev/null');
                self::sh('iptables -X ' . self::CHAIN . ' 2>/dev/null'); break;
            case 'firewalld':
                self::sh('firewall-cmd --permanent --delete-ipset=' . self::SET_DENY . ' 2>/dev/null');
                self::sh('firewall-cmd --reload'); break;
        }
        @unlink(self::STATE_DIR . '/nftables.rules');
        @unlink(self::STATE_DIR . '/iptables.rules');
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static function validIp(string $ip): bool
    {
        // CIDR is accepted: blocking a whole offending range is a normal action.
        if (strpos($ip, '/') !== false) {
            [$addr, $bits] = explode('/', $ip, 2);
            return filter_var($addr, FILTER_VALIDATE_IP) !== false
                && ctype_digit($bits) && (int)$bits >= 8 && (int)$bits <= 32;
        }
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    private static function has(string $bin): bool
    {
        $r = self::sh('command -v ' . escapeshellarg($bin));
        return $r['code'] === 0 && trim($r['out']) !== '';
    }

    private static function serviceActive(string $svc): bool
    {
        return trim(self::sh('systemctl is-active ' . escapeshellarg($svc) . ' 2>/dev/null')['out']) === 'active';
    }

    /**
     * Command runner, replaceable by tests.
     *
     * Every write path in this class ends in a shell command against nft,
     * iptables, csf or apachectl. None of those exist on a development machine,
     * so none of this code could be executed before it reached a customer's
     * server -- which is exactly how the write paths came to be the last
     * untested part of the product. Injecting the runner makes the decision
     * logic testable without pretending the tools are present.
     *
     * @var (callable(string):array{out:string,code:int})|null
     */
    private static $runner = null;

    /** @param (callable(string):array{out:string,code:int})|null $runner */
    public static function setRunner(?callable $runner): void
    {
        self::$runner = $runner;
    }

    private static function sh(string $cmd): array
    {
        if (self::$runner !== null) {
            return (self::$runner)($cmd);
        }
        $out = [];
        $code = 0;
        @exec($cmd . ' 2>&1', $out, $code);
        return ['out' => implode("\n", $out), 'code' => $code];
    }
}
