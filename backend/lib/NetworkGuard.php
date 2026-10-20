<?php
/**
 * ServerScrub — Network-layer guards
 *
 * Port-scan detection, connection flood limits and egress policy.
 *
 * ── PROVENANCE ───────────────────────────────────────────────────────────────
 * Clean-room, like FirewallEngine. No CSF or CPGuard source was consulted.
 * These capabilities exist in CSF (PS_INTERVAL, CT_LIMIT, outbound TCP_OUT) and
 * capabilities are not copyrightable; code is. CSF and its surviving forks are
 * GPLv3, and deriving from them would oblige this product to be GPLv3 too,
 * which is incompatible with licensing it commercially. So everything here is
 * written against the kernel's own interfaces — /proc/net, conntrack, nftables
 * and iptables — and reads nothing from CSF.
 *
 * ── WHY IT REUSES BruteForce RATHER THAN BLOCKING ITSELF ─────────────────────
 * A detector that does its own blocking needs its own escalation ladder, its
 * own expiry, its own whitelist and its own release path. This product already
 * has all four, and they are the parts that are dangerous to get wrong: the
 * single worst outcome here is permanently blocking a customer, a backup server
 * or the operator's own address.
 *
 * So a confirmed detection is recorded as an attempt in brute_force_attempts
 * under its own service name, and BruteForce::evaluate() escalates it through
 * the same ladder (3h → 6h → 24h → permanent), honours the same whitelist, and
 * BruteForce::releaseExpired() lets it go again. One blocking path, already
 * tested, already visible in the offenders UI.
 *
 * ── WHAT IS DELIBERATELY NOT AUTOMATIC ──────────────────────────────────────
 * Egress filtering is OFF by default and has no auto-enable. Getting an
 * outbound policy wrong does not block an attacker, it breaks the server's own
 * updates, DNS, licensing, mail and backups — silently, and usually at 3am.
 * It is offered as an explicit, reviewable action with a dry run.
 */

class NetworkGuard
{
    /** Service names used in brute_force_attempts, so the UI can tell them apart. */
    public const SVC_SCAN  = 'portscan';
    public const SVC_FLOOD = 'connflood';

    /** Never acted on, whatever they do. */
    private const ALWAYS_SAFE = ['127.0.0.1', '::1'];

    // ── Settings ────────────────────────────────────────────────────────────

    public static function scanEnabled(): bool
    {
        return Database::setting('ng_scan_enabled', '1') === '1';
    }

    public static function floodEnabled(): bool
    {
        return Database::setting('ng_flood_enabled', '1') === '1';
    }

    /** Distinct closed ports from one source that count as a scan. */
    public static function scanPortThreshold(): int
    {
        return max(3, min(1000, (int)Database::setting('ng_scan_ports', '10')));
    }

    /** Concurrent connections from one source that count as a flood. */
    public static function floodLimit(): int
    {
        return max(10, min(10000, (int)Database::setting('ng_flood_limit', '150')));
    }

    /**
     * Ports exempt from the flood limit.
     *
     * HTTP and HTTPS are exempt by DEFAULT and that is not an oversight. A
     * browser opens six connections per page, a CDN or corporate NAT presents
     * hundreds of real users as one address, and this product's own dashboard
     * is served over 443. A flood limit applied to :443 blocks a shopping
     * centre's whole wifi, then the operator, then cannot be undone from the
     * panel because the panel is on :443.
     */
    public static function floodExemptPorts(): array
    {
        $raw = (string)Database::setting('ng_flood_exempt_ports', '80,443');
        $out = [];
        foreach (explode(',', $raw) as $p) {
            $p = (int)trim($p);
            if ($p > 0 && $p <= 65535) $out[] = $p;
        }
        return $out;
    }

    // ── Port-scan detection ─────────────────────────────────────────────────

    /**
     * One pass of scan detection.
     *
     * HOW IT SEES A SCAN WITHOUT A PACKET CAPTURE: a connection to a port
     * nothing is listening on leaves a short-lived SYN_RECV/conntrack entry
     * and no established socket. Reading which ports a single address has
     * touched that are NOT in the local listening set is enough to tell a scan
     * from traffic — a real client connects to the one port it wants.
     *
     * Deliberately cheap. It reads /proc/net (two small virtual files) rather
     * than shelling out, and it runs on the scheduler, not in a loop. An
     * unbounded or repeated conntrack dump on a shared host is itself a
     * performance incident, which this server has already had once this month.
     *
     * @return array{checked:int,scanners:int,recorded:int,ports:array<string,int>}
     */
    public static function detectScans(): array
    {
        if (!self::scanEnabled()) {
            return ['checked' => 0, 'scanners' => 0, 'recorded' => 0, 'ports' => [],
                    'skipped' => 'port-scan detection is switched off'];
        }

        $listening = self::listeningPorts();
        // No listening ports read means /proc is unreadable or the format has
        // changed. Treating that as "every port is closed" would report the
        // entire internet as scanning us, so stop instead.
        if ($listening === []) {
            return ['checked' => 0, 'scanners' => 0, 'recorded' => 0, 'ports' => [],
                    'skipped' => 'could not read the local listening set — not guessing'];
        }

        $perIp = [];
        foreach (self::halfOpenConnections() as [$ip, $port]) {
            if (in_array($port, $listening, true)) continue;   // a real service
            $perIp[$ip][$port] = true;
        }

        $need     = self::scanPortThreshold();
        $white    = array_merge(BruteForce::whitelist(), self::ALWAYS_SAFE);
        $recorded = 0;
        $scanners = 0;
        $ports    = [];

        foreach ($perIp as $ip => $set) {
            $n = count($set);
            if ($n < $need) continue;
            if (self::isWhitelisted($ip, $white)) continue;

            $scanners++;
            $ports[$ip] = $n;

            // One row per distinct closed port touched, so the existing
            // threshold in BruteForce reads naturally: "37 attempts" for an
            // address that probed 37 ports it had no business probing.
            $recorded += self::record($ip, self::SVC_SCAN, $n,
                                      'probed ' . $n . ' closed ports');
        }

        if ($scanners > 0) {
            Logger::warn(sprintf('Port scan: %d address(es) probing closed ports (%s)',
                $scanners, implode(', ', array_map(
                    fn($k, $v) => "$k:$v", array_keys($ports), $ports))));
        }

        return ['checked' => count($perIp), 'scanners' => $scanners,
                'recorded' => $recorded, 'ports' => $ports];
    }

    // ── Connection flood limits ─────────────────────────────────────────────

    /**
     * Addresses holding an unreasonable number of concurrent connections.
     *
     * @return array{checked:int,offenders:int,recorded:int,counts:array<string,int>}
     */
    public static function detectFloods(): array
    {
        if (!self::floodEnabled()) {
            return ['checked' => 0, 'offenders' => 0, 'recorded' => 0, 'counts' => [],
                    'skipped' => 'connection flood limits are switched off'];
        }

        $exempt = self::floodExemptPorts();
        $limit  = self::floodLimit();
        $counts = [];

        foreach (self::establishedConnections() as [$ip, $port]) {
            if (in_array($port, $exempt, true)) continue;
            $counts[$ip] = ($counts[$ip] ?? 0) + 1;
        }

        $white     = array_merge(BruteForce::whitelist(), self::ALWAYS_SAFE);
        $offenders = 0;
        $recorded  = 0;
        $hit       = [];

        foreach ($counts as $ip => $n) {
            if ($n < $limit) continue;
            if (self::isWhitelisted($ip, $white)) continue;
            $offenders++;
            $hit[$ip] = $n;
            $recorded += self::record($ip, self::SVC_FLOOD, $n,
                                      $n . ' concurrent connections');
        }

        if ($offenders > 0) {
            Logger::warn(sprintf('Connection flood: %d address(es) over %d concurrent',
                                 $offenders, $limit));
        }

        return ['checked' => count($counts), 'offenders' => $offenders,
                'recorded' => $recorded, 'counts' => $hit];
    }

    // ── Both, for the scheduler ─────────────────────────────────────────────

    public static function run(): array
    {
        $scan  = self::detectScans();
        $flood = self::detectFloods();

        // Escalation, blocking, expiry and the whitelist are BruteForce's, so
        // anything recorded above is acted on by the same code path that
        // handles a failed SSH login — with the same ladder and the same
        // release. Nothing here blocks an address itself.
        $acted = (BruteForce::enabled() && ($scan['recorded'] || $flood['recorded']))
               ? BruteForce::evaluate()
               : ['blocked' => 0];

        return ['scan' => $scan, 'flood' => $flood,
                'blocked' => (int)($acted['blocked'] ?? 0)];
    }

    // ── Egress policy ───────────────────────────────────────────────────────

    /**
     * Outbound port policy.
     *
     * OFF by default, and there is no automatic enable anywhere in this class.
     * A wrong inbound rule blocks visitors and you hear about it. A wrong
     * OUTBOUND rule breaks the server's own package updates, DNS, NTP, mail
     * delivery, licence checks and backups — quietly, and often only at the
     * next cron run. So:
     *
     *   - $dryRun defaults to true and returns the rules without applying them.
     *   - The default allow-list carries what a cPanel server genuinely needs
     *     outbound, including 53 for DNS and 2703 for Razor/mail filtering.
     *   - Applying it with no allow-list at all is refused outright.
     *
     * @return array{success:bool,dry_run:bool,rules:array,error?:string}
     */
    public static function applyEgress(array $allowPorts = [], bool $dryRun = true): array
    {
        if ($allowPorts === []) {
            $allowPorts = self::defaultEgressPorts();
        }

        $clean = [];
        foreach ($allowPorts as $p) {
            $p = (int)$p;
            if ($p > 0 && $p <= 65535) $clean[] = $p;
        }
        $clean = array_values(array_unique($clean));

        if ($clean === []) {
            return ['success' => false, 'dry_run' => $dryRun, 'rules' => [],
                    'error' => 'Refusing to apply an empty outbound allow-list: that '
                             . 'would cut the server off from DNS, updates and its '
                             . 'own licence check.'];
        }

        // DNS is non-negotiable. Without it the server cannot resolve its own
        // package mirrors, this product's update channel or its licence server,
        // and every failure that follows looks like something else.
        if (!in_array(53, $clean, true)) {
            return ['success' => false, 'dry_run' => $dryRun, 'rules' => [],
                    'error' => 'Refusing to apply an outbound policy that does not '
                             . 'allow port 53. Without DNS nothing on this server '
                             . 'resolves, and the cause is very hard to see.'];
        }

        $backend = FirewallEngine::detect();
        $rules   = self::egressRules($backend, $clean);

        if ($dryRun) {
            return ['success' => true, 'dry_run' => true, 'rules' => $rules,
                    'note' => 'Nothing was applied. Review these, then call again '
                            . 'with dry_run = false.'];
        }

        // Only our own chain is touched, as everywhere else in this product.
        $applied = [];
        foreach ($rules as $r) {
            @exec($r . ' 2>&1', $o, $rc);
            $applied[] = ['rule' => $r, 'ok' => $rc === 0,
                          'output' => implode(' ', array_slice($o, 0, 2))];
        }
        Database::setSetting('ng_egress_ports', implode(',', $clean));
        Database::setSetting('ng_egress_enabled', '1');
        Logger::warn('Outbound policy applied, allowing: ' . implode(',', $clean));

        return ['success' => true, 'dry_run' => false, 'rules' => $applied];
    }

    /** What a cPanel server actually needs to reach the outside world. */
    public static function defaultEgressPorts(): array
    {
        return [
            20, 21,      // FTP
            22,          // SSH / SFTP out
            25, 587, 465, // SMTP
            43,          // whois
            53,          // DNS — mandatory, see applyEgress()
            80, 443,     // HTTP(S): updates, licence checks, APIs
            110, 995,    // POP3
            143, 993,    // IMAP
            123,         // NTP
            873,         // rsync
            2703,        // Razor
            3306,        // remote MySQL
        ];
    }

    private static function egressRules(string $backend, array $ports): array
    {
        $list = implode(',', $ports);
        if ($backend === 'nftables' || $backend === 'nft') {
            $t = FirewallEngine::TABLE;
            return [
                sprintf('nft add chain inet %s sg_out { type filter hook output priority 0 \; policy accept \; }', $t),
                sprintf('nft flush chain inet %s sg_out', $t),
                sprintf('nft add rule inet %s sg_out ct state established,related accept', $t),
                sprintf('nft add rule inet %s sg_out meta l4proto { tcp, udp } th dport { %s } accept', $t, $list),
                sprintf('nft add rule inet %s sg_out oifname "lo" accept', $t),
                sprintf('nft add rule inet %s sg_out meta skuid 0 accept', $t),
                sprintf('nft add rule inet %s sg_out drop', $t),
            ];
        }
        $c = FirewallEngine::CHAIN . '_OUT';
        return [
            sprintf('iptables -N %s', $c),
            sprintf('iptables -F %s', $c),
            sprintf('iptables -A %s -m state --state ESTABLISHED,RELATED -j ACCEPT', $c),
            sprintf('iptables -A %s -o lo -j ACCEPT', $c),
            sprintf('iptables -A %s -p tcp -m multiport --dports %s -j ACCEPT', $c, $list),
            sprintf('iptables -A %s -p udp -m multiport --dports %s -j ACCEPT', $c, $list),
            sprintf('iptables -A %s -m owner --uid-owner 0 -j ACCEPT', $c),
            sprintf('iptables -A %s -j DROP', $c),
            sprintf('iptables -C OUTPUT -j %s || iptables -A OUTPUT -j %s', $c, $c),
        ];
    }

    /** Remove the outbound policy. Always available, even if applying failed. */
    public static function clearEgress(): array
    {
        $backend = FirewallEngine::detect();
        if ($backend === 'nftables' || $backend === 'nft') {
            @exec(sprintf('nft delete chain inet %s sg_out 2>&1', FirewallEngine::TABLE));
        } else {
            $c = FirewallEngine::CHAIN . '_OUT';
            @exec(sprintf('iptables -D OUTPUT -j %s 2>&1', $c));
            @exec(sprintf('iptables -F %s 2>&1', $c));
            @exec(sprintf('iptables -X %s 2>&1', $c));
        }
        Database::setSetting('ng_egress_enabled', '0');
        Logger::info('Outbound policy removed');
        return ['success' => true];
    }

    // ── Reading the kernel ──────────────────────────────────────────────────

    /**
     * Local listening TCP/UDP ports, from /proc/net.
     *
     * Read rather than assumed: a hosting server listens on a long and
     * site-specific set, and a hardcoded list would report every legitimate
     * service's traffic as a scan.
     */
    public static function listeningPorts(): array
    {
        $out = [];
        foreach (['tcp', 'tcp6'] as $f) {
            foreach (self::procNet($f) as $row) {
                // st 0A = TCP_LISTEN
                if (($row['st'] ?? '') === '0A') $out[] = $row['local_port'];
            }
        }
        // UDP has no listen state; a bound socket is the equivalent.
        foreach (['udp', 'udp6'] as $f) {
            foreach (self::procNet($f) as $row) {
                $out[] = $row['local_port'];
            }
        }
        return array_values(array_unique($out));
    }

    /** Remote address/local port pairs for half-open inbound connections. */
    public static function halfOpenConnections(): array
    {
        $out = [];
        foreach (['tcp', 'tcp6'] as $f) {
            foreach (self::procNet($f) as $row) {
                // 03 = SYN_RECV, 02 = SYN_SENT, 06 = TIME_WAIT
                if (!in_array($row['st'] ?? '', ['03', '02', '06'], true)) continue;
                if ($row['remote_ip'] === '' || $row['remote_ip'] === '0.0.0.0') continue;
                $out[] = [$row['remote_ip'], $row['local_port']];
            }
        }
        return $out;
    }

    /** Remote address/local port pairs for established inbound connections. */
    public static function establishedConnections(): array
    {
        $out = [];
        foreach (['tcp', 'tcp6'] as $f) {
            foreach (self::procNet($f) as $row) {
                if (($row['st'] ?? '') !== '01') continue;   // TCP_ESTABLISHED
                if ($row['remote_ip'] === '' || $row['remote_ip'] === '0.0.0.0') continue;
                $out[] = [$row['remote_ip'], $row['local_port']];
            }
        }
        return $out;
    }

    /**
     * Parse one /proc/net/{tcp,tcp6,udp,udp6}.
     *
     * Bounded: a busy server can hold a lot of sockets and this runs on a
     * schedule, so the read stops at a ceiling rather than loading an
     * unbounded file into memory. A truncated sample still detects a scan —
     * a scanner shows up in any sample of its own traffic.
     *
     * @return array<int,array{st:string,local_port:int,remote_ip:string}>
     */
    public static function procNet(string $which, ?string $path = null): array
    {
        $path = $path ?? '/proc/net/' . $which;
        if (!is_readable($path)) return [];

        $fh = @fopen($path, 'r');
        if (!$fh) return [];

        $rows = 0;
        $max  = 60000;
        $out  = [];
        fgets($fh);                                   // header
        while (($line = fgets($fh)) !== false && $rows < $max) {
            $rows++;
            $p = preg_split('/\s+/', trim($line));
            if (!is_array($p) || count($p) < 4) continue;

            // local_address and rem_address are HEX:HEXPORT
            $rem = explode(':', $p[2]);
            $loc = explode(':', $p[1]);
            if (count($rem) < 2 || count($loc) < 2) continue;

            $out[] = [
                'st'         => strtoupper($p[3]),
                'local_port' => (int)hexdec(end($loc)),
                'remote_ip'  => self::hexToIp($rem[0]),
            ];
        }
        fclose($fh);
        return $out;
    }

    /**
     * /proc/net hex address to a printable IP.
     *
     * IPv4 is little-endian per 32-bit word, and IPv6 is four little-endian
     * words — getting this wrong does not fail loudly, it blocks the wrong
     * address, which is why it is a separate function with its own tests.
     */
    public static function hexToIp(string $hex): string
    {
        $hex = strtoupper(trim($hex));
        if (strlen($hex) === 8) {
            $b = str_split($hex, 2);
            return implode('.', [hexdec($b[3]), hexdec($b[2]),
                                 hexdec($b[1]), hexdec($b[0])]);
        }
        if (strlen($hex) === 32) {
            $words = str_split($hex, 8);
            $bytes = '';
            foreach ($words as $w) {
                $p = str_split($w, 2);
                $bytes .= $p[3] . $p[2] . $p[1] . $p[0];
            }
            $packed = @hex2bin($bytes);
            if ($packed === false) return '';
            $ip = @inet_ntop($packed);
            return is_string($ip) ? $ip : '';
        }
        return '';
    }

    // ── Plumbing ────────────────────────────────────────────────────────────

    /**
     * Record a detection as attempts, for BruteForce to escalate.
     *
     * The count is capped. A single scan of all 65,535 ports would otherwise
     * write 65,535 rows in one pass, and the table would be the incident.
     */
    private static function record(string $ip, string $service, int $count,
                                    string $note): int
    {
        BruteForce::ensureSchema();
        $n   = max(1, min(200, $count));
        $now = time();

        $db = Database::get();
        $stmt = $db->prepare(
            'INSERT INTO brute_force_attempts (ip_address, service, username, attempted_at)
             VALUES (?,?,?,?)');
        for ($i = 0; $i < $n; $i++) {
            $stmt->execute([$ip, $service, $note, $now]);
        }
        return $n;
    }

    /**
     * Whitelist check, CIDR-aware.
     *
     * The handoff from the October incident names addresses that must never be
     * blocked — the operator's own, and two JetBackup servers. A backup server
     * opening many parallel connections looks exactly like a flood, so this
     * check is the difference between a working guard and losing backups.
     */
    public static function isWhitelisted(string $ip, array $list): bool
    {
        foreach ($list as $entry) {
            $entry = trim((string)$entry);
            if ($entry === '') continue;
            if ($entry === $ip) return true;
            if (strpos($entry, '/') !== false && self::inCidr($ip, $entry)) return true;
        }
        return false;
    }

    private static function inCidr(string $ip, string $cidr): bool
    {
        [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
        $bits = (int)$bits;
        $a = @inet_pton($ip);
        $b = @inet_pton((string)$net);
        if ($a === false || $b === false || strlen($a) !== strlen($b)) return false;
        if ($bits <= 0 || $bits > strlen($a) * 8) return false;

        $whole = intdiv($bits, 8);
        $rem   = $bits % 8;
        if ($whole > 0 && strncmp($a, $b, $whole) !== 0) return false;
        if ($rem === 0) return true;

        $mask = chr(0xFF << (8 - $rem) & 0xFF);
        return (($a[$whole] & $mask) === ($b[$whole] & $mask));
    }

    /** For the dashboard. */
    public static function status(): array
    {
        return [
            'scan_enabled'   => self::scanEnabled(),
            'scan_ports'     => self::scanPortThreshold(),
            'flood_enabled'  => self::floodEnabled(),
            'flood_limit'    => self::floodLimit(),
            'flood_exempt'   => self::floodExemptPorts(),
            'egress_enabled' => Database::setting('ng_egress_enabled', '0') === '1',
            'egress_ports'   => Database::setting('ng_egress_ports', ''),
            'backend'        => FirewallEngine::detect(),
            'recent'         => Database::fetchAll(
                "SELECT ip_address, service, COUNT(*) AS n, MAX(attempted_at) AS last
                   FROM brute_force_attempts
                  WHERE service IN (?,?) AND attempted_at >= CAST(? AS INTEGER)
               GROUP BY ip_address, service
               ORDER BY last DESC LIMIT 50",
                [self::SVC_SCAN, self::SVC_FLOOD, time() - 86400]),
        ];
    }
}
