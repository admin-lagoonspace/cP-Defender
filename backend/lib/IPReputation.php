<?php
/**
 * Sentinel Gate — IP Reputation & RBL Checker
 */

class IPReputation {

    private array $rblFeeds;

    public function __construct() {
        $this->rblFeeds = unserialize(RBL_FEEDS);
    }

    public function check(string $ip): array {
        $this->validateIP($ip);

        // Check cache first (TTL 1 hour)
        $cached = Database::fetchOne(
            "SELECT * FROM ip_reputation WHERE ip_address = ? AND cached_at > ?",
            [$ip, time() - 3600]
        );
        if ($cached) return $this->formatResult($cached);

        $score    = 0;
        $rblHits  = [];
        $country  = $this->getCountry($ip);
        $asn      = $this->getASN($ip);

        // DNS-based RBL checks
        $reversed = implode('.', array_reverse(explode('.', $ip)));
        foreach (['spamhaus' => 'zen.spamhaus.org', 'sorbs' => 'dnsbl.sorbs.net',
                  'barracuda' => 'b.barracudacentral.org', 'spamcop' => 'bl.spamcop.net'] as $name => $rbl) {
            $lookup = "$reversed.$rbl";
            if (checkdnsrr($lookup, 'A')) {
                $rblHits[] = $name;
                $score    += 25;
            }
        }

        // AbuseIPDB check (if API key set)
        $abuseKey = Database::setting('abuseipdb_key');
        if ($abuseKey) {
            $abuseScore = $this->checkAbuseIPDB($ip, $abuseKey);
            $score = max($score, $abuseScore);
        }

        $score = min($score, 100);

        // Upsert cache
        $existing = Database::fetchOne("SELECT id FROM ip_reputation WHERE ip_address = ?", [$ip]);
        if ($existing) {
            Database::query(
                "UPDATE ip_reputation SET score=?, country=?, asn=?, rbl_hits=?, last_seen=?, cached_at=? WHERE ip_address=?",
                [$score, $country, $asn, json_encode($rblHits), time(), time(), $ip]
            );
        } else {
            Database::insert('ip_reputation', [
                'ip_address' => $ip,
                'score'      => $score,
                'country'    => $country,
                'asn'        => $asn,
                'rbl_hits'   => json_encode($rblHits),
                'last_seen'  => time(),
                'cached_at'  => time(),
            ]);
        }

        return [
            'ip'       => $ip,
            'score'    => $score,
            'risk'     => $this->riskLabel($score),
            'country'  => $country,
            'asn'      => $asn,
            'rbl_hits' => $rblHits,
        ];
    }

    private function checkAbuseIPDB(string $ip, string $key): int {
        $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" . urlencode($ip) . "&maxAgeInDays=90";
        $ctx = stream_context_create(['http' => [
            'header'  => "Key: $key\r\nAccept: application/json\r\n",
            'timeout' => 5
        ]]);
        $resp = @file_get_contents($url, false, $ctx);
        if (!$resp) return 0;
        $data = json_decode($resp, true);
        return (int) ($data['data']['abuseConfidenceScore'] ?? 0);
    }

    private function getCountry(string $ip): string {
        // Use GeoIP if available (MaxMind or ip-api free)
        $ctx = stream_context_create(['http' => ['timeout' => 3]]);
        $resp = @file_get_contents("http://ip-api.com/json/$ip?fields=countryCode", false, $ctx);
        if ($resp) {
            $d = json_decode($resp, true);
            return $d['countryCode'] ?? 'XX';
        }
        return 'XX';
    }

    private function getASN(string $ip): string {
        $ctx = stream_context_create(['http' => ['timeout' => 3]]);
        $resp = @file_get_contents("http://ip-api.com/json/$ip?fields=as", false, $ctx);
        if ($resp) {
            $d = json_decode($resp, true);
            return $d['as'] ?? '';
        }
        return '';
    }

    public function bulkCheck(array $ips): array {
        return array_map(fn($ip) => $this->check($ip), $ips);
    }

    public function getTopAttackers(int $limit = 20): array {
        return Database::fetchAll(
            "SELECT * FROM ip_reputation WHERE score > 50 ORDER BY score DESC, last_seen DESC LIMIT ?",
            [$limit]
        );
    }

    public function getTopAttackingIPs(): array {
        return Database::fetchAll(
            "SELECT e.ip_address, r.country, r.score, COUNT(e.id) as hits,
                    MAX(e.timestamp) as last_seen
             FROM security_events e
             LEFT JOIN ip_reputation r ON r.ip_address = e.source_ip
             WHERE e.timestamp > ?
             GROUP BY e.source_ip
             ORDER BY hits DESC
             LIMIT 20",
            [time() - 86400]
        );
    }

    private function riskLabel(int $score): string {
        if ($score >= 75) return 'critical';
        if ($score >= 50) return 'high';
        if ($score >= 25) return 'medium';
        return 'low';
    }

    private function formatResult(array $row): array {
        return [
            'ip'       => $row['ip_address'],
            'score'    => (int) $row['score'],
            'risk'     => $this->riskLabel((int) $row['score']),
            'country'  => $row['country'],
            'asn'      => $row['asn'],
            'rbl_hits' => json_decode($row['rbl_hits'] ?? '[]', true),
            'cached'   => true,
        ];
    }

    private function validateIP(string $ip): void {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid IP']);
            exit;
        }
    }
}
