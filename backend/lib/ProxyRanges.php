<?php
/**
 * ServerScrub — addresses that are a proxy, not a visitor.
 *
 * WHY THIS EXISTS
 * ---------------
 * FROM A LIVE SERVER. Two Cloudflare edge addresses were sitting in
 * /etc/csf/csf.deny with our name on them:
 *
 *     104.21.83.159   Mon Oct 26 18:45
 *     172.67.178.100  Tue Oct 27 06:30
 *
 * A site on that server sits behind Cloudflare. Its logs record the Cloudflare
 * EDGE as the client, because the real address only ever arrives in a header.
 * So the brute-force sweep counted every failed login that came through that
 * edge as one attacker, crossed the threshold, and blocked the proxy.
 *
 * That is wrong twice over. The attacker simply returns through a different
 * edge address, of which there are thousands -- so the block achieves nothing.
 * And every genuine visitor routed through those two edges is now dropped: the
 * site is down for a slice of its audience, with nothing in that site's own
 * logs to explain it, because the requests never reach the server at all.
 *
 * Blocking a shared proxy is never the right answer. Either the real client is
 * recoverable from the log line, in which case act on THAT, or it is not, in
 * which case the honest outcome is to decline and say why -- not to drop the
 * proxy and call it a block.
 *
 * MAINTAINING THE LIST
 * --------------------
 * A static copy, deliberately. The alternative is fetching
 * https://www.cloudflare.com/ips-v4 on the blocking path, which puts a network
 * round trip -- and a failure mode -- between an attack and the response to it.
 * These ranges change very rarely; Cloudflare has announced every change years
 * in advance. Only ranges that are certain belong here: a wrong entry here is
 * an attacker this product will not block, which is worse than an omission.
 */

class ProxyRanges
{
    /**
     * Cloudflare, https://www.cloudflare.com/ips/ — verified against the two
     * addresses above: 104.21.83.159 falls in 104.16.0.0/13 and
     * 172.67.178.100 in 172.64.0.0/13.
     */
    public const CLOUDFLARE = [
        '173.245.48.0/20',  '103.21.244.0/22', '103.22.200.0/22',
        '103.31.4.0/22',    '141.101.64.0/18', '108.162.192.0/18',
        '190.93.240.0/20',  '188.114.96.0/20', '197.234.240.0/22',
        '198.41.128.0/17',  '162.158.0.0/15',  '104.16.0.0/13',
        '104.24.0.0/14',    '172.64.0.0/13',   '131.0.72.0/22',
        '2400:cb00::/32',   '2606:4700::/32',  '2803:f800::/32',
        '2405:b500::/32',   '2405:8100::/32',  '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    /** name => ranges. Adding a provider is adding one entry here. */
    public static function providers(): array
    {
        return ['Cloudflare' => self::CLOUDFLARE];
    }

    /**
     * Which provider owns this address, or null if none does.
     *
     * @return string|null e.g. "Cloudflare"
     */
    public static function nameFor(string $ip): ?string
    {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) { return null; }
        foreach (self::providers() as $name => $ranges) {
            foreach ($ranges as $cidr) {
                if (self::inRange($ip, $cidr)) { return $name; }
            }
        }
        return null;
    }

    /** True when the address belongs to any known shared proxy. */
    public static function isProxy(string $ip): bool
    {
        return self::nameFor($ip) !== null;
    }

    /**
     * Is $ip inside $cidr?
     *
     * Compares packed bytes, so one implementation covers IPv4 and IPv6 and
     * neither needs the 32-bit arithmetic that silently misbehaves on a /13.
     * An address and a range of different families never match.
     */
    public static function inRange(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) { return $ip === $cidr; }
        [$net, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $a = @inet_pton($ip);
        $b = @inet_pton($net);
        if ($a === false || $b === false) { return false; }
        if (strlen($a) !== strlen($b)) { return false; }   // v4 vs v6
        if ($bits < 0 || $bits > strlen($a) * 8) { return false; }

        $whole = intdiv($bits, 8);
        $rest  = $bits % 8;
        if ($whole > 0 && strncmp($a, $b, $whole) !== 0) { return false; }
        if ($rest === 0) { return true; }

        $mask = chr((0xFF << (8 - $rest)) & 0xFF);
        return (($a[$whole] & $mask) === ($b[$whole] & $mask));
    }

    /**
     * Pull the originating client out of a log line that came through a proxy.
     *
     * Looks for a quoted field that is ENTIRELY a comma-separated list of IP
     * addresses — the shape an X-Forwarded-For log field has and that no user
     * agent, referrer or request line ever has. Matching on shape rather than
     * on field position is what makes this safe to run against whatever log
     * format a given vhost happens to use: a format without the header simply
     * yields nothing, rather than yielding the user agent.
     *
     * The FIRST entry is the original client; everything after it is the chain
     * of proxies. That entry is attacker-controlled — anyone can send an
     * X-Forwarded-For header — so it is only ever read from a line whose
     * connecting address was a proxy we recognise, which is the one case where
     * the header was rewritten by that proxy and can be trusted.
     *
     * @return string|null a valid, non-proxy IP, or null if none is recoverable
     */
    public static function clientFromLine(string $line): ?string
    {
        // Quoted fields in order. Matching the CONTENT shape instead -- a class
        // of digits, dots, colons and commas -- paired the quotes wrongly: in
        //
        //     ... HTTP/1.1" 200 1234 "-" ... "203.0.113.9"
        //
        // the run between the request line and the next field is ` 200 1234 `,
        // which is entirely digits and spaces, so it matched as a "field" and
        // every quote after it paired up one position out. Taking whole fields
        // first and judging their content second keeps the pairing right.
        if (!preg_match_all('/"([^"]*)"/', $line, $m)) { return null; }

        foreach ($m[1] as $field) {
            $parts = array_filter(array_map('trim', explode(',', $field)), 'strlen');
            if ($parts === []) { continue; }

            $ips = [];
            foreach ($parts as $p) {
                if (filter_var($p, FILTER_VALIDATE_IP) === false) { $ips = []; break; }
                $ips[] = $p;
            }
            if ($ips === []) { continue; }

            // The first entry the proxy recorded. If that is itself a proxy
            // the chain tells us nothing useful, so decline rather than block
            // another intermediary.
            $first = $ips[0];
            if (self::isProxy($first)) { continue; }
            return $first;
        }
        return null;
    }
}
