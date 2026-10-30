<?php
/**
 * ServerScrub — crawlers that must never be blocked.
 *
 * WHY THIS EXISTS
 * ---------------
 * FROM A LIVE SERVER. At 00:15 this product put Googlebot into csf.deny:
 *
 *     66.249.73.8 # ServerScrub - Fri Oct 30 00:15:06 2026
 *
 * Nothing stopped it. Bot Shield has a good-bot check, but it matches on the
 * USER AGENT and lives only in Bot Shield -- HttpFlood and BruteForce have no
 * concept of a good bot at all, so a crawler working through a site with dead
 * links trips the not-found threshold and is blocked outright.
 *
 * The cost is asymmetric and that is the whole argument. A blocked crawler
 * means a customer's pages quietly fall out of the search index, which they
 * discover weeks later as lost traffic and cannot attribute to anything. A
 * crawler we decline to block costs a few requests.
 *
 * WHY NOT THE USER AGENT
 * ----------------------
 * Anyone can send "Googlebot" -- scrapers do it constantly, precisely because
 * so many products allow-list on that string. Trusting it would turn this file
 * into a bypass: claim to be Googlebot, never be blocked.
 *
 * So verification is by ADDRESS, the method Google and Bing both document:
 * the reverse DNS of the address must end in the operator's domain, and a
 * forward lookup of that name must come back to the same address. The PTR
 * alone is not enough -- whoever owns an address can point its PTR anywhere,
 * so the forward lookup is what makes it an operator's claim about its own
 * name rather than an attacker's claim about someone else's.
 */

class GoodBots
{
    /**
     * Published crawler ranges, checked first so the common case needs no DNS
     * at all. Deliberately short: only ranges that are documented and stable.
     * Being absent here is not a problem, it just means the slower rDNS path
     * runs. Being WRONG here is a problem, so nothing speculative goes in.
     */
    private const CRAWLER_RANGES = [
        '66.249.64.0/19'  => 'Googlebot',
        '157.55.39.0/24'  => 'Bingbot',
        '207.46.13.0/24'  => 'Bingbot',
        '40.77.167.0/24'  => 'Bingbot',
        '204.79.197.0/24' => 'Bingbot',
    ];

    /**
     * rDNS suffix => operator. A name must END with one of these, matched on a
     * dot boundary so "notgooglebot.com" and "googlebot.com.evil.net" cannot
     * pass.
     */
    private const RDNS_SUFFIXES = [
        'googlebot.com'        => 'Googlebot',
        'google.com'           => 'Google',
        'search.msn.com'       => 'Bingbot',
        'crawl.yahoo.net'      => 'Yahoo Slurp',
        'yandex.com'           => 'YandexBot',
        'yandex.ru'            => 'YandexBot',
        'yandex.net'           => 'YandexBot',
        'baidu.com'            => 'Baiduspider',
        'duckduckgo.com'       => 'DuckDuckBot',
        'applebot.apple.com'   => 'Applebot',
    ];

    /** Answers already worked out this run. */
    private static array $memo = [];

    /**
     * Which search engine operates this address, or null.
     *
     * @return string|null e.g. "Googlebot"
     */
    public static function nameFor(string $ip): ?string
    {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) { return null; }
        if (array_key_exists($ip, self::$memo)) { return self::$memo[$ip]; }

        foreach (self::CRAWLER_RANGES as $cidr => $name) {
            if (ProxyRanges::inRange($ip, $cidr)) { return self::$memo[$ip] = $name; }
        }

        return self::$memo[$ip] = self::verifyByDns($ip);
    }

    public static function isGoodBot(string $ip): bool
    {
        return self::nameFor($ip) !== null;
    }

    /**
     * Forward-confirmed reverse DNS.
     *
     * Both lookups are bounded. This runs on the path that blocks an attacker,
     * and on a loaded server DNS is exactly what goes slow first -- an
     * unbounded resolver call here would stall the thing that is supposed to
     * be stopping an attack.
     */
    private static function verifyByDns(string $ip): ?string
    {
        $name = self::ptr($ip);
        if ($name === '') { return null; }
        $name = rtrim(strtolower($name), '.');

        $operator = null;
        foreach (self::RDNS_SUFFIXES as $suffix => $who) {
            // Dot boundary, or "evil-googlebot.com" would match.
            if ($name === $suffix || substr($name, -strlen('.' . $suffix)) === '.' . $suffix) {
                $operator = $who;
                break;
            }
        }
        if ($operator === null) { return null; }

        // Forward-confirm. Anyone who controls an address controls its PTR, so
        // without this step a scraper could name itself crawl-x.googlebot.com
        // and become unblockable.
        foreach (self::forward($name) as $resolved) {
            if ($resolved === $ip) { return $operator; }
        }
        return null;
    }

    /** Reverse lookup, bounded. '' when it cannot be answered. */
    private static function ptr(string $ip): string
    {
        $out = self::dig(['-x', $ip, '+short', '+time=2', '+tries=1']);

        // No dig, no lookup.
        //
        // The obvious fallback is gethostbyaddr(), and it is the wrong answer:
        // it cannot be given a timeout, and this runs on the path that blocks
        // an attacker. On a loaded server DNS is the first thing to go slow,
        // so that fallback would stall the response to an attack precisely
        // when the attack is what made it slow -- and it hung the test suite
        // outright, which is how it was caught.
        //
        // Declining to verify costs a crawler outside the published ranges.
        // Published ranges cover Googlebot and Bingbot, which is the case that
        // actually occurred, and they need no DNS at all.
        return $out === null ? '' : trim((string) ($out[0] ?? ''));
    }

    /** Forward lookup, bounded. @return string[] */
    private static function forward(string $name): array
    {
        $out = self::dig([$name, 'A', '+short', '+time=2', '+tries=1']);
        if ($out !== null) {
            return array_values(array_filter(array_map('trim', $out), static function ($v) {
                return filter_var($v, FILTER_VALIDATE_IP) !== false;
            }));
        }
        return [];   // see ptr(): no unbounded resolver call on this path
    }

    /**
     * Run dig with a hard timeout. null when dig is unavailable, so the caller
     * knows to fall back rather than reading "no answer" into an empty array.
     *
     * @param string[] $args
     * @return string[]|null
     */
    private static function dig(array $args): ?array
    {
        static $bin = null;
        if ($bin === null) {
            $bin = false;
            foreach (['/usr/bin/dig', '/bin/dig', '/usr/local/bin/dig'] as $p) {
                if (@is_executable($p)) { $bin = $p; break; }
            }
        }
        if ($bin === false) { return null; }

        $cmd = escapeshellarg($bin);
        foreach ($args as $a) { $cmd .= ' ' . escapeshellarg($a); }
        $out = [];
        @exec($cmd . ' 2>/dev/null', $out, $code);
        return $code === 0 ? $out : [];
    }
}
