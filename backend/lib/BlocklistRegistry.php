<?php
/**
 * Sentinel Gate — DNS blocklist registry and checker
 *
 * Queries the major public DNSBL/RBL services and reports EACH ONE separately,
 * so the UI can show the full matrix and highlight exactly which services list
 * an address. The previous implementation checked four lists and collapsed them
 * into a single score, which tells an operator that something is wrong but not
 * where to go to fix it — and delisting requires knowing the specific service.
 *
 * ── HOW A DNSBL WORKS ────────────────────────────────────────────────────────
 * The address is reversed and prefixed to the zone: 1.2.3.4 against
 * zen.spamhaus.org becomes a lookup of 4.3.2.1.zen.spamhaus.org. An A record
 * means listed; NXDOMAIN means clean. The returned 127.0.0.x address encodes
 * WHY it is listed, which differs per service — hence the per-service return
 * code maps below.
 *
 * ── ACCURACY NOTES ───────────────────────────────────────────────────────────
 * * Some zones return a result for every query when used through a public
 *   resolver (Spamhaus in particular blocks bulk/public DNS). A 127.255.255.x
 *   answer means "query refused", NOT "listed" — treating it as a listing would
 *   report every address on the internet as blacklisted.
 * * Lists are weighted. Being on a policy list such as a dynamic-IP range is
 *   normal for residential space and is not evidence of abuse, whereas an
 *   exploit or botnet listing is serious. A flat count would rank those equally.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class BlocklistRegistry
{
    /**
     * category: spam | exploit | policy | proxy | composite
     * weight:   contribution to the risk score when listed (0-25)
     */
    public const LISTS = [
        // ── Spamhaus ────────────────────────────────────────────────────────
        ['id'=>'spamhaus_zen','name'=>'Spamhaus ZEN','zone'=>'zen.spamhaus.org',
         'category'=>'composite','weight'=>25,'site'=>'https://check.spamhaus.org/',
         'codes'=>['127.0.0.2'=>'SBL — direct spam source','127.0.0.3'=>'CSS — snowshoe spam',
                   '127.0.0.4'=>'XBL — exploited machine','127.0.0.9'=>'DROP — hijacked netblock',
                   '127.0.0.10'=>'PBL — not a legitimate mail sender',
                   '127.0.0.11'=>'PBL — ISP-declared dynamic range']],

        // ── Barracuda ───────────────────────────────────────────────────────
        ['id'=>'barracuda','name'=>'Barracuda BRBL','zone'=>'b.barracudacentral.org',
         'category'=>'spam','weight'=>18,'site'=>'https://www.barracudacentral.org/rbl/removal-request'],

        // ── SpamCop ─────────────────────────────────────────────────────────
        ['id'=>'spamcop','name'=>'SpamCop','zone'=>'bl.spamcop.net',
         'category'=>'spam','weight'=>18,'site'=>'https://www.spamcop.net/bl.shtml'],

        // ── SORBS family ────────────────────────────────────────────────────
        ['id'=>'sorbs','name'=>'SORBS Aggregate','zone'=>'dnsbl.sorbs.net',
         'category'=>'composite','weight'=>12,'site'=>'https://www.sorbs.net/lookup.shtml'],
        ['id'=>'sorbs_spam','name'=>'SORBS Spam','zone'=>'spam.dnsbl.sorbs.net',
         'category'=>'spam','weight'=>15,'site'=>'https://www.sorbs.net/lookup.shtml'],
        ['id'=>'sorbs_web','name'=>'SORBS Web (vulnerable)','zone'=>'web.dnsbl.sorbs.net',
         'category'=>'exploit','weight'=>12,'site'=>'https://www.sorbs.net/lookup.shtml'],

        // ── UCEPROTECT ──────────────────────────────────────────────────────
        ['id'=>'uceprotect1','name'=>'UCEPROTECT L1','zone'=>'dnsbl-1.uceprotect.net',
         'category'=>'spam','weight'=>12,'site'=>'https://www.uceprotect.net/en/rblcheck.php'],
        ['id'=>'uceprotect2','name'=>'UCEPROTECT L2','zone'=>'dnsbl-2.uceprotect.net',
         'category'=>'policy','weight'=>5,'site'=>'https://www.uceprotect.net/en/rblcheck.php'],
        ['id'=>'uceprotect3','name'=>'UCEPROTECT L3','zone'=>'dnsbl-3.uceprotect.net',
         'category'=>'policy','weight'=>3,'site'=>'https://www.uceprotect.net/en/rblcheck.php'],

        // ── Abusix / Mailspike / others ─────────────────────────────────────
        ['id'=>'spameatingmonkey','name'=>'Spam Eating Monkey','zone'=>'bl.spameatingmonkey.net',
         'category'=>'spam','weight'=>10,'site'=>'https://spameatingmonkey.com/lookup'],
        ['id'=>'mailspike','name'=>'Mailspike','zone'=>'bl.mailspike.net',
         'category'=>'spam','weight'=>12,'site'=>'https://www.mailspike.net/iplookup'],
        ['id'=>'spfbl','name'=>'SPFBL','zone'=>'dnsbl.spfbl.net',
         'category'=>'spam','weight'=>8,'site'=>'https://spfbl.net/en/dnsbl/'],
        ['id'=>'blocklist_de','name'=>'Blocklist.de','zone'=>'bl.blocklist.de',
         'category'=>'exploit','weight'=>15,'site'=>'https://www.blocklist.de/en/delist.html'],
        ['id'=>'drone_abuse','name'=>'Abuse.ch DroneBL','zone'=>'dnsbl.dronebl.org',
         'category'=>'exploit','weight'=>18,'site'=>'https://dronebl.org/lookup'],
        ['id'=>'cbl_abuseat','name'=>'CBL / abuseat','zone'=>'cbl.abuseat.org',
         'category'=>'exploit','weight'=>20,'site'=>'https://www.abuseat.org/lookup.cgi'],
        ['id'=>'psbl','name'=>'PSBL (Passive Spam)','zone'=>'psbl.surriel.com',
         'category'=>'spam','weight'=>10,'site'=>'https://psbl.org/'],
        ['id'=>'interserver','name'=>'InterServer RBL','zone'=>'rbl.interserver.net',
         'category'=>'spam','weight'=>8,'site'=>'https://rbl.interserver.net/'],
        ['id'=>'woody','name'=>'Woody SMTP BL','zone'=>'db.wpbl.info',
         'category'=>'spam','weight'=>8,'site'=>'https://www.wpbl.info/'],
        ['id'=>'nordspam','name'=>'NordSpam','zone'=>'bl.nordspam.com',
         'category'=>'spam','weight'=>8,'site'=>'https://www.nordspam.com/removal/'],
        ['id'=>'gbudb','name'=>'GBUdb Truncate','zone'=>'truncate.gbudb.net',
         'category'=>'spam','weight'=>10,'site'=>'https://www.gbudb.com/'],
        ['id'=>'s5h','name'=>'s5h.net','zone'=>'all.s5h.net',
         'category'=>'composite','weight'=>8,'site'=>'https://www.usenix.org.uk/content/rbl.html'],
        ['id'=>'suomispam','name'=>'SuomiSpam','zone'=>'bl.suomispam.net',
         'category'=>'spam','weight'=>5,'site'=>'https://suomispam.net/'],
        ['id'=>'anonmails','name'=>'AnonMails','zone'=>'spam.dnsbl.anonmails.de',
         'category'=>'spam','weight'=>6,'site'=>'https://anonmails.de/dnsbl.php'],
        ['id'=>'0spam','name'=>'0SPAM','zone'=>'bl.0spam.org',
         'category'=>'spam','weight'=>8,'site'=>'https://0spam.org/'],
        ['id'=>'backscatterer','name'=>'Backscatterer','zone'=>'ips.backscatterer.org',
         'category'=>'policy','weight'=>5,'site'=>'https://www.backscatterer.org/'],
    ];

    /** Answers meaning "your query was refused", not "this address is listed". */
    private const REFUSAL_PREFIXES = ['127.255.255.'];

    /**
     * Check one address against every list.
     *
     * @param int $timeout per-query seconds
     * @return array{ip:string,checked:int,listed:int,score:int,risk:string,results:array}
     */
    public static function checkAll(string $ip, int $timeout = 3): array
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return ['error' => 'Only IPv4 addresses can be checked against these lists.',
                    'ip' => $ip, 'results' => []];
        }

        $rev = implode('.', array_reverse(explode('.', $ip)));
        $results = [];
        $score = 0;
        $listed = 0;

        foreach (self::LISTS as $l) {
            $r = self::query($rev, $l, $timeout);
            if ($r['listed']) {
                $listed++;
                $score += $l['weight'];
            }
            $results[] = $r;
        }

        // Cap at 100 — enough overlapping lists would otherwise exceed it and
        // make the number meaningless.
        $score = min(100, $score);

        return [
            'ip'         => $ip,
            'checked'    => count(self::LISTS),
            'listed'     => $listed,
            'score'      => $score,
            'risk'       => self::risk($score),
            'results'    => $results,
            'checked_at' => time(),
        ];
    }

    private static function query(string $rev, array $list, int $timeout): array
    {
        $host = $rev . '.' . $list['zone'];
        $base = [
            'id'       => $list['id'],
            'name'     => $list['name'],
            'zone'     => $list['zone'],
            'category' => $list['category'],
            'weight'   => $list['weight'],
            'site'     => $list['site'] ?? '',
        ];

        // dns_get_record is used rather than checkdnsrr so the returned 127.0.0.x
        // value is available — that code is what explains WHY the address is
        // listed, and it differs per service.
        $rec = @dns_get_record($host, DNS_A);

        if (!$rec) {
            return $base + ['listed' => false, 'status' => 'clean', 'code' => null, 'reason' => null];
        }

        $codes = [];
        foreach ($rec as $r) {
            if (!empty($r['ip'])) { $codes[] = $r['ip']; }
        }
        if (!$codes) {
            return $base + ['listed' => false, 'status' => 'clean', 'code' => null, 'reason' => null];
        }

        // A refusal answer is not a listing. Reporting it as one would mark
        // every address as blacklisted whenever a public resolver is in use.
        foreach ($codes as $c) {
            foreach (self::REFUSAL_PREFIXES as $p) {
                if (strpos($c, $p) === 0) {
                    return $base + ['listed' => false, 'status' => 'refused', 'code' => $c,
                        'reason' => 'The list refused this query (public resolvers are often '
                                  . 'blocked). Result unknown, not clean.'];
                }
            }
        }

        $reasons = [];
        foreach ($codes as $c) {
            $reasons[] = $list['codes'][$c] ?? ('Listed (' . $c . ')');
        }

        return $base + [
            'listed' => true,
            'status' => 'listed',
            'code'   => implode(', ', $codes),
            'reason' => implode('; ', array_unique($reasons)),
        ];
    }

    private static function risk(int $score): string
    {
        if ($score >= 60) { return 'critical'; }
        if ($score >= 35) { return 'high'; }
        if ($score >= 15) { return 'medium'; }
        if ($score > 0)   { return 'low'; }
        return 'clean';
    }

    /** The addresses this server sends mail from — what an operator most wants checked. */
    public static function serverIps(): array
    {
        $ips = [];
        @exec("ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1", $out);
        foreach ((array)$out as $ip) {
            $ip = trim($ip);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $ips[] = $ip; }
        }
        if (!$ips) {
            $h = gethostname();
            $ip = $h ? gethostbyname($h) : '';
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $ips[] = $ip; }
        }
        return array_values(array_unique($ips));
    }
}
