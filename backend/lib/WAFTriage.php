<?php
/**
 * ServerScrub — WAF triage
 * ─────────────────────────
 * What would happen if the rule engine were switched from detection only to
 * blocking, answered from the events already recorded rather than by trying
 * it and finding out.
 *
 * The decision an operator is actually facing is not "are these attacks". Most
 * of them obviously are. It is "which of these rules, if armed, would turn
 * away one of my customers' real visitors" — because on a shared server a
 * single false positive in blocking mode is somebody's shop refusing orders,
 * and it will be reported as the hosting being broken.
 *
 * So the question this answers per rule is: does this look like SOMEBODY
 * SCANNING THE INTERNET, or like ONE SITE'S OWN TRAFFIC?
 *
 *   many IPs × many hosts × probe-shaped URIs   → scanning. Arm it.
 *   few IPs × one host × ordinary-looking URIs  → that host's own traffic,
 *                                                 or someone targeting it.
 *                                                 Look before arming.
 *
 * Neither signal is conclusive on its own, which is why three are used and
 * why the verdict for anything in between is "review" rather than a guess.
 * A tool that says "safe to block" about a rule that is not costs more than
 * one that says "look at this".
 *
 * WHAT THE NUMBERS ARE NOT
 * ────────────────────────
 * saveWafEvent() drops an event matching the same rule from the same IP
 * within 60 seconds of the last one. So these are not request counts; they
 * are distinct rule+IP+minute observations, and a flood is undercounted. They
 * are the right numbers for comparing rules against each other, which is what
 * this does, and the wrong numbers for reporting attack volume. Said here
 * because the difference is invisible in the output.
 */

require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';
// For the engine mode printed in the report header. Required rather than
// guarded with class_exists: "report the mode if somebody happens to have
// loaded the class" means the header silently says unknown from cron.
require_once __DIR__ . '/WAFInstaller.php';

class WAFTriage
{
    /** Hard ceiling on rows examined, so a triage cannot become the load. */
    private const MAX_ROWS = 200000;

    /**
     * URIs that are nobody's real traffic.
     *
     * A request for /.env is not a visitor who mistyped. Nothing here is a
     * path a browser follows from a link on a working site, which is what
     * makes a rule that only ever fires on these safe to arm.
     *
     * Deliberately narrow. Adding something broad like /admin would mark
     * every site with an admin panel as scanner traffic and the verdicts
     * would stop meaning anything.
     */
    /**
     * URIs that are nobody's real traffic.
     *
     * A request for /.env is not a visitor who mistyped. Nothing here is a
     * path a browser follows from a link on a working site, which is what
     * makes a rule that only ever fires on these safe to arm.
     *
     * THE FIRST VERSION WAS TOO STRICT AND IT SHOWED. Anchoring `.env` on a
     * preceding slash missed /config.env, /secrets.env and /ses.env; the
     * optional-suffix form missed /.env.supabase and /.env.anthropic. So a
     * rule whose every URI was an env-file probe scored 0% and came back as
     * "check a few before arming" -- 33 rules landed in that pile on a live
     * server, which leaves the operator reading exactly the list the tool was
     * supposed to read for them. Being conservative is right; being so
     * conservative that nothing is decided is just a slower way of not
     * helping.
     *
     * Still deliberately narrow. Nothing here matches a path a real site
     * serves: no bare /admin, no /index.php, no /login.
     */
    private const PROBE_URI = '#(?:^|/)\.(?:env|git|aws|ssh|svn|hg|htpasswd|npmrc|docker)(?:[./]|$)
                               |\.env(?:[.\-_][\w.\-]*)?(?:$|\?)
                               |(?:^|/)env(?:[.\-_][\w.\-]*)?(?:$|\?)
                               |wp-config(?:-sample)?\.php[~.]?\w*$
                               |wp-config\.(?:bak|old|save|txt|orig|swp)$
                               |configuration\.php[~.]?\w*$
                               |config(?:uration)?\.(?:php|inc|ini|json|yml|yaml)\.(?:bak|old|save|txt|orig|swp|dist)$
                               |(?:^|/)(?:phpinfo|info|test|hello)\w*\.php\d?$
                               |(?:^|/)(?:shell|c99|r57|wso|alfa|alfa-rex|adminer|b1ack|filefuns|
                                         wp-conflg|wp-l0gin|xmrlpc|worksec|wp-firewall|mail\d|
                                         wp-plain|lndex|gecko|cache|dog|uGaFTFu|moon)\w*\.php\d?$
                               |\.(?:sql|sql\.gz|tar\.gz|tgz|zip|bak|old|swp|log)(?:$|\?)
                               |(?:^|/)vendor/phpunit/
                               |(?:^|/)(?:cgi-bin|boaform|HNAP1|actuator|druid|solr|jenkins)/
                               |(?:\.\.|%2e%2e|\.\.%2f|\.\.\.\.//)
                               |proc/self/environ
                               |credentials(?:%3F|\?|\.|$)
                               |(?:^|/)wp-content/(?:upgrade|uploads|plugins/WordPressCore)/[\w.\-]*\.php\d?$
                              #xi';

    /**
     * Addresses that are not the internet.
     *
     * 127.0.0.1 appeared in this server's attacker list with 862 hits across
     * 39 rules and 84 sites. That is not somebody attacking from the machine
     * itself -- it is the real client address being lost, because cPanel's
     * nginx reverse proxy terminates the connection and Apache sees loopback
     * unless mod_remoteip is configured to read X-Forwarded-For.
     *
     * It matters twice. Those events have no usable source, so the IP-spread
     * signal is wrong for every rule they appear in. And an operator reading
     * "127.0.0.1, 39 rules" as an attacker and blocking it takes the site
     * down. Separated out and called what it is.
     */
    private static function isLocalOrPrivate(string $ip): bool
    {
        if ($ip === '') { return true; }
        return filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    /** A window that has rows in it, expressed as a unix timestamp. */
    private static function since(int $days): int
    {
        return time() - (max(1, min(365, $days)) * 86400);
    }

    /**
     * The triage report.
     *
     * @return array{window_days:int,generated_at:int,totals:array,
     *               rules:array,hosts:array,attackers:array,notes:string[]}
     */
    public static function report(int $days = 7, int $topRules = 25): array
    {
        $since = self::since($days);
        $notes = [];

        $total = (int) (Database::fetchOne(
            "SELECT COUNT(*) c FROM waf_events WHERE timestamp >= ?", [$since])['c'] ?? 0);

        if ($total > self::MAX_ROWS) {
            $notes[] = sprintf(
                'Only the most recent %s of %s events in the window were examined.',
                number_format(self::MAX_ROWS), number_format($total));
        }

        // One pass, aggregated in SQL. Pulling 148,000 rows into PHP to count
        // them would be the slowest possible way to do this on a live server.
        $rules = Database::fetchAll(
            "SELECT rule_id,
                    COUNT(*)                      AS hits,
                    COUNT(DISTINCT ip_address)    AS ips,
                    COUNT(DISTINCT host)          AS hosts,
                    MIN(timestamp)                AS first_seen,
                    MAX(timestamp)                AS last_seen,
                    MAX(severity)                 AS severity,
                    MAX(rule_msg)                 AS rule_msg
               FROM waf_events
              WHERE timestamp >= ? AND rule_id IS NOT NULL AND rule_id != ''
           GROUP BY rule_id
           ORDER BY hits DESC
              LIMIT ?", [$since, max(1, min(200, $topRules))]);

        foreach ($rules as &$r) {
            $rid = (string) $r['rule_id'];

            // A sample of this rule's URIs, to judge their shape. Capped: the
            // question is what they look like, and twenty answers it as well
            // as twenty thousand.
            $uris = Database::fetchAll(
                "SELECT uri, COUNT(*) c FROM waf_events
                  WHERE timestamp >= ? AND rule_id = ? AND uri IS NOT NULL AND uri != ''
               GROUP BY uri ORDER BY c DESC LIMIT 20", [$since, $rid]);

            $probe = 0;
            $sample = [];
            foreach ($uris as $u) {
                if (preg_match(self::PROBE_URI, (string) $u['uri'])) { $probe++; }
                if (count($sample) < 5) {
                    $sample[] = ['uri' => mb_substr((string) $u['uri'], 0, 120),
                                 'hits' => (int) $u['c']];
                }
            }
            $distinctUris   = count($uris);
            $r['uri_sample']  = $sample;
            $r['probe_ratio'] = $distinctUris > 0
                ? round($probe / $distinctUris, 2)
                : 0.0;

            // Which sites it fires on, since that is who an armed rule would
            // affect.
            $r['top_hosts'] = Database::fetchAll(
                "SELECT COALESCE(NULLIF(host,''),'(not recorded)') h, COUNT(*) c
                   FROM waf_events WHERE timestamp >= ? AND rule_id = ?
               GROUP BY h ORDER BY c DESC LIMIT 5", [$since, $rid]);

            [$r['verdict'], $r['why']] = self::verdict($r, $distinctUris);
        }
        unset($r);

        // The sites an armed engine would affect most, which is the other way
        // round from the rule list and the one that answers "whose site?".
        $hosts = Database::fetchAll(
            "SELECT COALESCE(NULLIF(host,''),'(not recorded)') AS host,
                    COUNT(*) AS hits,
                    COUNT(DISTINCT rule_id) AS rules,
                    COUNT(DISTINCT ip_address) AS ips
               FROM waf_events WHERE timestamp >= ?
           GROUP BY host ORDER BY hits DESC LIMIT 15", [$since]);

        // Addresses tripping many different rules are running a scanner, not
        // stumbling into one.
        $rawAttackers = Database::fetchAll(
            "SELECT ip_address, COUNT(*) AS hits,
                    COUNT(DISTINCT rule_id) AS rules,
                    COUNT(DISTINCT host)    AS hosts,
                    MAX(timestamp)          AS last_seen
               FROM waf_events
              WHERE timestamp >= ? AND ip_address IS NOT NULL AND ip_address != ''
           GROUP BY ip_address
           HAVING rules >= 2
           ORDER BY rules DESC, hits DESC LIMIT 40", [$since]);

        // Loopback and RFC1918 are not attackers. Listing them invites
        // somebody to block 127.0.0.1, which takes the server off the air.
        $attackers = [];
        $proxied   = 0;
        foreach ($rawAttackers as $a) {
            if (self::isLocalOrPrivate((string) $a['ip_address'])) {
                $proxied += (int) $a['hits'];
                continue;
            }
            if (count($attackers) < 15) { $attackers[] = $a; }
        }

        $localTotal = (int) (Database::fetchOne(
            "SELECT COUNT(*) c FROM waf_events
              WHERE timestamp >= ? AND (ip_address = '127.0.0.1' OR ip_address = '::1'
                                        OR ip_address LIKE '10.%' OR ip_address LIKE '192.168.%'
                                        OR ip_address = '')", [$since])['c'] ?? 0);
        if ($localTotal > 0) {
            $notes[] = sprintf(
                '%s event(s) — %d%% — were recorded from loopback or a private '
              . 'address. The real client IP is being lost, almost certainly '
              . 'because a reverse proxy (cPanel ships nginx in front of '
              . 'Apache) terminates the connection and mod_remoteip is not '
              . 'reading X-Forwarded-For. Those events cannot be attributed, '
              . 'the IP-spread signal is understated for every rule they '
              . 'appear in, and NOTHING in that group should ever be blocked.',
                number_format($localTotal),
                $total > 0 ? (int) round($localTotal / $total * 100) : 0);
        }

        $hostRecorded = (int) (Database::fetchOne(
            "SELECT COUNT(*) c FROM waf_events
              WHERE timestamp >= ? AND host IS NOT NULL AND host != ''",
            [$since])['c'] ?? 0);
        if ($total > 0 && $hostRecorded === 0) {
            // Worth saying loudly: without a host the per-site view is empty
            // and the verdicts lose one of their three signals.
            $notes[] = 'No event in this window recorded a Host header, so the '
                     . 'per-site breakdown is empty and rule verdicts rest on '
                     . 'IP spread and URI shape alone. SecAuditLogParts must '
                     . 'include B for the host to be logged.';
        }

        return [
            'window_days'  => $days,
            'generated_at' => time(),
            'engine_mode'  => WAFInstaller::currentMode(),
            'totals'       => [
                'events'        => $total,
                'rules'         => (int) (Database::fetchOne(
                    "SELECT COUNT(DISTINCT rule_id) c FROM waf_events WHERE timestamp >= ?",
                    [$since])['c'] ?? 0),
                'ips'           => (int) (Database::fetchOne(
                    "SELECT COUNT(DISTINCT ip_address) c FROM waf_events WHERE timestamp >= ?",
                    [$since])['c'] ?? 0),
                'hosts'         => (int) (Database::fetchOne(
                    "SELECT COUNT(DISTINCT host) c FROM waf_events
                      WHERE timestamp >= ? AND host != ''", [$since])['c'] ?? 0),
            ],
            'rules'     => $rules,
            'hosts'     => $hosts,
            'attackers' => $attackers,
            'notes'     => $notes,
        ];
    }

    /**
     * Scanner traffic, one site's own traffic, or not enough to say.
     *
     * Three signals, none trusted alone:
     *
     *   ips    how many different addresses tripped it. One address is a
     *          person or one broken client; hundreds is the internet.
     *   hosts  how many different sites. A rule firing across the server is
     *          not about any one site's application.
     *   probe  what fraction of its distinct URIs are paths nobody requests
     *          by accident.
     *
     * The conservative direction is deliberate. "Review" costs a minute of
     * reading; "safe to block" about a rule that is not costs a customer's
     * site, and the trust that it will not happen again.
     */
    private static function verdict(array $r, int $distinctUris): array
    {
        $ips   = (int) $r['ips'];
        $hosts = (int) $r['hosts'];
        $probe = (float) $r['probe_ratio'];
        $hits  = (int) $r['hits'];

        if ($hits < 5) {
            return ['too-few', 'Only ' . $hits . ' observation(s) — not enough '
                             . 'to tell scanning from a one-off.'];
        }

        // Unambiguous scanning: spread wide, and asking for things that do not
        // exist on anybody's site.
        if ($probe >= 0.8 && $ips >= 5) {
            return ['arm', 'Fires on ' . $ips . ' addresses across '
                         . max(1, $hosts) . ' site(s), and '
                         . (int) round($probe * 100) . '% of its URIs are paths '
                         . 'nobody requests by accident. Blocking these turns '
                         . 'away nothing real.'];
        }

        // Wide spread, ordinary-looking URIs. Probably still scanning, but the
        // URI signal is not backing it up, so it is not called safe.
        if ($ips >= 20 && $hosts >= 3) {
            return ['likely-arm', 'Spread across ' . $ips . ' addresses and '
                                . $hosts . ' sites, but its URIs do not look '
                                . 'like probes — check a few before arming.'];
        }

        // The shape that costs customers: one site, few sources, normal paths.
        if ($hosts <= 1 && $ips <= 3 && $probe < 0.3) {
            return ['false-positive-risk',
                    'Confined to one site and ' . $ips . ' address(es), on '
                  . 'ordinary-looking URIs. This is the shape of a rule '
                  . 'matching that site\'s own application — arming it may '
                  . 'break that site.'];
        }

        return ['review', 'Mixed signals: ' . $ips . ' address(es), '
                        . max(1, $hosts) . ' site(s), '
                        . (int) round($probe * 100) . '% probe-shaped URIs '
                        . 'across ' . $distinctUris . ' distinct path(s).'];
    }

    /** The report as text, for a terminal or for pasting into a message. */
    public static function text(array $rep): string
    {
        $o = [];
        // A closure binding $o BY REFERENCE. As `fn($s = '') => $o[] = $s`
        // this silently produced an empty report: arrow functions capture by
        // value, so every line was appended to a copy and thrown away. The
        // function returned a string, the caller printed it, and it was
        // blank -- no error anywhere.
        $w = function ($s = '') use (&$o) { $o[] = $s; };
        $num = fn($n) => number_format((int) $n);

        $w('ServerScrub — WAF triage');
        $w('Generated ' . date('Y-m-d H:i:s', (int) $rep['generated_at'])
           . '  ·  last ' . $rep['window_days'] . ' day(s)'
           . '  ·  engine: ' . $rep['engine_mode']);
        $w(str_repeat('=', 72));
        $w();

        $t = $rep['totals'];
        $w(sprintf('%s events · %s distinct rules · %s source IPs · %s sites',
                   $num($t['events']), $num($t['rules']), $num($t['ips']),
                   $num($t['hosts'])));
        $w();
        $w('Counts are distinct rule+IP observations, not requests: an event');
        $w('matching the same rule from the same IP within 60s is not stored');
        $w('again. Good for comparing rules; not a measure of attack volume.');
        $w();

        foreach ($rep['notes'] as $n) { $w('NOTE: ' . $n); }
        if ($rep['notes']) { $w(); }

        // Grouped by verdict, because the verdict is the thing being acted on.
        $order = ['false-positive-risk' => 'WOULD LIKELY BREAK A SITE — look before arming',
                  'review'              => 'NEEDS A LOOK',
                  'likely-arm'          => 'PROBABLY SAFE — spot-check a URI',
                  'arm'                 => 'SAFE TO ARM — scanner traffic only',
                  'too-few'             => 'TOO FEW OBSERVATIONS'];

        foreach ($order as $verdict => $heading) {
            $set = array_values(array_filter($rep['rules'],
                fn($r) => $r['verdict'] === $verdict));
            if (!$set) { continue; }

            $w(str_repeat('-', 72));
            $w($heading . '  (' . count($set) . ' rule(s))');
            $w(str_repeat('-', 72));
            foreach ($set as $r) {
                $w(sprintf('  rule %-8s  %s hits · %s IPs · %s site(s) · %s',
                           $r['rule_id'], $num($r['hits']), $num($r['ips']),
                           $num($r['hosts']), $r['severity'] ?: 'severity?'));
                $w('    ' . mb_substr((string) $r['rule_msg'], 0, 100));
                $w('    ' . wordwrap($r['why'], 66, "\n    "));
                foreach ($r['uri_sample'] as $u) {
                    $w(sprintf('      %6s  %s', $num($u['hits']), $u['uri']));
                }
                $hs = array_map(fn($h) => $h['h'] . ' (' . $num($h['c']) . ')',
                                $r['top_hosts']);
                if ($hs) { $w('      sites: ' . implode(', ', array_slice($hs, 0, 4))); }
                $w();
            }
        }

        if ($rep['hosts']) {
            $w(str_repeat('-', 72));
            $w('SITES MOST AFFECTED IF THE ENGINE IS ARMED');
            $w(str_repeat('-', 72));
            foreach ($rep['hosts'] as $h) {
                $w(sprintf('  %-44s %8s hits · %s rules · %s IPs',
                           mb_substr((string) $h['host'], 0, 44), $num($h['hits']),
                           $num($h['rules']), $num($h['ips'])));
            }
            $w();
        }

        if ($rep['attackers']) {
            $w(str_repeat('-', 72));
            $w('ADDRESSES TRIPPING SEVERAL RULES — running a scanner, not stumbling');
            $w(str_repeat('-', 72));
            foreach ($rep['attackers'] as $a) {
                $w(sprintf('  %-40s %6s hits · %s rules · %s sites · last %s',
                           $a['ip_address'], $num($a['hits']), $num($a['rules']),
                           $num($a['hosts']),
                           date('Y-m-d H:i', (int) $a['last_seen'])));
            }
            $w();
        }

        return implode("\n", $o) . "\n";
    }
}
