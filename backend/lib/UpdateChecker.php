<?php

/* Pulls in what it calls, rather than trusting the caller to have done it.
 * UserReport did not, and `serverscrub user-reports` died with
 * Class "UserScanRequest" not found on all 132 accounts -- silently,
 * because writeAll() catches Throwable per account. require_once is
 * idempotent and safe across the cycles these classes form. */
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';

/**
 * ServerScrub — Update Checker
 * Polls the GitHub Releases API and stores the result in the DB.
 * The cron script calls checkForUpdates() once a day.
 * The API exposes the cached result so the frontend can show a banner.
 */

class UpdateChecker {

    // GitHub repo — change if the repo moves
    /**
     * WHERE "IS THERE AN UPDATE?" IS ANSWERED FROM
     * --------------------------------------------
     * latest.json on the release channel, which is the SAME source update.sh
     * downloads from. It has to be the same source. This class used to ask the
     * GitHub Releases API instead, and the two disagreed:
     *
     *   - publish.sh creates the Release through the API, and skips that step
     *     when there is no gh binary and no GH_TOKEN on the machine doing the
     *     release. v4.6.0 shipped exactly that way.
     *   - So the Releases API still described v4.5.1 while latest.json, the
     *     CDN and the committed zip all described v4.6.0.
     *
     * The panel therefore reported "up to date" on a server a version behind,
     * and automatic updating — which asks this class whether to run — would
     * never have fired at all. A manifest that the updater itself reads cannot
     * drift away from what the updater installs.
     *
     * The channel order matches update.sh: our own CDN first (no API rate
     * limit, and it works on servers whose firewall blocks github.com, which
     * is the failure that broke updates in the field at v3.3.6), then the
     * GitHub raw mirror.
     *
     * The Releases API is not consulted at all any more, not even as a
     * fallback. A fallback to a source that can be a version behind would
     * reintroduce the same disagreement under a rarer condition, which is
     * worse than not having one -- it would be wrong only occasionally.
     */
    private const USER_AGENT = 'ServerScrub-UpdateChecker/1.0';

    /**
     * Test seam. Null in production, and nothing but tests/ may set it.
     *
     * Channel selection is the logic that decided, wrongly, that every server
     * in the field was up to date on 2026-11-13, and it is pure decision-
     * making over what the channels answered. Without a seam it can only be
     * exercised against the live CDN, which is to say not at all in CI, and
     * untested selection logic is exactly what shipped. The callable receives
     * the FINAL url -- cache-buster and all -- plus the request headers, so a
     * test can assert the fetch itself and not merely the choice made from it.
     *
     * @var callable|null (string $url, array $headers): ?string
     */
    private static $fetcher = null;

    /** @param callable|null $f (string $url, array $headers): ?string */
    public static function setFetcherForTests(?callable $f): void
    {
        if (!defined('SG_TEST')) {
            throw new RuntimeException(
                'UpdateChecker::setFetcherForTests is for tests/ only');
        }
        self::$fetcher = $f;
    }

    private static function channels(): array
    {
        $cdn  = getenv('SG_CDN_BASE') ?: 'https://serverscrub.com/releases';
        $repo = getenv('SG_RELEASES_REPO') ?: 'admin-lagoonspace/cP-Defender';
        $raw  = 'https://raw.githubusercontent.com/' . $repo . '/'
              . (getenv('SG_RELEASES_BRANCH') ?: 'main');

        $explicit = getenv('SG_MANIFEST_URL');
        if (is_string($explicit) && $explicit !== '') {
            return [preg_replace('#/latest\.json$#', '', $explicit)];
        }
        return [$cdn, $raw];
    }

    private static function repoSlug(): string
    {
        return getenv('SG_RELEASES_REPO') ?: 'admin-lagoonspace/cP-Defender';
    }

    /**
     * The url of a manifest that is addressed BY VERSION, and so cannot be
     * served stale by anything.
     *
     * `?cb=` is not enough on every channel. MEASURED 2026-11-23 against
     * raw.githubusercontent.com, the same object, two consecutive requests:
     *
     *   .../main/latest.json                   -> X-Cache: MISS  ETag "f7a7cab..."
     *   .../main/latest.json?cb=17954488137754 -> X-Cache: HIT   ETag "f7a7cab..."
     *
     * Identical ETag, cache HIT on the "cache-busted" url: the query string is
     * not part of Fastly's cache key for raw, so the trick that does defeat
     * cPanel's nginx cache in front of our own CDN does nothing there. The
     * branch path is served with max-age=300, which is the five-minute window
     * the operator landed in when v4.37.8 was published and the updater
     * reported v4.37.7 as current.
     *
     * The shape differs per channel. On raw the version is a git ref and
     * REPLACES the branch component; appending v<ver> to .../<repo>/main/ is a
     * 404 and always was. On a file channel it is a directory under the root.
     */
    private static function pinnedManifestUrl(string $base, string $ver): string
    {
        if (strncmp($base, 'https://raw.githubusercontent.com/', 34) === 0) {
            return 'https://raw.githubusercontent.com/' . self::repoSlug()
                 . '/v' . $ver . '/latest.json';
        }
        return rtrim($base, '/') . '/v' . $ver . '/latest.json';
    }

    /**
     * The newest version a channel can name without reading a mutable path.
     *
     * For the GitHub channel that is the tag list. The releases API is not
     * used: github.com/<repo>/releases/latest 302s to /releases, which is what
     * a repo with no published Release objects does, so there is no "latest
     * release" object to read. Tags exist, and publish.sh fails a release
     * without one.
     *
     * One request. Unauthenticated the limit is 60/hour/IP and the answer
     * carries s-maxage=60 -- so the LIST can be a minute old, which is worth
     * saying plainly. It is the manifest under the tag that cannot be stale,
     * and that is what gets fetched and compared next.
     *
     * A channel that is just files over HTTP has no ref listing; it
     * corroborates through latest/VERSION and its per-build manifest instead.
     */
    private static function immutableChannelVersion(string $base): string
    {
        if (strncmp($base, 'https://raw.githubusercontent.com/', 34) !== 0) {
            return '';
        }
        $body = self::httpGet('https://api.github.com/repos/' . self::repoSlug()
                            . '/tags?per_page=10');
        if ($body === null) {
            return '';
        }
        if (!preg_match_all('/"name"\s*:\s*"v?(\d+\.\d+\.\d+[^"]*)"/', $body, $mm)) {
            return '';
        }
        // Highest by version, not whatever the API listed first: tag order is
        // not a documented guarantee, and v4.9.0 sorts above v4.36.0 when
        // compared one character at a time.
        $best = '';
        foreach ($mm[1] as $v) {
            if ($best === '' || version_compare($v, $best, '>')) {
                $best = $v;
            }
        }
        return $best;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Return the cached update state stored in the DB.
     * Called by the frontend on every dashboard load (cheap — no HTTP).
     */
    public static function getCachedStatus(): array {
        $latest      = ltrim((string) Database::setting('update_latest_ver',  ''), 'v');
        $current     = defined('SG_VERSION') ? SG_VERSION : (Database::setting('sg_version', '0.0.0'));
        $checkedAt   = Database::setting('update_checked_at',  '0');
        $releaseUrl  = Database::setting('update_release_url', '');
        $releaseNotes= Database::setting('update_release_notes','');

        // DERIVED HERE, never read back from the stored flag.
        //
        // `update_available` is a function of (latest, current). Persisting the
        // ANSWER meant it was computed against the version that was installed
        // at check time -- and then the install was upgraded, which is the one
        // event guaranteed to invalidate it.
        //
        // The result: immediately after every successful upgrade the panel
        // announced "New version available - v4.15.0" directly above "You are
        // running v4.15.0". The flag said 1 because it was written while the
        // server was still on 4.14.1, and nothing cleared it. Upgrades run from
        // a shell script that has no reason to touch this database, so there
        // was no moment at which it could have been cleared.
        //
        // Deriving at read time is self-correcting whatever upgraded the files:
        // the panel's own updater, /home/upgrade.sh, or an rsync by hand.
        $available = $latest !== ''
                  && preg_match('/^\d+\.\d+\.\d+/', $latest)
                  && version_compare($latest, (string)$current, '>');

        // Self-heal the stored value so anything reading the raw setting -- a
        // log line, a future caller -- cannot disagree with this answer.
        if (!$available && Database::setting('update_available', '0') === '1') {
            Database::setSetting('update_available', '0');
        }

        return [
            'update_available'  => $available,
            'current_version'   => $current,
            'latest_version'    => $latest ?: $current,
            'checked_at'        => (int) $checkedAt,
            'release_url'       => $releaseUrl,
            'release_notes'     => $releaseNotes,
            'download_url'      => Database::setting('update_download_url', ''),
            'sha256'            => Database::setting('update_sha256', ''),
            // Surfaced, not swallowed. A server that cannot reach the channel
            // looks identical to one that is up to date, and that is the state
            // an unpatched install sits in for months.
            'check_error'       => Database::setting('update_check_error', ''),
            // THREE STATES, not two. "No newer version" and "could not find
            // out" are different facts about a security product's patch
            // level, and until now the panel rendered them identically.
            //
            // `corroborated` is false when the newest version seen came only
            // from a cacheable url -- which, on the GitHub channel, can be up
            // to five minutes behind a release (max-age=300, and ?cb= does not
            // miss Fastly's cache). The note says so in words, and the
            // dashboard shows it where the unreachable-channel message goes.
            'corroborated'      => Database::setting('update_corroborated', '0') === '1',
            'version_source'    => Database::setting('update_version_source', ''),
            'uncorroborated_note' => Database::setting('update_uncorroborated', ''),
            // A channel behind the newest version seen is a release that was
            // never mirrored. Nine of them (4.37.1 ... 4.37.9) went that way
            // with no indication anywhere a human looks.
            'mirror_lag'        => Database::setting('update_mirror_lag', ''),
        ];
    }

    /**
     * Hit the GitHub API, compare versions, persist result.
     * Returns the same shape as getCachedStatus().
     * Safe to call from cron — exits silently on network failure.
     */
    public static function checkForUpdates(): array {
        $current = defined('SG_VERSION') ? SG_VERSION : '0.0.0';

        $m = self::fetchManifest();
        if ($m === null) {
            // Unreachable. Return the cached state WITHOUT touching
            // update_checked_at, so the panel keeps showing when the last
            // successful check was rather than claiming it just checked.
            // A stale "checked 2 minutes ago" on a server that has not reached
            // the channel in a week is worse than an old timestamp.
            Logger::warn('UpdateChecker: no release channel reachable, using cached state');
            Database::setSetting('update_check_error',
                'Could not reach any release channel at ' . date('Y-m-d H:i'));
            return self::getCachedStatus();
        }

        $latest = ltrim((string)($m['version'] ?? ''), 'v');
        if ($latest === '' || !preg_match('/^\d+\.\d+\.\d+/', $latest)) {
            Logger::error('UpdateChecker: manifest carried no usable version');
            Database::setSetting('update_check_error', 'Release manifest is malformed');
            return self::getCachedStatus();
        }

        $available = version_compare($latest, $current, '>');

        // Recorded as a fact about the EVIDENCE, separately from the version.
        // The updater and the panel may only claim an install is current when
        // the newest version seen was confirmed against a url that names the
        // version, because nothing else can be ruled out as a cached answer.
        $corroborated = !empty($m['_corroborated']);
        $source       = (string)($m['_source'] ?? '');
        $note         = '';
        if (!$corroborated) {
            $note = 'Latest version read as v' . $latest . ' from '
                  . (string)($m['_base'] ?? 'the release channel')
                  . '/latest.json, a cacheable url that can be up to 5 minutes '
                  . 'behind a release. Nothing addressed by version could be '
                  . 'reached to confirm it, so this is not a confirmation that '
                  . 'this install is current.';
        }
        Database::setSetting('update_corroborated',   $corroborated ? '1' : '0');
        Database::setSetting('update_version_source', $source);
        Database::setSetting('update_uncorroborated',  $note);
        Database::setSetting('update_mirror_lag',     (string)($m['_lag'] ?? ''));
        if (!$corroborated) {
            Logger::warn('UpdateChecker: v' . $latest . ' is an uncorroborated '
                       . 'reading from a cacheable url');
        }
        if (($m['_lag'] ?? '') !== '') {
            Logger::warn('UpdateChecker: ' . $m['_lag']);
        }

        Database::setSetting('update_available',   $available ? '1' : '0');
        Database::setSetting('update_latest_ver',  $latest);
        Database::setSetting('update_checked_at',  (string)time());
        Database::setSetting('update_check_error', '');
        Database::setSetting('update_release_url', (string)($m['notes'] ?? ''));
        // Recorded so the updater and the panel cannot disagree about which
        // file is the update, and so an operator can verify a download by hand.
        Database::setSetting('update_download_url', (string)($m['url'] ?? ''));
        Database::setSetting('update_sha256',       (string)($m['sha256'] ?? ''));

        if ($available) {
            Logger::info("UpdateChecker: v{$latest} available (current v{$current})");
        } else {
            Logger::info("UpdateChecker: up to date (v{$current})");
        }

        // One shape, derived from what was just persisted, so a caller
        // cannot see a field here that getCachedStatus() would answer
        // differently on the next page load.
        return self::getCachedStatus();
    }

    /**
     * Fetch latest.json from EVERY channel and return the newest manifest.
     *
     * This used to return the first channel that answered, which is the same
     * defect update.sh carried: a channel that replies with STALE data is
     * believed, and nothing downstream can tell that answer from a correct
     * one. It is not hypothetical. On 2026-11-13, with v4.36.0 published and
     * synced, serverscrub.com/releases/latest.json served 4.35.1 out of
     * cPanel's nginx reverse-proxy cache -- reproduced with this class's own
     * User-Agent and Accept headers -- so no operator's panel would ever have
     * raised the update notification.
     *
     * A channel that 404s is safe, because the loop moves on. A channel that
     * is confidently wrong is not, so correctness cannot depend on reply
     * order.
     *
     * @return array<string,mixed>|null
     */
    private static function fetchManifest(): ?array
    {
        $best    = null;
        $bestVer = '';
        $seen    = [];          // channel => version it answered with

        foreach (self::channels() as $base) {
            $base = rtrim($base, '/');
            $m = self::channelManifest($base);
            if ($m === null) {
                continue;
            }
            $v = ltrim((string)($m['version'] ?? ''), 'v');
            if (!preg_match('/^\d+\.\d+\.\d+/', $v)) {
                Logger::warn("UpdateChecker: $base answered but carried no usable version");
                continue;
            }
            $seen[$base] = $v;
            if ($best === null || version_compare($v, $bestVer, '>')) {
                $best    = $m;
                $bestVer = $v;
            }
        }

        // ── Corroborate against a url that names the version ───────────────
        //
        // Both mitigations above -- ask every channel, cross-check the tree --
        // were already here on 2026-11-23 and both missed the reported
        // failure, because on the GitHub channel ?cb= does not miss the edge
        // cache and latest/VERSION is a 404. So the answer is confirmed
        // against the manifest committed under the newest release tag, which
        // is written once and cannot be stale. If that cannot be reached the
        // branch answer still stands -- the panel has to keep working on a
        // firewalled box -- but it is marked uncorroborated and said out loud.
        foreach (self::channels() as $base) {
            $base = rtrim($base, '/');
            $iv = self::immutableChannelVersion($base);
            if ($iv === '') {
                // No ref listing here. Its per-build manifest is still
                // addressed by version, so it can corroborate what we have.
                $iv = $bestVer;
            }
            if ($iv === '' || !preg_match('/^\d+\.\d+\.\d+/', $iv)) {
                continue;
            }
            // Only ever corroborate forwards. A ref older than the answer in
            // hand is a lagging mirror, reported below, not something to take.
            if ($bestVer !== '' && version_compare($iv, $bestVer, '<')) {
                continue;
            }
            $url = self::pinnedManifestUrl($base, $iv);
            $body = self::httpGet($url);
            if ($body === null) {
                continue;
            }
            $j = json_decode($body, true);
            if (!is_array($j) || ltrim((string)($j['version'] ?? ''), 'v') !== $iv) {
                // Ref exists, manifest under it does not or disagrees:
                // mid-push, or a tag over a tree without the file. Nothing is
                // claimed from it.
                continue;
            }
            if ($bestVer === '' || version_compare($iv, $bestVer, '>')) {
                Logger::warn('UpdateChecker: channel manifests say v'
                           . ($bestVer === '' ? '(none)' : $bestVer)
                           . ' but the newest release ref holds v' . $iv
                           . ' — taking the version-pinned manifest');
                $j['_base'] = $base;
                $best    = $j;
                $bestVer = $iv;
            }
            $best['_corroborated'] = true;
            $best['_source']       = $url;
        }

        if ($best !== null) {
            $lag = [];
            foreach ($seen as $base => $v) {
                if (version_compare($v, $bestVer, '<')) {
                    $lag[] = $base . ' serves v' . $v;
                }
            }
            if ($lag) {
                $best['_lag'] = 'Release mirror behind: ' . implode(', ', $lag)
                              . ' — newest is v' . $bestVer
                              . '. That mirror\'s sync has stalled; installs '
                              . 'pointed at it cannot get the current build.';
            }
        }

        return $best;
    }

    /**
     * The best manifest ONE channel can offer, cross-checked against the
     * extracted tree it serves.
     *
     * latest/VERSION is read out of the build itself and cannot claim a
     * version the tree beside it does not contain. latest.json is a small,
     * long-lived, constantly-requested url -- precisely the shape a proxy
     * cache pins, and the one cPanel's nginx cache did pin for six days. When
     * the tree is NEWER than the manifest, the tree wins.
     *
     * @return array<string,mixed>|null
     */
    private static function channelManifest(string $base): ?array
    {
        $manifest = null;
        $body     = self::httpGet($base . '/latest.json');
        if ($body !== null) {
            $j = json_decode($body, true);
            if (is_array($j) && isset($j['version'])) {
                $manifest = $j;
                $manifest['_base'] = $base;
            } else {
                Logger::warn("UpdateChecker: $base/latest.json answered but was not a manifest");
            }
        } else {
            Logger::debug("UpdateChecker: $base/latest.json did not answer");
        }

        $live    = self::httpGet($base . '/latest/VERSION');
        $live    = $live === null ? '' : ltrim(trim($live), 'v');
        $liveSrc = $base . '/latest/VERSION';
        // A channel serving only dist/ has no latest/ tree. Normal, not an
        // error -- and NOT a passed cross-check either, which is how the one
        // safety net built for a cached manifest came to be a no-op on the
        // channel that matters: raw.githubusercontent.com/<repo>/main/latest/
        // VERSION is a 404 and always has been, because there is no latest/
        // tree in the repo. Where that path is missing, try the one that does
        // exist on a git-shaped channel: VERSION at the repo root. It shares
        // the manifest's five-minute cache window, so it corroborates only in
        // the weak sense of being a separately-keyed object -- enough to catch
        // a manifest the cache has pinned on its own, not enough to call the
        // answer confirmed.
        if (!preg_match('/^\d+\.\d+\.\d+/', $live)) {
            $live = '';
            $root = self::httpGet($base . '/VERSION');
            $root = $root === null ? '' : ltrim(trim($root), 'v');
            if (preg_match('/^\d+\.\d+\.\d+/', $root)) {
                $live    = $root;
                $liveSrc = $base . '/VERSION';
            }
        }
        if ($live === '') {
            return $manifest;
        }

        $mVer = $manifest === null ? '' : ltrim((string)($manifest['version'] ?? ''), 'v');
        if ($mVer !== '' && version_compare($live, $mVer, '<=')) {
            // Manifest is current, or ahead mid-sync. latest/VERSION is read
            // out of the extracted build and a ?cb= request WAS measured to
            // miss cPanel's nginx cache in front of it, so when it agrees with
            // the manifest the answer is corroborated. The repo-root VERSION
            // is not: it sits behind the same edge cache as the manifest.
            if ($manifest !== null && $live === $mVer
                && substr($liveSrc, -15) === '/latest/VERSION') {
                $manifest['_corroborated'] = true;
                $manifest['_source']       = $liveSrc;
            }
            return $manifest;
        }

        Logger::warn("UpdateChecker: $base serves manifest v"
                   . ($mVer === '' ? '(none)' : $mVer)
                   . " but $liveSrc reads v$live — trusting the deployed tree");

        // cdn-sync.sh writes a per-version copy of the manifest beside each
        // build. That url is requested about once ever, so no cache holds it,
        // and it carries the url + sha256 for THIS build.
        $pinned = self::httpGet($base . '/v' . $live . '/latest.json');
        if ($pinned !== null) {
            $j = json_decode($pinned, true);
            if (is_array($j) && ltrim((string)($j['version'] ?? ''), 'v') === $live) {
                $j['_corroborated'] = true;
                $j['_source']       = $base . '/v' . $live . '/latest.json';
                return $j;
            }
        }

        // No per-version manifest. Report the version anyway -- the whole
        // point is that the operator finds out -- but carry no url or
        // checksum, so nothing downstream can present an unverified download
        // as a verified one. update.sh resolves the real artifact itself.
        return [
            'version' => $live,
            'notes'   => $manifest === null ? '' : (string)($manifest['notes'] ?? ''),
            '_base'   => $base,
        ];
    }

    /**
     * GET a URL, or null. Never throws; callers must handle null.
     *
     * Every url this class fetches is version-bearing, and all of them sit
     * behind cPanel's nginx reverse-proxy cache, which ignores client
     * revalidation. Measured on the live host:
     *
     *   plain GET                                  -> 4.35.1 (six days stale)
     *   GET with no-cache + no-store + Pragma      -> 4.35.1
     *   GET with a ?cb= the proxy has not seen     -> 4.36.0
     *
     * Only a different cache key misses it, so a single-use query parameter
     * goes on every request. The headers are sent too: they are free, and
     * they do work on the caches between a server and us that DO honour them.
     */
    private static function httpGet(string $url): ?string
    {
        $url .= (strpos($url, '?') === false ? '?' : '&')
              . 'cb=' . time() . mt_rand(100, 999);

        $headers = ['User-Agent: ' . self::USER_AGENT,
                    'Accept: application/json',
                    'Cache-Control: no-cache, no-store, max-age=0',
                    'Pragma: no-cache'];

        if (self::$fetcher !== null) {
            $r = (self::$fetcher)($url, $headers);
            return is_string($r) ? $r : null;
        }

        $ctx = stream_context_create(['http' => [
            'method'        => 'GET',
            'header'        => $headers,
            'timeout'       => 10,
            'ignore_errors' => true,
        ], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);

        $body = @file_get_contents($url, false, $ctx);
        if ($body === false) return null;

        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#HTTP/\S+\s+(\d+)#', $h, $mm)) {
                return ((int)$mm[1] === 200) ? $body : null;
            }
        }
        return null;
    }

    // ── Private ───────────────────────────────────────────────────────────────

}
