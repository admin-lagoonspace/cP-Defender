<?php
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

    private static function channels(): array
    {
        $cdn  = getenv('SG_CDN_BASE') ?: 'https://serverscrub.com/serverscrub/code';
        $repo = getenv('SG_RELEASES_REPO') ?: 'admin-lagoonspace/cP-Defender';
        $raw  = 'https://raw.githubusercontent.com/' . $repo . '/'
              . (getenv('SG_RELEASES_BRANCH') ?: 'main');

        $explicit = getenv('SG_MANIFEST_URL');
        if (is_string($explicit) && $explicit !== '') {
            return [preg_replace('#/latest\.json$#', '', $explicit)];
        }
        return [$cdn, $raw];
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

        return [
            'update_available' => $available,
            'current_version'  => $current,
            'latest_version'   => $latest,
            'checked_at'       => time(),
            'release_url'      => (string)($m['notes'] ?? ''),
            'release_notes'    => Database::setting('update_release_notes', ''),
            'download_url'     => (string)($m['url'] ?? ''),
            'sha256'           => (string)($m['sha256'] ?? ''),
        ];
    }

    /**
     * Fetch latest.json from the first channel that answers.
     *
     * @return array<string,mixed>|null
     */
    private static function fetchManifest(): ?array
    {
        foreach (self::channels() as $base) {
            $url  = rtrim($base, '/') . '/latest.json';
            $body = self::httpGet($url);
            if ($body === null) {
                Logger::debug("UpdateChecker: $url did not answer");
                continue;
            }
            $j = json_decode($body, true);
            if (is_array($j) && isset($j['version'])) {
                return $j;
            }
            Logger::warn("UpdateChecker: $url answered but was not a manifest");
        }
        return null;
    }

    /** GET a URL, or null. Never throws; callers must handle null. */
    private static function httpGet(string $url): ?string
    {
        $ctx = stream_context_create(['http' => [
            'method'        => 'GET',
            'header'        => ['User-Agent: ' . self::USER_AGENT,
                                'Accept: application/json'],
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
