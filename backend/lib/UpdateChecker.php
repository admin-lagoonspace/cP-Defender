<?php
/**
 * Sentinel Gate — Update Checker
 * Polls the GitHub Releases API and stores the result in the DB.
 * The cron script calls checkForUpdates() once a day.
 * The API exposes the cached result so the frontend can show a banner.
 */

class UpdateChecker {

    // GitHub repo — change if the repo moves
    private const GITHUB_API = 'https://api.github.com/repos/admin-lagoonspace/cP-Defender/releases/latest';
    private const USER_AGENT  = 'SentinelGate-UpdateChecker/1.0';

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Return the cached update state stored in the DB.
     * Called by the frontend on every dashboard load (cheap — no HTTP).
     */
    public static function getCachedStatus(): array {
        $available   = Database::setting('update_available',   '0');
        $latest      = Database::setting('update_latest_ver',  '');
        $current     = defined('SG_VERSION') ? SG_VERSION : (Database::setting('sg_version', '0.0.0'));
        $checkedAt   = Database::setting('update_checked_at',  '0');
        $releaseUrl  = Database::setting('update_release_url', '');
        $releaseNotes= Database::setting('update_release_notes','');

        return [
            'update_available'  => $available === '1',
            'current_version'   => $current,
            'latest_version'    => $latest ?: $current,
            'checked_at'        => (int) $checkedAt,
            'release_url'       => $releaseUrl,
            'release_notes'     => $releaseNotes,
        ];
    }

    /**
     * Hit the GitHub API, compare versions, persist result.
     * Returns the same shape as getCachedStatus().
     * Safe to call from cron — exits silently on network failure.
     */
    public static function checkForUpdates(): array {
        $current = defined('SG_VERSION') ? SG_VERSION : '0.0.0';

        $raw = self::fetchLatestRelease();
        if ($raw === null) {
            // Network error — return cached state without updating timestamps
            Logger::info('UpdateChecker: GitHub API unreachable, using cached state');
            return self::getCachedStatus();
        }

        $latestTag   = ltrim($raw['tag_name'] ?? '', 'v');
        $releaseUrl  = $raw['html_url']  ?? '';
        $releaseBody = $raw['body']       ?? '';

        // Truncate release notes to 1000 chars for DB
        if (strlen($releaseBody) > 1000) {
            $releaseBody = substr($releaseBody, 0, 997) . '…';
        }

        $available = version_compare($latestTag, $current, '>');

        Database::setSetting('update_available',    $available ? '1' : '0');
        Database::setSetting('update_latest_ver',   $latestTag);
        Database::setSetting('update_checked_at',   (string) time());
        Database::setSetting('update_release_url',  $releaseUrl);
        Database::setSetting('update_release_notes', $releaseBody);

        if ($available) {
            Logger::info("UpdateChecker: new version available — v{$latestTag} (current: v{$current})");
        } else {
            Logger::info("UpdateChecker: up to date (v{$current})");
        }

        return [
            'update_available'  => $available,
            'current_version'   => $current,
            'latest_version'    => $latestTag,
            'checked_at'        => time(),
            'release_url'       => $releaseUrl,
            'release_notes'     => $releaseBody,
        ];
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private static function fetchLatestRelease(): ?array {
        $ctx = stream_context_create([
            'http' => [
                'method'          => 'GET',
                'header'          => [
                    'User-Agent: '    . self::USER_AGENT,
                    'Accept: application/vnd.github+json',
                    'X-GitHub-Api-Version: 2022-11-28',
                ],
                'timeout'         => 10,
                'ignore_errors'   => true,
            ],
        ]);

        $response = @file_get_contents(self::GITHUB_API, false, $ctx);
        if ($response === false) return null;

        // Check HTTP status code from response headers
        $status = 0;
        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#HTTP/\S+\s+(\d+)#', $h, $m)) {
                $status = (int) $m[1];
                break;
            }
        }
        if ($status !== 200) return null;

        $data = json_decode($response, true);
        return is_array($data) ? $data : null;
    }
}
