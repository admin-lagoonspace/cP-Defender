<?php
/**
 * Scans a cPanel user asked for themselves.
 *
 * WHY A FILE, AGAIN
 *
 * The cPanel page runs as the user and cannot reach the database (0700 root)
 * or the API (admin role). UserReport solved the outbound direction by having
 * root write a report into the user's home. This is the same boundary in
 * reverse: the user writes a small request file into their own home, and the
 * privileged side picks it up on its next tick.
 *
 * Nothing in that file is trusted. It carries a timestamp and nothing else
 * that matters -- the path to scan is derived from the account's passwd entry
 * here, as root, and never read from the request. A request naming /root would
 * otherwise be a request to scan /root.
 *
 * WHY A COOLDOWN AND A CAP
 *
 * There are 118 accounts on the server this was built for, and its recurring
 * problem is CPU: load 22 from one scanner, load 13 from a backup, HTTP
 * challenges timing out at 30 seconds. A button that starts a ClamAV run,
 * exposed to every customer, is a denial-of-service feature unless it is
 * bounded. So: one scan per account per cooldown window, and at most a fixed
 * number of user-requested scans started per tick, server-wide.
 *
 * Both limits are enforced HERE, as root. The page shows the cooldown so the
 * customer is not confused, but that display is a courtesy -- a user who edits
 * their own request file gains nothing, because this side decides.
 */

class UserScanRequest
{
    /** Lives beside report.json, in the directory UserReport already owns. */
    private const FILE = 'scan-request.json';

    /** A request file should be a few dozen bytes. */
    private const MAX_BYTES = 4096;

    /** Defaults; both are operator-settable. */
    private const DEFAULT_COOLDOWN_HOURS = 6;
    private const DEFAULT_MAX_PER_RUN    = 1;

    public static function cooldownSeconds(): int
    {
        $h = (int) Database::setting('user_scan_cooldown_hours',
                                     (string) self::DEFAULT_COOLDOWN_HOURS);
        // One minute floor: zero would make the cap the only limit, and a
        // customer holding the button down would then start a scan every tick.
        return max(60, min(7 * 86400, $h * 3600));
    }

    public static function maxPerRun(): int
    {
        $n = (int) Database::setting('user_scan_max_per_run',
                                     (string) self::DEFAULT_MAX_PER_RUN);
        return max(1, min(10, $n));
    }

    /** Is the feature switched on at all? */
    public static function enabled(): bool
    {
        return Database::setting('user_scan_enabled', '1') === '1';
    }

    public static function requestPath(string $user): ?string
    {
        $home = UserReport::homeDir($user);
        return $home === null ? null : $home . '/.serverscrub/' . self::FILE;
    }

    /**
     * Read one account's request, or null.
     *
     * Every step refuses rather than following something it did not create.
     * This is root opening a path inside a directory a hostile user can
     * rearrange between one call and the next.
     */
    public static function read(string $user): ?array
    {
        $path = self::requestPath($user);
        if ($path === null || is_link($path) || !is_file($path)) { return null; }

        // Owned by the account it claims to be from. Root acting on a file
        // another user planted there would be acting on someone else's say-so.
        $uid = @fileowner($path);
        $pw  = function_exists('posix_getpwnam') ? @posix_getpwnam($user) : null;
        if ($uid === false || (is_array($pw) && (int) $pw['uid'] !== (int) $uid)) {
            return null;
        }

        if ((int) @filesize($path) > self::MAX_BYTES) { return null; }
        $raw = @file_get_contents($path, false, null, 0, self::MAX_BYTES);
        $d   = $raw === false ? null : json_decode($raw, true);
        if (!is_array($d)) { return null; }

        $at = (int) ($d['requested_at'] ?? 0);
        if ($at <= 0) { return null; }

        // A timestamp in the future, or older than a day, is not a request
        // anybody is still waiting on.
        $now = time();
        if ($at > $now + 300 || $at < $now - 86400) { return null; }

        return ['user' => $user, 'requested_at' => $at];
    }

    /** Remove a request once it has been acted on, or discarded. */
    public static function clear(string $user): void
    {
        $path = self::requestPath($user);
        if ($path !== null && !is_link($path) && is_file($path)) { @unlink($path); }
    }

    /** When this account last had a requested scan started. */
    public static function lastRunAt(string $user): int
    {
        return (int) Database::setting('user_scan_last_' . $user, '0');
    }

    public static function coolingDown(string $user, ?int $now = null): bool
    {
        $now = $now ?? time();
        return ($now - self::lastRunAt($user)) < self::cooldownSeconds();
    }

    /**
     * Act on every pending request, oldest first.
     *
     * Oldest first because the alternative -- directory order -- means an
     * account early in the alphabet can starve one late in it whenever the cap
     * bites, and the customer who has waited longest is the one who should be
     * served.
     *
     * @return array{started:array,skipped:array,errors:array}
     */
    public static function process(): array
    {
        $out = ['started' => [], 'skipped' => [], 'errors' => []];
        if (!self::enabled()) { return $out; }

        // When the privileged side last looked at requests. The page cannot
        // know this -- it has no access to cron, the database or the
        // scheduler -- and without it the only honest thing it can say is
        // "queued", which reads like nothing is happening.
        Database::setSetting('user_scan_last_check', (string) time());

        $pending = [];
        foreach (UserReport::listUsers() as $user) {
            $req = self::read($user);
            if ($req !== null) { $pending[] = $req; }
        }
        if ($pending === []) { return $out; }

        usort($pending, static function ($a, $b) {
            return $a['requested_at'] <=> $b['requested_at'];
        });

        $cap      = self::maxPerRun();
        $started  = 0;
        $position = 1;   // how many are ahead, for the ones that must wait

        foreach ($pending as $req) {
            $user = $req['user'];

            if (self::coolingDown($user)) {
                $wait = self::cooldownSeconds() - (time() - self::lastRunAt($user));
                $out['skipped'][] = ['user' => $user, 'reason' => 'cooling down',
                                     'retry_in' => max(0, $wait)];
                self::note($user, 'cooldown', 0);
                // The request is KEPT. The customer asked, the answer is "not
                // yet", and discarding it would mean their click did nothing
                // and they would click again.
                continue;
            }

            if ($started >= $cap) {
                $out['skipped'][] = ['user' => $user, 'reason' => 'queued',
                                     'position' => $position];
                self::note($user, 'waiting_turn', $position);
                $position++;
                continue;   // kept, picked up on the next tick
            }

            $home = UserReport::homeDir($user);
            if ($home === null) {
                $out['errors'][] = ['user' => $user, 'error' => 'no usable home directory'];
                self::clear($user);
                continue;
            }

            try {
                // The path comes from passwd, never from the request file.
                $scanner = new Scanner();
                $jobId   = $scanner->startScan($home, 'quick');
                Database::setSetting('user_scan_last_' . $user, (string) time());
                self::note($user, 'started', 0);
                self::clear($user);
                $started++;
                $out['started'][] = ['user' => $user, 'job' => $jobId];
                Logger::info("User scan: started job {$jobId} for {$user} on {$home}");
            } catch (Throwable $e) {
                // startScan() refuses while a backup is running, which is a
                // reason to wait rather than to lose the request.
                $out['errors'][] = ['user' => $user, 'error' => $e->getMessage()];
                self::note($user, 'blocked', 0, $e->getMessage());
                Logger::warn("User scan: could not start for {$user} - " . $e->getMessage());
            }
        }

        return $out;
    }

    /**
     * Record why this account's request is in the state it is.
     *
     * Written here, as root, because every reason lives on this side: the
     * cap, the cooldown, the backup that refused the scan. The page has none
     * of it, and a page that can only say "queued" leaves the customer
     * deciding between "it is working" and "it is broken" with no evidence
     * either way -- which is how a working feature generates a support
     * ticket.
     */
    private static function note(string $user, string $state, int $position,
                                 string $detail = ''): void
    {
        Database::setSetting('user_scan_note_' . $user, (string) json_encode([
            'at'       => time(),
            'state'    => $state,
            'position' => $position,
            'detail'   => mb_substr($detail, 0, 200),
        ]));
    }

    /** The recorded note, or null. */
    public static function noteFor(string $user): ?array
    {
        $raw = (string) Database::setting('user_scan_note_' . $user, '');
        if ($raw === '') { return null; }
        $d = json_decode($raw, true);
        return is_array($d) && isset($d['state']) ? $d : null;
    }

    /**
     * What the user's page should say, carried in their report.
     *
     * @return array{enabled:bool,pending:bool,cooldown_seconds:int,last_run_at:int,retry_in:int}
     */
    public static function statusFor(string $user): array
    {
        $now  = time();
        $last = self::lastRunAt($user);
        return [
            'enabled'          => self::enabled(),
            'pending'          => self::read($user) !== null,
            'cooldown_seconds' => self::cooldownSeconds(),
            'last_run_at'      => $last,
            'retry_in'         => max(0, self::cooldownSeconds() - ($now - $last)),
            // Everything below exists so the page can explain a wait instead
            // of just announcing one.
            'last_check_at'    => (int) Database::setting('user_scan_last_check', '0'),
            'per_check'        => self::maxPerRun(),
            'note'             => self::noteFor($user),
        ];
    }
}
