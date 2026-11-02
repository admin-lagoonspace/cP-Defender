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

    /** Left by the same page to stop a scan this account started. */
    private const CANCEL = 'scan-cancel.json';

    /** A request file should be a few dozen bytes. */
    private const MAX_BYTES = 4096;

    /** Defaults; both operator-settable. Two scans per twelve hours. */
    private const DEFAULT_WINDOW_HOURS = 12;
    private const DEFAULT_PER_WINDOW   = 2;

    /**
     * The length of the rolling window.
     *
     * This replaced a single cooldown between scans. A cooldown forces an even
     * spacing the customer did not ask for: somebody who scans, finds
     * something, cleans it and wants to confirm is made to wait the full gap
     * for a scan that costs the same as the one they just ran. A window of two
     * lets them do exactly that and still bounds the cost per account.
     */
    public static function windowSeconds(): int
    {
        $h = (int) Database::setting('user_scan_window_hours',
                                     (string) self::DEFAULT_WINDOW_HOURS);
        return max(600, min(7 * 86400, $h * 3600));
    }

    /** How many scans one account may start inside that window. */
    public static function perWindow(): int
    {
        $n = (int) Database::setting('user_scan_per_window',
                                     (string) self::DEFAULT_PER_WINDOW);
        return max(1, min(24, $n));
    }

    /** Is the feature switched on at all? */
    public static function enabled(): bool
    {
        return Database::setting('user_scan_enabled', '1') === '1';
    }

    public static function requestPath(string $user): ?string
    {
        return self::pathFor($user, self::FILE);
    }

    /** Where this account leaves a request to stop the scan it started. */
    public static function cancelPath(string $user): ?string
    {
        return self::pathFor($user, self::CANCEL);
    }

    private static function pathFor(string $user, string $file): ?string
    {
        $home = UserReport::homeDir($user);
        return $home === null ? null : $home . '/.serverscrub/' . $file;
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
        $at = self::readStamp($user, self::FILE, 'requested_at');
        return $at === null ? null : ['user' => $user, 'requested_at' => $at];
    }

    /**
     * Read this account's request to stop its own scan, or null.
     *
     * Same checks as a scan request, and for the same reason: this is root
     * about to act on a file sitting in a directory a hostile user controls.
     * What it authorises is narrow -- stopping a job this same account
     * started, which process() verifies against the job row -- but "narrow"
     * is not "harmless", and the ownership check is what keeps one customer
     * from leaving a file in another's home.
     */
    public static function readCancel(string $user): ?int
    {
        return self::readStamp($user, self::CANCEL, 'requested_at');
    }

    /** Remove a cancel request once it has been acted on. */
    public static function clearCancel(string $user): void
    {
        $path = self::cancelPath($user);
        if ($path !== null && !is_link($path) && is_file($path)) { @unlink($path); }
    }

    /** The timestamp inside one of these files, if it passes every check. */
    private static function readStamp(string $user, string $file, string $key): ?int
    {
        $path = self::pathFor($user, $file);
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

        $at = (int) ($d[$key] ?? 0);
        if ($at <= 0) { return null; }

        // A timestamp in the future, or older than a day, is not a request
        // anybody is still waiting on.
        $now = time();
        if ($at > $now + 300 || $at < $now - 86400) { return null; }

        return $at;
    }

    /** Remove a request once it has been acted on, or discarded. */
    public static function clear(string $user): void
    {
        $path = self::requestPath($user);
        if ($path !== null && !is_link($path) && is_file($path)) { @unlink($path); }
    }

    /**
     * The start times still inside the window, oldest first.
     *
     * Kept as a list rather than a count so the page can say WHEN the next
     * scan becomes available. A counter would have to be reset by something,
     * and whatever did the resetting would be another thing to get wrong.
     *
     * @return int[]
     */
    public static function recentStarts(string $user, ?int $now = null): array
    {
        $now = $now ?? time();
        $raw = (string) Database::setting('user_scan_starts_' . $user, '');
        $all = $raw === '' ? [] : json_decode($raw, true);
        if (!is_array($all)) { $all = []; }

        $cut  = $now - self::windowSeconds();
        $keep = [];
        foreach ($all as $t) {
            $t = (int) $t;
            // A timestamp in the future would never expire, so it would lock
            // the account out permanently. Clock changes happen.
            if ($t > $cut && $t <= $now + 300) { $keep[] = $t; }
        }
        sort($keep);
        return $keep;
    }

    /** Record that a scan started now. */
    private static function recordStart(string $user): void
    {
        $starts   = self::recentStarts($user);
        $starts[] = time();
        // Never store more than the window allows plus a little slack.
        $starts = array_slice($starts, -max(2, self::perWindow() * 2));
        Database::setSetting('user_scan_starts_' . $user, (string) json_encode($starts));
    }

    /** When this account last had a requested scan started. */
    public static function lastRunAt(string $user): int
    {
        $s = self::recentStarts($user);
        return $s === [] ? 0 : (int) end($s);
    }

    /** Has this account used up its allowance for the window? */
    public static function atLimit(string $user, ?int $now = null): bool
    {
        return count(self::recentStarts($user, $now)) >= self::perWindow();
    }

    /**
     * Seconds until another scan is allowed; 0 when one is allowed now.
     *
     * The oldest start in the window is the one whose expiry frees a slot.
     */
    public static function retryIn(string $user, ?int $now = null): int
    {
        $now    = $now ?? time();
        $starts = self::recentStarts($user, $now);
        if (count($starts) < self::perWindow()) { return 0; }
        $oldest = (int) $starts[0];
        return max(0, ($oldest + self::windowSeconds()) - $now);
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
        $out = ['started' => [], 'skipped' => [], 'errors' => [], 'cancelled' => []];
        if (!self::enabled()) { return $out; }

        Database::setSetting('user_scan_last_check', (string) time());

        // Cancels first, and for every account, before anything is started.
        //
        // Order matters: a customer who presses Cancel and then has their own
        // request honoured a moment later would watch the scan they just
        // stopped begin. Doing this pass first means a cancel that arrives in
        // the same minute as the start still wins.
        $out['cancelled'] = self::processCancels();

        $pending = [];
        foreach (UserReport::listUsers() as $user) {
            $req = self::read($user);
            if ($req !== null) { $pending[] = $req; }
        }
        if ($pending === []) { return $out; }

        // Oldest first. There is no cap any more, but Scanner::startScan()
        // still refuses once scan_max_concurrent is reached, so on a busy
        // server some of these will not start this time round -- and the one
        // that has waited longest should be the one that gets the slot.
        usort($pending, static function ($a, $b) {
            return $a['requested_at'] <=> $b['requested_at'];
        });

        foreach ($pending as $req) {
            $user = $req['user'];

            // The allowance, and the only thing that makes a customer wait by
            // our choice rather than the server's.
            if (self::atLimit($user)) {
                $out['skipped'][] = ['user' => $user, 'reason' => 'at limit',
                                     'retry_in' => self::retryIn($user)];
                self::note($user, 'at_limit', 0);
                // Kept: the customer asked, the answer is "not yet", and
                // discarding it would mean their click did nothing.
                continue;
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
                // Third argument: do not stand down for JetBackup, rsync or
                // anything else. A customer is sitting in front of the page
                // waiting for this, and one account's quick scan is nothing
                // like the server-wide sweep that gate was written for.
                $jobId   = $scanner->startScan($home, 'quick', true, $user);
                self::recordStart($user);
                self::note($user, 'started', 0);
                self::clear($user);
                $out['started'][] = ['user' => $user, 'job' => $jobId];
                Logger::info("User scan: started job {$jobId} for {$user} on {$home}");
            } catch (Throwable $e) {
                // startScan() still refuses once scan_max_concurrent scans are
                // already going -- a reason to wait rather than to lose the
                // request. (It no longer refuses for a backup: see above.)
                $out['errors'][] = ['user' => $user, 'error' => $e->getMessage()];
                self::note($user, 'blocked', 0, $e->getMessage());
                Logger::warn("User scan: could not start for {$user} - " . $e->getMessage());
            }
        }

        return $out;
    }

    /**
     * Honour "stop my scan" for every account that asked.
     *
     * WHAT A CUSTOMER IS ALLOWED TO STOP
     *
     * Only the job whose requested_by is their own account. Not the scheduled
     * server-wide sweep, not another customer's scan, and not a scan an
     * operator started from WHM -- all of which cover their files too, so
     * "the scan is reading my directory" is deliberately NOT the test. The
     * test is who asked for it, which is a string comparison against the job
     * row that no amount of rearranging their own home can change.
     *
     * A cancel with no live job of their own is not an error: the scan
     * finished between their click and this tick. The request is cleared and
     * the page shows the result.
     *
     * @return array<int,array{user:string,job:int}>
     */
    private static function processCancels(): array
    {
        $done = [];
        foreach (UserReport::listUsers() as $user) {
            if (self::readCancel($user) === null) { continue; }

            // Clear FIRST. If stopScan() throws, or the process is killed
            // mid-signal, a cancel left on disk would be retried every minute
            // -- and could land on a LATER scan the customer started, which
            // they never asked to stop.
            self::clearCancel($user);

            // A queued-but-unstarted request is cancelled by dropping it.
            // Their page does this itself and does not need us, but a request
            // that arrived in the same tick is still sitting here.
            self::clear($user);

            $job = Scanner::liveJobFor($user);
            if ($job === null) {
                self::note($user, 'cancelled', 0);
                continue;
            }

            $id = (int) $job['id'];

            // Belt and braces. liveJobFor() already filters on requested_by,
            // so this can only fail if that query is ever loosened -- which is
            // exactly the change that would quietly hand one customer the
            // ability to stop the server's own scan.
            if (Scanner::jobOwner($id) !== $user) {
                Logger::warn("User scan: {$user} tried to cancel job {$id}, "
                           . 'which is not theirs - refused');
                continue;
            }

            $r = Scanner::stopScan($id);
            if (!empty($r['success'])) {
                $done[] = ['user' => $user, 'job' => $id];
                self::note($user, 'cancelled', 0);
                Logger::info("User scan: {$user} cancelled their job {$id}");
            } else {
                self::note($user, 'cancel_failed', 0, (string) ($r['error'] ?? ''));
                Logger::warn("User scan: could not cancel job {$id} for {$user} - "
                           . ($r['error'] ?? 'unknown'));
            }
        }
        return $done;
    }

    /**
     * Record why this account's request is in the state it is.
     *
     * Written here, as root, because every reason lives on this side: the
     * allowance, and the backup or concurrency limit that refused the scan.
     * The page has none of it, and a page that can only say "queued" leaves
     * the customer deciding between "it is working" and "it is broken" with
     * no evidence either way -- which is how a working feature generates a
     * support ticket.
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
        $starts = self::recentStarts($user);
        return [
            'enabled'       => self::enabled(),
            'pending'       => self::read($user) !== null,
            'last_run_at'   => self::lastRunAt($user),
            'retry_in'      => self::retryIn($user),
            // The allowance, so the page can say "1 of 2 used" rather than
            // simply refusing.
            'window_hours'  => (int) round(self::windowSeconds() / 3600),
            'per_window'    => self::perWindow(),
            'used'          => count($starts),
            'last_check_at' => (int) Database::setting('user_scan_last_check', '0'),
            'note'          => self::noteFor($user),
        ];
    }
}
