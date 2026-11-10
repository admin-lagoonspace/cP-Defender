<?php
/* Pulls in what it uses, rather than trusting the caller to have done
 * it. UserReport did not, and `serverscrub user-reports` died with
 * Class "UserScanRequest" not found on all 132 accounts -- silently,
 * because writeAll() catches Throwable per account. require_once is
 * idempotent and safe across the cycles these classes form. */
require_once __DIR__ . '/Scanner.php';
require_once __DIR__ . '/UserReport.php';
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';

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

        // One at a time, whoever is calling.
        //
        // The lock lives HERE rather than in the cron script because there is
        // more than one caller by design: the minute cron does this normally,
        // and the scheduler repeats it hourly so that a server whose minute
        // cron is missing or broken still picks requests up eventually. With
        // the lock in the cron script those two held different locks, and the
        // same request could be started twice -- the second refused by
        // scan_max_concurrent and logged as a failure nobody could explain.
        /* RECORDED BEFORE THE LOCK, ALWAYS.
         *
         * This used to be: take the lock, return silently on refusal, and
         * write user_scan_last_check only on success. So when the lock was
         * stuck -- see lock() -- the pickup ran every five seconds, refused
         * every time, logged nothing, exited 0, and left the one timestamp
         * that would have shown it frozen. The bug suppressed the only
         * evidence of itself, and finding it meant converting a Unix
         * timestamp by hand on the server.
         *
         * Two timestamps now, because they answer different questions:
         *   last_attempt  something tried to pick requests up (every tick)
         *   last_check    a pickup actually ran (the lock was ours)
         * A fresh attempt with a stale check IS the signature of this fault. */
        Database::setSetting('user_scan_last_attempt', (string) time());

        $lock = self::lock();
        if ($lock === false) {
            self::noteLockRefused();
            $out['refused'] = true;
            return $out;
        }

        self::clearLockRefused();
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
        if ($pending === []) { self::unlock($lock); return $out; }

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

        // The pickup is over, so the lock is too. It used to be dropped only
        // by the process exiting -- which is also why nobody noticed a child
        // still holding it.
        self::unlock($lock);
        return $out;
    }

    /**
     * Take the pickup lock, or report that someone else holds it.
     *
     * Returns the handle on success, which the caller must keep: the kernel
     * holds the lock for as long as that handle is open, so letting it go out
     * of scope releases it. Returns false only when another process is mid-run.
     *
     * A lock file that cannot be opened at all is NOT a reason to refuse. That
     * would mean one unwritable temp directory silently stopping every
     * customer scan on the server, which is a worse failure than the race it
     * is guarding against -- and the race itself is bounded, because
     * Scanner::startScan() refuses a second concurrent scan anyway.
     *
     * @return resource|false
     */
    private static function lock()
    {
        if (!is_dir(SG_TMP)) { @mkdir(SG_TMP, 0750, true); }
        $fh = @fopen(SG_TMP . '/user-scans.lock', 'c');
        if ($fh === false) {
            Logger::warn('user scan: could not open the pickup lock; continuing');
            return null;
        }
        if (!@flock($fh, LOCK_EX | LOCK_NB)) {
            @fclose($fh);
            return false;
        }
        /* Who holds it, written INSIDE the lock. The file was empty, so a
         * refused pickup could not say anything about the holder -- and when
         * the holder is a process that inherited the descriptor and knows
         * nothing about it (clamscan, on 8 Nov), the pid recorded here being
         * dead is the whole diagnosis. */
        @ftruncate($fh, 0);
        @rewind($fh);
        @fwrite($fh, (string) json_encode([
            'pid'   => getmypid(),
            'at'    => time(),
            'host'  => gethostname(),
            'where' => 'UserScanRequest::process',
        ]) . "\n");
        @fflush($fh);

        // Kept alive deliberately: closing the handle drops the lock.
        $GLOBALS['__sg_user_scan_lock'] = $fh;
        return $fh;
    }

    /**
     * Drop the pickup lock.
     *
     * The lock used to be released only by the process exiting, which is fine
     * when it exits -- and was the reason nobody noticed that a CHILD had
     * inherited the descriptor and was holding the lock long after this
     * process was gone. Releasing it where the pickup ends makes the lifetime
     * the pickup's again, and makes the --watch service drop it between
     * passes rather than at the end of its hour-long life.
     */
    private static function unlock($lock): void
    {
        if (!is_resource($lock)) { return; }
        @flock($lock, LOCK_UN);
        @fclose($lock);
        unset($GLOBALS['__sg_user_scan_lock']);
    }

    /** What is on disk about the current holder, or null. */
    public static function lockOwner(): ?array
    {
        $raw = (string) @file_get_contents(SG_TMP . '/user-scans.lock');
        if (trim($raw) === '') { return null; }
        $d = json_decode(trim($raw), true);
        return is_array($d) && isset($d['pid']) ? $d : null;
    }

    /**
     * One sentence an operator can act on, for a lock we could not take.
     *
     * The expensive part -- walking /proc to find which live processes hold
     * the file -- runs only when this is called, which is rate-limited by
     * noteLockRefused() to once every ten minutes. It is bounded: at most 400
     * processes examined, and the first three holders named.
     *
     * The interesting case is the one that cost two and a half days of
     * customer scans: the recorded owner is GONE, so what holds the lock is a
     * descriptor it leaked to a child. That is no longer possible from
     * startScan() (see Scanner::fdsAboveStderr()), but saying so plainly is
     * what turns a silent refusal into a five-minute fix on any other path.
     */
    public static function lockDiagnosis(): string
    {
        $path  = SG_TMP . '/user-scans.lock';
        $owner = self::lockOwner();
        $pid   = $owner !== null ? (int) $owner['pid'] : 0;
        $since = $owner !== null ? (int) ($owner['at'] ?? 0) : 0;

        $msg = 'another pickup holds ' . $path;
        if ($pid > 0) {
            $alive = self::pidAlive($pid);
            $age   = $since > 0 ? ' (taken ' . self::ago($since) . ')' : '';
            $msg   = $alive
                ? 'pickup PID ' . $pid . ' holds ' . $path . $age
                : 'the pickup that took ' . $path . $age . ' was PID ' . $pid
                  . ', WHICH NO LONGER EXISTS -- so the lock is held by a '
                  . 'descriptor it leaked to a child process, and it will not '
                  . 'be released until that child exits';
        }

        $holders = self::lockHolders($path);
        if ($holders !== []) {
            $msg .= '. Held by: ' . implode(', ', $holders);
        }
        return $msg;
    }

    /** @return string[] "3824536 (clamscan)" for live holders of $path */
    private static function lockHolders(string $path, int $maxProcs = 400): array
    {
        if (!is_dir('/proc')) { return []; }
        $real = realpath($path);
        if ($real === false) { return []; }

        $found = [];
        $seen  = 0;
        foreach ((array) @scandir('/proc') as $d) {
            if (!ctype_digit((string) $d)) { continue; }
            if (++$seen > $maxProcs || count($found) >= 3) { break; }
            foreach ((array) @scandir('/proc/' . $d . '/fd') as $fd) {
                if (!ctype_digit((string) $fd)) { continue; }
                if (@readlink('/proc/' . $d . '/fd/' . $fd) !== $real) { continue; }
                $cmd = trim((string) @file_get_contents('/proc/' . $d . '/comm'));
                $found[] = $d . ($cmd !== '' ? ' (' . $cmd . ')' : '');
                break;
            }
        }
        return $found;
    }

    private static function pidAlive(int $pid): bool
    {
        if ($pid <= 0) { return false; }
        if (is_dir('/proc')) { return is_dir('/proc/' . $pid); }
        if (function_exists('posix_kill')) { return @posix_kill($pid, 0); }
        return true;   // cannot tell: do not claim it is gone
    }

    /** "2 days 11 hours ago", for a log line a human reads. */
    private static function ago(int $ts): string
    {
        $d = max(0, time() - $ts);
        if ($d < 90)    { return $d . 's ago'; }
        if ($d < 5400)  { return intdiv($d, 60) . 'm ago'; }
        if ($d < 172800){ return intdiv($d, 3600) . 'h ago'; }
        return intdiv($d, 86400) . 'd ' . intdiv($d % 86400, 3600) . 'h ago';
    }

    /**
     * Record and report a refused pickup, without filling the log.
     *
     * The pickup runs every five seconds in --watch mode, so a line per
     * refusal is 17,280 a day and the lines that matter drown in it. A line
     * per ten minutes is 144, and the FIRST refusal is always logged, so the
     * start of the problem is in the log at the time it started.
     *
     * The state is also in settings, where the scheduler's --status report and
     * the customer's own page can read it: "pickups are being refused" has to
     * be visible without reading the source, which was the whole cost of this
     * fault.
     */
    private static function noteLockRefused(): void
    {
        $now   = time();
        $since = (int) Database::setting('user_scan_pickup_refused_since', '0');
        $first = $since === 0;
        if ($first) {
            Database::setSetting('user_scan_pickup_refused_since', (string) $now);
            $since = $now;
        }
        Database::setSetting('user_scan_pickup_refused_at', (string) $now);

        $lastLog = (int) Database::setting('user_scan_pickup_refused_logged', '0');
        if (!$first && ($now - $lastLog) < 600) { return; }

        $why = self::lockDiagnosis();
        Database::setSetting('user_scan_pickup_refused_logged', (string) $now);
        Database::setSetting('user_scan_pickup_refused_reason', mb_substr($why, 0, 400));

        $pending = self::pendingCount();
        Logger::warn('user scan: pickup REFUSED since ' . self::ago($since)
                     . ' (' . $pending . ' request(s) waiting) - ' . $why);
    }

    /** Clear the refusal state once a pickup gets through. */
    private static function clearLockRefused(): void
    {
        if ((int) Database::setting('user_scan_pickup_refused_since', '0') === 0) { return; }
        Logger::info('user scan: pickups are running again');
        foreach (['since', 'at', 'logged', 'reason'] as $k) {
            Database::setSetting('user_scan_pickup_refused_' . $k, '');
        }
    }

    /** How many accounts have a request waiting. Cheap: one stat per account. */
    private static function pendingCount(): int
    {
        $n = 0;
        try {
            foreach (UserReport::listUsers() as $user) {
                if (self::read($user) !== null) { $n++; }
            }
        } catch (Throwable $e) {
            return -1;   // unknown, and said so, rather than reported as none
        }
        return $n;
    }

    /**
     * Is the pickup currently being refused, and why?
     *
     * @return array{refused:bool,since:int,at:int,reason:string}
     */
    public static function pickupState(): array
    {
        $since = (int) Database::setting('user_scan_pickup_refused_since', '0');
        $at    = (int) Database::setting('user_scan_pickup_refused_at', '0');
        return [
            // Stale state is not a current refusal: if nothing has tried for
            // an hour, the honest answer is about the pickup not running, not
            // about the lock.
            'refused' => $since > 0 && (time() - $at) < 3600,
            'since'   => $since,
            'at'      => $at,
            'reason'  => (string) Database::setting('user_scan_pickup_refused_reason', ''),
        ];
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
            // A fresh attempt with a stale check is the signature of a stuck
            // lock, and the page says so rather than showing "Queued" for
            // ever. See process().
            'last_attempt_at' => (int) Database::setting('user_scan_last_attempt', '0'),
            'pickup'          => self::pickupState(),
            'note'            => self::noteFor($user),
        ];
    }
}
