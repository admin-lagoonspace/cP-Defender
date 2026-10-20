<?php
/**
 * ServerScrub — Outbound mail monitoring
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
 * On 2026-10-18 a single Contact Form 7 form on one site relayed **92,954
 * messages** off this server in about a day, roughly 1,690 an hour, through its
 * autoresponder. Nothing on disk was modified, so the malware scanner had
 * nothing to find. No tool noticed. It was discovered by hand, afterwards, by
 * reading exim_mainlog — and the server's mail reputation was the damage.
 *
 * Every signal needed to have caught it inside a few minutes was already on the
 * server the whole time. That is what this module reads.
 *
 * ── OUTBOUND ONLY ────────────────────────────────────────────────────────────
 * This does not touch inbound mail, filtering or scoring. MagicSpam handles
 * incoming on this server and two tools fighting over inbound policy is worse
 * than one. Nothing here reads a message body or makes a spam/ham judgement:
 * it counts, attributes and reports.
 *
 * ── WHAT IT WATCHES ──────────────────────────────────────────────────────────
 *   queue depth         exim -bpc. 93,255 queued is not a busy day.
 *   send rate           arrivals per account per hour.
 *   the script          exim's cwd= on a locally injected message names the
 *                       directory that sent it. This is the signal that turns
 *                       "inditdel is sending a lot" into "this form on this
 *                       site is the relay", which took hours to work out by
 *                       hand.
 *   authenticated sends A=dovecot_login:... means a real mailbox password is
 *                       being used, which is a different incident: stolen
 *                       credentials rather than an exploited script.
 *   failures            a high bounce ratio means mail aimed at lists that do
 *                       not exist.
 *   frozen              a spike means the relay itself is failing, which is
 *                       usually how it is first noticed from outside.
 *
 * ── WHAT IT WILL NOT DO ──────────────────────────────────────────────────────
 * It does not delete mail and it does not suspend accounts. A queue holds real
 * customer mail alongside the spam — during the incident 92,954 of 93,255
 * messages were the relay, which still leaves 301 that somebody was waiting
 * for. Throttling is available, is explicit, and is reversible.
 */

class MailGuard
{
    /** Where exim writes. First readable one wins. */
    private const LOGS = ['/var/log/exim_mainlog', '/var/log/exim/mainlog',
                          '/var/log/exim4/mainlog'];

    /**
     * Bytes of new log read in one pass.
     *
     * Bounded on purpose. During the incident the log grew by hundreds of
     * megabytes in a day, and a module that reads "everything new" would read
     * all of it in one go on a server already struggling — turning the monitor
     * into a second incident. 8 MB per tick at four ticks an hour keeps up with
     * any plausible rate, and the offset means nothing is lost, only deferred.
     */
    private const MAX_READ = 8388608;

    // -- System accounts, which are not customers ----------------------------

    /**
     * Unix users that are part of the mail system itself.
     *
     * THIS LIST IS NOT COSMETIC. On a live cPanel server this module reported
     * `mailnull` as the top sender at 3,114 messages an hour and labelled it
     * CRITICAL, above a real customer account. mailnull is the user exim
     * itself runs as: that traffic is exim processing mail, overwhelmingly
     * bounces, not an account sending spam. The finding was wrong, it buried
     * the real one underneath it, and the "Cap rate" button offered next to it
     * would have run `whmapi1 modifyacct user=mailnull`, which is not a cPanel
     * account at all.
     *
     * magicspam appeared for the same reason: it is the MagicSpam product's
     * own system user.
     *
     * A detector whose loudest alarm is always the same false positive trains
     * the operator to ignore it, which costs more than having no detector.
     */
    public const SYSTEM_ACCOUNTS = [
        'mailnull', 'nobody', 'root', 'cpanel', 'cpanelsolr', 'cpaneleximfilter',
        'cpanelroundcube', 'mailman', 'exim', 'mail', 'daemon', 'bin',
        'magicspam', 'dovecot', 'dovenull', 'clamav', 'spamd',
    ];

    public static function isSystemAccount(string $account): bool
    {
        $a = strtolower(trim($account));
        if ($a === '' || $a === '(unattributed)') return true;
        return in_array($a, self::SYSTEM_ACCOUNTS, true);
    }


    // ── Settings ────────────────────────────────────────────────────────────

    public static function enabled(): bool
    {
        return Database::setting('mg_enabled', '1') === '1';
    }

    /** Messages per hour from one account before it is reported. */
    public static function hourlyThreshold(): int
    {
        return max(50, min(100000, (int)Database::setting('mg_hourly', '500')));
    }

    /** Queue depth that is a problem regardless of who caused it. */
    public static function queueThreshold(): int
    {
        return max(100, min(1000000, (int)Database::setting('mg_queue', '2000')));
    }

    /** Frozen messages that indicate a failing relay. */
    public static function frozenThreshold(): int
    {
        return max(10, min(100000, (int)Database::setting('mg_frozen', '250')));
    }

    /** Accounts exempt from rate reporting — a genuine bulk sender. */
    public static function exemptAccounts(): array
    {
        $raw = (string)Database::setting('mg_exempt', '');
        $out = [];
        foreach (preg_split('/[\s,]+/', $raw) as $a) {
            $a = trim($a);
            if ($a !== '') $out[] = $a;
        }
        return $out;
    }

    // ── Schema ──────────────────────────────────────────────────────────────

    public static function ensureSchema(): void
    {
        $db = Database::get();
        $db->exec("
            CREATE TABLE IF NOT EXISTS mail_activity (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket      INTEGER NOT NULL,
                account     TEXT    NOT NULL,
                source      TEXT    NOT NULL DEFAULT 'unknown',
                script      TEXT,
                sent        INTEGER NOT NULL DEFAULT 0,
                recipients  INTEGER NOT NULL DEFAULT 0,
                failed      INTEGER NOT NULL DEFAULT 0,
                frozen      INTEGER NOT NULL DEFAULT 0,
                bytes       INTEGER NOT NULL DEFAULT 0
            )");
        // Aggregated per hour per account per script, so a day of a 1,690/hour
        // relay is a couple of dozen rows rather than 40,000.
        $db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_bucket
                     ON mail_activity(bucket, account, source, script)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_mail_recent
                     ON mail_activity(bucket DESC)");
    }

    // ── Reading exim's log ──────────────────────────────────────────────────

    public static function logPath(): ?string
    {
        foreach (self::LOGS as $p) {
            if (is_readable($p)) return $p;
        }
        return null;
    }

    /**
     * The hour bucket a log line belongs to, from ITS OWN timestamp.
     *
     * THE BUG THIS FIXES. collect() used to compute one bucket from time() and
     * file every line it read into it. On a first run the offset is 0, so it
     * reads up to 8 MB of HISTORICAL log -- days of mail on a busy server --
     * and attributed all of it to the current hour.
     *
     * On a live server that reported a customer account as sending 5,036
     * messages in the last hour, at CRITICAL, and another 19,862 through
     * exim's own user. The real figure was 22 messages across 300,000 log
     * lines: a normal multi-site reseller doing nothing wrong. The operator
     * went looking for a backdoor and capped a 25-domain account to 100
     * messages an hour, which broke that customer's password resets and
     * contact forms, because of a number this module invented.
     *
     * A monitor that cannot say WHEN something happened cannot say how fast it
     * is happening, and a rate is the only thing this module reports.
     *
     * Returns null when the line carries no usable timestamp, so the caller
     * can decide rather than silently guessing "now".
     */
    public static function lineBucket(string $line): ?int
    {
        // exim writes "2026-10-20 15:38:37" at the start of every line, and
        // optionally a timezone offset after it.
        if (!preg_match('/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):/', $line, $m)) {
            return null;
        }
        // Hour precision is all a bucket needs, so the minute and second are
        // read only to confirm the shape.
        $ts = @mktime((int)$m[4], 0, 0, (int)$m[2], (int)$m[3], (int)$m[1]);
        if ($ts === false) return null;

        // Refuse a timestamp from the future or from before this product could
        // plausibly have been running. A corrupt or mis-parsed line must not
        // create a bucket that then reads as "the last hour" for ever.
        $now = time();
        if ($ts > $now + 86400) return null;
        if ($ts < $now - 86400 * 400) return null;

        return (int)(floor($ts / 3600) * 3600);
    }

    /**
     * Parse one exim log line into an activity record.
     *
     * Public and pure so it can be tested against real log lines without a mail
     * server. Returns null for the many lines that are neither an arrival nor
     * an outcome.
     *
     * @return array{kind:string,account:?string,source:string,script:?string,
     *               recipients:int,bytes:int}|null
     */
    public static function parseLine(string $line): ?array
    {
        // Arrival: "<=" means exim accepted a message for sending.
        if (strpos($line, ' <= ') !== false) {
            $acct = null;
            $src  = 'unknown';
            $script = null;

            // U=<unix user> on a locally injected message. On cPanel that IS
            // the account, which is what makes attribution possible at all.
            if (preg_match('/\sU=([A-Za-z0-9._-]+)/', $line, $m)) {
                $acct = $m[1];
                $src  = 'script';
            }

            // An authenticated send. A real mailbox password is in use, so this
            // is stolen credentials rather than an exploited script -- a
            // different incident with a different fix, so it is recorded
            // differently.
            if (preg_match('/\sA=[A-Za-z0-9_]*(?:login|auth)[^:]*:(\S+)/i', $line, $m)) {
                $src = 'smtp_auth';
                $login = $m[1];
                $dom = strpos($login, '@') !== false
                     ? substr($login, strpos($login, '@') + 1) : '';
                $mapped = $dom !== '' ? self::accountForDomain($dom) : null;
                if ($mapped !== null) { $acct = $mapped; }
                elseif ($acct === null) { $acct = $login; }
            }

            // cwd= names the directory the sending script ran from. THE useful
            // field: it turns "this account sends a lot" into "this form on
            // this site is the relay".
            if (preg_match('/\scwd=(\S+)/', $line, $m)) {
                $script = $m[1];
                if ($acct === null) {
                    $acct = self::accountForPath($m[1]);
                    if ($acct !== null) $src = 'script';
                }
            }

            $bytes = preg_match('/\sS=(\d+)/', $line, $m) ? (int)$m[1] : 0;

            // "for a@b c@d" lists the envelope recipients. A single message to
            // many recipients is one arrival but a lot of mail, and a blast is
            // often shaped exactly that way.
            $rcpt = 1;
            if (preg_match('/\sfor\s+(.+)$/', $line, $m)) {
                $n = preg_match_all('/[^\s<>,]+@[^\s<>,]+/', $m[1]);
                if ($n > 0) $rcpt = $n;
            }

            return ['kind' => 'arrival', 'account' => $acct, 'source' => $src,
                    'script' => $script, 'recipients' => $rcpt, 'bytes' => $bytes];
        }

        // Permanent failure. "**" is exim's own marker.
        if (strpos($line, ' ** ') !== false) {
            return ['kind' => 'failed', 'account' => null, 'source' => 'unknown',
                    'script' => null, 'recipients' => 1, 'bytes' => 0];
        }

        if (stripos($line, 'Frozen') !== false) {
            return ['kind' => 'frozen', 'account' => null, 'source' => 'unknown',
                    'script' => null, 'recipients' => 0, 'bytes' => 0];
        }

        return null;
    }

    /**
     * Read new log lines and aggregate them.
     *
     * Incremental, following the same offset pattern BruteForce uses: the
     * position is remembered, and a file smaller than the offset means it
     * rotated, so it starts again rather than seeking past the end and reading
     * nothing for ever.
     *
     * @return array{read:int,arrivals:int,buckets:int,skipped?:string}
     */
    public static function collect(): array
    {
        if (!self::enabled()) {
            return ['read' => 0, 'arrivals' => 0, 'buckets' => 0,
                    'skipped' => 'outbound mail monitoring is switched off'];
        }
        self::ensureSchema();

        $path = self::logPath();
        if ($path === null) {
            return ['read' => 0, 'arrivals' => 0, 'buckets' => 0,
                    'skipped' => 'no readable exim log (' . implode(', ', self::LOGS) . ')'];
        }

        $offset = (int)Database::setting('mg_offset', '0');
        $size   = (int)@filesize($path);
        if ($size < $offset) { $offset = 0; }        // rotated
        if ($size === $offset) {
            return ['read' => 0, 'arrivals' => 0, 'buckets' => 0];
        }

        $fh = @fopen($path, 'r');
        if (!$fh) {
            return ['read' => 0, 'arrivals' => 0, 'buckets' => 0,
                    'skipped' => "cannot open $path"];
        }
        if ($offset > 0) @fseek($fh, $offset);

        // The CURRENT hour is only a fallback for a line with no readable
        // timestamp. Every line that has one is bucketed by its own.
        $nowBucket = (int)(floor(time() / 3600) * 3600);
        $agg       = [];
        $arrivals  = 0;
        $read      = 0;
        $undated   = 0;
        // Consecutive lines usually share a timestamp, so the last conversion
        // is reused rather than re-parsed for every line of an 8 MB read.
        $lastStamp = '';
        $lastBucket = $nowBucket;

        while (($line = fgets($fh)) !== false) {
            $read += strlen($line);
            if ($read > self::MAX_READ) break;

            $p = self::parseLine($line);
            if ($p === null) continue;

            $stamp = substr($line, 0, 13);          // "2026-10-20 15"
            if ($stamp !== $lastStamp) {
                $b = self::lineBucket($line);
                if ($b === null) {
                    $undated++;
                    $b = $nowBucket;
                }
                $lastStamp  = $stamp;
                $lastBucket = $b;
            }
            $bucket = $lastBucket;

            $acct   = $p['account'] ?? '(unattributed)';
            $script = $p['script'];
            $key    = $bucket . "\0" . $acct . "\0" . $p['source'] . "\0" . (string)$script;

            if (!isset($agg[$key])) {
                $agg[$key] = ['bucket' => $bucket, 'account' => $acct,
                              'source' => $p['source'], 'script' => $script,
                              'sent' => 0, 'recipients' => 0, 'failed' => 0,
                              'frozen' => 0, 'bytes' => 0];
            }
            switch ($p['kind']) {
                case 'arrival':
                    $agg[$key]['sent']++;
                    $agg[$key]['recipients'] += $p['recipients'];
                    $agg[$key]['bytes']      += $p['bytes'];
                    $arrivals++;
                    break;
                case 'failed': $agg[$key]['failed']++; break;
                case 'frozen': $agg[$key]['frozen']++; break;
            }
        }

        $newOffset = ftell($fh);
        fclose($fh);
        Database::setSetting('mg_offset', (string)$newOffset);

        self::flush($agg);

        // Reported, not swallowed. A log whose lines cannot be dated means
        // every rate this module publishes is a guess, and the operator needs
        // to know that before acting on one.
        if ($undated > 0) {
            Logger::warn(sprintf('MailGuard: %d log line(s) had no readable '
                               . 'timestamp and were counted in the current hour',
                                 $undated));
        }

        return ['read' => $read, 'arrivals' => $arrivals, 'buckets' => count($agg),
                'undated' => $undated];
    }

    /** Merge aggregated counts into the hour buckets. */
    private static function flush(array $agg): void
    {
        if ($agg === []) return;
        $db = Database::get();
        $db->beginTransaction();
        try {
            $sel = $db->prepare(
                "SELECT id FROM mail_activity
                  WHERE bucket = ? AND account = ? AND source = ?
                    AND IFNULL(script,'') = IFNULL(?,'') LIMIT 1");
            $ins = $db->prepare(
                "INSERT INTO mail_activity
                   (bucket, account, source, script, sent, recipients, failed, frozen, bytes)
                 VALUES (?,?,?,?,?,?,?,?,?)");
            $upd = $db->prepare(
                "UPDATE mail_activity
                    SET sent = sent + ?, recipients = recipients + ?,
                        failed = failed + ?, frozen = frozen + ?, bytes = bytes + ?
                  WHERE id = ?");

            foreach ($agg as $a) {
                $sel->execute([$a['bucket'], $a['account'], $a['source'], $a['script']]);
                $row = $sel->fetch(PDO::FETCH_ASSOC);
                if ($row) {
                    $upd->execute([$a['sent'], $a['recipients'], $a['failed'],
                                   $a['frozen'], $a['bytes'], $row['id']]);
                } else {
                    $ins->execute([$a['bucket'], $a['account'], $a['source'],
                                   $a['script'], $a['sent'], $a['recipients'],
                                   $a['failed'], $a['frozen'], $a['bytes']]);
                }
            }
            $db->commit();
        } catch (Throwable $e) {
            $db->rollBack();
            Logger::error('MailGuard: could not record activity — ' . $e->getMessage());
        }
    }

    // ── The queue ───────────────────────────────────────────────────────────

    /** Messages waiting. -1 when exim cannot be asked. */
    public static function queueDepth(): int
    {
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $bin) {
            if (!is_executable($bin)) continue;
            $out = trim((string)@shell_exec('nice -n 19 ' . escapeshellarg($bin)
                                            . ' -bpc 2>/dev/null'));
            if ($out !== '' && ctype_digit($out)) return (int)$out;
        }
        return -1;
    }

    /**
     * Frozen messages.
     *
     * `exim -bpc` counts everything; frozen specifically means delivery gave up
     * and the message is parked. A spike is often the first outside sign of a
     * relay, because the spam is being rejected by its targets.
     *
     * Uses exim's own summary rather than walking the spool: on a queue of
     * 93,000 messages, listing it is itself expensive.
     */
    public static function frozenCount(): int
    {
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $bin) {
            if (!is_executable($bin)) continue;
            $out = (string)@shell_exec('nice -n 19 ' . escapeshellarg($bin)
                                       . ' -bp 2>/dev/null | grep -c frozen');
            $out = trim($out);
            if ($out !== '' && ctype_digit($out)) return (int)$out;
        }
        return -1;
    }

    // ── Judging it ──────────────────────────────────────────────────────────

    /**
     * Findings, worst first. Reports; changes nothing.
     *
     * @return array<int,array{type:string,severity:string,what:string,action:string}>
     */
    public static function evaluate(): array
    {
        self::ensureSchema();
        $f      = [];
        $exempt = self::exemptAccounts();

        // The queue itself. Independent of attribution, because a queue that is
        // climbing is a problem even before anyone knows whose mail it is.
        $q = self::queueDepth();
        if ($q >= 0 && $q >= self::queueThreshold()) {
            $f[] = [
                'type' => 'queue_depth', 'severity' => $q >= self::queueThreshold() * 5
                                                       ? 'critical' : 'high',
                'what' => sprintf('%s messages are waiting in the mail queue '
                                . '(threshold %s)', number_format($q),
                                  number_format(self::queueThreshold())),
                'action' => 'Find the sender before clearing anything: see the per-'
                          . 'account table below. The queue holds real customer mail '
                          . 'alongside whatever caused this, so do not empty it blind.',
            ];
        }

        $fr = self::frozenCount();
        if ($fr >= 0 && $fr >= self::frozenThreshold()) {
            $f[] = [
                'type' => 'frozen_mail', 'severity' => 'high',
                'what' => sprintf('%s frozen messages — deliveries are being '
                                . 'rejected and parked', number_format($fr)),
                'action' => 'Usually the first outside sign of a relay: the spam is '
                          . 'being refused by its targets. Check which account is '
                          . 'sending, not just the queue size.',
            ];
        }

        // Per-account rate over the last complete hours.
        $since = (int)(floor(time() / 3600) * 3600) - 3600;
        $rows  = Database::fetchAll(
            "SELECT account, source, script,
                    SUM(sent) AS sent, SUM(recipients) AS rcpt,
                    SUM(failed) AS failed
               FROM mail_activity
              WHERE bucket >= CAST(? AS INTEGER) AND account <> '(unattributed)'
           GROUP BY account, source, script
           ORDER BY SUM(sent) DESC LIMIT 50", [$since]);

        $limit  = self::hourlyThreshold();
        $system = [];
        foreach ($rows as $r) {
            $sent = (int)$r['sent'];
            if ($sent < $limit) continue;
            if (in_array($r['account'], $exempt, true)) continue;

            // Not a customer. exim's own run user and the other mail-system
            // accounts are reported separately below, because "mailnull is
            // sending 3,114/hour" is not an account to cap -- it is exim
            // telling you something else is wrong.
            if (self::isSystemAccount((string)$r['account'])) {
                $system[(string)$r['account']] = ($system[(string)$r['account']] ?? 0) + $sent;
                continue;
            }

            $where = $r['script'] ? ' from ' . $r['script'] : '';
            $auth  = $r['source'] === 'smtp_auth';

            $f[] = [
                'type'     => $auth ? 'auth_send_burst' : 'account_send_burst',
                // 3x a threshold the operator set deliberately is not
                // ambiguous. The relay this module exists for ran at ~1,690/hour
                // against a 500 default -- 3.4x -- and sustained that for a day,
                // which is 40,000 messages. At x4 that real incident would have
                // been reported merely as "high", which is the wrong answer to
                // the one case this was built from.
                'severity' => $sent >= $limit * 3 ? 'critical' : 'high',
                'what'     => sprintf('%s sent %s messages to %s recipients in the '
                                    . 'last hour%s (threshold %s)',
                                      $r['account'], number_format($sent),
                                      number_format((int)$r['rcpt']), $where,
                                      number_format($limit)),
                // The two cases need different fixes, so they get different advice.
                'action'   => $auth
                    ? 'This used a real mailbox password, so the credentials are '
                    . 'compromised rather than a script being exploited. Change that '
                    . 'mailbox password, end its sessions, then look for how it leaked.'
                    : ($r['script']
                        ? 'A script in that directory is sending. Check its contact '
                        . 'forms first: one Contact Form 7 autoresponder relayed '
                        . '92,954 messages from this server in a day without any file '
                        . 'being modified. Disable the second mail template or add a '
                        . 'captcha.'
                        : 'Identify the sending script. Then cap the account with '
                        . 'MailGuard::throttle() while you fix it.'),
            ];
        }

        // High volume through the mail system's own accounts.
        //
        // Reported, but never as "that account is spamming". On cPanel this is
        // almost always BOUNCES, and a flood of bounces means spam has already
        // left the server and is being rejected elsewhere -- so it is a signal
        // worth acting on, pointing somewhere other than itself.
        foreach ($system as $acct => $n) {
            $f[] = [
                'type' => 'system_mail_volume', 'severity' => 'medium',
                'what' => sprintf('%s messages passed through the system account '
                                . '"%s" in the last hour', number_format($n), $acct),
                'action' => $acct === 'mailnull'
                    ? 'mailnull is the user exim itself runs as, so this is not an '
                    . 'account to cap. At this volume it is usually bounces, which '
                    . 'means mail has already left and is being rejected elsewhere. '
                    . 'Look at the per-account table for who actually sent it.'
                    : 'A mail-system account rather than a customer. Worth knowing, '
                    . 'but cap the account that fed it, not this one.',
            ];
        }

        $order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
        usort($f, fn($a, $b) => $order[$a['severity']] <=> $order[$b['severity']]);
        return $f;
    }

    /**
     * One pass for the scheduler: read the log, judge it, record alerts.
     */
    public static function run(): array
    {
        $c = self::collect();
        if (!empty($c['skipped'])) return $c + ['findings' => 0];

        $f = self::evaluate();
        foreach ($f as $x) {
            // Deduplicated by the hour, so a relay running all day raises one
            // alert an hour rather than one every 15 minutes.
            $key = 'mg_alert_' . md5($x['type'] . '|' . $x['what']);
            $last = (int)Database::setting($key, '0');
            if (time() - $last < 3600) continue;
            Database::setSetting($key, (string)time());

            Logger::event('outbound_mail', $x['severity'], '', 'mail queue',
                          $x['what'] . ' — ' . $x['action']);
            Logger::warn('Outbound mail: ' . $x['what']);
        }
        return $c + ['findings' => count($f)];
    }

    // ── Acting, only when asked ─────────────────────────────────────────────

    /**
     * Cap an account's hourly send rate.
     *
     * Through cPanel's own per-account limit, which is the mechanism cPanel
     * already enforces and already reports on — rather than inventing a second
     * one that exim does not consult.
     *
     * NOT automatic anywhere in this class. Capping a real business's mail is a
     * decision with a customer on the other end of it, and the right cap for a
     * newsletter is not the right cap for a contact form. During the incident
     * the operator chose 1,000/hour deliberately after seeing the numbers.
     *
     * @return array{success:bool,error?:string,limit?:int}
     */
    public static function throttle(string $account, int $perHour): array
    {
        if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,31}$/i', $account)) {
            return ['success' => false, 'error' => 'Not a valid account name'];
        }
        if ($perHour < 1 || $perHour > 1000000) {
            return ['success' => false, 'error' => 'Limit must be between 1 and 1000000'];
        }
        if (!is_executable(WHMAPI_BINARY)) {
            return ['success' => false,
                    'error' => 'whmapi1 not available — set the limit in WHM under '
                             . 'Email → Mail Send Limits'];
        }

        $cmd = sprintf('%s modifyacct user=%s MAX_EMAIL_PER_HOUR=%d --output=json 2>&1',
                       escapeshellarg(WHMAPI_BINARY), escapeshellarg($account), $perHour);
        @exec($cmd, $out, $rc);
        $raw  = implode(' ', $out);
        $json = json_decode($raw, true);
        $ok   = $rc === 0 && (int)($json['metadata']['result'] ?? 0) === 1;

        if ($ok) {
            Logger::warn(sprintf('Outbound mail: %s capped at %d messages/hour',
                                 $account, $perHour));
            return ['success' => true, 'limit' => $perHour];
        }
        return ['success' => false,
                'error' => $json['metadata']['reason'] ?? trim(substr($raw, 0, 200))];
    }


    // -- Settings, written through validation --------------------------------

    /**
     * Save the operator's settings.
     *
     * Every numeric value goes back out through the same getter that clamps it,
     * so what the panel shows afterwards is what will actually be used. Writing
     * a raw value and letting the getter silently clamp it later would mean the
     * panel reports a threshold the detector is not using -- and an operator
     * who sets 10/hour and sees 10/hour would reasonably expect an alert that
     * never comes.
     *
     * @param array<string,mixed> $in
     * @return array{success:bool,saved:array<string,string>,rejected:array<string,string>}
     */
    public static function saveSettings(array $in): array
    {
        $saved    = [];
        $rejected = [];

        if (array_key_exists('enabled', $in)) {
            $v = !empty($in['enabled']) ? '1' : '0';
            Database::setSetting('mg_enabled', $v);
            $saved['enabled'] = $v;
        }

        // key => [setting, getter] -- the getter is the authority on range.
        $nums = [
            'hourly'       => ['mg_hourly',       'hourlyThreshold'],
            'queue'        => ['mg_queue',        'queueThreshold'],
            'frozen'       => ['mg_frozen',       'frozenThreshold'],
            'retain_days'  => ['mg_retain_days',  null],
        ];

        foreach ($nums as $key => [$setting, $getter]) {
            if (!array_key_exists($key, $in)) continue;

            $raw = $in[$key];
            if (!is_numeric($raw)) {
                $rejected[$key] = 'not a number';
                continue;
            }
            $asked = (int)$raw;
            Database::setSetting($setting, (string)$asked);

            if ($getter !== null) {
                $effective = self::$getter();
                $saved[$key] = (string)$effective;
                // Told plainly when a value was clamped, rather than quietly
                // storing one number and using another.
                if ($effective !== $asked) {
                    $rejected[$key] = sprintf(
                        'adjusted from %d to %d, which is the usable range',
                        $asked, $effective);
                    Database::setSetting($setting, (string)$effective);
                }
            } else {
                $clamped = max(7, min(365, $asked));
                Database::setSetting($setting, (string)$clamped);
                $saved[$key] = (string)$clamped;
                if ($clamped !== $asked) {
                    $rejected[$key] = sprintf('adjusted from %d to %d days',
                                              $asked, $clamped);
                }
            }
        }

        if (array_key_exists('exempt', $in)) {
            // Account names only. An unchecked string here would end up in the
            // exemption list, and an exemption that matches more than intended
            // silently stops reporting the thing this module exists for.
            $clean = [];
            // Split on COMMAS and newlines only, never on spaces. Splitting on
            // whitespace turns "bad name!" into "bad" plus "name!" -- the
            // second is rejected and the first, which looks like a perfectly
            // valid account, is silently exempted. An exemption added by
            // accident stops the alerts this whole module exists for, without
            // anything appearing to go wrong.
            foreach (preg_split('/[,
]+/', (string)$in['exempt']) as $a) {
                $a = trim($a);
                if ($a === '') continue;
                if (preg_match('/^[a-z0-9][a-z0-9_-]{0,31}$/i', $a)) {
                    $clean[] = $a;
                } else {
                    $rejected['exempt'] = 'ignored "' . substr($a, 0, 24)
                                        . '" — not a valid account name';
                }
            }
            $v = implode(',', array_unique($clean));
            Database::setSetting('mg_exempt', $v);
            $saved['exempt'] = $v;
        }

        if ($saved !== []) {
            Logger::info('Outbound mail settings changed: '
                . implode(', ', array_map(
                    fn($k, $v) => "$k=$v", array_keys($saved), $saved)));
        }

        return ['success' => true, 'saved' => $saved, 'rejected' => $rejected];
    }

    /** Current settings and the range each one accepts, for the panel. */
    public static function settings(): array
    {
        return [
            'enabled'     => self::enabled(),
            'hourly'      => self::hourlyThreshold(),
            'queue'       => self::queueThreshold(),
            'frozen'      => self::frozenThreshold(),
            'exempt'      => implode(', ', self::exemptAccounts()),
            'retain_days' => max(7, min(365, (int)Database::setting('mg_retain_days', '60'))),
            // Shown next to each field so the clamps are visible BEFORE a value
            // is rejected, not after.
            'ranges'      => [
                'hourly'      => [50, 100000],
                'queue'       => [100, 1000000],
                'frozen'      => [10, 100000],
                'retain_days' => [7, 365],
            ],
        ];
    }

    // -- Looking in the queue, and emptying parts of it ----------------------

    /**
     * An exim message id, strictly.
     *
     * Every id reaching a delete goes through this. The ids come back from the
     * panel, so they are user input by the time they return, and they are
     * interpolated into a root command: nothing that is not an exim id may get
     * that far.
     */
    public static function isMessageId(string $id): bool
    {
        return (bool)preg_match('/^[A-Za-z0-9]{6}-[A-Za-z0-9]{6,20}-[A-Za-z0-9]{2,6}$/', $id);
    }

    /**
     * List queued messages.
     *
     * BOUNDED, and that is not optional. `exim -bp` on the 93,255-message
     * queue this module was built after would return megabytes of text and
     * take real time on a server already in trouble. The panel shows a page,
     * not the queue.
     *
     * @param bool $frozenOnly only messages exim has given up on
     * @return array{messages:array,total:int,shown:int,truncated:bool,error?:string}
     */
    public static function queueList(bool $frozenOnly = false, int $limit = 200,
                                     string $search = ''): array
    {
        $bin = null;
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $b) {
            if (is_executable($b)) { $bin = $b; break; }
        }
        if ($bin === null) {
            return ['messages' => [], 'total' => 0, 'shown' => 0,
                    'truncated' => false, 'error' => 'exim not found'];
        }

        $limit = max(1, min(1000, $limit));
        $cmd = 'nice -n 19 ' . escapeshellarg($bin) . ' -bp 2>/dev/null';
        $out = (string)@shell_exec($cmd);
        if ($out === '') {
            return ['messages' => [], 'total' => 0, 'shown' => 0, 'truncated' => false];
        }

        $messages = [];
        $total    = 0;
        $cur      = null;

        foreach (explode("\n", $out) as $line) {
            if (trim($line) === '') {
                if ($cur !== null) { self::pushMsg($messages, $cur, $frozenOnly,
                                                   $search, $limit, $total); }
                $cur = null;
                continue;
            }
            // Header line: "25m  2.5K 1aBcDe-0001AB-XY <sender@dom>"
            if (preg_match('/^\s*(\S+)\s+(\S+)\s+([A-Za-z0-9]{6}-[A-Za-z0-9]{6,20}-[A-Za-z0-9]{2,6})\s+(.*)$/',
                           $line, $m)) {
                if ($cur !== null) { self::pushMsg($messages, $cur, $frozenOnly,
                                                   $search, $limit, $total); }
                $rest   = $m[4];
                $frozen = stripos($rest, 'frozen') !== false;
                $sender = '';
                if (preg_match('/<([^>]*)>/', $rest, $sm)) $sender = $sm[1];
                $cur = ['id' => $m[3], 'age' => $m[1], 'size' => $m[2],
                        'sender' => $sender === '' ? '<>' : $sender,
                        'frozen' => $frozen, 'recipients' => []];
                continue;
            }
            // Continuation lines are recipients.
            if ($cur !== null) {
                $r = trim($line);
                if ($r !== '' && $r[0] !== '*') $cur['recipients'][] = $r;
            }
        }
        if ($cur !== null) { self::pushMsg($messages, $cur, $frozenOnly,
                                           $search, $limit, $total); }

        return ['messages' => $messages, 'total' => $total,
                'shown' => count($messages), 'truncated' => $total > count($messages)];
    }

    /** Collect a parsed message if it matches, keeping the page bounded. */
    private static function pushMsg(array &$acc, array $msg, bool $frozenOnly,
                                    string $search, int $limit, int &$total): void
    {
        if ($frozenOnly && empty($msg['frozen'])) return;

        if ($search !== '') {
            $hay = strtolower($msg['sender'] . ' ' . implode(' ', $msg['recipients'])
                              . ' ' . $msg['id']);
            if (strpos($hay, strtolower($search)) === false) return;
        }

        $total++;
        if (count($acc) >= $limit) return;   // counted, not shown
        $msg['account'] = self::senderAccount($msg['sender']);
        $acc[] = $msg;
    }

    /** Best guess at which cPanel account a sender address belongs to. */
    public static function senderAccount(string $sender): ?string
    {
        if ($sender === '' || $sender === '<>') return null;
        $at = strrpos($sender, '@');
        if ($at === false) return null;
        return self::accountForDomain(substr($sender, $at + 1));
    }

    /**
     * Remove messages from the queue, by id.
     *
     * THE ONLY DESTRUCTIVE THING IN THIS MODULE, and it is deliberately
     * per-message rather than "empty the queue".
     *
     * During the incident this module was built after, 92,954 of 93,255 queued
     * messages were a relay -- which still left 301 that a real customer was
     * waiting for. A button that empties the queue destroys those 301 with no
     * way back and no record of what they were. So: ids are chosen, validated,
     * capped per call, and every deletion is logged with its sender and
     * recipients first, because afterwards there is nothing left to log.
     *
     * @return array{success:bool,deleted:int,failed:array,error?:string}
     */
    public static function deleteMessages(array $ids): array
    {
        // VALIDATE FIRST, then look for exim.
        //
        // Input validation must not depend on a binary being present: a server
        // without exim would otherwise return "exim not found" for a hostile
        // id and never record that it was hostile. The check that keeps shell
        // metacharacters away from a root command is the one thing here that
        // has to run unconditionally.
        $clean = [];
        $failed = [];
        foreach ($ids as $id) {
            $id = trim((string)$id);
            if (self::isMessageId($id)) { $clean[] = $id; }
            else { $failed[] = ['id' => substr($id, 0, 40),
                                'error' => 'not a valid exim message id']; }
        }
        if ($clean === []) {
            return ['success' => false, 'deleted' => 0, 'failed' => $failed,
                    'error' => 'No valid message ids'];
        }
        // Capped per call so one click cannot clear a queue of 93,000.
        if (count($clean) > 500) {
            return ['success' => false, 'deleted' => 0, 'failed' => $failed,
                    'error' => 'Refusing more than 500 messages in one go — '
                             . 'delete in batches so the action stays reviewable'];
        }

        $bin = null;
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $b) {
            if (is_executable($b)) { $bin = $b; break; }
        }
        if ($bin === null) {
            return ['success' => false, 'deleted' => 0, 'failed' => $failed,
                    'error' => 'exim not found'];
        }

        // Record WHAT is being destroyed before destroying it.
        Logger::warn(sprintf('Deleting %d queued message(s): %s',
                             count($clean), implode(' ', array_slice($clean, 0, 50))));

        $deleted = 0;
        foreach (array_chunk($clean, 50) as $chunk) {
            $cmd = 'nice -n 19 ' . escapeshellarg($bin) . ' -Mrm '
                 . implode(' ', array_map('escapeshellarg', $chunk)) . ' 2>&1';
            @exec($cmd, $o, $rc);
            if ($rc === 0) {
                $deleted += count($chunk);
            } else {
                foreach ($chunk as $id) {
                    $failed[] = ['id' => $id,
                                 'error' => trim(implode(' ', array_slice($o, 0, 2)))
                                            ?: 'exim refused'];
                }
            }
            $o = [];
        }

        Logger::event('mail_queue_delete', 'high', '', 'mail queue',
                      sprintf('%d message(s) removed from the queue by an operator',
                              $deleted));

        return ['success' => $deleted > 0, 'deleted' => $deleted, 'failed' => $failed];
    }

    /**
     * A message's headers, for deciding whether it is spam before deleting it.
     *
     * Headers only -- never the body. The body is a customer's private mail,
     * and nothing here needs it to tell a relay from a receipt.
     */
    public static function messageHeaders(string $id): array
    {
        if (!self::isMessageId($id)) {
            return ['success' => false, 'error' => 'Not a valid message id'];
        }
        $bin = null;
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $b) {
            if (is_executable($b)) { $bin = $b; break; }
        }
        if ($bin === null) return ['success' => false, 'error' => 'exim not found'];

        $out = (string)@shell_exec('nice -n 19 ' . escapeshellarg($bin) . ' -Mvh '
                                   . escapeshellarg($id) . ' 2>&1');
        // cPanel adds X-Source headers to locally generated mail, which name
        // the script. That is the same answer cwd= gives in the log, from the
        // other side -- and on servers where the log does not carry cwd= it is
        // the only place it exists.
        $source = [];
        foreach (['X-Source', 'X-Source-Args', 'X-Source-Dir', 'X-PHP-Script'] as $h) {
            if (preg_match('/^' . preg_quote($h, '/') . ':\s*(.+)$/mi', $out, $m)) {
                $source[$h] = trim($m[1]);
            }
        }
        return ['success' => true,
                'headers' => substr($out, 0, 16384),
                'source'  => $source];
    }

    // ── Reporting ───────────────────────────────────────────────────────────

    public static function topSenders(int $hours = 24, int $limit = 25): array
    {
        self::ensureSchema();
        $since = time() - max(1, $hours) * 3600;
        return Database::fetchAll(
            "SELECT account, source, script,
                    SUM(sent) AS sent, SUM(recipients) AS recipients,
                    SUM(failed) AS failed, SUM(bytes) AS bytes,
                    MAX(bucket) AS last_seen
               FROM mail_activity
              WHERE bucket >= CAST(? AS INTEGER)
           GROUP BY account, source, script
           ORDER BY SUM(sent) DESC
              LIMIT " . max(1, min(200, $limit)), [$since]);
    }

    public static function status(): array
    {
        self::ensureSchema();
        $q  = self::queueDepth();
        $fr = self::frozenCount();
        return [
            'enabled'        => self::enabled(),
            'log'            => self::logPath(),
            'queue'          => $q,
            'frozen'         => $fr,
            'queue_threshold'  => self::queueThreshold(),
            'hourly_threshold' => self::hourlyThreshold(),
            'frozen_threshold' => self::frozenThreshold(),
            'exempt'         => self::exemptAccounts(),
            // -1, not 0. A queue that cannot be read and an empty queue are
            // very different things and must not look the same on a panel.
            'queue_readable' => $q >= 0,
            'findings'       => self::evaluate(),
            'top'            => self::topSenders(24, 25),
        ];
    }

    /** Keep the table small; hourly buckets still add up over a year. */
    public static function prune(?int $days = null): int
    {
        self::ensureSchema();
        $days = $days ?? max(7, min(365, (int)Database::setting('mg_retain_days', '60')));
        $cut  = time() - $days * 86400;
        $st = Database::query("DELETE FROM mail_activity WHERE bucket < CAST(? AS INTEGER)",
                              [$cut]);
        return $st->rowCount();
    }

    // ── Attribution helpers ─────────────────────────────────────────────────

    /** cPanel account owning a domain, via /etc/trueuserdomains. */
    public static function accountForDomain(string $domain, ?string $mapFile = null): ?string
    {
        static $map = null;
        $file = $mapFile ?? '/etc/trueuserdomains';
        if ($map === null || $mapFile !== null) {
            $map = [];
            foreach (@file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $l) {
                $parts = explode(':', $l, 2);
                if (count($parts) === 2) {
                    $map[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
            }
        }
        $d = strtolower(ltrim($domain, '.'));
        if (isset($map[$d])) return $map[$d];
        // A subdomain or mail.<domain> belongs to the parent's account.
        $bits = explode('.', $d);
        while (count($bits) > 2) {
            array_shift($bits);
            $try = implode('.', $bits);
            if (isset($map[$try])) return $map[$try];
        }
        return null;
    }

    /** cPanel account owning a filesystem path. */
    public static function accountForPath(string $path): ?string
    {
        if (preg_match('#^/home\d*/([^/]+)/#', $path . '/', $m)) {
            return $m[1];
        }
        return null;
    }
}
