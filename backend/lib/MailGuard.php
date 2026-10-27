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

        // Why mail is NOT going out.
        //
        // Counted server-wide rather than per account, deliberately. A
        // delivery line carries the message id but not the sending user, so
        // attributing it would mean holding a message-id-to-account map across
        // log passes -- state that goes wrong quietly. The reason is what the
        // operator needs ("the IP is rate-limited" vs "one mailbox is full"),
        // and that is not per-account anyway.
        $db->exec("
            CREATE TABLE IF NOT EXISTS mail_delivery (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket  INTEGER NOT NULL,
                kind    TEXT    NOT NULL,
                code    TEXT    NOT NULL DEFAULT '',
                reason  TEXT    NOT NULL DEFAULT '',
                n       INTEGER NOT NULL DEFAULT 0
            )");
        $db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_maildel
                     ON mail_delivery(bucket, kind, code, reason)");

        // Attachments an operator has judged malicious.
        //
        // Recorded rather than removed: exim has no clean way to strip one
        // part from a queued message, and a half-rewritten message is worse
        // than a flagged one. The sha256 is the valuable column -- it lets the
        // malware scanner recognise the same bytes when they land on disk,
        // which is where they end up if anybody opens the mail.
        $db->exec("
            CREATE TABLE IF NOT EXISTS mail_flagged_attachments (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id   TEXT    NOT NULL,
                filename     TEXT    NOT NULL,
                sha256       TEXT    NOT NULL DEFAULT '',
                content_type TEXT    NOT NULL DEFAULT '',
                bytes        INTEGER NOT NULL DEFAULT 0,
                note         TEXT    NOT NULL DEFAULT '',
                flagged_by   TEXT    NOT NULL DEFAULT '',
                flagged_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE(message_id, filename)
            )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_mailflag_hash
                     ON mail_flagged_attachments(sha256)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_maildel_recent
                     ON mail_delivery(bucket DESC)");
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
                    'script' => null, 'recipients' => 1, 'bytes' => 0]
                 + self::failureReason($line);
        }

        // Temporary failure. "==" lines were ignored entirely, and they are
        // where the answer lives.
        //
        // On a live server the whole queue sat undelivered for four days and
        // the panel said nothing at all, because it only ever counted
        // ARRIVALS. The reason was in these lines the whole time:
        // "421-4.7.0 Gmail has detected..." (the IP being rate-limited) and
        // "452-4.2.2 The recipient..." (one mailbox full). Three different
        // problems -- a rate limit, a full mailbox and a routing defer -- look
        // identical as "mail is stuck", and need completely different fixes.
        if (strpos($line, ' == ') !== false) {
            return ['kind' => 'deferred', 'account' => null, 'source' => 'unknown',
                    'script' => null, 'recipients' => 1, 'bytes' => 0]
                 + self::failureReason($line);
        }

        if (stripos($line, 'Frozen') !== false) {
            return ['kind' => 'frozen', 'account' => null, 'source' => 'unknown',
                    'script' => null, 'recipients' => 0, 'bytes' => 0]
                 + self::failureReason($line);
        }

        return null;
    }

    /**
     * The SMTP code and a normalised reason from a delivery-outcome line.
     *
     * NORMALISED so it can be counted. Raw reasons carry the remote IP, the
     * message id and a timestamp, so a thousand identical rate-limit refusals
     * would otherwise be a thousand distinct strings and aggregate to nothing.
     * Digits, addresses and ids are collapsed; the sentence that identifies the
     * problem survives.
     *
     * @return array{code:string,reason:string}
     */
    public static function failureReason(string $line): array
    {
        // Everything after the recipient is the explanation.
        $tail = $line;
        foreach ([' ** ', ' == ', ' <= '] as $mark) {
            $at = strpos($tail, $mark);
            if ($at !== false) { $tail = substr($tail, $at + strlen($mark)); break; }
        }

        $code = '';
        if (preg_match('/\b([45]\d{2})(?:[-\s]|$)/', $tail, $m)) {
            $code = $m[1];
        }

        // Keep the human sentence, drop everything that varies per message.
        $r = $tail;
        $r = preg_replace('/\b\d{1,3}(?:\.\d{1,3}){3}\b/', 'IP', $r);
        $r = preg_replace('/[A-Za-z0-9]{6}-[A-Za-z0-9]{6,20}-[A-Za-z0-9]{2,6}/', 'ID', $r);
        $r = preg_replace('/<[^>]*>/', '', $r);
        $r = preg_replace('/\S+@\S+/', 'ADDR', $r);
        $r = preg_replace('/\b\d+\b/', 'N', $r);
        $r = preg_replace('/\s+/', ' ', (string)$r);
        $r = trim((string)$r);

        return ['code' => $code, 'reason' => substr($r, 0, 160)];
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
        $del       = [];
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
                case 'failed':   $agg[$key]['failed']++; break;
                case 'frozen':   $agg[$key]['frozen']++; break;
                case 'deferred': break;   // counted below, not against an account
            }

            // Why mail is not going out, counted by reason.
            if (in_array($p['kind'], ['failed', 'deferred', 'frozen'], true)) {
                $dk = $bucket . "\0" . $p['kind'] . "\0" . ($p['code'] ?? '')
                    . "\0" . ($p['reason'] ?? '');
                if (!isset($del[$dk])) {
                    $del[$dk] = ['bucket' => $bucket, 'kind' => $p['kind'],
                                 'code' => (string)($p['code'] ?? ''),
                                 'reason' => (string)($p['reason'] ?? ''), 'n' => 0];
                }
                $del[$dk]['n']++;
            }
        }

        $newOffset = ftell($fh);
        fclose($fh);
        Database::setSetting('mg_offset', (string)$newOffset);

        self::flush($agg);
        self::flushDelivery($del);

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


    /** Merge delivery outcomes into their hour buckets. */
    private static function flushDelivery(array $del): void
    {
        if ($del === []) return;
        $db = Database::get();
        $db->beginTransaction();
        try {
            $sel = $db->prepare(
                "SELECT id FROM mail_delivery
                  WHERE bucket = ? AND kind = ? AND code = ? AND reason = ? LIMIT 1");
            $ins = $db->prepare(
                "INSERT INTO mail_delivery (bucket, kind, code, reason, n)
                 VALUES (?,?,?,?,?)");
            $upd = $db->prepare("UPDATE mail_delivery SET n = n + ? WHERE id = ?");

            foreach ($del as $d) {
                $sel->execute([$d['bucket'], $d['kind'], $d['code'], $d['reason']]);
                $row = $sel->fetch(PDO::FETCH_ASSOC);
                if ($row) { $upd->execute([$d['n'], $row['id']]); }
                else { $ins->execute([$d['bucket'], $d['kind'], $d['code'],
                                      $d['reason'], $d['n']]); }
            }
            $db->commit();
        } catch (Throwable $e) {
            $db->rollBack();
            Logger::error('MailGuard: could not record delivery outcomes -- '
                          . $e->getMessage());
        }
    }

    /**
     * Why mail is not going out, worst first.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function deliveryFailures(int $hours = 24, int $limit = 20): array
    {
        self::ensureSchema();
        $since = time() - max(1, $hours) * 3600;
        return Database::fetchAll(
            "SELECT kind, code, reason, SUM(n) AS n, MAX(bucket) AS last_seen
               FROM mail_delivery
              WHERE bucket >= CAST(? AS INTEGER)
           GROUP BY kind, code, reason
           ORDER BY SUM(n) DESC
              LIMIT " . max(1, min(100, $limit)), [$since]);
    }

    /**
     * What a given SMTP code actually means for the operator.
     *
     * Three failures that all present as "mail is stuck" need three different
     * responses, and the panel showed none of this. These are the ones seen in
     * the field.
     */
    public static function explainCode(string $code, string $reason): ?array
    {
        $r = strtolower($reason);

        if ($code === '421' || str_contains($r, 'unusual rate')
            || str_contains($r, 'rate-limit') || str_contains($r, 'rate limit')) {
            return ['severity' => 'high',
                    'what' => 'A receiving provider is rate-limiting this server',
                    'action' => 'The IP\'s sending reputation is damaged -- usually '
                              . 'after spam has left the server. Do NOT force the '
                              . 'queue (exim -qff): that sends the provider exactly '
                              . 'the burst it is objecting to. Stop any unwanted '
                              . 'sending, confirm SPF/DKIM/DMARC, and let it '
                              . 'recover.'];
        }
        if ($code === '452' || str_contains($r, 'out of storage')
            || str_contains($r, 'quota') || str_contains($r, 'mailbox full')) {
            return ['severity' => 'medium',
                    'what' => 'A recipient mailbox is full',
                    'action' => 'Nothing is wrong with this server. Tell whoever '
                              . 'owns that address -- their mail is bouncing and '
                              . 'they do not know.'];
        }
        if (str_contains($r, 'routing defer') || str_contains($r, 'retry time')) {
            return ['severity' => 'low',
                    'what' => 'Exim is backing off after an earlier failure',
                    'action' => 'A symptom, not a cause. The real error is in the '
                              . 'retry database: run  exinext <address>'];
        }
        if ($code !== '' && $code[0] === '5') {
            return ['severity' => 'medium',
                    'what' => 'Permanent rejection by the receiving server',
                    'action' => 'The address is wrong, or this server is blocked. '
                              . 'The reason text says which.'];
        }
        return null;
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

        // Why mail is NOT going out.
        //
        // This is the half the panel was missing. On a live server the whole
        // queue sat undelivered for four days while the dashboard reported
        // nothing, because it only counted arrivals. The reasons were in the
        // log the entire time, and they were three different problems with
        // three different fixes.
        foreach (self::deliveryFailures(6, 10) as $d) {
            $n = (int)$d['n'];
            if ($n < 20) continue;             // noise: every server defers some
            $e = self::explainCode((string)$d['code'], (string)$d['reason']);
            if ($e === null) continue;
            if ($e['severity'] === 'low') continue;   // symptoms, not causes

            $f[] = [
                'type'     => 'delivery_failure',
                'severity' => $e['severity'],
                'what'     => sprintf('%s: %s delivery failure(s) in the last 6 '
                                    . 'hours%s', $e['what'], number_format($n),
                                      $d['code'] !== '' ? ' (SMTP ' . $d['code'] . ')' : ''),
                'action'   => $e['action'],
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

        // Subjects, for the page we are actually showing.
        //
        // `exim -bp` does not carry one, which is why a queue listing is a wall
        // of message ids and addresses with no way to tell a receipt from a
        // relay at a glance. ConfigServer Mail Manage showed the subject and
        // that is most of why it was pleasant to use.
        //
        // Read from the spool header file directly: one small file read per
        // message, never a fork. 200 reads is cheap; 200 forks of exim -Mvh on
        // a box with a 93,000-message queue is not.
        self::addSubjects($messages);

        return ['messages' => $messages, 'total' => $total,
                'shown' => count($messages), 'truncated' => $total > count($messages)];
    }

    /** Where exim keeps its spool. One fork, cached for the request. */
    private static function spoolDir(): string
    {
        static $dir = null;
        if ($dir !== null) { return $dir; }

        $bin = null;
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $b) {
            if (is_executable($b)) { $bin = $b; break; }
        }
        $dir = '/var/spool/exim';
        if ($bin !== null) {
            $o = (string) @shell_exec(escapeshellarg($bin)
                                    . ' -bP spool_directory 2>/dev/null');
            if (preg_match('/spool_directory\s*=\s*(\S+)/', $o, $m)) {
                $dir = rtrim($m[1], '/');
            }
        }
        return $dir;
    }

    /**
     * Fill in `subject` for each message, from the spool header file.
     *
     * Bounded three ways, because this runs on a box that is often already in
     * trouble: at most MAX_SUBJECT_READS files, each read capped, and only for
     * messages already selected for display.
     *
     * A message whose header we cannot read keeps an empty subject rather than
     * a guess — the queue listing still works, it is just less informative for
     * that row.
     */
    public static function fillSubjects(array &$messages): void
    {
        self::addSubjects($messages);
    }

    private static function addSubjects(array &$messages): void
    {
        $spool = self::spoolDir();
        $n     = 0;
        foreach ($messages as &$m) {
            $m['subject'] = '';
            if ($n >= self::MAX_SUBJECT_READS) { continue; }
            $id = (string) ($m['id'] ?? '');
            if (!self::isMessageId($id)) { continue; }

            // With split_spool_directory the subdirectory is the SIXTH
            // character of the message id. Both layouts are tried rather than
            // reading exim's config for a boolean.
            $candidates = [
                $spool . '/input/' . substr($id, 5, 1) . '/' . $id . '-H',
                $spool . '/input/' . $id . '-H',
            ];
            foreach ($candidates as $path) {
                if (!@is_file($path) || !@is_readable($path)) { continue; }
                $fh = @fopen($path, 'rb');
                if ($fh === false) { continue; }
                $raw = (string) @fread($fh, self::MAX_HEADER_BYTES);
                @fclose($fh);
                $n++;
                // Spool headers are prefixed with a byte count and a type
                // letter, so this is not an RFC822 block.
                if (preg_match('/^\d+[A-Za-z]?\s*Subject:\s*(.*)$/mi', $raw, $sm)
                    || preg_match('/^Subject:\s*(.*)$/mi', $raw, $sm)) {
                    $m['subject'] = self::decodeWords(trim($sm[1]));
                }
                break;
            }
        }
        unset($m);
    }

    /** At most this many spool header files per queue listing. */
    private const MAX_SUBJECT_READS = 250;

    /** And at most this much of each one. */
    private const MAX_HEADER_BYTES  = 65536;

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

        $local  = substr($sender, 0, $at);
        $domain = substr($sender, $at + 1);

        // bgkgvs@host.lws-s1.com -> bgkgvs, NOT lwss1.
        //
        // WordPress sends as <account>@<server hostname> when a site has no
        // From address configured, which is most of them. Resolving the
        // DOMAIN then gives whoever owns the server's own hostname -- on this
        // server, lwss1 -- so every such row in the queue viewer was labelled
        // with the same wrong account. Technically correct ownership,
        // materially useless: it pointed the operator at the wrong customer.
        //
        // When the domain is the server itself the local part is the account,
        // so it is checked first and only trusted if that account exists.
        if ($local !== '' && self::isServerHostname($domain)
            && self::accountExists($local)) {
            return $local;
        }

        $byDomain = self::accountForDomain($domain);
        if ($byDomain !== null) return $byDomain;

        // Last resort: a local part that names a real account. Covers hosts
        // whose mail is sent as <account>@<something-else-local>.
        return self::accountExists($local) ? $local : null;
    }

    /** Is this the server's own hostname rather than a customer domain? */
    public static function isServerHostname(string $domain): bool
    {
        $d = strtolower(rtrim($domain, '.'));
        if ($d === '') return false;
        foreach ([gethostname(), php_uname('n')] as $h) {
            if (is_string($h) && $h !== '' && strtolower(rtrim($h, '.')) === $d) {
                return true;
            }
        }
        return false;
    }

    /** Does a cPanel account of this name exist? */
    public static function accountExists(string $name): bool
    {
        if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,31}$/i', $name)) return false;
        if (self::isSystemAccount($name)) return false;
        static $seen = [];
        if (isset($seen[$name])) return $seen[$name];
        $seen[$name] = is_file('/var/cpanel/users/' . $name)
                    || is_dir('/home/' . $name);
        return $seen[$name];
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
     * Force a delivery attempt on queued messages — cPanel's "Deliver" button.
     *
     * `exim -M <id>` runs a delivery attempt immediately, ignoring the retry
     * schedule. That is the right tool: the usual reason mail sits in this
     * queue is a retry timer that has not expired, not a permanent failure. A
     * Gmail `421-4.7.0` rate limit or a full recipient mailbox parks a genuine
     * customer message for hours, and the operator can see it is genuine.
     *
     * THREE THINGS THIS HAS TO GET RIGHT THAT DELETION DOES NOT:
     *
     * 1. IT THAWS. The Exim spec is explicit: with -M, "if any of the messages
     *    are frozen, they are automatically thawed before the delivery
     *    attempt". Frozen means Exim already gave up, so delivering a frozen
     *    message is not a neutral retry and the UI says so before you click.
     *
     * 2. IT BLOCKS ON THE NETWORK. Deletion is a local unlink and returns at
     *    once; a delivery attempt opens an SMTP conversation with a remote MTA
     *    that may be slow, rate-limiting or black-holing. Unbounded, one
     *    unreachable domain hangs the request until the CGI times out and the
     *    operator learns nothing. So: a per-message timeout, an overall wall
     *    clock budget, and a much lower cap than deletion's 500.
     *
     * 3. EXIT 0 DOES NOT MEAN DELIVERED. It means the attempt ran. A message
     *    that deferred again is still in the queue and exim is still happy.
     *    Reporting that as "delivered" would be a lie the operator acts on, so
     *    the queue is re-read afterwards and success is defined as LEFT THE
     *    QUEUE.
     *
     * This server relayed 92,954 spam messages in one incident. Forcing
     * delivery is therefore an outbound send of whatever is selected, logged
     * at warning level with the ids, and never a one-click action in the UI.
     *
     * @param string[] $ids
     * @param int $budgetSeconds total wall clock across the batch
     * @return array{success:bool,delivered:int,deferred:int,attempted:int,
     *               skipped:int,failed:array,error?:string}
     */
    public static function deliverMessages(array $ids, int $budgetSeconds = 90): array
    {
        // VALIDATE FIRST, then look for exim — same order as deleteMessages(),
        // and for the same reason: the check that keeps shell metacharacters
        // out of a root command must not depend on a binary being installed.
        $clean  = [];
        $failed = [];
        foreach ($ids as $id) {
            $id = trim((string)$id);
            if (self::isMessageId($id)) { $clean[] = $id; }
            else { $failed[] = ['id' => substr($id, 0, 40),
                                'error' => 'not a valid exim message id']; }
        }
        if ($clean === []) {
            return ['success' => false, 'delivered' => 0, 'deferred' => 0,
                    'attempted' => 0, 'skipped' => 0, 'failed' => $failed,
                    'error' => 'No valid message ids'];
        }

        // Capped far lower than deletion. Each of these is a network round
        // trip, not an unlink: 500 would be 500 SMTP conversations in one
        // request on a box that is usually already struggling when somebody
        // opens this page.
        if (count($clean) > 100) {
            return ['success' => false, 'delivered' => 0, 'deferred' => 0,
                    'attempted' => 0, 'skipped' => 0, 'failed' => $failed,
                    'error' => 'Refusing more than 100 messages in one go — '
                             . 'each one is a live delivery attempt, so deliver '
                             . 'in batches'];
        }

        $bin = null;
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $b) {
            if (is_executable($b)) { $bin = $b; break; }
        }
        if ($bin === null) {
            return ['success' => false, 'delivered' => 0, 'deferred' => 0,
                    'attempted' => 0, 'skipped' => 0, 'failed' => $failed,
                    'error' => 'exim not found'];
        }

        // What is being SENT, recorded before it is sent. If this turns out to
        // have pushed spam out, this line is the record of who did it.
        Logger::warn(sprintf(
            'Forcing delivery of %d queued message(s): %s',
            count($clean), implode(' ', array_slice($clean, 0, 50))));

        // One at a time, each with its own timeout.
        //
        // Not batched like deletion: `exim -M a b c` processes them in turn, so
        // a single hung remote MTA would eat the whole budget and the caller
        // could not tell which message caused it. Per-message also means a
        // per-message result, which is what the operator needs.
        $perMsg   = max(5, min(30, (int) ceil($budgetSeconds / 3)));
        $deadline = microtime(true) + $budgetSeconds;
        $attempted = [];
        $skipped   = 0;
        $hasTimeout = self::hasTimeoutBinary();

        foreach ($clean as $id) {
            if (microtime(true) >= $deadline) {
                // Out of budget. Reported, never silently dropped: "nothing
                // happened to 60 of your messages" is something the operator
                // has to know to click again.
                $skipped++;
                continue;
            }

            $cmd = 'nice -n 19 ';
            if ($hasTimeout) {
                $cmd .= 'timeout ' . (int)$perMsg . ' ';
            }
            $cmd .= escapeshellarg($bin) . ' -M ' . escapeshellarg($id) . ' 2>&1';

            $o = []; $rc = 0;
            @exec($cmd, $o, $rc);
            $attempted[$id] = ['rc' => $rc,
                               'out' => trim(implode(' ', array_slice($o, 0, 2)))];

            // 124 is `timeout` killing it. The attempt is still in flight as
            // far as exim is concerned, so this is not a failure — it is "we
            // stopped waiting", and saying so is the honest report.
            if ($rc === 124) {
                $failed[] = ['id' => $id,
                             'error' => 'still running after ' . $perMsg
                                      . 's — the remote server is slow; it may '
                                      . 'yet be delivered'];
            }
        }

        // SUCCESS = LEFT THE QUEUE.
        //
        // exim exits 0 for an attempt that deferred, so the exit code cannot
        // tell delivered from still-stuck. One cheap re-read of the queue can.
        $stillQueued = self::queuedIdSet(array_keys($attempted));

        $delivered = 0; $deferred = 0;
        foreach ($attempted as $id => $res) {
            if (isset($stillQueued[$id])) {
                $deferred++;
                if ($res['rc'] !== 0 && $res['rc'] !== 124) {
                    $failed[] = ['id' => $id,
                                 'error' => $res['out'] ?: 'exim refused'];
                }
            } else {
                $delivered++;
            }
        }

        Logger::event(
            'mail_queue_deliver', 'medium', '', 'mail queue',
            sprintf('%d message(s) left the queue, %d still deferred, after an '
                  . 'operator forced delivery of %d',
                    $delivered, $deferred, count($attempted)));

        return [
            'success'   => $delivered > 0 || $deferred > 0,
            'delivered' => $delivered,
            'deferred'  => $deferred,
            'attempted' => count($attempted),
            'skipped'   => $skipped,
            'failed'    => $failed,
        ];
    }

    /** Is GNU coreutils `timeout` available to bound a delivery attempt? */
    private static function hasTimeoutBinary(): bool
    {
        foreach (['/usr/bin/timeout', '/bin/timeout'] as $t) {
            if (is_executable($t)) { return true; }
        }
        return false;
    }

    /**
     * Which of these ids are STILL in the queue.
     *
     * Used to tell a real delivery from a deferral, because exim's exit status
     * cannot. Reads ids only -- `exim -bp` output is parsed for the id column
     * and nothing else, so this stays cheap even on a large queue.
     *
     * @param string[] $ids
     * @return array<string,true>
     */
    private static function queuedIdSet(array $ids): array
    {
        if ($ids === []) { return []; }

        $bin = null;
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $b) {
            if (is_executable($b)) { $bin = $b; break; }
        }
        if ($bin === null) {
            // Cannot tell. Treat every message as still queued rather than
            // reporting deliveries that may not have happened -- overstating
            // success here is how an operator stops chasing real stuck mail.
            $all = [];
            foreach ($ids as $id) { $all[$id] = true; }
            return $all;
        }

        $o = []; $rc = 0;
        @exec('nice -n 19 ' . escapeshellarg($bin) . ' -bp 2>/dev/null', $o, $rc);
        if ($rc !== 0) {
            $all = [];
            foreach ($ids as $id) { $all[$id] = true; }
            return $all;
        }

        $want = array_fill_keys($ids, true);
        $set  = [];
        foreach ($o as $line) {
            // "  34h 24K 1aBcDe-0001Xy-Zz <sender@example.com>"
            if (preg_match('/\b([A-Za-z0-9]{6}-[A-Za-z0-9]{6,20}-[A-Za-z0-9]{2,6})\b/', $line, $m)
                && isset($want[$m[1]])) {
                $set[$m[1]] = true;
            }
        }
        return $set;
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

    /**
     * The most of a message body we will ever read off the spool.
     *
     * A queue entry can be tens of megabytes. Reading one whole to show a
     * 1,000-character preview would be absurd on a box that is usually already
     * struggling when somebody opens this page.
     */
    private const MAX_BODY_BYTES = 2097152;    // 2 MB

    /** How much of the body is shown. The operator asked for 1,000. */
    public const BODY_PREVIEW_CHARS = 1000;

    /**
     * One message, in full enough detail to judge it: who sent it, to whom,
     * the subject, what is attached, and the first 1,000 characters.
     *
     * ON SHOWING THE BODY AT ALL
     * --------------------------
     * Until now this module read headers and never the body, deliberately:
     * "the body is a customer's private mail and nothing here needs it to tell
     * a relay from a receipt". That is still true of the automatic detection,
     * and nothing here is automatic — this runs only when an operator opens a
     * specific message.
     *
     * The compromise is that it is capped at 1,000 characters, it is admin
     * only, and every view is written to the security timeline. Reading a
     * customer's mail should leave a mark.
     *
     * @return array{success:bool,error?:string,...}
     */
    public static function messageView(string $id, string $by = ''): array
    {
        if (!self::isMessageId($id)) {
            return ['success' => false, 'error' => 'Not a valid message id'];
        }
        $bin = null;
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $b) {
            if (is_executable($b)) { $bin = $b; break; }
        }
        if ($bin === null) { return ['success' => false, 'error' => 'exim not found']; }

        $hdrRaw = (string) @shell_exec('nice -n 19 ' . escapeshellarg($bin) . ' -Mvh '
                                     . escapeshellarg($id) . ' 2>&1');
        if (trim($hdrRaw) === '') {
            return ['success' => false,
                    'error' => 'That message is no longer in the queue'];
        }

        // Bounded at the pipe, not after reading. `head -c` stops exim writing
        // once we have enough, so a 50 MB message costs 2 MB of I/O.
        $bodyRaw = (string) @shell_exec(
            'nice -n 19 ' . escapeshellarg($bin) . ' -Mvb ' . escapeshellarg($id)
            . ' 2>/dev/null | head -c ' . self::MAX_BODY_BYTES);

        $headers = self::parseHeaders($hdrRaw);
        $parts   = self::mimeParts($headers, $bodyRaw);

        $attachments = [];
        $preview     = '';
        $previewType = '';
        foreach ($parts as $p) {
            if ($p['is_attachment']) {
                $attachments[] = [
                    'filename'     => $p['filename'],
                    'content_type' => $p['content_type'],
                    'bytes'        => $p['bytes'],
                    'sha256'       => $p['sha256'],
                    // Honest about what we could not hash. A hash of a
                    // truncated attachment is not that attachment's hash, and
                    // acting on it later would be acting on a fiction.
                    'truncated'    => $p['truncated'],
                    'suspicious'   => self::riskyAttachment($p['filename'],
                                                            $p['content_type']),
                ];
            } elseif ($preview === '' && $p['text'] !== '') {
                $preview     = $p['text'];
                $previewType = $p['content_type'];
            }
        }
        if ($preview === '' && $parts === []) {
            // Not MIME at all: a plain message is its own body.
            $preview     = self::decodeText($bodyRaw, '');
            $previewType = 'text/plain';
        }

        $full = $preview;
        $preview = mb_substr($preview, 0, self::BODY_PREVIEW_CHARS);

        // Reading someone's mail leaves a mark.
        Logger::event('mail_body_viewed', 'low', '', $id,
            'Operator ' . ($by !== '' ? $by : 'unknown') . ' viewed message '
          . $id . ' (' . count($attachments) . ' attachment(s))');

        return [
            'success'      => true,
            'id'           => $id,
            'from'         => $headers['from'] ?? '',
            'to'           => $headers['to'] ?? [],
            'subject'      => $headers['subject'] ?? '',
            'date'         => $headers['date'] ?? '',
            'source'       => $headers['source'] ?? [],
            'attachments'  => $attachments,
            'body'         => $preview,
            'body_type'    => $previewType,
            'body_truncated' => mb_strlen($full) > self::BODY_PREVIEW_CHARS
                                || strlen($bodyRaw) >= self::MAX_BODY_BYTES,
            'flagged'      => self::flagsFor($id),
        ];
    }

    /**
     * Headers we actually use, from `exim -Mvh` output.
     *
     * exim's -Mvh prefixes each line with a byte count and a marker, so the
     * raw text is NOT an RFC822 header block and cannot be parsed as one.
     */
    private static function parseHeaders(string $raw): array
    {
        // Strip exim's "045 " style prefixes and unfold continuations.
        $lines = [];
        foreach (explode("\n", $raw) as $line) {
            $line = preg_replace('/^\d+[A-Za-z]?\s/', '', rtrim($line, "\r"));
            if ($line === null) { continue; }
            if ($line !== '' && ($line[0] === ' ' || $line[0] === "\t") && $lines) {
                $lines[count($lines) - 1] .= ' ' . trim($line);
            } else {
                $lines[] = $line;
            }
        }
        $text = implode("\n", $lines);

        $get = function (string $h) use ($text): string {
            return preg_match('/^' . preg_quote($h, '/') . ':\s*(.*)$/mi', $text, $m)
                ? trim($m[1]) : '';
        };

        $to = [];
        foreach (['To', 'Cc'] as $h) {
            $v = $get($h);
            if ($v !== '') {
                foreach (explode(',', $v) as $one) {
                    $one = trim($one);
                    if ($one !== '') { $to[] = mb_substr($one, 0, 200); }
                }
            }
        }

        $source = [];
        foreach (['X-Source', 'X-Source-Args', 'X-Source-Dir', 'X-PHP-Script'] as $h) {
            $v = $get($h);
            if ($v !== '') { $source[$h] = $v; }
        }

        return [
            'from'         => self::decodeWords($get('From')),
            'to'           => array_slice(array_map([self::class, 'decodeWords'], $to), 0, 50),
            'subject'      => self::decodeWords($get('Subject')),
            'date'         => $get('Date'),
            'content_type' => $get('Content-Type'),
            'source'       => $source,
            'raw'          => $text,
        ];
    }

    /**
     * MIME parts, flat.
     *
     * Deliberately simple: split on the boundary, read each part's own headers,
     * decode base64/quoted-printable. Nested multipart/* is walked one level,
     * which covers multipart/mixed wrapping multipart/alternative — the shape
     * of essentially every real message with an attachment.
     *
     * @return list<array{is_attachment:bool,filename:string,content_type:string,
     *                    bytes:int,sha256:string,truncated:bool,text:string}>
     */
    private static function mimeParts(array $headers, string $body, int $depth = 0): array
    {
        $ctype = (string) ($headers['content_type'] ?? '');
        if (!preg_match('/boundary\s*=\s*"?([^";\s]+)"?/i', $ctype, $m)) {
            return [];
        }
        $boundary = $m[1];
        $chunks   = explode('--' . $boundary, $body);
        $out      = [];

        foreach ($chunks as $chunk) {
            $chunk = ltrim($chunk, "\r\n");
            if ($chunk === '' || strpos($chunk, '--') === 0) { continue; }

            $split = preg_split("/\r?\n\r?\n/", $chunk, 2);
            if (count($split) !== 2) { continue; }
            [$ph, $pb] = $split;

            $pct  = self::headerValue($ph, 'Content-Type');
            $pcd  = self::headerValue($ph, 'Content-Disposition');
            $pcte = strtolower(trim(self::headerValue($ph, 'Content-Transfer-Encoding')));

            // Nested multipart: one level down, which is where the text parts
            // of a message with an attachment actually live.
            if ($depth < 1 && stripos($pct, 'multipart/') === 0) {
                foreach (self::mimeParts(['content_type' => $pct], $pb, $depth + 1) as $sub) {
                    $out[] = $sub;
                }
                continue;
            }

            $filename = '';
            foreach ([$pcd, $pct] as $src) {
                if (preg_match('/(?:file)?name\s*=\s*"?([^";\r\n]+)"?/i', $src, $fm)) {
                    $filename = self::decodeWords(trim($fm[1]));
                    break;
                }
            }

            $isAttachment = $filename !== ''
                         || stripos($pcd, 'attachment') === 0;

            // A part that ran past our 2 MB cap is incomplete, and we say so
            // rather than reporting a size and a hash that are both wrong.
            $truncated = (strlen($body) >= self::MAX_BODY_BYTES
                          && $chunk === end($chunks));

            if ($isAttachment) {
                $decoded = $pcte === 'base64'
                    ? (string) base64_decode(preg_replace('/\s+/', '', $pb) ?? '', true)
                    : self::decodeText($pb, $pcte);
                $out[] = [
                    'is_attachment' => true,
                    'filename'      => $filename !== '' ? $filename : '(unnamed)',
                    'content_type'  => trim(explode(';', $pct)[0]) ?: 'application/octet-stream',
                    'bytes'         => strlen($decoded),
                    'sha256'        => ($truncated || $decoded === '')
                                        ? '' : hash('sha256', $decoded),
                    'truncated'     => $truncated,
                    'text'          => '',
                ];
                continue;
            }

            if (stripos($pct, 'text/') === 0 || $pct === '') {
                $text = self::decodeText($pb, $pcte);
                if (stripos($pct, 'text/html') === 0) {
                    $text = trim(html_entity_decode(strip_tags($text),
                                                    ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                }
                $out[] = [
                    'is_attachment' => false, 'filename' => '',
                    'content_type'  => trim(explode(';', $pct)[0]) ?: 'text/plain',
                    'bytes' => strlen($text), 'sha256' => '', 'truncated' => $truncated,
                    'text'  => $text,
                ];
            }
        }
        return $out;
    }

    private static function headerValue(string $block, string $name): string
    {
        return preg_match('/^' . preg_quote($name, '/') . ':\s*(.*)$/mi', $block, $m)
            ? trim($m[1]) : '';
    }

    private static function decodeText(string $s, string $encoding): string
    {
        $e = strtolower(trim($encoding));
        if ($e === 'base64')            { $s = (string) base64_decode(preg_replace('/\s+/', '', $s) ?? '', true); }
        elseif ($e === 'quoted-printable') { $s = (string) quoted_printable_decode($s); }
        // Anything that is not valid UTF-8 would break json_encode and take the
        // whole response with it.
        if (!mb_check_encoding($s, 'UTF-8')) {
            $s = (string) mb_convert_encoding($s, 'UTF-8', 'UTF-8');
        }
        return trim($s);
    }

    /** RFC 2047 =?utf-8?B?...?= subjects and filenames. */
    private static function decodeWords(string $s): string
    {
        if ($s === '' || strpos($s, '=?') === false) { return mb_substr($s, 0, 400); }
        $d = @iconv_mime_decode($s, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
        $s = ($d === false || $d === '') ? $s : $d;
        if (!mb_check_encoding($s, 'UTF-8')) {
            $s = (string) mb_convert_encoding($s, 'UTF-8', 'UTF-8');
        }
        return mb_substr($s, 0, 400);
    }

    /**
     * Extensions and types worth a second look, so the operator's eye goes to
     * the right row. A hint, never a verdict — the flag is theirs to set.
     */
    public static function riskyAttachment(string $filename, string $type): bool
    {
        $risky = '/\.(exe|scr|pif|com|bat|cmd|js|jse|vbs|vbe|wsf|wsh|hta|jar|
                      ps1|msi|dll|lnk|iso|img|img|php|phtml|sh)$/xi';
        if (preg_match($risky, $filename)) { return true; }
        // A double extension is the oldest trick there is.
        if (preg_match('/\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.[a-z0-9]{1,4}$/i', $filename)) {
            return true;
        }
        return (bool) preg_match('#^application/(x-msdownload|x-dosexec|x-executable)#i', $type);
    }

    // ── Flagging an attachment ──────────────────────────────────────────────

    /**
     * Record that an operator judged an attachment malicious.
     *
     * Recorded, not deleted. Removing one attachment from a queued message is
     * not something exim supports cleanly, and a half-rewritten message is
     * worse than a flagged one — so this marks it, raises an event, and lets
     * the operator decide whether to delete the whole message.
     *
     * The sha256 is the useful part: it lets the malware scanner recognise the
     * same bytes on disk later, which is where the file will actually land if
     * anybody opens it.
     */
    public static function flagAttachment(string $id, string $filename,
                                          string $sha256 = '', string $ctype = '',
                                          int $bytes = 0, string $note = '',
                                          string $by = ''): array
    {
        if (!self::isMessageId($id)) {
            return ['success' => false, 'error' => 'Not a valid message id'];
        }
        $filename = trim($filename);
        if ($filename === '') {
            return ['success' => false, 'error' => 'No attachment named'];
        }
        $sha256 = strtolower(trim($sha256));
        if ($sha256 !== '' && !preg_match('/^[a-f0-9]{64}$/', $sha256)) {
            return ['success' => false, 'error' => 'That is not a sha256'];
        }

        self::ensureSchema();
        Database::query(
            "INSERT INTO mail_flagged_attachments
                 (message_id, filename, sha256, content_type, bytes, note, flagged_by)
             VALUES (?,?,?,?,?,?,?)
             ON CONFLICT(message_id, filename) DO UPDATE SET
                 sha256 = excluded.sha256, note = excluded.note,
                 flagged_by = excluded.flagged_by, flagged_at = strftime('%s','now')",
            [$id, mb_substr($filename, 0, 255), $sha256, mb_substr($ctype, 0, 120),
             max(0, $bytes), mb_substr(trim($note), 0, 500),
             mb_substr(trim($by) !== '' ? trim($by) : 'unknown', 0, 64)]
        );

        Logger::event('mail_attachment_flagged', 'high', '', $id,
            'Attachment "' . mb_substr($filename, 0, 120) . '" in message ' . $id
          . ' flagged as malicious'
          . ($sha256 !== '' ? ' (sha256 ' . substr($sha256, 0, 16) . ')' : '')
          . (trim($note) !== '' ? ' — ' . mb_substr(trim($note), 0, 160) : ''));

        return ['success' => true, 'id' => $id, 'filename' => $filename,
                'sha256' => $sha256];
    }

    public static function unflagAttachment(string $id, string $filename): array
    {
        if (!self::isMessageId($id)) {
            return ['success' => false, 'error' => 'Not a valid message id'];
        }
        self::ensureSchema();
        Database::query(
            'DELETE FROM mail_flagged_attachments WHERE message_id=? AND filename=?',
            [$id, trim($filename)]);
        Logger::info('Mail: attachment flag withdrawn for ' . $filename . ' in ' . $id);
        return ['success' => true];
    }

    /** @return array<string,array> filename => flag row */
    public static function flagsFor(string $id): array
    {
        if (!self::isMessageId($id)) { return []; }
        self::ensureSchema();
        $out = [];
        foreach (Database::fetchAll(
                    'SELECT * FROM mail_flagged_attachments WHERE message_id=?',
                    [$id]) ?: [] as $r) {
            $out[(string) $r['filename']] = $r;
        }
        return $out;
    }

    /** Everything flagged, newest first, for the Logs tab. */
    public static function flaggedAttachments(int $limit = 200): array
    {
        self::ensureSchema();
        return Database::fetchAll(
            'SELECT * FROM mail_flagged_attachments ORDER BY flagged_at DESC LIMIT '
            . max(1, min(1000, $limit))) ?: [];
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
            // Shown as its own table: a count of what left is only half the
            // picture, and the half that was missing is why it did not arrive.
            'delivery'       => array_map(function (array $d): array {
                $e = self::explainCode((string)$d['code'], (string)$d['reason']);
                $d['meaning'] = $e['what']   ?? '';
                $d['advice']  = $e['action'] ?? '';
                return $d;
            }, self::deliveryFailures(24, 20)),
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
        $n = $st->rowCount();
        // The delivery table grows the same way and was being left behind.
        $st2 = Database::query("DELETE FROM mail_delivery WHERE bucket < CAST(? AS INTEGER)",
                               [$cut]);
        return $n + $st2->rowCount();
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
