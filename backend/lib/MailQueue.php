<?php
/**
 * Mail Queue — a working queue manager, as its own section.
 *
 * WHY THIS IS SEPARATE FROM SPAM MONITOR
 * --------------------------------------
 * Spam Monitor answers "who is sending too much, from which script". The queue
 * is a different job: find a specific message among thousands, read it, and
 * decide whether it goes out or gets destroyed. Bolting one onto the other
 * gave a tab where neither question was properly answered.
 *
 * ON PRIOR ART
 * ------------
 * ConfigServer Mail Queue (cmq) did this well and is discontinued. It is
 * GPL-3.0 (Copyright 2006-2025 Jonathan Michaelson), and this product is not
 * GPL, so NOTHING here is copied from it. What is reused is knowledge that is
 * not anyone's to own: which exim command does what, and which questions an
 * operator actually needs to ask of a queue.
 *
 *   exim -bp          list the queue          exim -bpc   count it
 *   exim -Mvh <id>    headers                 exim -Mvb   body
 *   exim -M <id>      force delivery          exim -Mrm   remove
 *   exigrep <id>      that message's story from the main log
 *
 * The useful ideas worth having independently:
 *
 *   - INBOUND vs OUTBOUND, decided by whether the recipient domain is in
 *     /etc/localdomains. On a cPanel box that single split is the difference
 *     between "my customers' mail is stuck" and "we are relaying spam".
 *   - A CACHED SNAPSHOT. `exim -bp` on a large queue is expensive, and a UI
 *     that re-runs it for every search and page is unusable precisely when the
 *     queue is big enough to need searching.
 *   - Searching the SUBJECT or BODY costs a file read per message, so it is an
 *     explicit, bounded choice rather than something that happens by default.
 */

declare(strict_types=1);

class MailQueue
{
    /** How long a snapshot stays usable before it is rebuilt. */
    private const CACHE_TTL = 60;

    /** Never parse more than this many messages into a snapshot. */
    private const MAX_MESSAGES = 20000;

    /** Deep search (subject/header/body) reads files. This many, at most. */
    private const MAX_DEEP_READS = 400;

    /** And at most this much of each message. */
    private const MAX_PEEK_BYTES = 65536;

    // ── Snapshot ────────────────────────────────────────────────────────────

    private static function cacheFile(): string
    {
        return rtrim(Database::storagePath('logs'), '/') . '/mailqueue-snapshot.json';
    }

    public static function eximBin(): ?string
    {
        foreach (['/usr/sbin/exim', '/usr/bin/exim'] as $b) {
            if (@is_executable($b)) { return $b; }
        }
        return null;
    }

    private static function exigrepBin(): ?string
    {
        foreach (['/usr/sbin/exigrep', '/usr/bin/exigrep'] as $b) {
            if (@is_executable($b)) { return $b; }
        }
        return null;
    }

    /** Domains this server is the destination for. */
    public static function localDomains(): array
    {
        static $cache = null;
        if ($cache !== null) { return $cache; }
        $cache = [];
        foreach (['/etc/localdomains', '/etc/exim/localdomains'] as $f) {
            if (!@is_file($f) || !@is_readable($f)) { continue; }
            $fh = @fopen($f, 'rb');
            if ($fh === false) { continue; }
            $raw = (string) @fread($fh, 1048576);
            @fclose($fh);
            foreach (explode("\n", $raw) as $d) {
                $d = strtolower(trim($d));
                if ($d !== '' && $d[0] !== '#') { $cache[$d] = true; }
            }
            break;
        }
        return $cache;
    }

    /**
     * The queue, parsed.
     *
     * Cached for CACHE_TTL seconds. A UI that re-runs `exim -bp` for every
     * search and every page is unusable exactly when the queue is big enough
     * to need searching — which is the moment it matters.
     *
     * @return array{messages:array,total:int,built_at:int,truncated:bool,error?:string}
     */
    public static function snapshot(bool $refresh = false): array
    {
        $file = self::cacheFile();
        if (!$refresh && @is_file($file)) {
            $age = time() - (int) (@filemtime($file) ?: 0);
            if ($age >= 0 && $age < self::CACHE_TTL) {
                $raw = (string) @file_get_contents($file);
                $j   = json_decode($raw, true);
                if (is_array($j) && isset($j['messages'])) {
                    $j['cached'] = true;
                    $j['age']    = $age;
                    return $j;
                }
            }
        }

        $bin = self::eximBin();
        if ($bin === null) {
            return ['messages' => [], 'total' => 0, 'built_at' => time(),
                    'truncated' => false, 'error' => 'exim not found'];
        }

        $out = (string) @shell_exec('nice -n 19 ' . escapeshellarg($bin) . ' -bp 2>/dev/null');
        $snap = self::parseQueue($out);
        $snap['built_at'] = time();

        // Best effort: a queue we cannot cache still works, just slower.
        @file_put_contents($file, json_encode($snap), LOCK_EX);
        @chmod($file, 0600);

        $snap['cached'] = false;
        $snap['age']    = 0;
        return $snap;
    }

    /**
     * Parse `exim -bp`.
     *
     *   25m  2.5K 1abcDe-0001AB-XY <from@dom>
     *            recipient@example.com
     *          D delivered@example.com
     *
     * The "D " prefix means that recipient has ALREADY been delivered to and
     * the message is only still queued for the others. Showing it as pending
     * tells the operator the opposite of the truth, so it is marked.
     */
    public static function parseQueue(string $out): array
    {
        $messages  = [];
        $cur       = null;
        $truncated = false;

        $flush = function () use (&$cur, &$messages, &$truncated) {
            if ($cur === null) { return; }
            if (count($messages) >= self::MAX_MESSAGES) { $truncated = true; $cur = null; return; }
            $cur['direction'] = self::directionOf($cur['recipients']);
            $messages[] = $cur;
            $cur = null;
        };

        foreach (explode("\n", $out) as $line) {
            if (trim($line) === '') { $flush(); continue; }

            if (preg_match('/^\s*(\S+)\s+(\S+)\s+([A-Za-z0-9]{6}-[A-Za-z0-9]{6,20}-[A-Za-z0-9]{2,6})\s*(.*)$/',
                           $line, $m)) {
                $flush();
                $rest   = $m[4];
                $sender = '';
                if (preg_match('/<([^>]*)>/', $rest, $sm)) { $sender = $sm[1]; }
                $cur = [
                    'id'         => $m[3],
                    'age'        => $m[1],
                    'age_mins'   => self::ageMinutes($m[1]),
                    'size'       => $m[2],
                    'sender'     => $sender === '' ? '<>' : $sender,
                    // An empty envelope sender is a bounce. Worth separating:
                    // a queue full of bounces is a different problem from a
                    // queue full of outbound mail.
                    'bounce'     => $sender === '',
                    'frozen'     => stripos($rest, 'frozen') !== false,
                    'recipients' => [],
                    'subject'    => '',
                ];
                continue;
            }

            if ($cur !== null) {
                $r = trim($line);
                if ($r === '') { continue; }
                $delivered = false;
                // "D recipient@x" — already delivered for this message.
                if (preg_match('/^\+?D\s+(.+)$/', $r, $dm)) {
                    $delivered = true;
                    $r = trim($dm[1]);
                }
                if ($r === '' || $r[0] === '*') { continue; }
                $cur['recipients'][] = ['address' => mb_substr($r, 0, 320),
                                        'delivered' => $delivered];
            }
        }
        $flush();

        return ['messages' => $messages, 'total' => count($messages),
                'truncated' => $truncated];
    }

    /** "25m", "3h", "2d" -> minutes. */
    public static function ageMinutes(string $age): int
    {
        if (!preg_match('/^(\d+)\s*([mhdws])/i', trim($age), $m)) { return 0; }
        $n = (int) $m[1];
        switch (strtolower($m[2])) {
            case 'm': return $n;
            case 'h': return $n * 60;
            case 'd': return $n * 1440;
            case 'w': return $n * 10080;
            case 's': return 0;
        }
        return 0;
    }

    /**
     * inbound, outbound, or mixed.
     *
     * A recipient whose domain is in /etc/localdomains is being delivered TO
     * this server; anything else is leaving it. On a cPanel box that single
     * split separates "my customers' mail is stuck" from "we are relaying".
     */
    public static function directionOf(array $recipients): string
    {
        $local = self::localDomains();
        if ($local === []) { return 'unknown'; }
        $in = false; $out = false;
        foreach ($recipients as $r) {
            $addr = is_array($r) ? (string) ($r['address'] ?? '') : (string) $r;
            $at   = strrpos($addr, '@');
            if ($at === false) { continue; }
            $dom = strtolower(substr($addr, $at + 1));
            if (isset($local[$dom])) { $in = true; } else { $out = true; }
        }
        if ($in && $out) { return 'mixed'; }
        if ($in)  { return 'inbound'; }
        if ($out) { return 'outbound'; }
        return 'unknown';
    }

    // ── Search ──────────────────────────────────────────────────────────────

    /**
     * Filter the snapshot.
     *
     * $f: direction (any|inbound|outbound|mixed), state (any|frozen|bounce|normal),
     *     older_than_mins, field (from|to|id|subject), op (contains|starts|ends|equals),
     *     text, negate, sort (newest|oldest|largest), limit, offset
     *
     * Searching the SUBJECT reads a file per message, so it is capped and the
     * result says when the cap was reached — a search that silently examined
     * only part of the queue would be worse than refusing.
     */
    public static function search(array $f): array
    {
        $snap = self::snapshot(!empty($f['refresh']));
        $rows = $snap['messages'] ?? [];
        $deepTruncated = false;

        $dir   = (string) ($f['direction'] ?? 'any');
        $state = (string) ($f['state'] ?? 'any');
        $older = max(0, (int) ($f['older_than_mins'] ?? 0));
        $field = (string) ($f['field'] ?? '');
        $op    = (string) ($f['op'] ?? 'contains');
        $text  = trim((string) ($f['text'] ?? ''));
        $neg   = !empty($f['negate']);

        $kept = [];
        $deep = 0;
        foreach ($rows as $r) {
            if ($dir !== 'any' && ($r['direction'] ?? '') !== $dir) { continue; }

            if ($state === 'frozen'  && empty($r['frozen']))  { continue; }
            if ($state === 'bounce'  && empty($r['bounce']))  { continue; }
            if ($state === 'normal'  && (!empty($r['frozen']) || !empty($r['bounce']))) { continue; }

            if ($older > 0 && (int) ($r['age_mins'] ?? 0) < $older) { continue; }

            if ($text !== '' && $field !== '') {
                if ($field === 'subject') {
                    if ($deep >= self::MAX_DEEP_READS) { $deepTruncated = true; continue; }
                    $deep++;
                    $r['subject'] = self::subjectOf((string) $r['id']);
                }
                $hay = [];
                switch ($field) {
                    case 'from':    $hay[] = (string) $r['sender']; break;
                    case 'id':      $hay[] = (string) $r['id']; break;
                    case 'subject': $hay[] = (string) $r['subject']; break;
                    case 'to':
                        foreach (($r['recipients'] ?? []) as $rc) {
                            $hay[] = (string) ($rc['address'] ?? '');
                        }
                        break;
                    default: $hay[] = '';
                }
                $hit = false;
                foreach ($hay as $h) { if (self::matches($h, $op, $text)) { $hit = true; break; } }
                if ($neg ? $hit : !$hit) { continue; }
            }

            $kept[] = $r;
        }

        switch ((string) ($f['sort'] ?? 'newest')) {
            case 'oldest':  usort($kept, fn($a, $b) => ($b['age_mins'] ?? 0) <=> ($a['age_mins'] ?? 0)); break;
            case 'largest': usort($kept, fn($a, $b) => self::sizeBytes((string) $b['size'])
                                                   <=> self::sizeBytes((string) $a['size'])); break;
            default:        usort($kept, fn($a, $b) => ($a['age_mins'] ?? 0) <=> ($b['age_mins'] ?? 0));
        }

        $matched = count($kept);
        $offset  = max(0, (int) ($f['offset'] ?? 0));
        $limit   = max(1, min(500, (int) ($f['limit'] ?? 100)));
        $page    = array_slice($kept, $offset, $limit);

        // Subjects for the page being shown, not for the whole queue.
        foreach ($page as &$p) {
            if (($p['subject'] ?? '') === '') { $p['subject'] = self::subjectOf((string) $p['id']); }
        }
        unset($p);

        return [
            'messages'   => $page,
            'matched'    => $matched,
            'total'      => $snap['total'] ?? 0,
            'offset'     => $offset,
            'limit'      => $limit,
            'built_at'   => $snap['built_at'] ?? 0,
            'cached'     => !empty($snap['cached']),
            'truncated'  => !empty($snap['truncated']),
            // Said plainly: a search that quietly examined only part of the
            // queue is worse than one that refuses.
            'deep_truncated' => $deepTruncated,
            'deep_limit' => self::MAX_DEEP_READS,
            'error'      => $snap['error'] ?? null,
        ];
    }

    private static function matches(string $hay, string $op, string $needle): bool
    {
        $h = mb_strtolower($hay);
        $n = mb_strtolower($needle);
        switch ($op) {
            case 'equals': return $h === $n;
            case 'starts': return $n !== '' && strncmp($h, $n, strlen($n)) === 0;
            case 'ends':   return $n !== '' && substr($h, -strlen($n)) === $n;
            default:       return $n !== '' && strpos($h, $n) !== false;
        }
    }

    public static function sizeBytes(string $s): int
    {
        if (!preg_match('/^([\d.]+)\s*([KMG])?/i', trim($s), $m)) { return 0; }
        $n = (float) $m[1];
        switch (strtoupper($m[2] ?? '')) {
            case 'K': return (int) ($n * 1024);
            case 'M': return (int) ($n * 1048576);
            case 'G': return (int) ($n * 1073741824);
        }
        return (int) $n;
    }

    /** Subject from the spool header, bounded. Delegates to MailGuard's reader. */
    public static function subjectOf(string $id): string
    {
        require_once __DIR__ . '/MailGuard.php';
        if (!MailGuard::isMessageId($id)) { return ''; }
        $one = [['id' => $id]];
        MailGuard::fillSubjects($one);
        return (string) ($one[0]['subject'] ?? '');
    }

    // ── One message's story ─────────────────────────────────────────────────

    /**
     * What the main log says about this message.
     *
     * `exigrep` scans the whole of exim_mainlog, which on a busy server is
     * hundreds of megabytes — so it runs under a timeout and says so when it
     * runs out, rather than hanging the panel.
     */
    public static function deliveryLog(string $id, int $timeout = 20): array
    {
        require_once __DIR__ . '/MailGuard.php';
        if (!MailGuard::isMessageId($id)) {
            return ['success' => false, 'error' => 'Not a valid message id'];
        }
        $bin = self::exigrepBin();
        if ($bin === null) {
            return ['success' => false, 'error' => 'exigrep not found'];
        }
        $log = null;
        foreach (['/var/log/exim_mainlog', '/var/log/exim/mainlog'] as $f) {
            if (@is_file($f)) { $log = $f; break; }
        }
        if ($log === null) {
            return ['success' => false, 'error' => 'exim main log not found'];
        }

        $hasTimeout = @is_executable('/usr/bin/timeout') || @is_executable('/bin/timeout');
        $cmd = 'nice -n 19 ' . ($hasTimeout ? 'timeout ' . max(5, $timeout) . ' ' : '')
             . escapeshellarg($bin) . ' ' . escapeshellarg($id) . ' '
             . escapeshellarg($log) . ' 2>/dev/null | head -c 65536';
        $out = (string) @shell_exec($cmd);

        return ['success' => true, 'id' => $id, 'log' => $out,
                'searched' => $log,
                // An empty result after a timeout is not "nothing happened".
                'note' => trim($out) === ''
                    ? 'Nothing found. On a busy server the log is large and this '
                    . 'search is time-limited, so an older message may have been '
                    . 'missed rather than absent.'
                    : ''];
    }

    /** Queue depth without parsing it. */
    public static function count(): int
    {
        $bin = self::eximBin();
        if ($bin === null) { return 0; }
        $o = (string) @shell_exec('nice -n 19 ' . escapeshellarg($bin) . ' -bpc 2>/dev/null');
        return (int) trim($o);
    }

    /** Totals for the section header, from the snapshot we already have. */
    public static function summary(): array
    {
        $snap = self::snapshot();
        $in = 0; $out = 0; $frozen = 0; $bounce = 0; $oldest = 0;
        foreach (($snap['messages'] ?? []) as $m) {
            if (($m['direction'] ?? '') === 'inbound')  { $in++; }
            if (($m['direction'] ?? '') === 'outbound') { $out++; }
            if (!empty($m['frozen'])) { $frozen++; }
            if (!empty($m['bounce'])) { $bounce++; }
            $oldest = max($oldest, (int) ($m['age_mins'] ?? 0));
        }
        return [
            'total'       => $snap['total'] ?? 0,
            'inbound'     => $in,
            'outbound'    => $out,
            'frozen'      => $frozen,
            'bounce'      => $bounce,
            'oldest_mins' => $oldest,
            'built_at'    => $snap['built_at'] ?? 0,
            'cached'      => !empty($snap['cached']),
            'local_domains' => count(self::localDomains()),
            'error'       => $snap['error'] ?? null,
        ];
    }

    /** Drop the cached snapshot, so the next read rebuilds it. */
    public static function invalidate(): void
    {
        @unlink(self::cacheFile());
    }
}
