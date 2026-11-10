<?php

/* Pulls in what it calls rather than trusting the caller. This runs from the
 * CLI, and a missing require_once in a cron or CLI path is a fatal nobody
 * sees. require_once is idempotent and safe across the cycles these form. */
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';
require_once __DIR__ . '/Verdicts.php';
// legacyQuarantineDirs(): a file quarantined before the rename, or
// before quarantine was relocated, is not under the active directory.
require_once __DIR__ . '/Scanner.php';

/**
 * ServerScrub — putting quarantined files back.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
 *
 * On 10 Nov scan job 12457 quarantined 154,323 customer files in one run, from
 * a single third-party ClamAV signature:
 *
 *     {HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL   154,323
 *     {HEX}php.cmdshell.gifheader.400.UNOFFICIAL                        1
 *
 * across at least twelve unrelated accounts. 154,252 of them were `.md`:
 * README.md and CHANGELOG.md inside node_modules and vendor trees, matched by
 * a signature that looks for long hex strings — changelogs are full of git
 * SHAs. Not one .php, .js or .html. Plus 72 archives that are plausibly
 * customer backups.
 *
 * The product had no way to put any of it back. The CLI had status, sweep,
 * prune and move; `restoreFromQuarantine()` existed for ONE id, was reachable
 * only from an API route, reconstructed the quarantine path by guessing a date
 * directory instead of reading the path it had recorded, verified nothing,
 * restored no ownership, and returned a bare bool. So an operator facing a
 * false positive at scale had no supported path at all.
 *
 * ── THE RULES THIS FOLLOWS ───────────────────────────────────────────────────
 *
 * 1. SCOPED, ALWAYS. There is no "restore everything". The caller says which
 *    job, which signature, which account, which file — and anything outside
 *    that is not touched. A blanket restore would undo real detections along
 *    with the false ones, which is the mirror image of the fault it fixes.
 * 2. DRY RUN BY DEFAULT. run() moves nothing unless it is told to apply. The
 *    default answer to "restore 154,323 files" is a list, not an action.
 * 3. VERIFIED BEFORE MOVED. The quarantined copy is hashed against the hash
 *    recorded when it was taken, where one was recorded. A mismatch is
 *    reported and the file is left alone: restoring the wrong bytes over a
 *    customer's file is worse than leaving it in quarantine.
 * 4. NEVER OVERWRITES. A file that exists at the destination again means the
 *    customer, or their deployment, has put something there. Those are
 *    reported separately and skipped, never replaced.
 * 5. OWNERSHIP AND MODE. These are files in customer homes. Root writing them
 *    back as root:root would break the site a different way, so the owner and
 *    mode recorded at quarantine time are used — and where an older record has
 *    none, they are inferred from the directory the file is going back into,
 *    and the report says which of the two happened.
 * 6. RESUMABLE AND BOUNDED. Restoring is one batch at a time, paging by id, and
 *    a restored row leaves the selection as it is processed — so an
 *    interrupted run is re-runnable and does no work twice. 154,323 files is
 *    not a single transaction.
 * 7. NO BARE SUCCESS COUNT. Restored, skipped-with-reason, failed-with-reason,
 *    and examples of each.
 *
 * ── WHAT IT DELIBERATELY DOES NOT DO ─────────────────────────────────────────
 *
 * It does not stop the next scan quarantining the same files again. That is a
 * different decision with two different answers — clear the file (a verdict
 * per file) or suppress the signature (one row for all of them) — and quietly
 * choosing one on the operator's behalf would hide a hole in the defence. The
 * CLI says so in its output and names both.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class QuarantineRestore
{
    /** Rows per page. Big enough to be quick, small enough to interrupt. */
    const DEFAULT_BATCH = 500;

    /** The mode a restored file gets when nothing better was recorded. */
    const FALLBACK_MODE = 0644;

    /**
     * Build the WHERE clause for a scope.
     *
     * @param array<string,mixed> $scope job|signature|account|path|id
     * @return array{sql:string,args:array,desc:string}|array{error:string}
     */
    public static function selector(array $scope): array
    {
        /* Both spellings. Everything in this product writes 'quarantined'
         * with action_taken 'quarantine', and the live server's rows were
         * reported to me as status 'quarantine' -- almost certainly the pair
         * being read as one, but a recovery tool that silently matches
         * nothing is the last thing an operator needs at 2am, and accepting
         * the singular costs nothing because nothing writes it. */
        $where = ["status IN ('quarantined', 'quarantine')"];
        $args  = [];
        $desc  = [];

        if (!empty($scope['id'])) {
            // A list, because the narrowest possible scope -- "these exact
            // findings and nothing else" -- is the one a frightened operator
            // reaches for first.
            $ids = [];
            foreach (explode(',', (string) $scope['id']) as $raw) {
                $n = (int) trim($raw);
                if ($n > 0) { $ids[] = $n; }
            }
            if ($ids === []) {
                return ['error' => 'No usable finding id in: ' . $scope['id']];
            }
            $where[] = 'id IN (' . implode(',', array_fill(0, count($ids), '?')) . ')';
            $args    = array_merge($args, $ids);
            $desc[]  = count($ids) === 1
                ? 'finding #' . $ids[0]
                : count($ids) . ' named findings';
        }
        if (!empty($scope['job'])) {
            $where[] = 'scan_job_id = ?';
            $args[]  = (int) $scope['job'];
            $desc[]  = 'scan job ' . (int) $scope['job'];
        }
        if (!empty($scope['signature'])) {
            $sig = (string) $scope['signature'];
            /* A trailing * is the only wildcard, and it is explicit. ClamAV
             * signature names carry braces, dots and digits; letting a whole
             * LIKE pattern through would make `%` in a name mean something
             * nobody intended. */
            if (substr($sig, -1) === '*') {
                $where[] = 'threat_name LIKE ?';
                $args[]  = str_replace(['%', '_'], ['\%', '\_'], rtrim($sig, '*')) . '%';
                $desc[]  = 'signature starting "' . rtrim($sig, '*') . '"';
            } else {
                $where[] = 'threat_name = ?';
                $args[]  = $sig;
                $desc[]  = 'signature "' . $sig . '"';
            }
        }
        if (!empty($scope['account'])) {
            $user = (string) $scope['account'];
            if (!preg_match('/^[a-z0-9][a-z0-9_.-]{0,31}$/i', $user)) {
                return ['error' => 'Not a username: ' . $user];
            }
            // cpanel_user is recorded per finding, but it was added later, so
            // the path is checked as well or an older row would be missed.
            $where[] = '(cpanel_user = ? OR file_path LIKE ?)';
            $args[]  = $user;
            $args[]  = '/home/' . $user . '/%';
            $desc[]  = 'account ' . $user;
        }
        if (!empty($scope['ext'])) {
            /* THE 72 THAT MATTER. Of job 12457's 154,323 files, 154,252 are
             * markdown inside node_modules and vendor trees -- documentation,
             * breaking nothing -- and 72 are archives (34 .tar, 34 .gz, 4
             * .zip) which are plausibly a customer's own backups. Those are
             * the ones to hand back first, and an extension is how an operator
             * says so without composing a list of 72 ids. */
            $exts = [];
            foreach (explode(',', (string) $scope['ext']) as $raw) {
                $e = strtolower(ltrim(trim($raw), '.'));
                if ($e === '' || !preg_match('/^[a-z0-9]{1,16}$/', $e)) { continue; }
                $exts[] = $e;
            }
            if ($exts === []) {
                return ['error' => 'No usable extension in: ' . $scope['ext']];
            }
            $parts = [];
            foreach ($exts as $e) {
                // LOWER() both sides: README.MD and readme.md are the same
                // file to an operator naming an extension.
                $parts[] = 'LOWER(file_path) LIKE ?';
                $args[]  = '%.' . $e;
            }
            $where[] = '(' . implode(' OR ', $parts) . ')';
            $desc[]  = 'extension ' . implode('/', $exts);
        }
        if (!empty($scope['path'])) {
            $p = (string) $scope['path'];
            if ($p === '' || $p[0] !== '/') {
                return ['error' => 'A path must be absolute: ' . $p];
            }
            $where[] = 'file_path = ?';
            $args[]  = $p;
            $desc[]  = $p;
        }

        if ($desc === []) {
            return ['error' => 'Refusing to restore without a scope. Name a job '
                             . '(--job=), a signature (--signature=), an account '
                             . '(--account=), a path (--path=) or a finding '
                             . '(--id=). "Everything" would put real detections '
                             . 'back as well as false ones.'];
        }

        return ['sql' => implode(' AND ', $where), 'args' => $args,
                'desc' => implode(' + ', $desc)];
    }

    /** How many findings a scope covers, and how many bytes they hold. */
    public static function count(array $scope): array
    {
        $sel = self::selector($scope);
        if (isset($sel['error'])) { return $sel; }
        $row = Database::fetchOne(
            'SELECT COUNT(*) AS c, COALESCE(SUM(size),0) AS b FROM threats WHERE ' . $sel['sql'],
            $sel['args']
        );
        return ['count' => (int) ($row['c'] ?? 0), 'bytes' => (int) ($row['b'] ?? 0),
                'desc'  => $sel['desc']];
    }

    /**
     * What a scope is made of, so an operator can sanity-check it before
     * moving 154,323 files: the signatures, the accounts and the extensions.
     */
    public static function breakdown(array $scope, int $top = 8): array
    {
        $sel = self::selector($scope);
        if (isset($sel['error'])) { return $sel; }

        $bySig = Database::fetchAll(
            'SELECT threat_name AS k, COUNT(*) AS c FROM threats WHERE ' . $sel['sql']
          . ' GROUP BY threat_name ORDER BY c DESC LIMIT ' . (int) $top, $sel['args']);
        $byUser = Database::fetchAll(
            'SELECT COALESCE(NULLIF(cpanel_user, \'\'), \'(unknown)\') AS k, COUNT(*) AS c '
          . 'FROM threats WHERE ' . $sel['sql']
          . ' GROUP BY k ORDER BY c DESC LIMIT ' . (int) $top, $sel['args']);

        /* Extensions are counted in PHP: SQLite has no right-of-last-dot
         * function, and the alternative is a LIKE per extension guessed in
         * advance. Bounded by the same page size as everything else. */
        $ext = [];
        $rows = Database::fetchAll(
            'SELECT file_path FROM threats WHERE ' . $sel['sql'] . ' LIMIT 200000', $sel['args']);
        foreach ($rows as $r) {
            $e = strtolower((string) pathinfo((string) $r['file_path'], PATHINFO_EXTENSION));
            if ($e === '') { $e = '(none)'; }
            $ext[$e] = ($ext[$e] ?? 0) + 1;
        }
        arsort($ext);

        return ['signatures' => $bySig, 'accounts' => $byUser,
                'extensions' => array_slice($ext, 0, $top, true)];
    }

    /**
     * Restore the files a scope covers.
     *
     * @param array<string,mixed> $scope see selector()
     * @param array{apply?:bool,limit?:int,batch?:int,mode?:int,by?:string,
     *              clear_verdict?:bool} $opts
     * @return array<string,mixed>
     */
    public static function run(array $scope, array $opts = []): array
    {
        $sel = self::selector($scope);
        if (isset($sel['error'])) { return ['success' => false, 'error' => $sel['error']]; }

        $apply  = !empty($opts['apply']);
        $limit  = max(0, (int) ($opts['limit'] ?? 0));
        $batch  = max(1, min(5000, (int) ($opts['batch'] ?? self::DEFAULT_BATCH)));
        $by     = mb_substr(trim((string) ($opts['by'] ?? 'cli')), 0, 64);
        $clear  = !empty($opts['clear_verdict']);
        $mode   = isset($opts['mode']) ? ((int) $opts['mode'] & 07777) : null;

        $total = self::count($scope);

        $out = [
            'success'    => true,
            'dry_run'    => !$apply,
            'scope'      => $sel['desc'],
            'matched'    => (int) ($total['count'] ?? 0),
            'considered' => 0,
            'restored'   => 0,
            'bytes'      => 0,
            'skipped'    => [],
            'failed'     => [],
            'examples'   => ['restored' => [], 'skipped' => [], 'failed' => []],
            'ownership'  => ['from_record' => 0, 'inferred' => 0, 'not_changed' => 0],
            'verdicts'   => 0,
        ];

        $lastId = 0;
        while (true) {
            if ($limit > 0 && $out['considered'] >= $limit) { break; }

            $take = $batch;
            if ($limit > 0) { $take = min($take, $limit - $out['considered']); }

            /* Paged by id rather than OFFSET. A row that cannot be restored
             * stays 'quarantined' and would be selected again for ever by an
             * OFFSET-free query; paging past it means one pass does one pass,
             * and a re-run after an interruption picks up where this stopped
             * because restored rows leave the selection. */
            $rows = Database::fetchAll(
                'SELECT * FROM threats WHERE ' . $sel['sql'] . ' AND id > ?'
              . ' ORDER BY id LIMIT ' . (int) $take,
                array_merge($sel['args'], [$lastId])
            );
            if ($rows === []) { break; }

            foreach ($rows as $row) {
                $lastId = (int) $row['id'];
                $out['considered']++;
                self::one($row, $apply, $mode, $by, $clear, $out);
            }

            if ($apply) {
                Logger::info('quarantine restore: ' . $out['restored'] . ' restored, '
                             . array_sum($out['skipped']) . ' skipped, '
                             . array_sum($out['failed']) . ' failed (scope: '
                             . $sel['desc'] . ')');
            }
        }

        $after = self::count($scope);
        $out['remaining'] = (int) ($after['count'] ?? 0);

        if ($apply) {
            Logger::event('quarantine_restored', 'medium', '', '',
                'Restored ' . $out['restored'] . ' file(s) from quarantine (scope: '
                . $sel['desc'] . '; ' . array_sum($out['skipped']) . ' skipped, '
                . array_sum($out['failed']) . ' failed)');
        }
        return $out;
    }

    /**
     * One file. Appends to the report rather than returning, so the caller's
     * counters and the reasons stay in one shape.
     */
    private static function one(array $row, bool $apply, ?int $modeOverride,
                                string $by, bool $clear, array &$out): void
    {
        $dest = (string) $row['file_path'];
        $src  = self::quarantinedCopy($row);

        if ($src === null) {
            self::tally($out, 'skipped',
                        'the quarantined copy is not on disk any more', $dest);
            return;
        }
        if (file_exists($dest)) {
            // The customer, or a deployment, has put something there since.
            self::tally($out, 'skipped',
                        'a file already exists at the original path', $dest);
            return;
        }
        $dir = dirname($dest);
        if (!is_dir($dir)) {
            // Not created: re-making a directory tree that has been deleted is
            // a different decision, and one an operator should take knowingly.
            self::tally($out, 'skipped',
                        'the original directory no longer exists', $dest);
            return;
        }

        $recorded = strtolower(trim((string) ($row['hash'] ?? '')));
        if ($recorded !== '') {
            $actual = strtolower((string) (@hash_file('sha256', $src) ?: ''));
            if ($actual !== $recorded) {
                self::tally($out, 'failed',
                    'the quarantined copy does not match the hash recorded when it '
                  . 'was taken', $dest);
                return;
            }
        }

        $size = (int) (@filesize($src) ?: 0);

        if (!$apply) {
            self::tally($out, 'restored', '', $dest);
            $out['bytes'] += $size;
            return;
        }

        if (!self::move($src, $dest)) {
            self::tally($out, 'failed',
                        'the file could not be moved back (' . self::lastError() . ')', $dest);
            return;
        }

        self::applyOwnership($row, $dest, $modeOverride, $out);
        @unlink($dest . '.serverscrub_removed');

        Database::query(
            "UPDATE threats SET status='restored', resolved_at=?,"
          . " action_taken=? WHERE id=?",
            [time(), 'restored from quarantine by ' . $by, (int) $row['id']]
        );

        if ($clear) {
            // The file is at its original path again and hashes the same, so
            // this records "these bytes at this path are not malware" and the
            // next scan leaves it alone.
            $v = Verdicts::clearThreat((int) $row['id'],
                                       'restored from quarantine', $by);
            if (!empty($v['success'])) { $out['verdicts']++; }
        }

        self::tally($out, 'restored', '', $dest);
        $out['bytes'] += $size;
    }

    /**
     * Where the quarantined copy actually is, or null.
     *
     * quarantine_path is authoritative. The legacy guess below is for rows
     * written before that column existed — and it is a guess, which is why
     * restoreFromQuarantine() used to fail silently on anything whose
     * resolved_at landed on a different day from the directory it was written
     * into.
     */
    private static function quarantinedCopy(array $row): ?string
    {
        $p = trim((string) ($row['quarantine_path'] ?? ''));
        if ($p !== '' && is_file($p)) { return $p; }

        $when = (int) ($row['resolved_at'] ?? 0) ?: (int) ($row['detected_at'] ?? 0);
        $name = basename((string) $row['file_path']) . '_' . (int) $row['id'] . '.quarantine';

        /* The active directory, then the legacy ones. A file quarantined
         * before the product was renamed, or before an operator relocated
         * quarantine, is not under the current path -- `quarantine status`
         * reports /home/.sentinel-gate/quarantine for exactly that reason. A
         * restore that looked only at the active directory would report those
         * files as "not on disk any more" when they are sitting there. */
        $bases = array_merge([Database::storagePath('quarantine')],
                             Scanner::legacyQuarantineDirs());
        foreach ($bases as $base) {
            foreach ([$when, $when - 86400, $when + 86400] as $t) {
                if ($t <= 0) { continue; }
                $cand = rtrim($base, '/') . '/' . date('Y-m-d', $t) . '/' . $name;
                if (is_file($cand)) { return $cand; }
            }
        }
        return null;
    }

    /**
     * Everywhere quarantinedCopy() will look, for the report.
     *
     * Printed by the CLI, so "the quarantined copy is not on disk any more"
     * can be read as "and here is where it looked" rather than taken on
     * trust.
     *
     * @return string[]
     */
    public static function searchedDirs(): array
    {
        return array_values(array_unique(array_merge(
            [Database::storagePath('quarantine')], Scanner::legacyQuarantineDirs())));
    }

    /**
     * Move the file back, copying only if rename cannot cross the volume.
     *
     * Same discipline as Scanner::quarantine() in the other direction: verify
     * the copy before removing the source, because losing a customer's file
     * while handing it back would be the worst possible end to this.
     */
    private static function move(string $src, string $dest): bool
    {
        if (@rename($src, $dest)) { return true; }

        $bytes = (int) (@filesize($src) ?: 0);
        if (!@copy($src, $dest)) { return false; }
        if ((int) (@filesize($dest) ?: -1) !== $bytes) {
            @unlink($dest);
            return false;
        }
        // The quarantined copy is removed only once the restored one is
        // verified. If this fails the file exists in both places, which is
        // safe and is reported by the next sweep rather than silently fixed.
        @unlink($src);
        return true;
    }

    /**
     * Put the owner and mode back.
     *
     * prev_mode, orig_uid and orig_gid are recorded at quarantine time. Older
     * rows — including every one of the 154,323 from job 12457 — have none, so
     * the owner is taken from the directory the file is going back into, which
     * in a customer's home is the account that owns the site, and the mode
     * falls back to 0644. The report says which of the two was used, because
     * "restored" with the wrong owner is a different kind of broken and the
     * operator has to know which files to look at.
     */
    private static function applyOwnership(array $row, string $dest,
                                           ?int $modeOverride, array &$out): void
    {
        $uid = isset($row['orig_uid']) && $row['orig_uid'] !== null ? (int) $row['orig_uid'] : null;
        $gid = isset($row['orig_gid']) && $row['orig_gid'] !== null ? (int) $row['orig_gid'] : null;
        $mode = $modeOverride;
        if ($mode === null && isset($row['prev_mode']) && $row['prev_mode'] !== null) {
            $mode = ((int) $row['prev_mode']) & 07777;
        }

        $fromRecord = ($uid !== null || $mode !== null);

        if ($uid === null || $gid === null) {
            $st = @stat(dirname($dest));
            if (is_array($st)) {
                $uid = $uid ?? (int) $st['uid'];
                $gid = $gid ?? (int) $st['gid'];
            }
        }
        if ($mode === null) { $mode = self::FALLBACK_MODE; }

        $okOwner = true;
        if ($uid !== null) { $okOwner = @chown($dest, $uid) && $okOwner; }
        if ($gid !== null) { $okOwner = @chgrp($dest, $gid) && $okOwner; }
        $okMode = @chmod($dest, $mode);

        if (!$okOwner || !$okMode) {
            // Not a failure of the restore -- the file is back -- but it is not
            // silent either: a file in a customer's home owned by root is a
            // site that breaks in a new way.
            $out['ownership']['not_changed']++;
            Logger::warn('quarantine restore: restored ' . $dest
                         . ' but could not set ' . (!$okOwner ? 'ownership' : 'mode')
                         . ' (' . self::lastError() . ')');
            return;
        }
        $out['ownership'][$fromRecord ? 'from_record' : 'inferred']++;
    }

    /** @param array<string,mixed> $out */
    private static function tally(array &$out, string $bucket, string $reason,
                                  string $path): void
    {
        if ($bucket === 'restored') {
            $out['restored']++;
            if (count($out['examples']['restored']) < 5) {
                $out['examples']['restored'][] = $path;
            }
            return;
        }
        $out[$bucket][$reason] = ($out[$bucket][$reason] ?? 0) + 1;
        if (!isset($out['examples'][$bucket][$reason])) {
            $out['examples'][$bucket][$reason] = [];
        }
        if (count($out['examples'][$bucket][$reason]) < 3) {
            $out['examples'][$bucket][$reason][] = $path;
        }
    }

    private static function lastError(): string
    {
        $e = error_get_last();
        return $e === null ? 'no error reported' : (string) $e['message'];
    }
}
