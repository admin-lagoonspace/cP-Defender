<?php
/**
 * Operator verdicts on findings: "this is not malware".
 *
 * WHY THIS IS NOT AN EXCLUSION
 * ---------------------------
 * An exclusion is a path rule. Once /opt/ai-bolit/ is excluded the scanner
 * never looks inside it again, so a backdoor dropped there next week is
 * invisible forever. That is a permanent blind spot bought to silence five
 * rows in a table, and it is the wrong trade on a shared host.
 *
 * A verdict is a judgement about ONE FILE AS IT IS RIGHT NOW, keyed on
 * (file_path, sha256). The file is still opened, still read, still matched
 * against every signature on every scan. All the verdict does is suppress the
 * REPORT when the bytes are byte-for-byte the ones the operator already looked
 * at and cleared.
 *
 * The moment those bytes change the hash changes, no verdict matches, and the
 * file is reported again at full severity. Replacing a cleared
 * /opt/ai-bolit/procu2.php with a shell does not inherit its clearance.
 *
 * Consequences of that design, all deliberate:
 *
 *   - A verdict cannot be created without a readable file to hash. There is no
 *     such thing as a verdict on a path. Refusing is correct: a verdict with an
 *     empty hash would match whatever later appeared at that path, which is an
 *     exclusion wearing a different hat.
 *
 *   - A legitimate vendor UPDATE re-flags the file. That is not a defect. A new
 *     ai-bolit release is new code nobody has read yet, and one click clears it
 *     again.
 *
 *   - Verdicts are per-path. The same bytes at a different path get their own
 *     verdict, because what makes a file benign is partly where it lives --
 *     that is the entire basis of the drop-in detection in Heuristics.
 */

declare(strict_types=1);

class Verdicts
{
    /** Only ever this one verdict today; the column exists so other verdicts
     *  can be added later without a migration. */
    public const NOT_MALWARE = 'not_malware';

    /** A sha256 and nothing else. Guards against '', '0', 'null', truncation. */
    private const SHA256_RE = '/^[a-f0-9]{64}$/';

    // -- Reading -------------------------------------------------------------

    /**
     * Has the operator already cleared exactly these bytes at exactly this path?
     *
     * Both arguments must be present and the hash must be a real sha256. A null
     * or malformed hash returns false: it must never be possible for a FAILED
     * hash to read as "cleared", because that would turn an unreadable file
     * into a silently trusted one.
     */
    public static function isCleared(string $path, ?string $hash): bool
    {
        return self::covering($path, $hash) !== null;
    }

    /** The verdict row covering these bytes, for explaining a suppression. */
    public static function covering(string $path, ?string $hash): ?array
    {
        $path = trim($path);
        $hash = strtolower(trim((string) $hash));
        if ($path === '' || !preg_match(self::SHA256_RE, $hash)) {
            return null;
        }
        $row = Database::fetchOne(
            'SELECT * FROM file_verdicts WHERE file_path = ? AND sha256 = ? LIMIT 1',
            [$path, $hash]
        );
        return $row ?: null;
    }

    /**
     * Every verdict, newest first, annotated with what the file looks like NOW.
     *
     * `drifted` is the field that matters: the file at that path no longer
     * hashes to the cleared value, so the verdict is dormant and the file is
     * being reported again. The operator needs to see that, because a dormant
     * verdict looks identical to a live one in a plain list.
     */
    public static function listAll(int $limit = 500): array
    {
        $limit = max(1, min(2000, $limit));
        $rows  = Database::fetchAll(
            'SELECT * FROM file_verdicts ORDER BY created_at DESC LIMIT ' . $limit
        ) ?: [];

        foreach ($rows as &$r) {
            $p      = (string) ($r['file_path'] ?? '');
            $exists = $p !== '' && @is_file($p);
            $now    = $exists ? (string) (@hash_file('sha256', $p) ?: '') : '';
            $r['file_exists']    = $exists;
            $r['current_sha256'] = $now;
            // Only a hash that successfully differs counts as drift. An
            // unreadable file is unknown, not changed.
            $r['drifted'] = $exists && $now !== '' && $now !== (string) $r['sha256'];
        }
        unset($r);
        return $rows;
    }

    public static function stats(): array
    {
        $all = self::listAll(2000);
        $drifted = 0;
        $missing = 0;
        foreach ($all as $r) {
            if (empty($r['file_exists'])) { $missing++; }
            elseif (!empty($r['drifted'])) { $drifted++; }
        }
        return [
            'total'   => count($all),
            'active'  => count($all) - $drifted - $missing,
            'drifted' => $drifted,
            'missing' => $missing,
        ];
    }

    // -- Writing -------------------------------------------------------------

    /**
     * Clear one finding.
     *
     * The hash is recomputed from the file on disk rather than taken from the
     * threat row. The stored hash can be null (the realtime daemon wrote rows
     * without one before 4.14.0) or stale (the file changed after detection),
     * and a verdict recorded against a hash nobody verified is worthless.
     *
     * @return array{success:bool,error?:string,verdict_id?:int,sha256?:string,path?:string}
     */
    public static function clearThreat(int $threatId, string $note = '',
                                       string $by = ''): array
    {
        $t = Database::fetchOne('SELECT * FROM threats WHERE id = ?', [$threatId]);
        if (!$t) {
            return ['success' => false, 'error' => "Finding #$threatId no longer exists"];
        }

        $path = trim((string) ($t['file_path'] ?? ''));
        if ($path === '') {
            return ['success' => false, 'error' => "Finding #$threatId has no file path"];
        }

        // A quarantined file is not at its original path any more. Hash where it
        // actually IS, but record the verdict against where it will be when
        // restored, otherwise restoring re-flags it immediately.
        $readAt = $path;
        if (($t['status'] ?? '') === 'quarantined' && !empty($t['quarantine_path'])
            && @is_file((string) $t['quarantine_path'])) {
            $readAt = (string) $t['quarantine_path'];
        }

        if (!@is_file($readAt)) {
            return ['success' => false,
                    'error'   => 'File is gone from disk, so there are no bytes to clear. '
                               . 'Dismiss the finding instead: ' . $path];
        }
        if (!@is_readable($readAt)) {
            return ['success' => false,
                    'error'   => 'Cannot read the file to hash it: ' . $path];
        }

        $hash = strtolower((string) (@hash_file('sha256', $readAt) ?: ''));
        if (!preg_match(self::SHA256_RE, $hash)) {
            return ['success' => false, 'error' => 'Could not hash the file: ' . $path];
        }

        $size = @filesize($readAt);
        $size = ($size === false) ? 0 : (int) $size;

        // Same path + same bytes twice is not an error: two operators can reach
        // the same conclusion, and a second click should be a no-op rather than
        // a failure.
        $existing  = self::covering($path, $hash);
        $verdictId = (int) ($existing['id'] ?? 0);

        if ($verdictId === 0) {
            $verdictId = Database::insert('file_verdicts', [
                'file_path'   => $path,
                'sha256'      => $hash,
                'verdict'     => self::NOT_MALWARE,
                'threat_name' => (string) ($t['threat_name'] ?? ''),
                'size'        => $size,
                'note'        => mb_substr(trim($note), 0, 500),
                'created_by'  => mb_substr(trim($by) !== '' ? trim($by) : 'unknown', 0, 64),
            ]);
        }

        // The finding is resolved, not deleted. The row stays as the record that
        // this was once flagged and who decided otherwise.
        Database::query(
            "UPDATE threats SET status = 'not_malware',"
          . " resolved_at = strftime('%s','now'),"
          . " action_taken = 'marked not malware', hash = ? WHERE id = ?",
            [$hash, $threatId]
        );

        Logger::event(
            'verdict_not_malware', 'low', '', $path,
            'Marked not malware: ' . $path . ' (sha256 ' . substr($hash, 0, 16) . ')'
          . (trim($note) !== '' ? ' - ' . mb_substr(trim($note), 0, 200) : '')
        );

        return ['success' => true, 'verdict_id' => $verdictId,
                'sha256' => $hash, 'path' => $path];
    }

    /**
     * Clear several findings, reporting each one.
     *
     * Per-file results, never one pass/fail for the batch: with five selected
     * and two gone from disk, "some failed" is not something anyone can act on.
     */
    public static function clearMany(array $threatIds, string $note = '',
                                     string $by = ''): array
    {
        $ok = 0; $failed = 0; $results = [];
        foreach ($threatIds as $raw) {
            $id = (int) $raw;
            if ($id <= 0) { continue; }
            $r = self::clearThreat($id, $note, $by);
            if (!empty($r['success'])) { $ok++; } else { $failed++; }
            $results[] = [
                'id'    => $id,
                'ok'    => !empty($r['success']),
                'path'  => (string) ($r['path'] ?? ''),
                'error' => (string) ($r['error'] ?? ''),
            ];
        }
        return ['success' => true, 'ok' => $ok, 'failed' => $failed,
                'results' => $results];
    }

    /**
     * Withdraw a verdict. The file becomes reportable again on the next scan.
     *
     * Deliberately does NOT recreate the old threat row: whether the file is
     * still a finding is for the scanner to decide against today's signatures,
     * not for this function to assert from history.
     */
    public static function revoke(int $verdictId): array
    {
        $v = Database::fetchOne('SELECT * FROM file_verdicts WHERE id = ?', [$verdictId]);
        if (!$v) {
            return ['success' => false, 'error' => "Verdict #$verdictId not found"];
        }
        Database::query('DELETE FROM file_verdicts WHERE id = ?', [$verdictId]);
        Logger::event('verdict_revoked', 'medium', '', (string) $v['file_path'],
                      'Not-malware verdict withdrawn for ' . $v['file_path']
                    . ' - it will be reported again if it still matches');
        return ['success' => true, 'path' => (string) $v['file_path']];
    }

    /** Drop verdicts whose file no longer exists. Audit-safe: they match nothing. */
    public static function pruneMissing(): array
    {
        $n = 0;
        foreach (self::listAll(2000) as $r) {
            if (empty($r['file_exists'])) {
                Database::query('DELETE FROM file_verdicts WHERE id = ?', [(int) $r['id']]);
                $n++;
            }
        }
        return ['success' => true, 'pruned' => $n];
    }
}
