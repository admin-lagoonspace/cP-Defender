<?php
/**
 * The one place a detection becomes a row in `threats`.
 *
 * WHY A CHOKEPOINT
 * ----------------
 * Detections were written by five separate `Database::insert('threats', ...)`
 * calls in Scanner.php plus one in the Python daemon. Any rule that has to hold
 * for ALL findings -- and "respect the operator's not-malware verdict" is
 * exactly such a rule -- had to be copy-pasted into six places and would be
 * forgotten in the seventh.
 *
 * That is not a hypothetical. update.sh carried three divergent lists of files
 * to copy, and the one nobody remembered to update shipped customers an empty
 * cPanel menu for two releases. The same shape of bug left a bulk button
 * permanently disabled because a hardcoded id list did not know about it.
 *
 * So: every PHP detection goes through record(). scripts/check-threat-gate.py
 * fails the build if a raw insert into `threats` appears anywhere else.
 *
 * The Python daemon cannot call this, so it reimplements the same check in
 * monitor.py against the same table. That duplication is tested from both
 * sides (tests/test_verdicts.php and the daemon's own check) rather than
 * assumed.
 */

declare(strict_types=1);

class ThreatStore
{
    /** Findings suppressed by a verdict this process, for the scan summary. */
    private static int $suppressed = 0;

    /**
     * Record a detection, unless the operator has already cleared these exact
     * bytes at this exact path.
     *
     * Returns the new threat id, or NULL when the finding was suppressed. Every
     * caller must handle null: passing it to applyThreatPolicy() would act on
     * threat id 0, and on a cleared file at that.
     *
     * The hash is computed here when the caller did not supply one, so a writer
     * that forgets it cannot accidentally bypass the verdict -- a missing hash
     * must never read as "no verdict applies".
     *
     * @param array<string,mixed> $row Column => value for the threats table.
     */
    public static function record(array $row): ?int
    {
        $path = trim((string) ($row['file_path'] ?? ''));
        if ($path === '') {
            // Nothing sane to do with a pathless finding, and it cannot be
            // judged or cleared later. Record it rather than lose it.
            return Database::insert('threats', $row);
        }

        $hash = strtolower(trim((string) ($row['hash'] ?? '')));
        if ($hash === '' && @is_file($path) && @is_readable($path)) {
            $hash = strtolower((string) (@hash_file('sha256', $path) ?: ''));
            if ($hash !== '') {
                $row['hash'] = $hash;
            }
        }

        if ($hash !== '' && Verdicts::isCleared($path, $hash)) {
            self::$suppressed++;
            return null;
        }

        // Size is as useful as the hash for judging a finding and costs one
        // stat(). The realtime daemon wrote neither, so every realtime row in
        // the UI read "0 B".
        if (!array_key_exists('size', $row) || (int) ($row['size'] ?? 0) === 0) {
            $sz = @is_file($path) ? @filesize($path) : false;
            if ($sz !== false) { $row['size'] = (int) $sz; }
        }

        return Database::insert('threats', $row);
    }

    public static function suppressedCount(): int
    {
        return self::$suppressed;
    }

    public static function resetSuppressedCount(): void
    {
        self::$suppressed = 0;
    }
}
