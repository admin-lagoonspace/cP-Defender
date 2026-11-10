<?php

/* Pulls in what it calls. This is consulted from the scan worker, where a
 * missing require_once is a fatal in a detached process nobody is watching. */
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';

/**
 * ServerScrub — the bound on destructive action at scale.
 *
 * ── WHAT THIS IS FOR ─────────────────────────────────────────────────────────
 *
 * On 10 Nov scan job 12457 quarantined 154,323 customer files in one run, from
 * ONE third-party ClamAV signature, across at least twelve unrelated accounts.
 * 154,252 of them were `.md` — README.md and CHANGELOG.md inside node_modules
 * and vendor trees, matched by a signature that hunts long hex strings, which
 * is what a changelog full of git SHAs looks like. The scan ran for 59 hours
 * and did it silently. Nothing alerted anybody, and nothing stopped it.
 *
 * The verdict gate exists so the product cannot CLAIM what it has not
 * verified. This is the same principle applied to what it DOES: a single
 * signature accounting for an implausible number of a run's findings is
 * evidence about the signature, not about the customer's files. The standing
 * rule for WordPress databases — flag them and let a human decide — is the
 * same rule, and it generalises.
 *
 * ── WHY AN ABSOLUTE COUNT, AND WHY 500 ──────────────────────────────────────
 *
 * Four shapes were available and three of them are worse here:
 *
 *   - share of files scanned: unknowable at the moment it matters. At the
 *     500th detection a sweep of 132 accounts may be 1% through its walk, so
 *     the denominator does not exist yet.
 *   - share of detections: this incident was 99.9993% one signature, so the
 *     measure is right — and it is also 100% on a scan that finds three files
 *     with one signature, which is an ordinary infection. It cannot
 *     distinguish the case it is for.
 *   - per-account spread: twelve accounts is strong evidence, and a mass
 *     defacement of one reseller's sites looks identical. It is good evidence
 *     for the ALARM and a bad trigger on its own, so it is reported and not
 *     used to decide.
 *   - absolute count per signature per job: meaningful from the first
 *     detection, independent of how far the scan has got, and it is the only
 *     one of the four that would have stopped this at 500 instead of 154,323.
 *
 * 500 because an ordinary infection is dozens to low hundreds of files — a
 * defaced WordPress install, a tree of injected index.php — and those still
 * complete untouched, while anything an order of magnitude past that stops and
 * waits for a human. The brief was to err toward stopping too early: an
 * operator inconvenienced by a halt is recoverable, and 154,000 quarantined
 * customer files are barely.
 *
 * ── WHY THE WHOLE SCAN HALTS ────────────────────────────────────────────────
 *
 * Not just the offending signature. If one signature is wrong about 500 files,
 * every other conclusion in the run is suspect, and the run has 59 hours left
 * to act on them unattended. Stopping is also what gets a human to look: a
 * scan that keeps going while quietly flagging rather than quarantining is a
 * decision nobody is told about.
 *
 * Findings are still RECORDED. Flagging rather than quarantining means the
 * operator sees every file the signature matched, in the UI, and can judge the
 * signature on the evidence — which is the thing this product is for.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class MassDetection
{
    /** Per job, per signature. 0 disables the bound entirely. */
    const SETTING_MAX = 'scan_mass_signature_max';
    const DEFAULT_MAX = 500;

    /** Where the last trip is recorded, for the CLI, the UI and the operator. */
    const SETTING_LAST = 'scan_mass_last_trip';

    /**
     * Per-process memory of signatures already tripped.
     *
     * The worker asks about every detection. Without this, a run that trips at
     * 500 asks the database once per file for the rest of the batch it is in.
     *
     * @var array<string,bool>
     */
    private static $tripped = [];

    /** The configured bound, or 0 when it is switched off. */
    public static function limit(): int
    {
        $n = (int) (Database::setting(self::SETTING_MAX, (string) self::DEFAULT_MAX)
                    ?? self::DEFAULT_MAX);
        return $n > 0 ? $n : 0;
    }

    /**
     * May this detection be acted on destructively?
     *
     * Called before anything is quarantined, disabled or deleted. The answer
     * for an ordinary finding is yes, and costs one indexed COUNT.
     *
     * @return array{act:bool,count:int,limit:int,reason:string}
     */
    public static function allow(int $jobId, string $signature): array
    {
        $limit = self::limit();
        if ($limit === 0 || $jobId <= 0 || trim($signature) === '') {
            return ['act' => true, 'count' => 0, 'limit' => $limit, 'reason' => ''];
        }

        $key = $jobId . "\0" . $signature;
        if (!empty(self::$tripped[$key])) {
            return ['act' => false, 'count' => -1, 'limit' => $limit,
                    'reason' => self::reason($signature, $limit)];
        }

        /* Counted from the threats table, which is the only trustworthy
         * figure. scan_jobs.threats_found is NOT: it is written per scanned
         * PATH from a counter local to that path, so on job 12457 it read
         * 32,003 -- the first account's share -- while the table held
         * 154,323 rows. A bound built on that number would have been reading
         * a broken one. (The counter is fixed in Scanner::runClamScan(); this
         * does not depend on it either way.) */
        $row = Database::fetchOne(
            'SELECT COUNT(*) AS c FROM threats WHERE scan_job_id = ? AND threat_name = ?',
            [$jobId, $signature]
        );
        $count = (int) ($row['c'] ?? 0);

        if ($count < $limit) {
            return ['act' => true, 'count' => $count, 'limit' => $limit, 'reason' => ''];
        }

        self::trip($jobId, $signature, $count, $limit);
        return ['act' => false, 'count' => $count, 'limit' => $limit,
                'reason' => self::reason($signature, $limit)];
    }

    private static function reason(string $signature, int $limit): string
    {
        return 'flagged, not quarantined: signature ' . $signature . ' has matched '
             . $limit . '+ files in this scan, which is evidence about the '
             . 'signature rather than about these files. An operator has to '
             . 'decide.';
    }

    /**
     * Record the trip, halt the scan, and tell somebody.
     *
     * The facts in the alarm are the ones that make the case readable at a
     * glance: how many accounts, and the extensions. "154,252 of 154,323 are
     * .md across 12 accounts" is a sentence an operator can act on;
     * "154,323 threats found" is what the product said for 59 hours.
     */
    private static function trip(int $jobId, string $signature, int $count, int $limit): void
    {
        self::$tripped[$jobId . "\0" . $signature] = true;

        $accounts = (int) (Database::fetchOne(
            'SELECT COUNT(DISTINCT COALESCE(NULLIF(cpanel_user, \'\'), file_path)) AS c '
          . 'FROM threats WHERE scan_job_id = ? AND threat_name = ?',
            [$jobId, $signature])['c'] ?? 0);

        // Extensions, from a bounded sample: the shape of the evidence, not a
        // census. 2,000 rows is enough to show "almost all of these are .md"
        // and cheap enough to run while a scan is mid-batch.
        $ext = [];
        foreach (Database::fetchAll(
            'SELECT file_path FROM threats WHERE scan_job_id = ? AND threat_name = ? LIMIT 2000',
            [$jobId, $signature]) as $r) {
            $e = strtolower((string) pathinfo((string) $r['file_path'], PATHINFO_EXTENSION));
            if ($e === '') { $e = '(none)'; }
            $ext[$e] = ($ext[$e] ?? 0) + 1;
        }
        arsort($ext);
        $extText = [];
        foreach (array_slice($ext, 0, 4, true) as $e => $n) { $extText[] = $n . ' ' . $e; }

        $facts = [
            'at'        => time(),
            'job'       => $jobId,
            'signature' => $signature,
            'count'     => $count,
            'limit'     => $limit,
            'accounts'  => $accounts,
            'extensions' => implode(', ', $extText),
        ];
        Database::setSetting(self::SETTING_LAST, (string) json_encode($facts));

        $msg = 'MASS DETECTION: signature ' . $signature . ' matched ' . $count
             . ' file(s) in scan job ' . $jobId . ' (limit ' . $limit . '), across '
             . $accounts . ' account(s)'
             . ($extText ? '; mostly ' . implode(', ', $extText) : '')
             . '. Nothing further will be quarantined for this signature and the '
             . 'scan has been halted. These files are FLAGGED and still in place. '
             . 'Judge the signature: `serverscrub signatures suppress add '
             . $signature . '` if it is wrong, or restore what it has already '
             . 'taken with `serverscrub quarantine restore --job=' . $jobId
             . ' --signature=' . $signature . '`.';

        Logger::error($msg);
        Logger::event('mass_detection', 'critical', '', $signature, $msg);

        self::halt($jobId, $signature, $count);
    }

    /**
     * Stop the scan.
     *
     * 'halted' rather than 'cancelled': nobody cancelled it, and the operator
     * needs to be able to tell the difference between a scan they stopped and
     * a scan that stopped itself. Scanner::isCancelled() treats anything that
     * is not 'running' or 'pending' as a stop, so the worker leaves at the
     * next batch boundary with its partial results recorded.
     */
    private static function halt(int $jobId, string $signature, int $count): void
    {
        Database::query(
            "UPDATE scan_jobs SET status = 'halted', stop_reason = ? WHERE id = ?",
            ['halted by the mass-detection bound: ' . $signature . ' matched '
             . $count . ' files', $jobId]
        );
    }

    /** Whether a scan was halted this way, for the CLI and the panel. */
    public static function lastTrip(): ?array
    {
        $raw = (string) Database::setting(self::SETTING_LAST, '');
        if (trim($raw) === '') { return null; }
        $d = json_decode($raw, true);
        return is_array($d) && isset($d['signature']) ? $d : null;
    }

    /** Clear the record, once an operator has dealt with it. */
    public static function clearLastTrip(): void
    {
        Database::setSetting(self::SETTING_LAST, '');
    }

    /** Forget the per-process memory. For tests, and for a long-lived worker. */
    public static function reset(): void
    {
        self::$tripped = [];
    }
}
