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
 * The scan ran for 59 hours and did it silently. Nothing alerted anybody, and
 * nothing stopped it.
 *
 * So: past a bound, one signature stops being allowed to move, disable or
 * delete customer files unattended, and an operator is told at critical
 * severity immediately. That is the standing rule for WordPress databases —
 * flag it and let a human decide — and it generalises.
 *
 * ── WHAT THIS IS NOT FOR, AND THE INCIDENT THAT PROVED IT ───────────────────
 *
 * The first version of this file (2e160dc, never released) also HALTED the
 * scan past the bound, on the stated assumption that "a single signature
 * accounting for an implausible number of a run's findings is evidence about
 * the signature, not about the customer's files."
 *
 * That assumption is wrong, and this server is the counter-example.
 *
 * Between 13:11 and 13:31 on 2026-04-30 something with ROOT privilege wrote a
 * qTox ransom note named README.md into effectively every directory of every
 * account on host.lws-s1.com, and renamed database-shaped files (.sql, .db,
 * .sqlite, .bak) to *.sorry. It never touched /var/lib/mysql, never touched
 * site content and never touched PHP, so all 118 sites kept serving and NOBODY
 * NOTICED FOR SIX AND A HALF MONTHS. CPGuard was installed and running
 * throughout and reported none of it. 58,597 notes were still live on disk
 * when it was investigated on 11-13 Nov; ~160,000 had been quarantined; 1,864
 * .sorry stubs.
 *
 * The 154,323-file detection on 10 Nov was 100% CORRECT. Those were genuine
 * ransom notes, verified by reading the file contents and matching the
 * attacker's qTox TOX ID. The signature
 * {HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL is written to find
 * exactly that string and it found exactly that string. A 500-file halt would
 * have stopped that scan at the 500th note, left roughly 153,800 real
 * ransomware files on disk, and shown the operator a message reading "evidence
 * about the signature rather than about these files" — i.e. presented a
 * correct mass detection as a probable false positive, and stopped looking.
 *
 * A long hex string is not evidence of a false positive. Ransomware contact
 * IDs, wallet addresses and campaign identifiers are all long hex strings.
 *
 * Ransomware and mass defacement are mass-identical-file events BY NATURE.
 * Mass detection is therefore a real signal in precisely the case where it
 * matters most, and a bound that stops detection fails safe in the wrong
 * direction: it fails toward leaving malware in place. Nothing in this class
 * may stop, halt, cancel or shorten a scan. A scan must not stop finding
 * things because it found a lot of things. If you are reading this while
 * considering reintroducing a halt: test_mass_detection_bound.php asserts its
 * absence by name, and the 30 Apr replay asserts the consequence.
 *
 * ── TELLING THE TWO APART: CONTENT IDENTICALITY ─────────────────────────────
 *
 * Count alone cannot distinguish 10 Nov from 30 Apr: both are ~154,000 files
 * from one signature, and — this is the part that surprises people — both are
 * almost entirely `.md`. README.md is the name of a changelog in node_modules
 * AND the name the attacker gave the ransom note. Extension evidence reads the
 * same in both. Account spread reads the same in both (both server-wide).
 *
 * Content does not. A bad signature matching README/CHANGELOG across
 * node_modules and vendor matches files that are all DIFFERENT. Ransom notes
 * are the same file, over and over. 154,000 byte-identical files is evidence
 * FOR a real mass event, not against it.
 *
 * The test is "very few distinct contents across very many paths", not
 * byte-equality, because real ransomware personalises the note per victim and
 * a byte-equality test would be evaded by appending a counter. See
 * CLUSTERED_SHARE.
 *
 * We do not need to read the disk to know this. threats.hash is a full-file
 * sha256 recorded by ThreatStore::record() at DETECTION time, before any
 * policy action — so it is present for files that have since been quarantined,
 * it is the whole file rather than a prefix, and it costs no I/O now. A
 * bounded sample of rows is grouped by that hash, once per signature per job.
 *
 * Rows whose hash is empty — the file vanished between the match and the
 * record — are INCONCLUSIVE and are scored as evidence for neither verdict.
 * How many samples were conclusive is reported, because a verdict from four
 * readable files out of 154,323 is not a verdict.
 *
 * Where the evidence does not reach a threshold, the verdict is 'undetermined'
 * and it says so. It must not call a mass detection a probable false positive,
 * nor a confirmed infection, on count alone. Destructive action stops either
 * way: the operator's per-signature suppression (04aefc1) is where a "this
 * signature is wrong" decision belongs, after review, and `quarantine restore`
 * is how the already-taken files come back.
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
 *     one of the four that is a usable gate on the first file.
 *
 * 500 because an ordinary infection is dozens to low hundreds of files — a
 * defaced WordPress install, a tree of injected index.php — and those are
 * cleaned untouched by this. Past it, the product keeps FINDING and stops
 * DESTROYING. That is a cost an operator can pay: flagged files are listed in
 * the UI with their reason, and acting on 154,000 of them is a decision about
 * scope that a human makes once.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class MassDetection
{
    /** Per job, per signature. 0 disables the bound entirely. */
    const SETTING_MAX = 'scan_mass_signature_max';
    const DEFAULT_MAX = 500;

    /** Where the last trip is recorded, for the CLI, the UI and the operator. */
    const SETTING_LAST = 'scan_mass_last_trip';

    /* ── The identicality sample, bounded ──────────────────────────────────── */

    /** Rows read once per signature per job, for extensions, accounts, hashes. */
    const SAMPLE_ROWS = 2000;

    /** Fewer conclusive hashes than this and the verdict is 'undetermined'. */
    const SAMPLE_MIN = 8;

    /** Share of conclusive samples in one hash group that reads as one event. */
    const IDENTICAL_SHARE = 0.90;

    /**
     * Distinct-contents share at or below which this is a few files repeated.
     *
     * Byte-equality on its own is too narrow a test. Real ransomware
     * personalises the note per account -- the 30 Apr notes carried a victim
     * reference -- so 600 paths can hold four distinct files. Four distinct
     * contents over 600 matches is the same event as one over 600, and a rule
     * that only recognised the latter would be evaded by appending a counter.
     * What distinguishes the two cases is "very few distinct contents for very
     * many paths", not equality.
     */
    const CLUSTERED_SHARE = 0.10;

    /** Share of conclusive samples that are distinct files, reading as noise. */
    const VARIED_SHARE = 0.50;

    /**
     * Copies of one file that are a mass event whatever else is in the match
     * set.
     *
     * A job can hold both at once: a rule that matches changelogs across
     * node_modules AND the 2,000 identical ransom notes a real intruder left.
     * Fifty byte-identical copies of one file is a mass event in its own
     * right, and a verdict of "this rule matches ordinary files, suppress it"
     * over the top of it would bury the infection inside the false positive.
     * Past this floor the answer is at worst 'undetermined' -- never
     * 'varied-content'.
     */
    const CLUSTER_FLOOR = 50;

    /** A real mass event: many matches, a handful of files, repeated. */
    const V_IDENTICAL = 'mass-identical';
    /** The 10 Nov shape: many matches, all different files. */
    const V_VARIED    = 'varied-content';
    /** Not enough conclusive evidence. Say so; do not guess. */
    const V_UNKNOWN   = 'undetermined';

    /**
     * Per-process memory of signatures already tripped, and their verdicts.
     *
     * The worker asks about every detection. Without this, a run that trips at
     * 500 asks the database once per file for the rest of the batch it is in,
     * and would re-sample 2,000 rows each time.
     *
     * @var array<string,array>
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
     * for an ordinary finding is yes, and costs one indexed COUNT. The answer
     * past the bound is no — and NEVER "stop scanning". The finding is
     * recorded either way by the caller; this governs the destructive step
     * only.
     *
     * @return array{act:bool,count:int,limit:int,verdict:string,reason:string}
     */
    public static function allow(int $jobId, string $signature): array
    {
        $limit = self::limit();
        if ($limit === 0 || $jobId <= 0 || trim($signature) === '') {
            return ['act' => true, 'count' => 0, 'limit' => $limit,
                    'verdict' => '', 'reason' => ''];
        }

        $key = $jobId . "\0" . $signature;
        if (isset(self::$tripped[$key])) {
            $t = self::$tripped[$key];
            return ['act' => false, 'count' => (int) $t['count'], 'limit' => $limit,
                    'verdict' => (string) $t['verdict'],
                    'reason' => self::reason($signature, $limit, $t)];
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
            return ['act' => true, 'count' => $count, 'limit' => $limit,
                    'verdict' => '', 'reason' => ''];
        }

        $trip = self::trip($jobId, $signature, $count, $limit);
        return ['act' => false, 'count' => $count, 'limit' => $limit,
                'verdict' => (string) $trip['verdict'],
                'reason' => self::reason($signature, $limit, $trip)];
    }

    /**
     * What the operator is told, in the row and in the alarm.
     *
     * Three different sentences, because they call for three different next
     * steps, and one generic sentence about "evidence about the signature"
     * sent an operator looking for a false positive that was not there.
     */
    private static function reason(string $signature, int $limit, array $trip): string
    {
        $head = 'flagged, not quarantined: signature ' . $signature . ' has matched '
              . $limit . '+ files in this scan, so destructive action is paused '
              . 'for it. The scan continues and every match is recorded. ';

        $v = isset($trip['verdict']) ? (string) $trip['verdict'] : self::V_UNKNOWN;

        if ($v === self::V_IDENTICAL) {
            return $head . self::basis($trip) . ' A few distinct files repeated '
                 . 'across this many paths is what ransomware and mass '
                 . 'defacement look like, so treat this as a real mass event '
                 . 'until you have read one: do NOT suppress the signature. '
                 . 'Read a flagged file, then decide the SCOPE of the clean-up.';
        }
        if ($v === self::V_VARIED) {
            return $head . self::basis($trip) . ' Matches with differing contents '
                 . 'at this scale are what a bad signature looks like — a rule '
                 . 'hunting hex strings matching changelogs full of git SHAs. '
                 . 'Read a flagged file; if the signature is wrong, '
                 . '`serverscrub signatures suppress add ' . $signature . '`.';
        }
        return $head . self::basis($trip) . ' THAT IS NOT ENOUGH TO TELL whether '
             . 'this is one file repeated (a real mass event) or many different '
             . 'files (a bad signature), so the product does not claim either. '
             . 'Read a flagged file to decide: suppress the signature if it is '
             . 'wrong, or decide the scope of the clean-up if it is right.';
    }

    /** The evidence, stated with its sample size, never as a bare conclusion. */
    private static function basis(array $trip): string
    {
        $c = (int) ($trip['samples_conclusive'] ?? 0);
        $t = (int) ($trip['samples_taken'] ?? 0);
        if ($c <= 0) {
            return 'No file content hash was available for any of the ' . $t
                 . ' sampled matches.';
        }
        return 'Of ' . $c . ' of ' . $t . ' sampled matches with a recorded '
             . 'content hash, there are only '
             . (int) (isset($trip['distinct']) ? $trip['distinct'] : 0)
             . ' distinct file(s), the largest byte-identical group being '
             . (int) (isset($trip['identical_top']) ? $trip['identical_top'] : 0)
             . '.';
    }

    /**
     * Record the trip, weigh the evidence, and tell somebody. Once per
     * signature per job.
     *
     * The facts in the alarm are the ones that make the case readable at a
     * glance: how many accounts, the extensions, and whether the matched files
     * are the same file or different files. "154,252 of 154,323 are .md across
     * 12 accounts, all byte-identical" is a sentence an operator can act on;
     * "154,323 threats found" is what the product said for 59 hours.
     *
     * This does NOT stop the scan. See the class docblock.
     *
     * @return array The trip record, including the verdict and its sample sizes.
     */
    private static function trip(int $jobId, string $signature, int $count, int $limit): array
    {
        $accounts = (int) (Database::fetchOne(
            'SELECT COUNT(DISTINCT COALESCE(NULLIF(cpanel_user, \'\'), file_path)) AS c '
          . 'FROM threats WHERE scan_job_id = ? AND threat_name = ?',
            [$jobId, $signature])['c'] ?? 0);

        /* ONE bounded read for all three kinds of evidence: extensions,
         * content hashes, sample sizes. 2,000 rows is enough to show "almost
         * all of these are .md" and "almost all of these are the same file",
         * and cheap enough to run while a scan is mid-batch. Ordered by id so
         * the sample is deterministic and a test can reason about it.
         *
         * The hash is whatever ThreatStore recorded at detection time. It is
         * NOT re-read from disk: by the time the bound trips, the matches
         * before it have been quarantined and are no longer at their original
         * paths, so a disk read here would report "unreadable" for exactly the
         * files it most needs, and would call every real mass event
         * undetermined. */
        $rows = [];
        try {
            $rows = Database::fetchAll(
                'SELECT file_path, hash FROM threats '
              . 'WHERE scan_job_id = ? AND threat_name = ? ORDER BY id LIMIT '
              . self::SAMPLE_ROWS,
                [$jobId, $signature]
            );
        } catch (Throwable $e) {
            /* The sample failed outright. That is a "we do not know", not a
             * reason to skip the alarm, not a reason to resume destroying
             * files, and not a reason to stop the scan. */
            Logger::error('MASS DETECTION: content sample failed for ' . $signature
                        . ' in job ' . $jobId . ': ' . $e->getMessage());
            $rows = [];
        }

        $ext    = [];
        $hashes = [];
        $taken  = 0;
        foreach ($rows as $r) {
            $taken++;
            $e = strtolower((string) pathinfo((string) $r['file_path'], PATHINFO_EXTENSION));
            if ($e === '') { $e = '(none)'; }
            $ext[$e] = (isset($ext[$e]) ? $ext[$e] : 0) + 1;

            /* An empty hash is an INCONCLUSIVE sample -- the file vanished
             * between the match and the record. It is evidence for neither
             * verdict, and in particular must not be counted as a distinct
             * file, which would read as "all different" and so as a false
             * positive. */
            $h = trim((string) (isset($r['hash']) ? $r['hash'] : ''));
            if ($h === '') { continue; }
            $hashes[$h] = (isset($hashes[$h]) ? $hashes[$h] : 0) + 1;
        }

        arsort($ext);
        $extText = [];
        foreach (array_slice($ext, 0, 4, true) as $e => $n) { $extText[] = $n . ' ' . $e; }

        $conclusive = (int) array_sum($hashes);
        $distinct   = count($hashes);
        $top        = $distinct > 0 ? (int) max($hashes) : 0;
        $verdict    = self::weigh($conclusive, $distinct, $top);

        $facts = [
            'at'         => time(),
            'job'        => $jobId,
            'signature'  => $signature,
            'count'      => $count,
            'limit'      => $limit,
            'accounts'   => $accounts,
            'extensions' => implode(', ', $extText),
            'verdict'    => $verdict,
            'samples_taken'      => $taken,
            'samples_conclusive' => $conclusive,
            'distinct'           => $distinct,
            'identical_top'      => $top,
        ];
        self::$tripped[$jobId . "\0" . $signature] = $facts;
        Database::setSetting(self::SETTING_LAST, (string) json_encode($facts));

        $msg = 'MASS DETECTION: signature ' . $signature . ' matched ' . $count
             . ' file(s) in scan job ' . $jobId . ' (limit ' . $limit . '), across '
             . $accounts . ' account(s)'
             . ($extText ? '; mostly ' . implode(', ', $extText) : '')
             . '. ' . self::verdictHeadline($verdict) . ' '
             . self::basis($facts)
             . ' Nothing further will be quarantined for this signature. These '
             . 'files are FLAGGED and still in place, and THE SCAN IS STILL '
             . 'RUNNING -- it will find and record everything else this '
             . 'signature matches. ' . self::nextStep($verdict, $signature, $jobId);

        Logger::error($msg);
        Logger::event('mass_detection', 'critical', '', $signature, $msg);

        return $facts;
    }

    /**
     * The verdict, from the sampled hashes alone.
     *
     * Public so a test can exercise the thresholds directly rather than by
     * constructing 154,323 fixture rows, and so the shape of the judgement is
     * inspectable instead of buried in a 60-line method.
     */
    public static function weigh(int $conclusive, int $distinct, int $top): string
    {
        if ($conclusive < self::SAMPLE_MIN || $distinct < 1) {
            return self::V_UNKNOWN;
        }
        /* One file repeated: the plain ransom-note / defacement shape. */
        if ($top / $conclusive >= self::IDENTICAL_SHARE) {
            return self::V_IDENTICAL;
        }
        /* A handful of files repeated across many paths: the same event with a
         * per-account note. See CLUSTERED_SHARE. */
        if ($distinct / $conclusive <= self::CLUSTERED_SHARE) {
            return self::V_IDENTICAL;
        }
        /* A real cluster inside an otherwise mixed match set. Not enough to
         * call the whole thing one event, and far too much to call it noise. */
        if ($top >= self::CLUSTER_FLOOR) {
            return self::V_UNKNOWN;
        }
        if ($distinct / $conclusive >= self::VARIED_SHARE) {
            return self::V_VARIED;
        }
        return self::V_UNKNOWN;
    }

    /**
     * What to do next, per verdict, in the alarm an operator is paged with.
     *
     * THE SUPPRESSION COMMAND IS COMPOSED FOR ONE VERDICT ONLY.
     *
     * The first version of this alarm handed over a ready-to-paste
     * `serverscrub signatures suppress add <signature>` in every case,
     * including the case where the product had just said it could not judge
     * the detection. On the 30 Apr ransomware event that is a copy-pasteable
     * instruction for switching off detection of a live root-level compromise,
     * shown at 03:00 to somebody who has been woken up. The same objection as
     * the halt, wearing a different hat: the product steering toward the
     * dangerous branch of a question it has not answered.
     *
     * So: for 'varied-content' -- all matches are different files, which is
     * what a noisy rule looks like -- the command is written out, because that
     * is the case it fits. For a real mass event the alarm says NOT to
     * suppress. For 'undetermined' suppression is named as the lever for one
     * of the two readings, and is not typed out. Read a file first. Never hand
     * over a path you have not read.
     */
    private static function nextStep(string $verdict, string $signature, int $jobId): string
    {
        $restore = ' Files already taken come back with `serverscrub quarantine '
                 . 'restore --job=' . $jobId . ' --signature=' . $signature . '`.';

        if ($verdict === self::V_IDENTICAL) {
            return 'Read one of the flagged files. If it is malware, decide the '
                 . 'SCOPE of the clean-up and raise the bound deliberately with '
                 . '`serverscrub scan mass-bound <N>` -- do NOT suppress the '
                 . 'signature, which would hide a live compromise.' . $restore;
        }
        if ($verdict === self::V_VARIED) {
            return 'Read one of the flagged files; if the signature is wrong, '
                 . '`serverscrub signatures suppress add ' . $signature . '`.'
                 . $restore;
        }
        return 'READ ONE OF THE FLAGGED FILES BEFORE ANYTHING ELSE -- the '
             . 'product has not judged this and neither command below is safe '
             . 'to run blind. If it is malware, decide the scope of the '
             . 'clean-up and raise the bound with `serverscrub scan mass-bound '
             . '<N>`. If it is not, suppressing this signature is the lever '
             . '(`serverscrub signatures suppress add`, with the name you have '
             . 'just read).' . $restore;
    }

    /** One line naming the case, for the top of the alarm. */
    private static function verdictHeadline(string $verdict): string
    {
        if ($verdict === self::V_IDENTICAL) {
            return 'THE MATCHED FILES ARE THE SAME FEW FILES REPEATED, which is '
                 . 'what ransomware and mass defacement look like and is NOT what '
                 . 'a noisy signature looks like. Treat as a real mass event '
                 . 'until you have read one.';
        }
        if ($verdict === self::V_VARIED) {
            return 'THE MATCHED FILES DIFFER FROM EACH OTHER, which is what a '
                 . 'signature matching ordinary files looks like.';
        }
        return 'THE PRODUCT CANNOT TELL whether these are one file repeated or '
             . 'many different files, and does not guess.';
    }

    /** Whether a bound tripped, and on what evidence, for the CLI and the panel. */
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
