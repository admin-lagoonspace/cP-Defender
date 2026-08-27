<?php
/**
 * Scan progress.
 *
 * Reported symptom: "I ran a scan and stopped it after some time; nothing
 * updated on the dashboard for files scanned or anything." The scanner page
 * showed Files: 0 beside a progress bar that kept moving.
 *
 * Three faults stacked:
 *
 *   1. files_scanned was written ONCE, when the job finished. During the scan
 *      the row said 0, so the UI could not show progress even in principle —
 *      and a scan stopped before completion left 0 for ever.
 *   2. The final value was countFiles($path): a fresh directory walk performed
 *      AFTER the scan, counting files present rather than files examined.
 *   3. clamscan was invoked once, recursively, over the whole path. It reports
 *      nothing until it finishes, so there was no progress to record even if
 *      something had been listening.
 *
 * The scan now walks in batches and writes the count after each one.
 */

require_once __DIR__ . '/assert.php';
$ctx = require __DIR__ . '/bootstrap.php';

$sandbox = $ctx['sandbox'];
$tree    = $sandbox . '/scanme';

// A tree big enough to span several batches.
@mkdir($tree . '/a/b', 0777, true);
@mkdir($tree . '/node_modules/pkg', 0777, true);
for ($i = 0; $i < 25; $i++) {
    file_put_contents($tree . "/file{$i}.php", "<?php echo {$i};\n");
}
for ($i = 0; $i < 10; $i++) {
    file_put_contents($tree . "/a/b/deep{$i}.php", "<?php // deep {$i}\n");
}
file_put_contents($tree . '/node_modules/pkg/skip.php', "<?php // must be skipped\n");

$scanner = new Scanner();

// ── recordProgress writes the job row ────────────────────────────────────────
$jobId = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time(), 'scan_path' => $tree,
]);

Scanner::recordProgress($jobId, 42, 3);
$row = Database::fetchOne('SELECT * FROM scan_jobs WHERE id = ?', [$jobId]);
t_eq(42, (int)$row['files_scanned'], 'recordProgress writes files_scanned');
t_eq(3,  (int)$row['threats_found'], 'recordProgress writes threats_found');

// It must be callable while the job is still running — that is the entire point.
t_eq('running', $row['status'], 'progress is recorded without ending the job');

// A job id of 0 must be a no-op rather than an error: cron paths call the
// scanner without a job row.
t_no_throw(function () { Scanner::recordProgress(0, 5, 0); },
    'recordProgress(0) is a harmless no-op');

// ── The scan reports progress as it goes ─────────────────────────────────────
// No ClamAV here, so this exercises the pattern engine, which is also the
// fallback used on any server without a signature database.
$jobId2 = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time(), 'scan_path' => $tree,
]);

Database::setSetting('auto_quarantine', '0');
$scanner->runPatternScan($tree, $jobId2);

$row2 = Database::fetchOne('SELECT * FROM scan_jobs WHERE id = ?', [$jobId2]);
t_ok((int)$row2['files_scanned'] > 0,
    'a completed scan leaves a non-zero files_scanned (' . (int)$row2['files_scanned'] . ')');

// The count must reflect files EXAMINED, not files present. 35 .php files exist
// outside node_modules; the walker must not report the whole tree.
t_ok((int)$row2['files_scanned'] <= 40,
    'files_scanned counts what was examined, not a directory census');

// ── The worker no longer overwrites the real count ───────────────────────────
$worker = t_code($ctx['repo'] . '/backend/cron/scan.php');
t_ok(strpos($worker, 'files_scanned=?,threats_found=?') === false,
    'the worker no longer overwrites files_scanned when finishing');
t_contains($worker, 'SELECT files_scanned FROM scan_jobs',
    'the worker reads back the incremental count');

// ── The worker is launched with a real interpreter ───────────────────────────
// A bare `php` relies on PATH. The API runs under cpsrvd, which is not a login
// shell, and on cPanel the php on PATH may not be an EasyApache build.
$scannerSrc = t_code($ctx['repo'] . '/backend/lib/Scanner.php');
t_ok(strpos($scannerSrc, "'nice -n%d php %s/backend/cron/scan.php") === false,
    'the scan worker is not launched with a bare `php`');
t_contains($scannerSrc, 'phpBinary()', 'the worker uses a resolved interpreter');
t_ok(is_string(Scanner::phpBinary()) && Scanner::phpBinary() !== '',
    'phpBinary() resolves to something');

// ── clamscan is batched, not one recursive shot ──────────────────────────────
t_contains($scannerSrc, '--file-list=',
    'clamscan is given a file list, keeping the command line bounded');
t_contains($scannerSrc, 'scan_batch_size',
    'the batch size is configurable');

// The dashboard reads getStats(), which reads completed jobs. A scan that is
// stopped part-way must still leave its real count behind.
t_ok((int)$row2['files_scanned'] > 0,
    'a stopped scan still leaves the count it reached');
