<?php
/**
 * A customer's own scan does not wait for JetBackup.
 *
 * Asked for: "for user based scans do not wait for any backup processes like
 * jetbackup and or rsync, just kick it off".
 *
 * The backup gate was written for the scheduled server-wide sweep, where
 * standing down is obviously right: nothing is waiting on it, and a full
 * /home walk competes with rsync for exactly the same disks. A cPanel
 * customer pressing "Scan my account" is the opposite case on both counts --
 * someone is sitting in front of the page, and the work is one home
 * directory.
 *
 * Two gates had to give way, not one:
 *
 *   - Scanner::startScan() REFUSED outright while a backup was running;
 *   - the worker called waitOutBackup() between every batch, so a backup
 *     starting after the scan began would park it for up to four hours
 *     (scan_backup_max_wait) and then abandon the rest of it.
 *
 * Waiving only the first would have been the worse bug of the two: the scan
 * starts, the page says "running", and then it silently stalls.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The flag lives on the job, not in the caller ────────────────────────────
//
// It has to. The worker is a separate process that re-reads the row between
// batches; by then the row is all it knows about the scan.
$cols = array_column(
    Database::query('PRAGMA table_info(scan_jobs)')->fetchAll(PDO::FETCH_ASSOC),
    'name');
t_ok(in_array('ignore_backup', $cols, true),
     'scan_jobs carries the waiver, so the worker can read it back');

$plain = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running', 'started_at' => time(),
    'scan_path' => '/home',
]);
t_ok(!Scanner::ignoresBackup($plain),
     'DEFAULT UNCHANGED: a job inserted without the flag still waits for '
   . 'backups — the scheduled sweep must keep standing down');

$waived = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running', 'started_at' => time(),
    'scan_path' => '/home/demo', 'ignore_backup' => 1,
]);
t_ok(Scanner::ignoresBackup($waived), 'and a waived job is reported as waived');

// Both answers must be per job. A static cache keyed on nothing, or the first
// answer reused, would hand the scheduled sweep the customer's waiver.
t_ok(!Scanner::ignoresBackup($plain),
     'the two answers do not bleed into each other through the cache');

// ── startScan() takes the waiver and records it ─────────────────────────────
$src   = (string) file_get_contents($repo . '/backend/lib/Scanner.php');
$start = t_fn_body($src, 'startScan', 'php');

t_contains($start, "'ignore_backup' => \$ignoreBackup ? 1 : 0",
     'startScan() writes the waiver onto the row it inserts');
t_contains($start, '!$ignoreBackup',
     'and skips its own refusal when the waiver is set');

// The refusal itself is still there for everyone else.
t_contains($start, 'A backup is running (',
     'THE GATE REMAINS: a scheduled scan into a backup window is still '
   . 'refused, with the backup named');

// ── The worker stops parking the scan ───────────────────────────────────────
$wait = t_fn_body($src, 'waitOutBackup', 'php');
t_contains($wait, 'ignoresBackup($jobId)',
     'THE SECOND GATE: the worker checks the waiver between batches too — '
   . 'otherwise a backup starting mid-scan parks it for hours and then '
   . 'abandons it, while the page still says "running"');

// Cost: the lookup must sit behind the "is a backup even running" check, or
// every batch of every scan on every server pays for a query to answer a
// question that is almost always moot.
$posRunning = strpos($wait, 'if (!$running) { return true; }');
$posFlag    = strpos($wait, 'ignoresBackup($jobId)');
t_ok($posRunning !== false && $posFlag !== false && $posRunning < $posFlag,
     'and only looks when a backup is actually running, so an idle server '
   . 'pays nothing per batch');

t_contains($wait, 'continuing anyway',
     'the decision is logged — "scan ran during a backup" is exactly what '
   . 'someone looks for after a slow night');

// ── The customer path asks for it; nothing else does ────────────────────────
$usr = (string) file_get_contents($repo . '/backend/lib/UserScanRequest.php');
t_contains(t_fn_body($usr, 'process', 'php'), "startScan(\$home, 'quick', true, \$user)",
     'the customer-initiated scan passes the waiver, and says who asked');

foreach ([
    '/backend/cron/scheduler.php'  => 'the scheduled sweep',
    '/backend/api/index.php'       => 'the operator UI',
    '/backend/cli/serverscrub.php' => 'the CLI',
] as $file => $what) {
    // Real calls only: '->startScan(' or '::startScan('. Prose in a comment
    // that merely names startScan() is not a caller, and matching it would
    // have this test pass on an empty argument list.
    $other = t_code($repo . $file);
    if (!preg_match_all('/(?:->|::)startScan\s*\(/', $other, $m, PREG_OFFSET_CAPTURE)) {
        continue;
    }

    foreach ($m[0] as $hit) {
        // Walk the call to its matching paren. A regex cannot do this:
        // implode(',', $usable) has two commas of its own and would read as
        // three arguments.
        $i = $hit[1] + strlen($hit[0]);
        $depth = 1;
        $top    = 0;
        for ($n = strlen($other); $i < $n && $depth > 0; $i++) {
            $c = $other[$i];
            if ($c === '(') { $depth++; }
            elseif ($c === ')') { $depth--; }
            elseif ($c === ',' && $depth === 1) { $top++; }
        }
        t_eq(1, $top,
             $what . ' passes two arguments, not three, so it keeps the old '
           . 'behaviour and still stands down for a backup');
    }
}
