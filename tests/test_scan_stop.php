<?php
/**
 * Stopping a running scan, and the clamscan it has spawned.
 *
 * Reported as "the stop button in real time monitoring is not stopping
 * clamscan". Two separate things were true:
 *
 *   1. The real-time monitor never runs clamscan. It uses its own pattern
 *      engine, so its Stop button was never going to stop one. clamscan
 *      belongs to a SCAN.
 *   2. There was no way to stop a scan at all. The UI's Stop button cleared
 *      the progress poller, hid the card and announced "Scan stopped" without
 *      telling the server anything -- the scan carried on at full speed. The
 *      button did not stop something; it reported a stop that never happened.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// -- The job row can carry the process doing the work ------------------------
$cols = array_column(
    Database::fetchAll("PRAGMA table_info(scan_jobs)"), 'name'
);
t_ok(in_array('worker_pid', $cols, true),  'scan_jobs records the worker pid');
t_ok(in_array('worker_pgid', $cols, true), 'and its process group');

// -- Nothing running: stopping says so rather than pretending ----------------
$none = Scanner::stopScan();
t_eq(false, $none['success'], 'stopping with no scan running fails honestly');
t_contains($none['error'], 'No scan', 'and says why');

// -- A running job can be cancelled ------------------------------------------
$jobId = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time(), 'scan_path' => $ctx['sandbox'],
    // A pid that cannot exist, so nothing real is signalled by the test.
    'worker_pid' => 0, 'worker_pgid' => 0,
]);

t_eq(false, Scanner::isCancelled($jobId), 'a running job is not cancelled');

$running = Scanner::runningJob();
t_ok($running !== null, 'the running job is discoverable');
t_eq($jobId, (int)$running['id'], 'and it is the one just created');

$r = Scanner::stopScan($jobId);
t_eq(true, $r['success'], 'the scan can be stopped');
t_eq($jobId, $r['job_id'], 'the result names the job it stopped');

$after = Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$jobId]);
t_eq('cancelled', $after['status'], 'the job is marked cancelled');
t_ok((int)$after['finished_at'] > 0, 'and given a finish time');

// -- Stopping an already-finished scan is refused ----------------------------
// Reporting success would imply something was stopped.
$again = Scanner::stopScan($jobId);
t_eq(false, $again['success'], 'stopping a finished scan is refused');
t_contains($again['error'], 'already finished', 'and says it has already finished');

// -- The batch loop honours the flag -----------------------------------------
$jobId2 = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'cancelling',
    'started_at' => time(), 'scan_path' => $ctx['sandbox'],
]);
t_eq(true, Scanner::isCancelled($jobId2),
    'a job marked cancelling reports itself as cancelled to the scan loop');

$sc = t_code($repo . '/backend/lib/Scanner.php');
$loopStart = strpos($sc, 'foreach ($this->walkFiles($path) as $file)');
$loopEnd   = strpos($sc, 'self::recordProgress($jobId, $scanned, count($threats));', $loopStart);
$loop      = substr($sc, $loopStart, max(0, $loopEnd - $loopStart) + 400);
t_contains($loop, 'self::isCancelled($jobId)',
    'the scan loop checks for cancellation between batches');

// -- The process GROUP is signalled, not just the worker ---------------------
// The worker forks clamscan per batch; signalling only the worker leaves the
// clamscan it is blocked on running, which is the reported symptom.
t_contains($sc, 'signalGroup', 'the worker process group is signalled');
t_contains($sc, 'posix_kill(-$pgid', 'with a negative pid, which means the group');
t_contains($sc, 'clamscanPidsForGroup',
    'and any clamscan left behind is counted rather than ignored');

// -- The worker detaches so it HAS a group of its own ------------------------
$worker = t_code($repo . '/backend/cron/scan.php');
t_contains($worker, 'posix_setsid', 'the worker detaches into its own session');
t_contains($worker, 'worker_pgid', 'and records the group for the stopper to signal');

// A cancelled scan must not be recorded as a completed one: it examined part
// of the tree, and calling that 'done' tells the operator it was all checked.
t_contains($worker, "'cancelled' : 'done'",
    'a cancelled scan is not written up as done');

// -- The UI must call the API, not just hide its own progress bar ------------
$js = file_get_contents($repo . '/frontend/js/app.js');
t_contains($js, "'scanner/stop'", 'the Stop button calls the server');
$fn = substr($js, strpos($js, 'async function stopScan'), 1400);
t_contains($fn, 'await API.post', 'and awaits the result');
$hidePos = strpos($fn, "card.style.display = 'none'");
$callPos = strpos($fn, 'API.post');
t_ok($callPos !== false && $hidePos !== false && $callPos < $hidePos,
    'the progress card is hidden only after the server confirms the stop');
t_contains($fn, "Could not stop the scan",
    'a failed stop is reported instead of being announced as a success');

// The old behaviour: clear the timer, hide the card, claim success.
t_ok(strpos($fn, "toast('Scan stopped', 'info')") === false,
    'the unconditional "Scan stopped" message is gone');

// -- The API exposes it ------------------------------------------------------
$api = t_code($repo . '/backend/api/index.php');
t_contains($api, "'stop' => " . '$method' . " === 'POST'", 'scanner/stop is routed');
t_contains($api, "'running'", 'and the UI can ask whether a scan is in progress');

// -- A failed systemd unit must be clearable ---------------------------------
// `systemctl stop` on a failed unit succeeds and leaves it failed, so the
// dashboard showed "failed" with no way to clear it -- and once the start
// rate limit is hit, systemd refuses to start it again until it is reset.
$rtm = t_code($repo . '/backend/lib/RealTimeMonitor.php');
t_contains($rtm, 'systemctl reset-failed sentinel-gate-monitor',
    'stopping a failed unit clears the failed state');
t_contains($rtm, "\$detail['active'] ?? ''",
    'and reads the key serviceDetail actually returns');
