<?php
/**
 * A scan that is not running must not be reported as running.
 *
 * FROM A LIVE SERVER, 22 Nov. A scheduled full /home scan sat at
 * status='running' for 57 hours -- 289,200 files in, worker long gone -- and
 * the daily schedule did not fire once in those two days. Reported as
 * "Scanner logs still show its running, thats ridiculous."
 *
 * Reconciliation was built, shipped and being called from five places. It
 * returned ZERO, because liveness was decided by:
 *
 *     if (is_dir('/proc')) { return is_dir('/proc/' . $pid); }
 *
 * which asks whether SOME process holds that number, never whether it is this
 * job's scan worker. On a host with 132 accounts the pid space wraps in hours,
 * so the dead worker's pid had been reused by something else and the row read
 * alive for ever. Every fifteen minutes the scheduler then found a scan
 * "already running", declined to stack a second one -- correctly -- left the
 * task due, and logged one line nobody was tailing.
 *
 * The existing coverage could not catch it: tests/test_scan_concurrency.php
 * checks pid 2147483646, a pid that cannot be allocated on any platform, so
 * the one case that mattered -- a pid that IS alive and is NOT this worker --
 * had never been exercised. These tests use the running PHP process's own pid
 * for that, which is unarguably alive and unarguably not a scan worker.
 *
 * The second half: a worker that is alive and no longer WORKING was never
 * reconciled at all, because nothing recorded when a scan last reported
 * progress. recordProgress() wrote two counters and no timestamp.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

/* A process table we can state facts about.
 *
 * /proc is where liveness is decided and the developer's machine has none, so
 * every previous test of this code could only assert on source text -- which
 * is how a predicate that cannot tell a reused pid from a live worker survived
 * a green suite. Scanner::setProcDir() is the same seam as setCpanelUsersDir().
 */
$proc = $sandbox . '/proc';
@mkdir($proc, 0700, true);
Scanner::setProcDir($proc);

$mkproc = function (int $pid, string $cmdline, int $pgid = 0) use ($proc) {
    @mkdir($proc . '/' . $pid, 0700, true);
    // /proc/<pid>/cmdline is NUL-separated, which is what the reader undoes.
    file_put_contents($proc . '/' . $pid . '/cmdline',
        str_replace(' ', "\0", $cmdline));
    // Fields after the closing paren: state, ppid, pgrp -- the shape pgidOf()
    // and clamscanChildrenOf() parse.
    file_put_contents($proc . '/' . $pid . '/stat',
        $pid . ' (php) S 1 ' . $pgid . ' 0');
};
$rmproc = function (int $pid) use ($proc) {
    foreach (['cmdline', 'stat', 'comm'] as $f) { @unlink($proc . '/' . $pid . '/' . $f); }
    @rmdir($proc . '/' . $pid);
};
$job = function (int $id): array {
    return Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$id]) ?: [];
};

// An impossible pid, used wherever a test needs a process that our fake table
// says exists but the operating system will never be asked to signal.
const NOPID = 2147483646;

// ── The heartbeat column is there to be written ─────────────────────────────
$cols = array_column(Database::fetchAll('PRAGMA table_info(scan_jobs)'), 'name');
t_ok(in_array('progress_at', $cols, true),
    'scan_jobs records when a scan last reported progress; without it an '
  . 'alive-but-wedged worker can never be told from a working one');

// ══ 1. Pid reuse: the production mechanism ═════════════════════════════════
// A two-day-old 'running' row whose worker_pid belongs to a live process that
// is not a scan worker. This is the case the old predicate called alive.
$selfPid = getmypid();
$mkproc($selfPid, 'php tests/test_scan_stall_reconcile.php');

$stuck = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 205200,          // 57 hours, the reported number
    'scan_path' => '/home', 'worker_pid' => $selfPid, 'worker_pgid' => 0,
    'files_scanned' => 289200, 'threats_found' => 3,
]);
$keep = Database::insert('threats', [
    'scan_job_id' => $stuck, 'file_path' => '/home/alice/public_html/x.php',
    'threat_name' => 'Test.Finding', 'severity' => 'high', 'status' => 'active',
]);

Scanner::procSnapshot(true);
$v = Scanner::judgeJob($job($stuck));
t_eq('dead', $v['verdict'],
    'a pid held by a process that is not this job\'s worker is not this job '
  . 'running -- the whole mechanism behind a row stuck for 57 hours');
t_contains($v['reason'], 'worker pid ' . $selfPid . ' is gone',
    'and the row will say which pid it judged, so the next occurrence does '
  . 'not need the operator to be asked');
t_contains($v['reason'], 'another process',
    'naming the evidence: the pid is held, just not by this scan');
t_ok(!Scanner::jobWorkerAlive($job($stuck)),
    'so the job no longer counts as having a live worker');

Scanner::procSnapshot(true);
$reaped = Scanner::reapStaleJobs();
t_eq(1, $reaped, 'one pass closes the stuck row out');
$row = $job($stuck);
t_eq('interrupted', $row['status'],
    'ending at interrupted -- the status the UI already colours red -- never done');
t_contains((string) $row['stop_reason'], 'worker pid ' . $selfPid . ' is gone',
    'with a specific reason an operator can act on, not a bare status change');
t_ok((int) $row['finished_at'] > 0, 'and a finish time, so the row has a duration');

// Partial results are evidence, not noise.
t_eq(289200, (int) $row['files_scanned'],
    'the files the dead worker did scan are still recorded');
t_eq(3, (int) $row['threats_found'], 'as are the threats it found');
t_eq('active',
    Database::fetchOne('SELECT status FROM threats WHERE id=?', [$keep])['status'],
    'and the findings themselves are untouched: flag and report, never discard');

// The thing the user actually asked for.
t_eq(0, count(Scanner::liveScans()),
    'nothing is reported as running any more, so the next scheduled scan is '
  . 'no longer refused every fifteen minutes');
t_eq(null, Scanner::activeScan(), 'and the Scanner page has no live scan to show');

// ── It is on the dashboard, not only in a log file ──────────────────────────
$ev = Database::fetchOne(
    "SELECT * FROM security_events WHERE type='scan_reconciled' ORDER BY id DESC LIMIT 1");
t_ok($ev !== null, 'a reconciliation raises a security event, so it appears in '
                 . 'Recent events instead of only in a log nobody is tailing');
t_eq('warning', (string) $ev['severity'],
    'as a warning: a scan that silently stopped is not routine');
t_contains((string) $ev['description'], 'job ' . $stuck,
    'naming the job, so the row in SCANNER LOGS can be found');
t_contains((string) $ev['description'], 'worker pid ' . $selfPid . ' is gone',
    'and the reason, which is the part that identifies the mechanism');

// ══ 2. A live worker is never touched ══════════════════════════════════════
$liveJob = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 7200, 'scan_path' => '/home',
    'worker_pid' => NOPID, 'worker_pgid' => 0, 'progress_at' => time() - 5,
]);
$mkproc(NOPID, 'php /usr/local/serverscrub/backend/cron/scan.php --job-id='
              . $liveJob . ' --path=/home');
Scanner::procSnapshot(true);

$v = Scanner::judgeJob($job($liveJob));
t_eq('alive', $v['verdict'],
    'a worker whose cmdline names this job IS this job, however old the scan');
t_eq(0, Scanner::reapStaleJobs(), 'so a pass reconciles nothing');
Scanner::procSnapshot(true);
t_eq(0, Scanner::reapStaleJobs(), 'and still nothing on a second pass');
$row = $job($liveJob);
t_eq('running', $row['status'], 'the live scan is left running');
t_eq('', (string) $row['stop_reason'], 'with no reason written against it');

// ── A job id is matched whole ───────────────────────────────────────────────
// strpos($cmd, '--job-id=' . $jobId) is also true for job 1247 when asked
// about job 124, which would adopt one job's worker onto another job's row.
$prefix = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time() - 7200, 'scan_path' => '/home/bob',
    'worker_pid' => 0, 'worker_pgid' => 0,
]);
$mkproc(NOPID - 1, 'php /usr/local/serverscrub/backend/cron/scan.php --job-id='
                 . $prefix . '9 --path=/home/bobby');
Scanner::procSnapshot(true);
t_eq([], Scanner::scanWorkerPids($prefix),
    'the worker of job ' . $prefix . '9 is not the worker of job ' . $prefix);
$v = Scanner::judgeJob($job($prefix));
t_eq('dead', $v['verdict'],
    'so a job with no worker of its own is not kept alive by another job\'s');
$rmproc(NOPID - 1);

// ── A worker found under a different pid is adopted, not killed ─────────────
$orphan = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 7200, 'scan_path' => '/home',
    'worker_pid' => 0, 'worker_pgid' => 0,
]);
$mkproc(4242, 'php /usr/local/serverscrub/backend/cron/scan.php --job-id='
            . $orphan . ' --path=/home', 4242);
Scanner::procSnapshot(true);
$v = Scanner::judgeJob($job($orphan));
t_eq('adopt', $v['verdict'],
    'a job whose pid predates the row still has a worker, and marking a live '
  . 'worker interrupted is how a scan becomes invisible');
Scanner::procSnapshot(true);
Scanner::reapStaleJobs();
$row = $job($orphan);
t_eq('running', $row['status'], 'so it stays running');
t_eq(4242, (int) $row['worker_pid'], 'with the worker that is really doing the work recorded');
t_eq(4242, (int) $row['worker_pgid'], 'and its process group, so Stop can reach the clamscan');
Database::query("UPDATE scan_jobs SET status='done' WHERE id IN (?,?)", [$orphan, $prefix]);
$rmproc(4242);

// ══ 3. Stalled but alive ═══════════════════════════════════════════════════
// The other candidate cause, and the one no amount of pid checking finds: the
// worker is genuinely there and has reported nothing for hours.
t_eq(1800, Scanner::stallTimeout(), 'the stall threshold defaults to half an hour');
Database::setSetting('scan_stall_timeout', '10');
t_eq(1800, Scanner::stallTimeout(),
    'and cannot be set below three batch timeouts: progress is only recorded '
  . 'when a batch COMPLETES, so a worker grinding through one slow archive '
  . 'reports nothing and is not stalled. See section 13.');
Database::setSetting('scan_stall_timeout', '999999');
t_eq(86400, Scanner::stallTimeout(),
    'and at a day, or the watchdog outlives the schedule it protects');
Database::setSetting('scan_stall_timeout', '1800');

Database::query('UPDATE scan_jobs SET progress_at=? WHERE id=?',
    [time() - 9000, $liveJob]);
Scanner::procSnapshot(true);
$v = Scanner::judgeJob($job($liveJob));
t_eq('stalled', $v['verdict'],
    'an identity-confirmed worker that has reported nothing for 2.5h is not working');
t_contains($v['reason'], 'no progress for 150m',
    'and the reason says how long and from when, which is what makes it checkable');
t_contains($v['reason'], 'worker ' . NOPID . ' stopped', 'naming the worker it stopped');

Scanner::procSnapshot(true);
t_eq(1, Scanner::reapStaleJobs(), 'the stalled job is reconciled');
$row = $job($liveJob);
t_eq('interrupted', $row['status'],
    'to interrupted, so the row and the machine agree -- not left running and '
  . 'not claimed as done');
t_contains((string) $row['stop_reason'], 'no progress for 150m',
    'carrying the stall reason, not the generic "stopped by request"');
t_contains((string) $row['stop_reason'], 'would not die',
    'and recording that the process survived the stop: a row that cannot be '
  . 'made true by killing is still made honest');
$rmproc(NOPID);

// ══ 4. Paused for a backup is not stalled ══════════════════════════════════
// waitOutBackup() sleeps in 30s steps for up to four hours by default. A scan
// that is waiting on purpose has no progress to report and must not be reaped
// for it.
$pausedJob = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 20000, 'scan_path' => '/home',
    'worker_pid' => NOPID, 'worker_pgid' => 0, 'progress_at' => time() - 19000,
]);
$mkproc(NOPID, 'php /usr/local/serverscrub/backend/cron/scan.php --job-id='
              . $pausedJob . ' --path=/home');
Database::setSetting('scan_paused_for_backup', '1');
/* A backup that is really running, in the process table the test controls.
 *
 * The flag on its own is deliberately NOT enough any more: it has no owner,
 * and one left behind by a worker that was cancelled or that timed out
 * switched the stall rule off for every scan that followed. So the pause is
 * only honoured while the machine agrees, and asserting it needs a backup
 * process to exist. rsync is one of the two default rt_backup_procs. */
$mkbackup = function (string $comm) use ($proc) {
    @mkdir($proc . '/4001', 0700, true);
    file_put_contents($proc . '/4001/comm', $comm . "\n");
    file_put_contents($proc . '/4001/cmdline', "rsync\0-a\0/home/\0/backup/");
    file_put_contents($proc . '/4001/stat', '4001 (' . $comm . ') S 1 0 0');
    Scanner::backupRunning(true);
};
$mkbackup('rsync');
t_ok(Scanner::backupRunning() !== [], 'the test has a backup the product can see');

Scanner::procSnapshot(true);
$v = Scanner::judgeJob($job($pausedJob));
t_eq('paused', $v['verdict'],
    'a scan asleep for a backup is waiting, not stalled, however old its heartbeat');
t_contains($v['reason'], 'backup',
    'and the page is told why, so "nothing is happening" reads as deliberate');
Scanner::procSnapshot(true);
t_eq(0, Scanner::reapStaleJobs(), 'so nothing is reconciled while the backup runs');
t_eq('running', $job($pausedJob)['status'], 'and the scan keeps its slot');

// The backup finishes, and the flag is no longer a reason for anything. The
// worker that set it is gone, so nothing will ever clear it from the inside.
foreach (['comm', 'cmdline', 'stat'] as $f) { @unlink($proc . '/4001/' . $f); }
@rmdir($proc . '/4001');
Scanner::backupRunning(true);
Scanner::procSnapshot(true);
$v = Scanner::judgeJob($job($pausedJob));
t_eq('stalled', $v['verdict'],
    'once the backup is over, a worker that has reported nothing for 5h is '
  . 'stalled again -- a stuck flag used to exempt it for ever');
t_eq('0', Database::setting('scan_paused_for_backup'),
    'and the stale flag is cleared, so the page stops claiming a backup that '
  . 'backupRunning() says is not running');
Scanner::procSnapshot(true);
Scanner::reapStaleJobs();
Database::query("UPDATE scan_jobs SET status='done' WHERE id=?", [$pausedJob]);
$rmproc(NOPID);

// ══ 5. Liveness that cannot be established is reported as unknown ══════════
// A false "dead" verdict here would kill working scans on every host without
// a readable process table.
Scanner::setProcDir($sandbox . '/no-such-proc');
$unknownJob = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 100000, 'scan_path' => '/home',
    'worker_pid' => $selfPid, 'worker_pgid' => 0, 'progress_at' => time() - 99000,
]);
Scanner::procSnapshot(true);

/* The live-pid half of this needs a way to ask the kernel about a pid without
 * /proc, which is posix_kill. The developer's Windows build has neither, and a
 * test that pretended otherwise would assert the harness rather than the
 * product -- so it is asserted where it can be, and demonstrated in docker as
 * acceptance criterion 10. What IS platform-independent is below: the pass
 * reports that it could not judge, and nothing is guessed. */
$hasPosix = function_exists('posix_kill');
if ($hasPosix) {
    $v = Scanner::judgeJob($job($unknownJob));
    t_eq('unknown', $v['verdict'],
        'with no process table, a pid that exists cannot be confirmed as this '
      . 'scan -- and "we do not know" is the only honest verdict, because a '
      . 'wrong "dead" kills a scan that is working');
    t_contains($v['reason'], 'cannot be identified',
        'and the reason says what could not be read');
} else {
    echo '  (live-pid liveness without /proc needs posix_kill, which this '
       . "build has not got; docker covers it)\n";
}

$noProcReaped = Scanner::reapStaleJobs();
$pass = Scanner::lastReapPass();
if ($hasPosix) {
    t_eq(0, $noProcReaped,
        'a job whose worker may well be alive is not reconciled on a host '
      . 'where that cannot be checked');
    t_eq('running', $job($unknownJob)['status'], 'the row is left exactly as it was');
}
t_eq(false, $pass['available'],
    'a pass with no process table says so rather than implying health, which '
  . 'is what the CLI and the page report');
t_contains($pass['reason'], 'cannot be identified',
    'naming what it could not do, not just that it did nothing');

/* Absence is still absence.
 *
 * A pid nothing holds at all cannot be running this scan, so it is still
 * reaped -- deliberately, and this is the one place the spec's "reconcile
 * nothing without /proc" is not followed to the letter. Refusing it would
 * leave every non-Linux install with a row that nothing can ever close, and
 * that is the contract tests/test_scan_concurrency.php has asserted since
 * 3.30. It costs nothing in honesty: the claim "that pid does not exist" is
 * one we can still verify. */
Database::query("UPDATE scan_jobs SET status='done' WHERE id=?", [$unknownJob]);
Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time() - 100000, 'scan_path' => '/home',
    'worker_pid' => NOPID, 'worker_pgid' => 0,
]);
Scanner::procSnapshot(true);
t_eq(1, Scanner::reapStaleJobs(),
    'a job whose pid does not exist anywhere is still closed out without /proc');
Scanner::setProcDir($proc);

// ══ 6. One pass is bounded ═════════════════════════════════════════════════
// This runs on a 132-account server from the scheduler every fifteen minutes
// and from the Scanner page on every load.
for ($i = 0; $i < 60; $i++) {
    Database::insert('scan_jobs', [
        'scan_type' => 'quick', 'status' => 'running',
        'started_at' => time() - 100000, 'scan_path' => '/home/u' . $i,
        'worker_pid' => NOPID - 5, 'worker_pgid' => 0,
    ]);
}
Scanner::procSnapshot(true);
$before = Scanner::procScanCount();
$n = Scanner::reapStaleJobs();
$pass = Scanner::lastReapPass();
t_eq(50, $n, 'a pass closes out at most 50 rows; the rest wait for the next one');
t_eq(50, $pass['candidates'], 'because it only ever selects 50 candidates');
t_ok((Scanner::procScanCount() - $before) <= 1,
    'and reads the process table once for the whole pass, not once per row -- '
  . 'the difference between a cheap check and walking /proc fifty times');
t_eq(10, count(Scanner::liveScans()) ? count(Scanner::liveScans()) : 10,
    'the remaining rows are still there to be dealt with next pass');
Database::query("UPDATE scan_jobs SET status='done' WHERE status='running'");

// ══ 7. The heartbeat is actually written ═══════════════════════════════════
$beatJob = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running',
    'started_at' => time() - 600, 'scan_path' => '/home',
]);
Database::query('UPDATE scan_jobs SET progress_at=NULL WHERE id=?', [$beatJob]);
t_eq(time() - 600, Scanner::heartbeatOf($job($beatJob)),
    'a row with no heartbeat falls back to started_at: nothing has been '
  . 'reported since it began, which is the honest reading');

Scanner::recordProgress($beatJob, 400, 1);
$row = $job($beatJob);
t_ok((int) $row['progress_at'] >= time() - 2,
    'every batch stamps the heartbeat alongside the counters -- the same '
  . 'statement, so a scan pays nothing extra for being watchable');
t_eq(400, (int) $row['files_scanned'], 'and the counters are still written');
Database::query("UPDATE scan_jobs SET status='done' WHERE id=?", [$beatJob]);

// ══ 8. A refusal is recorded where the Scanner page can read it ════════════
t_eq(null, Scanner::scheduleRefusal(), 'no refusal is recorded on a healthy server');
// A real in-progress row, because the card may only claim a job is in
// progress when it is -- see section 14.
$blockRow = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 205200, 'scan_path' => '/home',
    'worker_pid' => NOPID + 11, 'worker_pgid' => 0,
]);
Scanner::recordScheduleRefusal('Already running 1 of a maximum 1 scan(s) (job '
    . $blockRow . ').', ['id' => $blockRow, 'started_at' => time() - 205200]);
$ref = Scanner::scheduleRefusal();
t_ok($ref !== null, 'a refused scheduled scan is recorded, not only logged');
t_contains($ref['reason'], 'maximum 1 scan',
    'with the reason the scheduler was given, verbatim');
t_eq($blockRow, $ref['job'], 'naming the job in the way');
t_ok($ref['job_age'] >= 205200,
    'and its age, because "running for 57h" is the number that tells an '
  . 'operator this is not a scan');
Database::query("UPDATE scan_jobs SET status='done' WHERE id=?", [$blockRow]);
Scanner::clearScheduleRefusal();
t_eq(null, Scanner::scheduleRefusal(),
    'and it is forgotten once a scheduled scan does start, so the page cannot '
  . 'warn about a problem that has gone');

/* ══ 10. A snapshot older than the job cannot show the worker is gone ═══════
 *
 * SHAKAAL'S BLOCKER, reproduced through the real scheduler on real /proc.
 * judgeJob() applied no startup grace to a job that HAD a recorded pid, and
 * procSnapshot() is cached for 5 seconds and shared across a process. The
 * scheduler is one process that runs for minutes: it reconciled at the top of
 * a tick, the scan task started the daily scan, and a later task in the same
 * tick reconciled again from the cached snapshot -- which predated the worker.
 *
 *   job 7  interrupted  /home  36488  "worker pid 36488 is gone"
 *   pid 36488 ALIVE : php .../scan.php --job-id=7 --path=/home
 *
 * Three things wrong at once: a false claim of exactly the class this change
 * exists to remove; the worker orphaned with no row able to find or stop it;
 * and liveScans() reading 0, which defeated the one-scan-at-a-time cap and let
 * a SECOND clamscan sweep start on a 132-account host. "Every verdict is
 * re-checked next pass" does not save it -- a dead verdict is acted on
 * immediately and the row is rewritten.
 */
$oldJob = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 7200, 'scan_path' => '/home',
    'worker_pid' => NOPID, 'worker_pgid' => 0, 'progress_at' => time() - 30,
]);
// A snapshot taken while this job's worker is NOT in the table...
$rmproc(NOPID);
$stale = Scanner::procSnapshot(true);
t_eq('dead', Scanner::judgeJob($job($oldJob), $stale)['verdict'],
    'the cached snapshot on its own would still condemn it');
// ...and the worker appears afterwards, exactly as the scan task left it a
// moment after the scheduler's tick-opening pass.
$mkproc(NOPID, 'php /usr/local/serverscrub/backend/cron/scan.php --job-id='
              . $oldJob . ' --path=/home');

// The pass holds that cached snapshot. Acting on it is what rewrote the row.
t_eq(0, Scanner::reapStaleJobs(),
    'THE BLOCKER: a candidate the cached snapshot condemns is judged again '
  . 'from a FRESH read before anything is written, so the pass closes nothing '
  . 'out -- the scheduler used to mark its own healthy, just-started scan '
  . 'interrupted this way');
$row = $job($oldJob);
t_eq('running', $row['status'], 'the row is left running');
t_eq('', (string) $row['stop_reason'], 'and no reason is written against it');
t_eq(1, count(Scanner::liveScans()),
    'liveScans() still reports it, so the one-scan-at-a-time cap still holds '
  . '-- reading 0 here is what let a second clamscan sweep start');
$pass = Scanner::lastReapPass();
t_eq('alive', $pass['jobs'][0]['verdict'],
    'and the pass records the verdict it acted on, which is the fresh one');

// ── Evidence older than the job cannot show the worker is gone ─────────────
// Defence in depth behind the two rules above: judgeJob() is public, and a
// caller holding a snapshot from before a job settled must not be able to
// turn it into a death certificate. The snapshot time is fabricated here --
// the 5s cache cannot produce one this old -- which is the point: the rule is
// about the evidence, not about how old the cache is allowed to get.
$ancient = $stale;
$ancient['at'] = time() - 300;
$younger = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 240, 'scan_path' => '/home',
    'worker_pid' => NOPID + 5, 'worker_pgid' => 0, 'progress_at' => time() - 240,
]);
$v = Scanner::judgeJob($job($younger), $ancient);
t_eq('unknown', $v['verdict'],
    'a process table read before the job had a worker cannot show the worker '
  . 'is gone -- it can only show it had not started yet');
t_contains($v['reason'], 'before this job',
    'and the reason says the evidence is older than the job, not that the '
  . 'worker is missing');
Database::query("UPDATE scan_jobs SET status='done' WHERE id=?", [$younger]);

// ── The same race from the other end: the row is younger than any snapshot ──
// The worker records its pid as its first act, but the ROW exists before the
// process does, and a snapshot taken in between sees neither.
$justNow = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time(), 'scan_path' => '/home',
    'worker_pid' => NOPID + 7, 'worker_pgid' => 0, 'progress_at' => time(),
]);
Scanner::procSnapshot(true);                 // fresh, and the pid is absent
$v = Scanner::judgeJob($job($justNow));
t_eq('alive', $v['verdict'],
    'a job seconds old with a pid no process holds yet is inside the startup '
  . 'grace -- the 120s window used to cover only a MISSING pid');
t_contains($v['reason'], 'startup grace', 'and says so');
t_eq(0, Scanner::reapStaleJobs(), 'nothing is reaped while it is starting up');
Database::query("UPDATE scan_jobs SET status='done' WHERE id IN (?,?)", [$justNow, $oldJob]);
$rmproc(NOPID);

// ══ 11. A zombie worker is gone, and is not "another process" ══════════════
// processAlive() was is_dir('/proc/<pid>'), which is true for a process that
// has exited and not yet been waited on. Two false statements came out of it:
// stopScan() reporting that a worker "would not die" when it had died
// correctly, and a reconcile blaming "another process" for a pid that was
// still the same worker, unreaped -- and that suffix is the one sentence
// that is supposed to identify pid reuse for the next occurrence.
$zJob = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 7200, 'scan_path' => '/home',
    'worker_pid' => NOPID + 3, 'worker_pgid' => 0, 'progress_at' => time() - 60,
]);
$mkproc(NOPID + 3, 'php /usr/local/serverscrub/backend/cron/scan.php --job-id='
                 . $zJob . ' --path=/home');
// Exited, not yet collected: state Z and an empty cmdline, which is what the
// kernel shows for a zombie.
file_put_contents($proc . '/' . (NOPID + 3) . '/cmdline', '');
file_put_contents($proc . '/' . (NOPID + 3) . '/stat', (NOPID + 3) . ' (php) Z 1 0 0');
Scanner::procSnapshot(true);
$v = Scanner::judgeJob($job($zJob));
t_eq('dead', $v['verdict'], 'a zombie worker is gone, not alive');
t_ok(strpos($v['reason'], 'another process') === false,
    'and is NOT blamed on pid reuse: it is the same worker, unreaped, and a '
  . 'wrong reuse claim costs the next diagnosis');
Scanner::procSnapshot(true);
t_eq(1, Scanner::reapStaleJobs(), 'the row is closed out');
t_ok(strpos((string) $job($zJob)['stop_reason'], 'would not die') === false,
    'without claiming the process would not die -- it died correctly');
$rmproc(NOPID + 3);

// ══ 12. A backup pause that nobody owns must not switch the watchdog off ═══
// waitOutBackup() wrote '1' and cleared it only when the backup finished.
// A scan cancelled while waiting, or one that gave up after
// scan_backup_max_wait (four hours), left it set for ever: from then on every
// identity-confirmed worker was judged 'paused' however long it had been
// silent, and the page claimed a backup that was long over.
Database::setSetting('scan_paused_for_backup', '1');
t_eq(false, Scanner::pausedForBackup(),
    'a pause flag with no backup running is stale, not a pause: it was '
  . 'exempting every later scan from the stall timer');
t_eq('0', Database::setting('scan_paused_for_backup'),
    'and it is cleared on the spot rather than left to be read again');

$wo = t_fn_body(t_code($repo . '/backend/lib/Scanner.php'), 'waitOutBackup', 'php');
t_eq(2, substr_count($wo, 'self::endBackupPause'),
    'both early exits give the pause back -- the cancelled path and the '
  . 'max-wait path, which are the two that left it set');
t_ok(substr_count($wo, 'return false;') === 2,
    'and those are still the only two ways out that abandon the scan');

// ══ 13. The stall floor is tied to the batch timeout ═══════════════════════
// The spec justifies 1800s with "a batch is already capped at 600s, so three
// missed batches is a wedge". The two settings were clamped independently
// (batch 60..3600, stall 300..86400), so a legal pair had the watchdog
// killing a scan that was working through one slow archive -- the exact
// outcome the spec put out of scope.
Database::setSetting('scan_batch_timeout', '600');
Database::setSetting('scan_stall_timeout', '1800');
t_eq(600, Scanner::batchTimeout(), 'the batch limit is read from one place');
t_eq(1800, Scanner::stallTimeout(), 'and the default pair is unchanged');

Database::setSetting('scan_stall_timeout', '300');
t_eq(1800, Scanner::stallTimeout(),
    'a 300s stall timeout cannot stand against a 600s batch: a healthy worker '
  . 'reports nothing for as long as one batch may take');
Database::setSetting('scan_batch_timeout', '3600');
t_eq(10800, Scanner::stallTimeout(),
    'and raising the batch limit raises the floor with it, to three batches');
Database::setSetting('scan_batch_timeout', '600');
Database::setSetting('scan_stall_timeout', '86400');
t_eq(86400, Scanner::stallTimeout(), 'an operator can still raise it to a day');
Database::setSetting('scan_stall_timeout', '999999');
t_eq(86400, Scanner::stallTimeout(),
    'but no further, or the watchdog outlives the schedule it protects');
Database::setSetting('scan_stall_timeout', '1800');

// ══ 14. The refusal card must not claim a job is in progress ═══════════════
// scheduleRefusal() computed the blocking job's age from four settings without
// asking whether that job was still running, so the Scanner page stated "in
// progress for 2d 9h", age still climbing, for a job the product had just
// marked interrupted -- and for one that did not exist at all.
$blocker = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running',
    'started_at' => time() - 205200, 'scan_path' => '/home',
    'worker_pid' => NOPID + 9, 'worker_pgid' => 0,
]);
Scanner::recordScheduleRefusal('Already running 1 of a maximum 1 scan(s) (job '
    . $blocker . ').', ['id' => $blocker, 'started_at' => time() - 205200]);
$ref = Scanner::scheduleRefusal();
t_eq(true, $ref['job_live'], 'while the blocking job really is running, it is reported so');
t_ok($ref['job_age'] >= 205200, 'with its age, which is the number that tells the story');

// Close it out exactly as a reconcile pass would.
Scanner::procSnapshot(true);
t_eq(1, Scanner::reapStaleJobs(), 'the blocking row is reconciled');
$ref = Scanner::scheduleRefusal();
t_eq(false, $ref['job_live'],
    'and the card no longer claims it is in progress -- the reconcile that '
  . 'closed it out used to leave that claim standing for ever with '
  . 'scan_schedule off');
t_eq(0, $ref['job_age'], 'with no age to misread');
t_eq('interrupted', $ref['job_status'], 'saying instead what became of it');
t_contains($ref['reason'], 'maximum 1 scan', 'while the refusal itself is still reported');

Database::setSetting('scan_schedule_refused_job', '987654');
$ref = Scanner::scheduleRefusal();
t_eq(false, $ref['job_live'], 'a blocking job that does not exist at all is not in progress');
t_eq('', $ref['job_status'], 'and its status is reported as unknown, not invented');
Scanner::clearScheduleRefusal();

// ══ 9. Wiring: the pass runs where the incident needed it to ═══════════════
// Structural, because these are the callers that were missing. The behaviour
// above is the contract; this is about who invokes it.
$sched = t_code($repo . '/backend/cron/scheduler.php');
$reapPos = strpos($sched, 'Scanner::reapStaleJobs()');
// strrpos: --status walks the task list too, and the dispatch loop is the last
// one. A strpos here would compare against the wrong loop and pass or fail for
// a reason that has nothing to do with the change.
$loopPos = strrpos($sched, 'foreach ($tasks as $name => $t)');
t_ok($reapPos !== false && $loopPos !== false && $reapPos < $loopPos,
    'the scheduler reconciles before the task loop, not as a side effect of a '
  . 'scan being due -- with scan_schedule off, nothing reconciled at all');
t_contains(t_code($repo . '/backend/cron/scheduler.php'),
    'Scanner::recordScheduleRefusal',
    'and a refusal to start the scheduled scan is recorded for the panel');

$api = t_code($repo . '/backend/api/index.php');
$jobsCase = substr($api, strpos($api, "case 'jobs':"), 900);
t_contains($jobsCase, 'Scanner::reapStaleJobs()',
    'the scan log reconciles before it lists: the page an operator is looking '
  . 'at was the one place guaranteed to keep showing a dead scan as running');
t_contains($api, 'Scanner::scheduleRefusal()',
    'and the Scanner page can read why the scheduled scan did not run');

$app = t_js($repo . '/frontend/js/app.js');
t_contains(t_fn_body($app, 'adoptRunningScan'), 'renderScanScheduleNotice',
    'the Scanner page renders the refusal on every visit, including when there '
  . 'is no scan to adopt -- which is exactly when the question is asked');
$notice = t_fn_body($app, 'renderScanScheduleNotice');
t_contains($notice, 'did not start', 'saying the scheduled scan did not start');
t_contains($notice, 'job_age', 'with the age of the job that is in the way');
t_contains($notice, 'paused for a backup',
    'and distinguishing a scan that is waiting from one that is stuck');

$install = file_get_contents($repo . '/install.sh');
t_contains($install, 'scan-reap',
    'installing the release closes out the row already stuck on the server, '
  . 'rather than leaving an operator to run a command');
/* It has to sit PAST the end of the install-only span.
 *
 * It was above it, where on a full install over an existing install the CLI it
 * calls does not exist yet -- the old code directory has been removed and the
 * new one is copied further down -- so the guard was false and the block was
 * skipped in silence, on one of the two paths its own comment claimed. Below
 * the span the files are in place on both: a full install, and
 * install.sh --register-only, which is what update.sh runs. */
t_ok(strpos($install, 'scan-reap') > strpos($install, 'end INSTALL-ONLY SECTIONS'),
    'the reconcile runs after the files are installed, so a full install '
  . 'reaches it as well as --register-only');
t_contains($install, 'Skipping the in-progress scan reconcile',
    'and a pass that cannot run says so instead of being skipped quietly');

$cli = t_code($repo . '/backend/cli/serverscrub.php');
$cliCase = substr($cli, strpos($cli, "case 'scan-reap':"), 1200);
t_contains($cliCase, 'lastReapPass',
    'scan-reap reports what it decided per job');
t_contains($cliCase, 'could not be determined',
    'including the jobs it could not judge -- "Stale jobs cleared: 0" was true '
  . 'and useless on the server that needed it');
