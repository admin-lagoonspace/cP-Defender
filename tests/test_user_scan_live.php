<?php
/**
 * The customer can see their scan, and stop it.
 *
 * Reported with a screenshot: press "Scan my account", and the card says
 * "Queued" — and goes on saying it while the scan runs and finishes. There was
 * no progress, no finish, and no way to stop it. The page is server-rendered
 * from report.json, which is rebuilt HOURLY, so the card was showing an answer
 * from before the click and could not have shown anything else.
 *
 * Three things were missing, and each needed a different fix:
 *
 *   - PROGRESS had nowhere to come from. The page runs as the customer and the
 *     database is 0700 root, deliberately, so the privileged side has to hand
 *     it over — one file, in that account's own home.
 *   - CANCELLING is a root action. The page cannot do it, so it leaves an ask
 *     that the privileged side checks against the job row.
 *   - The page never re-read itself.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$src  = (string) file_get_contents($repo . '/backend/lib/Scanner.php');
$usr  = (string) file_get_contents($repo . '/backend/lib/UserScanRequest.php');
$page = (string) file_get_contents($repo . '/cpanel/serverscrub/index.live.php');

// ── Who asked is recorded on the job ────────────────────────────────────────
$cols = array_column(
    Database::query('PRAGMA table_info(scan_jobs)')->fetchAll(PDO::FETCH_ASSOC),
    'name');
t_ok(in_array('requested_by', $cols, true),
     'scan_jobs records which account asked for the scan');

$mine = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running', 'started_at' => time(),
    'scan_path' => '/home/alice', 'requested_by' => 'alice',
]);
$sweep = Database::insert('scan_jobs', [
    'scan_type' => 'full', 'status' => 'running', 'started_at' => time(),
    'scan_path' => '/home',
]);

t_eq('alice', Scanner::jobOwner($mine), 'a customer scan names its owner');
t_eq('', Scanner::jobOwner($sweep),
     'and the scheduled sweep has none — nobody may stop it');

$live = Scanner::liveJobFor('alice');
t_eq($mine, (int) ($live['id'] ?? 0), "alice's live job is found");
t_eq(null, Scanner::liveJobFor('bob'),
     'THE AUTHORISATION: bob has no live job, even though the sweep running '
   . 'right now is reading his files too — "the scan covers my directory" is '
   . 'deliberately not the test, because /home/bob is a prefix of /home/bobby '
   . 'and neither is a claim to have started anything');
t_eq(null, Scanner::liveJobFor(''),
     'and an empty username does not match the server-initiated jobs, which '
   . 'is what an unauthenticated page would hand us');

// Run it, rather than only reading it.
t_eq(null, Scanner::publishUserStatus($sweep),
     'publishing a server-initiated scan writes nothing at all');
t_eq(null, Scanner::publishUserStatus(0), 'and a bad job id is not an error');
t_eq(null, Scanner::publishUserStatus($mine + 9999),
     'nor is a job that does not exist');

// ── Progress is published into the right home, and only there ───────────────
$pub = t_fn_body($src, 'publishUserStatus', 'php');
t_contains($pub, "\$user === '' || \$user[0] === '@'",
     'a server-initiated scan publishes nothing — there is nobody to tell, '
   . 'and writing one account a view of a server-wide sweep would leak that '
   . 'work is being done for everyone else');
t_eq(null, Scanner::publishUserStatus((int) Database::insert('scan_jobs', [
        'scan_type' => 'full', 'status' => 'running', 'started_at' => time(),
        'scan_path' => '/home', 'requested_by' => '@schedule'])),
     'and a marker like @schedule is not an account with a home to write to');
t_contains($pub, "UserReport::writeInHome(\$user, 'scan-status.json'",
     'and a customer scan goes into that customer\'s own home');
t_contains($pub, "'updated_at'",
     'with a write time, so the page can tell a scan that is working from one '
   . 'whose worker died without saying so');

t_contains(t_fn_body($src, 'recordProgress', 'php'), 'publishUserStatus',
     'THE MOVING NUMBER: progress is published every batch, which is what '
   . 'makes the card advance rather than sit on "Queued"');

// Every way a scan can end has to reach the page. A missed one leaves the
// customer looking at "Scanning now" forever.
$scan = (string) file_get_contents($repo . '/backend/cron/scan.php');
t_contains($scan, 'Scanner::publishUserStatus($jobId)',
     'a finished scan says so');
t_eq(3, substr_count($scan, 'Scanner::publishUserStatus('),
     'and so do the error and skipped paths — all three endings, because the '
   . 'one that is missed is the one that strands the page on "running"');
t_contains(t_fn_body($src, 'stopScan', 'php'), 'publishUserStatus',
     'a cancelled scan says so');
t_contains(t_fn_body($src, 'reapStaleJobs', 'php'), 'publishUserStatus',
     'and a scan whose worker died is reported as interrupted rather than '
   . 'running forever');

// ── Writing into a directory the customer controls ──────────────────────────
$wr = t_fn_body((string) file_get_contents($repo . '/backend/lib/UserReport.php'),
                'writeInHome', 'php');
t_contains($wr, 'is_link($dir)',
     'THE SYMLINK: a link at ~/.serverscrub would redirect root\'s write to '
   . 'anywhere the customer chose');
t_contains($wr, 'strpbrk($name',
     'and a filename carrying a separator is refused, since it would escape '
   . 'the one directory every other check here is about');
t_contains($wr, 'rename($tmp, $path)',
     'the file is renamed into place, so a reader never sees half of it and '
   . 'the rename replaces a planted symlink without opening it');
t_contains($wr, 'validUsername($user)', 'and the account name is validated');

// ── Cancelling ──────────────────────────────────────────────────────────────
t_contains($usr, "const CANCEL = 'scan-cancel.json'", 'there is a cancel request');

$pc = t_fn_body($usr, 'processCancels', 'php');
t_contains($pc, 'Scanner::liveJobFor($user)',
     'a cancel only ever reaches a job that account started');
t_contains($pc, "Scanner::jobOwner(\$id) !== \$user",
     'checked again against the row before acting — liveJobFor() already '
   . 'filters on it, so this can only fail if that query is loosened, which '
   . 'is exactly the change that would hand a customer the server\'s scan');

$clearPos = strpos($pc, 'self::clearCancel($user)');
$stopPos  = strpos($pc, 'Scanner::stopScan(');
t_ok($clearPos !== false && $stopPos !== false && $clearPos < $stopPos,
     'THE STUCK CANCEL: the request is cleared BEFORE the stop is attempted. '
   . 'Left on disk it would be retried every minute — and could land on a '
   . 'LATER scan the customer started and never asked to stop');

$proc = t_fn_body($usr, 'process', 'php');
$cPos = strpos($proc, 'processCancels()');
$sPos = strpos($proc, 'startScan(');
t_ok($cPos !== false && $sPos !== false && $cPos < $sPos,
     'cancels are handled before starts, so a customer who cancels and is '
   . 'then honoured in the same minute does not watch the scan they just '
   . 'stopped begin');

// ── One picker-up, not two ──────────────────────────────────────────────────
$sched = (string) file_get_contents($repo . '/backend/cron/scheduler.php');
t_contains($sched, 'UserScanRequest::process()',
     'THE FLOOR: the scheduler picks requests up too. This was removed once, '
   . 'to stop a double start — and on a server whose minute cron was not '
   . 'running, that left NOTHING picking requests up at all: the customer '
   . 'presses the button, the card says "Queued", and nothing happens for as '
   . 'long as they look at it. Reported from a live server with an 8h-stale '
   . 'pickup. The double start is fixed by sharing one lock instead');

// The fallback must not be reachable by a schedule setting. It is a customer
// waiting, not an operator's nightly job.
// From the task table to the start of the unconditional pickup block, which
// sits just before Dispatch — slicing to '── Dispatch' would swallow that
// block and the assertion would always fail.
$tStart = (int) strpos($sched, '$tasks = [');
$tEnd   = (int) strpos($sched, '── Customer scan requests');
t_ok($tStart > 0 && $tEnd > $tStart, 'the task table is where this test thinks');
$taskTable = substr($sched, $tStart, $tEnd - $tStart);
t_ok(strpos($taskTable, 'UserScanRequest::process()') === false,
     'and it is NOT inside a scheduled task, where setting that task to '
   . 'weekly would push a waiting customer out by a week');
t_contains($sched, "if (!\$status && !\$dryRun && \$force === null)",
     'while --status and --dry-run still start nothing');
t_contains($sched, 'UserReport::writeAll()',
     'but it still writes the per-user reports, which is its job');

// ── The page ────────────────────────────────────────────────────────────────
t_contains($page, "\$CARDS = ['scan' => \$renderScanCard, 'logs' => \$renderLogsCard];",
     'each live region can be fetched on its own');
t_contains($page, "if (isset(\$CARDS[\$want]))",
     'and only a region named in that list is rendered — ?card= picks a '
   . 'closure, so an unlisted value must fall through to the normal page '
   . 'rather than reach anything');
t_contains($page, 'while (ob_get_level() > 0) { ob_end_clean(); }',
     'and the buffered chrome is discarded rather than sent — this is a '
   . 'fragment, not a page, and cPanel\'s header must not wrap it');

t_contains($page, 'scan-status.json',
     'the page reads the live status directly, not out of the hourly report');
t_contains($page, 'name="cancel_scan"', 'there is a cancel control');
t_contains($page, 'data-poll=',
     'and the card states whether it is worth re-reading');

// Cancelling has to do both halves. A request not yet picked up is deleted
// here; a scan already running can only be asked about.
t_contains($page, "sg_leave(\$home, 'scan-cancel.json'",
     'a cancel leaves the ask for the privileged side');
t_contains($page, 'scan-request.json', 'and drops the request file itself');

t_ok(strpos($page, 'Scanner::') === false && strpos($page, 'Database::') === false,
     'THE BOUNDARY HOLDS: the page still reaches nothing privileged. It got a '
   . 'cancel button, not a route into the server\'s database');

// The stale guard. "Scanning now" for a job nothing is working on is the exact
// lie this card was reported for, in the other direction.
t_contains($page, "\$liveStatus = 'stalled'",
     'a status file that has stopped being updated reads as stalled');
t_contains($page, "&& \$liveStatus !== 'stalled'",
     'and a stalled scan stops the poller, rather than re-reading a dead job '
   . 'every few seconds for as long as the tab is open');

// ── "Cancel does nothing" ───────────────────────────────────────────────────
//
// Reported from the live server, and it was true from where the customer sat.
// The cancel HAD worked -- the page deletes the request file, which it owns
// and can do instantly -- but the card went on saying "Queued" afterwards,
// because queued was decided like this:
//
//     $srQueued = $requested || !empty($sr['pending']);
//
// $sr comes out of report.json, which is rebuilt HOURLY. So the card was
// reading an hour-old "pending" and putting the screen straight back the way
// it was, and would have kept doing that until the next report. The fresh
// request file WAS read, two lines further down, and then not used for this.
// Comments stripped: the fix is explained in a comment that quotes the old
// expression, and matching that prose would pass whatever the code did.
$pageCode = t_code($repo . '/cpanel/serverscrub/index.live.php');
t_ok(strpos($pageCode, "\$requested || !empty(\$sr['pending'])") === false,
     'THE CANCEL THAT DID NOTHING: queued is no longer decided from the '
   . 'hourly report, which could not reflect a click made seconds ago');
t_contains($page, "\$srQueued = !\$cancelling && (\$requested || \$reqAt > 0)",
     'it is decided from the request FILE, which the privileged side deletes '
   . 'the moment it acts and this page deletes on cancel — the only thing '
   . 'here that is current');

$qPos = (int) strpos($page, '$srQueued =');
$rPos = (int) strpos($page, '$reqAt = 0;');
t_ok($rPos > 0 && $qPos > $rPos,
     'and the file is read BEFORE that decision, not after it — reading it '
   . 'afterwards is how the stale value survived');

// ── "It should start right away" ────────────────────────────────────────────
//
// A cron is the wrong mechanism for something a person is sitting in front of:
// a minute is its floor, and whether it runs at all depends on a file in
// /etc/cron.d that an administrator can tidy away -- which is what was found
// on a live server. So the normal path is a resident service.
$usc = (string) file_get_contents($repo . '/backend/cron/user-scans.php');
t_contains($usc, "if (\$a === '--watch')", 'the pickup can stay resident');
t_contains($usc, '$interval = max(2, min(60,',
     'with a bounded interval — a zero would spin a CPU, an hour would defeat '
   . 'the point');

// The licence check belongs in the pass, not before the loop. Checking once
// at startup meant an unlicensed box exited immediately and systemd restarted
// it every five seconds forever, and a licence renewed later was never seen.
$passFn = substr($usc, (int) strpos($usc, '$sg_pass = function'));
$passFn = substr($passFn, 0, (int) strpos($passFn, "\n};"));
t_contains($passFn, 'License::protectionAllowed',
     'THE RESIDENT LICENCE CHECK: asked every pass, so an expiry stops scans '
   . 'without a restart and a renewal does not need one');
$beforeLoop = substr($usc, 0, (int) strpos($usc, '$sg_pass = function'));
t_ok(strpos($beforeLoop, 'License::protectionAllowed') === false,
     'and NOT once at startup, which would exit immediately on an unlicensed '
   . 'box and have systemd restart it every five seconds forever');

t_contains($usc, 'pcntl_signal(SIGTERM',
     'SIGTERM is handled, so systemd stopping it does not kill a pass '
   . 'half-way through and leave a request neither started nor cleared');
t_contains($usc, "Logger::error('user-scans: pass failed",
     'and one bad pass does not end the watcher — that failure mode is '
   . 'exactly what this file exists to prevent');
t_contains($usc, 'recycling after',
     'the process recycles rather than being trusted to run for weeks');

$ins2 = t_shell($repo . '/install.sh');
t_contains($ins2, 'user-scans.php --watch --interval=5',
     'the service runs it resident, every five seconds');
t_contains($ins2, 'Restart=always',
     'and is restarted always, not on-failure — it exits 0 on purpose when '
   . 'it recycles');
t_contains($ins2, 'No systemd — customer scans are picked up by cron',
     'a host without systemd still has the cron fallback, and is told so');

$unin = t_shell($repo . '/uninstall.sh');
t_contains($unin, 'stop_service "serverscrub-scans"',
     'the uninstaller stops it — left running it holds a PHP process against '
   . 'a database that is about to be deleted');
t_contains($unin, 'SCANS_SERVICE)',
     'and reads its path from the manifest rather than assuming');

// ── Who started this scan ───────────────────────────────────────────────────
//
// Asked for after the scan log was read and nothing distinguished the nightly
// server sweep from the account owner's own request: every row said "full".
$ur = (string) file_get_contents($repo . '/backend/lib/UserReport.php');
t_contains($ur, "'triggered_by'", 'each logged scan says what started it');
t_contains($ur, "unset(\$scans[\$i]['requested_by'])",
     'THE NAME LEAK: the raw account name is removed before the report is '
   . 'written. A scan of /home appears in EVERY customer\'s log, and the name '
   . 'on such a row is not theirs to see');

$build = t_fn_body($ur, 'build', 'php');
t_contains($build, "\$by === \$user && \$by !== ''",
     'their own request is labelled as theirs');
t_contains($build, "'unknown'",
     'and a row from before this was recorded says so, rather than guessing '
   . '"schedule" — which would be wrong for every scan an operator ever '
   . 'started by hand');

t_contains($page, "'Nightly scan'", 'the page names the scheduled sweep');
t_contains($page, "'Your hosting provider'",
     'and describes an operator by role');
t_ok(strpos($page, "\$j['requested_by']") === false,
     'the page never reads the raw name, because it is not in the report');
