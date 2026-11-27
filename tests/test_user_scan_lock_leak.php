<?php
/**
 * The lock that outlived its pickup, and stopped 132 accounts scanning.
 *
 * Diagnosed on the production server on 10 Nov with fuser and ps, not
 * inferred:
 *
 *     $ fuser -v /tmp/serverscrub/user-scans.lock
 *     root  2223916  F....  php          <- the pickup. Long gone.
 *     root  3824534  F....  sh
 *     root  3824535  F....  timeout
 *     root  3824536  F....  clamscan     <- holding a lock it knows nothing about
 *
 *     $ ps -eo pid,lstart,etime,cmd | grep scan.php
 *     2223916  Sun Nov 8 02:00:01 2026  2-11:10:13
 *       scan.php --job-id=12457 --path=/home/aaksh/public_html,… (~120 accounts)
 *
 * UserScanRequest::lock() takes flock(LOCK_EX|LOCK_NB) on
 * /tmp/serverscrub/user-scans.lock and deliberately keeps the handle open,
 * because closing it drops the lock. process() then calls
 * Scanner::startScan(), which spawns scan.php detached through the shell —
 * AND THE CHILD INHERITS THE DESCRIPTOR, and with it the lock. The pickup
 * exits; the lock lives as long as the scan does.
 *
 * The nightly sweep started Sunday 02:00 and was still in clamscan two and a
 * half days later, so every customer scan request on a 132-account server had
 * been refused since Sunday. The customer clicked Scan, the request file
 * landed in their home, the page said "Queued", and nothing ever happened.
 *
 * Three faults, one incident, and the second and third are why it took three
 * days to notice:
 *
 *   1. the lock's lifetime became the SCAN's lifetime instead of the pickup's;
 *   2. a refused pickup returned silently, exited 0, and skipped the one
 *      timestamp that would have shown it — the bug suppressed the evidence
 *      of itself;
 *   3. the customer's page said "Queued" for as long as they looked at it.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── 1. The close-list: what stops the child inheriting anything ────────────

t_eq('', Scanner::closeFdSuffix([]),
     'with nothing to close the command is untouched — a host that cannot '
   . 'enumerate its own descriptors gets the behaviour it had before');
t_eq(' 3>&- 7>&-', Scanner::closeFdSuffix([3, 7]),
     'each inherited descriptor is closed by the SHELL, with N>&-. PHP has no '
   . 'portable way to open a stream close-on-exec — fopen() has no "e" mode '
   . 'and the stream layer does not expose the fd — and this works identically '
   . 'at 7.4 and 8.5 because it is not PHP doing it');
t_eq(' 3>&-', Scanner::closeFdSuffix([0, 1, 2, 3]),
     'stdin, stdout and stderr are NOT closed: the caller redirects those '
   . 'deliberately, and closing them would send the worker\'s output nowhere');
t_eq(64, substr_count(Scanner::closeFdSuffix(range(3, 500)), '>&-'),
     'and the list is capped, so a process holding hundreds of descriptors '
   . 'cannot push an unbounded redirection list onto a command line');

$src = t_code($repo . '/backend/lib/Scanner.php');
$fn  = t_fn_body($src, 'startScan', 'php');
t_contains($fn, 'self::closeFdSuffix()',
     'THE SPAWN USES IT. This is the line that stopped a customer scan lock '
   . 'reaching clamscan');
$redirPos = strpos($fn, '2>&1%s &');
t_ok($redirPos !== false,
     'and the close-list sits with the other redirections, before the & that '
   . 'backgrounds the command');

// ── 2. Behaviour: a spawned child must not hold the lock ───────────────────
//
// This is the assertion that matters, and it can only be made where a process
// can look at another process's descriptors. In the container it is real; on
// Windows there is no /proc and no fork, so the mechanism above is what is
// asserted there instead. Nothing here passes vacuously: each platform
// asserts something it can actually observe.

if (is_dir('/proc/self/fd')) {
    $lockPath = SG_TMP . '/user-scans.lock';
    @mkdir(SG_TMP, 0750, true);

    $fh = fopen($lockPath, 'c');
    t_ok($fh !== false, 'the lock file opens');
    t_ok(flock($fh, LOCK_EX | LOCK_NB), 'and the lock is ours');

    $open = Scanner::fdsAboveStderr();
    t_ok($open !== [], 'this process has descriptors above stderr to leak');

    /* A child that outlives us, spawned exactly as startScan() spawns the
     * scan worker: through the shell, backgrounded, with the close-list. */
    $marker = SG_TMP . '/leak-probe-' . getmypid();
    $sleeper = escapeshellarg(PHP_BINARY) . ' -r '
             . escapeshellarg('file_put_contents(' . var_export($marker, true)
                              . ', getmypid()); sleep(8);');
    exec($sleeper . ' > /dev/null 2>&1' . Scanner::closeFdSuffix($open) . ' &');

    // Wait for the child to exist, bounded.
    $childPid = 0;
    for ($i = 0; $i < 60 && $childPid === 0; $i++) {
        usleep(100000);
        $childPid = (int) @file_get_contents($marker);
    }
    t_ok($childPid > 0, 'the child started (pid ' . $childPid . ')');

    // Our own handle is what holds the lock right now, so drop it: whatever
    // still holds the file afterwards is something that inherited it.
    flock($fh, LOCK_UN);
    fclose($fh);
    clearstatcache(true, $lockPath);

    $real = realpath($lockPath);
    $childHolds = false;
    foreach ((array) @scandir('/proc/' . $childPid . '/fd') as $fd) {
        if (!ctype_digit((string) $fd)) { continue; }
        if (@readlink('/proc/' . $childPid . '/fd/' . $fd) === $real) { $childHolds = true; }
    }
    t_ok(!$childHolds,
         'THE CHILD DOES NOT HOLD THE LOCK FILE AT ALL. This is the 10 Nov '
       . 'fault: the descriptor reached scan.php, then sh, then timeout, then '
       . 'clamscan, and the lock was held for two and a half days by a process '
       . 'that had never heard of it');

    // And the proof that matters to a customer: another pickup can take it.
    $second = fopen($lockPath, 'c');
    t_ok(flock($second, LOCK_EX | LOCK_NB),
         'so the NEXT pickup can take the lock while that child is still '
       . 'running — which is the difference between a customer scan starting '
       . 'and three days of silence');
    flock($second, LOCK_UN);
    fclose($second);

    // Show the leak is what was being prevented: the same spawn WITHOUT the
    // close-list does inherit it.
    $fh2 = fopen($lockPath, 'c');
    flock($fh2, LOCK_EX | LOCK_NB);
    $marker2 = SG_TMP . '/leak-probe2-' . getmypid();
    $sleeper2 = escapeshellarg(PHP_BINARY) . ' -r '
              . escapeshellarg('file_put_contents(' . var_export($marker2, true)
                               . ', getmypid()); sleep(8);');
    exec($sleeper2 . ' > /dev/null 2>&1 &');       // deliberately no close-list
    $child2 = 0;
    for ($i = 0; $i < 60 && $child2 === 0; $i++) {
        usleep(100000);
        $child2 = (int) @file_get_contents($marker2);
    }
    flock($fh2, LOCK_UN);
    fclose($fh2);
    $leaked = false;
    foreach ((array) @scandir('/proc/' . $child2 . '/fd') as $fd) {
        if (!ctype_digit((string) $fd)) { continue; }
        if (@readlink('/proc/' . $child2 . '/fd/' . $fd) === $real) { $leaked = true; }
    }
    t_ok($leaked,
         'CONTROL: without the close-list the same child DOES inherit the '
       . 'descriptor, so the assertion above is measuring the fix and not the '
       . 'platform');

    @unlink($marker);
    @unlink($marker2);
} else {
    t_ok(!is_dir('/proc'),
         'NOT EXERCISED ON THIS PLATFORM: the child-inheritance assertions '
       . 'need /proc to read another process\'s descriptors. They run in the '
       . 'AlmaLinux container, which is the platform the product ships to; '
       . 'what is asserted here is the close-list itself, above');
}

// ── 3. The silence ────────────────────────────────────────────────────────

$us = t_code($repo . '/backend/lib/UserScanRequest.php');
$proc = t_fn_body($us, 'process', 'php');

$attemptPos = strpos($proc, "Database::setSetting('user_scan_last_attempt'");
$lockPos    = strpos($proc, '$lock = self::lock();');
t_ok($attemptPos !== false && $lockPos !== false && $attemptPos < $lockPos,
     'THE EVIDENCE IS WRITTEN BEFORE THE LOCK IS TAKEN. It used to be written '
   . 'only after the lock succeeded, so a stuck lock froze the one timestamp '
   . 'that showed the pickup had stopped working — the bug suppressed the '
   . 'evidence of itself, and finding it meant converting a Unix timestamp by '
   . 'hand on the server');
t_contains($proc, 'self::noteLockRefused();',
     'and a refused pickup is recorded rather than returning in silence');
t_ok(strpos($proc, "if (\$lock === false) { return \$out; }") === false,
     'the silent early return is gone');

// Behaviour: a refusal is visible, and the state says why.
Database::setSetting('user_scan_pickup_refused_since', '0');
Database::setSetting('user_scan_pickup_refused_at', '0');
t_ok(UserScanRequest::pickupState()['refused'] === false,
     'with nothing recorded, nothing is claimed');

// One clock read: a second ticking between write and assert gave 3601.
$t = time();
Database::setSetting('user_scan_pickup_refused_since', (string) ($t - 3600));
Database::setSetting('user_scan_pickup_refused_at', (string) $t);
$pk = UserScanRequest::pickupState();
t_ok($pk['refused'] === true, 'a current refusal is reported as current');
t_eq(3600, $t - $pk['since'], 'with the time it started, not just "now"');

// Stale state must not read as a live refusal: if nothing has attempted a
// pickup for an hour, the honest answer is about the pickup not running at
// all, which is a different fault with a different fix.
Database::setSetting('user_scan_pickup_refused_at', (string) (time() - 7200));
t_ok(UserScanRequest::pickupState()['refused'] === false,
     'and a refusal nothing has re-confirmed for two hours is not reported as '
   . 'happening now');

$note = t_fn_body($us, 'noteLockRefused', 'php');
t_contains($note, '600',
     'the log line is rate-limited — the pickup runs every five seconds, so a '
   . 'line per refusal is 17,280 a day and buries what matters');
t_contains($note, '$first',
     'but the FIRST refusal is always logged, so the moment it started is in '
   . 'the log at the time it started');
t_contains($note, 'self::pendingCount()',
     'and the line says how many customers are waiting, which is what makes it '
   . 'an incident rather than a curiosity');

$diag = t_fn_body($us, 'lockDiagnosis', 'php');
t_contains($diag, 'WHICH NO LONGER EXISTS',
     'THE DIAGNOSIS NAMES THE SHAPE OF THE FAULT: a recorded owner that is '
   . 'gone means the lock is held by a descriptor it leaked, which is the '
   . 'sentence that would have replaced an afternoon with fuser');
t_contains($diag, 'self::lockHolders(',
     'and it names the live processes holding the file, which is what fuser '
   . 'was run by hand to find');
t_contains(t_fn_body($us, 'lockHolders', 'php'), '$maxProcs',
     'bounded: /proc is walked at most once per ten minutes and never past a '
   . 'cap, on a server with 132 accounts');

// The owner is recorded INSIDE the lock, or the diagnosis has nothing to read.
$lockFn = t_fn_body($us, 'lock', 'php');
t_contains($lockFn, "'pid'   => getmypid()",
     'the holder writes its pid into the lock file');
$flockPos = strpos($lockFn, 'flock($fh, LOCK_EX | LOCK_NB)');
$writePos = strpos($lockFn, 'getmypid()');
t_ok($flockPos < $writePos,
     'after taking the lock, so two pickups cannot write over each other');

// The lock is released where the pickup ends, not whenever the process dies.
t_contains($proc, 'self::unlock($lock);',
     'the pickup drops the lock when it is done. Relying on process exit is '
   . 'what let a child keep it, and in --watch mode the service holds it for '
   . 'an hour of five-second passes otherwise');
t_eq(2, substr_count($proc, 'self::unlock($lock)'),
     'on both exits — including the early one when there is nothing pending, '
   . 'which is the common case on a quiet server');

// ── 4. What the customer is told ──────────────────────────────────────────

$page = t_code($repo . '/cpanel/serverscrub/index.live.php');
t_contains($page, '$notPicked  = $reqAge >= 300;',
     'the page decides from the age of the REQUEST — the one signal in this '
   . 'account\'s own home that does not depend on report.json, the database or '
   . 'the pickup working at all');
t_contains($page, "\$notPicked ? 'Not started' : 'Queued'",
     'A REQUEST NOTHING HAS ACTED ON NO LONGER READS "QUEUED". It said Queued '
   . 'for two and a half days');
t_contains($page, "\$notPicked ? 'amber' : 'green'",
     'and the tag stops being green, because green is the reassurance that '
   . 'hid this');
t_contains($page, 'is being
            blocked on this server',
     'when the privileged side knows why, the customer is told why');
t_contains($page, 'it is their side, not yours',
     'and told it is not something they have done — they cannot fix a stuck '
   . 'lock and should not be left wondering');

$pageSrc = (string) file_get_contents($repo . '/cpanel/serverscrub/index.live.php');
$agePos  = strpos($pageSrc, '$age = $lastCheck > 0');
$cardPos = strpos($pageSrc, '$renderScanCard = function ()');
t_ok($agePos !== false && $agePos < $cardPos,
     '$age is computed before the card rather than inside one of its branches: '
   . 'with the new wording above it, a branch-local $age would have been an '
   . 'undefined variable AND a contradictory sentence on the same card');

// ── 5. The operator can see it without reading the source ────────────────

$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, 'PICKUPS ARE BEING REFUSED since',
     'the scheduler\'s --status report — the command an operator already runs '
   . 'to ask "is anything happening?" — says so outright');
t_contains($sched, "Database::setting('user_scan_last_attempt'",
     'and prints the last ATTEMPT beside the last successful run, because a '
   . 'fresh attempt next to a stale run is the signature of this exact fault');
t_contains($sched, 'scan-stop-all',
     'with the command that releases a lock held by a running scan');
