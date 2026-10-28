<?php
/**
 * One scheduler at a time.
 *
 * FROM A LIVE SERVER. 49 of 141 addresses in /etc/csf/csf.deny had been
 * written TWICE, the pairs 0-1 seconds apart, always on a quarter hour. The
 * installed cron runs scheduler.php every fifteen minutes, so that is one tick
 * overlapping the next: a run that takes longer than fifteen minutes is still
 * going when the
 * following one starts, and then both parse the auth logs, both read the mail
 * queue, and both block the same offenders.
 *
 * The duplicate deny lines were the visible part. The cost is that on a busy
 * server — which is exactly when a run overruns — the product does all of its
 * work twice, and the overlap grows the busier the box gets.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

$src = (string) file_get_contents(dirname(__DIR__) . '/backend/cron/scheduler.php');

t_contains($src, 'LOCK_EX | LOCK_NB',
     'THE FIX: the scheduler takes a non-blocking exclusive lock. scan.php has '
   . 'guarded itself since 3.x; the entry point that runs everything else '
   . 'never did.');
t_contains($src, "SG_TMP . '/scheduler.lock'", 'in a lock file of its own');
t_contains($src, '__sg_sched_lock',
     'and keeps the handle alive — a garbage-collected handle releases the '
   . 'lock while the run is still going, which is no lock at all');

// Standing aside is success. A cron that reported failure for it would page
// somebody every quarter of an hour.
$seg = substr($src, strpos($src, 'One scheduler at a time') ?: 0, 2600);
t_contains($seg, 'exit(0)', 'a run that finds the lock held exits successfully');
t_contains($seg, 'getmypid()', 'the holder records its pid, so the skip message can name it');

// The diagnostic switches must not be gated behind the lock: "is my nightly
// scan running?" is exactly the question asked while one IS running.
t_contains($src, 'if (!$status && !$dryRun) {',
     'THE TRAP AVOIDED: --status and --dry-run take no lock, or the one '
   . 'command that answers "what is running?" would refuse to answer whenever '
   . 'something was');

// A lock file that cannot be created must not stop the scheduler.
t_contains($seg, 'running unguarded',
     'and an unopenable lock file degrades to a warning — refusing to run at '
   . 'all would be worse than an occasional overlap');

// ── The lock actually excludes ──────────────────────────────────────────────

$dir = sys_get_temp_dir() . '/sg-locktest-' . getmypid();
@mkdir($dir, 0700, true);
$path = $dir . '/scheduler.lock';

$a = fopen($path, 'c');
t_ok(flock($a, LOCK_EX | LOCK_NB), 'the first run takes the lock');

$b = fopen($path, 'c');
t_ok(!flock($b, LOCK_EX | LOCK_NB),
     'and a second, overlapping run cannot — which is the entire point: '
   . 'without this both blocked the same offenders one second apart');
fclose($b);

// Releasing must let the next tick through, or one crash stops the product
// scheduling anything ever again.
fclose($a);
$c = fopen($path, 'c');
t_ok(flock($c, LOCK_EX | LOCK_NB),
     'once the holder exits the next run proceeds — the kernel drops the lock '
   . 'with the process, so a run killed mid-flight leaves nothing stale behind');
fclose($c);
@unlink($path);
@rmdir($dir);
