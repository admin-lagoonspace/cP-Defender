<?php
/**
 * The database does not quietly fall apart.
 *
 * Written after a live server answered every command with
 *
 *     SQLSTATE[HY000]: General error: 11 database disk image is malformed
 *
 * and `PRAGMA integrity_check` reported a miscounted freelist, a page
 * referenced twice, and a wrong entry count in `idx_bfa_ip` — the index on
 * `brute_force_attempts`, the highest-write-rate table in the product, fed by
 * every failed SSH, cPanel, mail and FTP login across 132 accounts.
 *
 * Nothing here can prove what corrupted it. What it can do is close the two
 * defects standing nearest to it and make the next one visible before it is
 * discovered by a command failing in somebody's hands.
 *
 *   NO BUSY TIMEOUT on the PHP side, while the Python monitor had ten
 *   seconds. Six writers share the file and the PHP ones gave up instantly
 *   on a held lock — every one a lost write that nothing retried.
 *
 *   MIGRATIONS THAT WERE NOT ATOMIC. Check marker, do work, write marker:
 *   three statements, no transaction, running on EVERY connection. Three
 *   processes opening the database in the same window each found no marker
 *   and each rewrote 148,551 rows.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The connection waits for a lock instead of failing ─────────────────────
$busy = (int) Database::get()->query('PRAGMA busy_timeout')->fetchColumn();
t_ok($busy >= 10000,
     'BUSY TIMEOUT IS SET: it was absent entirely on the PHP side while the '
   . 'monitor daemon set 10s, so a PHP writer meeting a held lock failed '
   . 'instantly rather than waiting the milliseconds the other writer needed');

$mon = (string) file_get_contents($repo . '/backend/daemon/monitor.py');
t_contains($mon, 'busy_timeout=10000',
     'and the daemon still agrees with it — one number, not two');

$wal = (int) Database::get()->query('PRAGMA wal_autocheckpoint')->fetchColumn();
t_ok($wal > 0 && $wal <= 4000,
     'the WAL is bounded: a mass UPDATE over 148,551 rows grows it without '
   . 'limit until something checkpoints, and an unbounded WAL on a server '
   . 'short of disk is one of the few ways SQLite genuinely corrupts');

// ── integrity_check is available to the product, not just to a human ───────
$r = Database::integrityCheck();
t_ok(is_array($r) && array_key_exists('ok', $r), 'the integrity check returns a verdict');
t_eq(true, $r['ok'], 'and a freshly built database passes it');
t_eq([], $r['problems'], 'with nothing to report');

$src = (string) file_get_contents($repo . '/backend/lib/Database.php');
$ic  = t_fn_body($src, 'integrityCheck', 'php');
t_contains($ic, 'catch (Throwable $e)',
     'THE CHECK FAILING IS THE FINDING: on the corrupted server the PRAGMA '
   . 'itself threw. Letting that exception escape would turn the one tool '
   . 'that detects the problem into another victim of it');
t_contains($ic, "'ok' => false",
     'and it is reported as a failure rather than as no problems found');

// ── A one-time migration runs once, and atomically ─────────────────────────
$once = t_fn_body($src, 'once', 'php');

t_contains($once, 'BEGIN IMMEDIATE',
     'the write lock is taken UP FRONT — a plain BEGIN discovers the conflict '
   . 'at COMMIT, when the work is done and has to be thrown away');
t_contains($once, "\$ins->execute([\$marker]);",
     'and the marker is written inside the same transaction as the work');

// The order is what makes it safe: work, then marker, then commit. Both land
// or neither does.
$posWork   = strpos($once, '$work($db);');
$posMarker = strpos($once, '$ins->execute');
$posCommit = strpos($once, "\$db->exec('COMMIT');", $posWork === false ? 0 : $posWork);
t_ok($posWork !== false && $posMarker > $posWork && $posCommit > $posMarker,
     'ATOMIC: work, marker, commit — a crash midway leaves the marker absent '
   . 'and the work undone, which is the right way round because it simply '
   . 'runs again next time');

t_contains($once, 'ROLLBACK',
     'a failed migration is rolled back rather than left half-applied');
t_ok(substr_count($once, '$st->execute([$marker]);') >= 2,
     'THE DOUBLE CHECK: the marker is tested again INSIDE the lock. Testing '
   . 'it only before is exactly the old bug — three processes opening the '
   . 'database in the same window all found no marker and all did the work');
t_contains($once, 'error_log',
     'and a migration that cannot run is logged rather than thrown — one '
   . 'bad migration must not stop the product starting');

// Every one-time migration goes through it. A new one written in the old
// shape would reintroduce the whole problem.
t_ok(!preg_match("/INSERT OR REPLACE INTO settings \(key, value\)\s*\n\s*VALUES \('(?:waf_action_honesty|scan_backup_gate)/", $src),
     'no migration still writes its own marker outside a transaction');
t_ok(substr_count($src, 'self::once($db,') >= 2,
     'and the existing ones were converted, not just the helper added');

// ── Reachable from the shell ───────────────────────────────────────────────
$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, "case 'db-check'",
     'an operator can run the check without opening the panel — which on the '
   . 'server that prompted this was not opening either');
t_contains($cli, 'Database::integrityCheck',
     'through the same implementation the scheduler uses');

// ── And it runs on its own ─────────────────────────────────────────────────
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "'dbcheck' => [",
     'NIGHTLY: the first anyone knew of the corruption was a command failing '
   . 'in their hands. Silent damage has to become something the product says');
t_contains($sched, "'type'        => 'database_corruption'",
     'and it raises a security event, so it appears where an operator looks');
t_contains($sched, "'severity'    => 'critical'",
     'at the severity a damaged database warrants');
