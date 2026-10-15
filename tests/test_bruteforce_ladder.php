<?php
/**
 * Escalating blocks for repeat offenders.
 *
 * Reported from a live server, and the screenshot was damning: a brute-force
 * page listing dozens of addresses, one with 234 failed attempts and another
 * with 266, every single row marked "Watching". Nothing was blocked.
 *
 * Three separate faults produced that, and each is pinned here.
 *
 *   1. Firewall::blockIP has always WRITTEN expires_at, and until 4.2.0
 *      nothing anywhere read it. Every temporary block was permanent at the
 *      firewall while the database reported a deadline -- the worse of the two
 *      failure modes, since an operator who believes a block is temporary does
 *      not go looking for the customer it is quietly holding out.
 *
 *   2. evaluate() blocked only when the address had never been blocked, and
 *      nothing ever cleared that flag. One block per address, for ever.
 *
 *   3. prune() deleted released offenders on the attempts clock, taking the
 *      strike count with them, so the ladder reset every week.
 *
 * The policy: more than four failures earns three hours, then six, then
 * twenty-four, then permanent.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

BruteForce::ensureSchema();

// A firewall that always succeeds.
//
// The sandbox has no iptables, so detect() returns 'none' and every block
// fails -- which is why the original brute-force test simply turned
// auto-blocking off and never exercised a block at all. That is exactly the
// path the live server runs, so it is the path worth testing. setRunner() is
// the engine's existing seam; the backend is pinned so detection does not go
// looking for a binary that is not there.
$fwCalls = [];
$ref = new ReflectionClass('FirewallEngine');
$bp  = $ref->getProperty('backend');
$bp->setValue(null, 'iptables');
FirewallEngine::setRunner(function ($cmd) use (&$fwCalls) {
    $fwCalls[] = $cmd;
    // 'iptables -C' asks whether a rule is already there; answering yes would
    // short-circuit the block as 'already'. Answer no.
    if (strpos($cmd, '-C ') !== false) { return ['out' => '', 'code' => 1]; }
    return ['out' => '', 'code' => 0];
});

// -- The ladder itself -------------------------------------------------------
t_eq([10800, 21600, 86400, 0], BruteForce::ladder(),
    'the ladder is 3h, 6h, 24h, then permanent');

t_eq(10800, BruteForce::termFor(1), 'a first offence costs three hours');
t_eq(21600, BruteForce::termFor(2), 'a second costs six');
t_eq(86400, BruteForce::termFor(3), 'a third costs a day');
t_eq(0,     BruteForce::termFor(4), 'a fourth is permanent');
t_eq(0,     BruteForce::termFor(9), 'and so is everything after it');

// An operator who removes the permanent rung must not have one reinstated
// silently -- never blocking permanently is a legitimate policy.
Database::setSetting('bf_ladder', '3600,7200');
t_eq(7200, BruteForce::termFor(5),
    'a ladder with no permanent rung repeats its last term rather than becoming permanent');
Database::setSetting('bf_ladder', '10800,21600,86400,0');

// -- Threshold: more than four failures --------------------------------------
t_eq(5, BruteForce::threshold(), 'five failures in the window is an attack');

// -- Walking one address up the whole ladder ---------------------------------
Database::query('DELETE FROM brute_force_attempts');
Database::query('DELETE FROM brute_force_offenders');
Database::query('DELETE FROM blocked_ips');
Database::setSetting('bf_auto_block', '1');

$ip = '198.51.100.77';

$attack = function () use ($ip) {
    for ($i = 0; $i < 6; $i++) {
        Database::insert('brute_force_attempts', [
            'ip_address' => $ip, 'service' => 'ssh',
            'username' => 'root', 'attempted_at' => time(),
        ]);
    }
};

// Pretend the clock has moved past the current term.
$serveTerm = function () use ($ip) {
    Database::query('UPDATE brute_force_offenders SET blocked_until=? WHERE ip_address=?',
        [time() - 10, $ip]);
    Database::query('UPDATE blocked_ips SET expires_at=? WHERE ip_address=?',
        [time() - 10, $ip]);
};

$state = function () use ($ip) {
    return Database::fetchOne('SELECT * FROM brute_force_offenders WHERE ip_address=?', [$ip]);
};

// -- Offence 1 ---------------------------------------------------------------
$attack();
$r = BruteForce::evaluate();
t_eq(1, $r['blocked'], 'the first attack is blocked, not watched');

$o = $state();
t_eq(1, (int) $o['blocked'],  'the address is marked blocked');
t_eq(1, (int) $o['offences'], 'and carries one strike');
$left = (int) $o['blocked_until'] - time();
t_ok($left > 10700 && $left <= 10800, "the term is three hours ({$left}s)");

$b = Database::fetchOne('SELECT * FROM blocked_ips WHERE ip_address=?', [$ip]);
t_ok($b !== null, 'a firewall block was recorded');
t_eq(0, (int) $b['permanent'], 'and it is not permanent');

// Evaluating again while the term runs must not re-block or re-strike.
$attack();
$r = BruteForce::evaluate();
t_eq(0, $r['blocked'], 'an address already serving a term is not blocked again');
t_eq(1, (int) $state()['offences'], 'and does not accrue a second strike for the same offence');

// -- The term is served, and the block actually lifts ------------------------
$serveTerm();
$rel = BruteForce::releaseExpired();
t_eq(1, $rel['released'], 'the term ends and the address is released');

$o = $state();
t_eq(0, (int) $o['blocked'], 'it is no longer blocked');
t_eq(1, (int) $o['offences'], 'but the strike is remembered -- that is the ladder');
t_eq(0, (int) Database::fetchOne(
        'SELECT COUNT(*) c FROM brute_force_attempts WHERE ip_address=?', [$ip])['c'],
    'and its served attempts are discarded, so it is not re-blocked on evidence '
  . 'it has already been punished for');

$r = BruteForce::evaluate();
t_eq(0, $r['blocked'], 'a just-released address is not immediately re-blocked');

// -- Offence 2 ---------------------------------------------------------------
$attack();
$r = BruteForce::evaluate();
t_eq(1, $r['blocked'], 'coming back earns another block');
$o = $state();
t_eq(2, (int) $o['offences'], 'now on its second strike');
$left = (int) $o['blocked_until'] - time();
t_ok($left > 21500 && $left <= 21600, "the second term is six hours ({$left}s)");

// -- Offence 3 ---------------------------------------------------------------
$serveTerm(); BruteForce::releaseExpired();
$attack(); BruteForce::evaluate();
$o = $state();
t_eq(3, (int) $o['offences'], 'third strike');
$left = (int) $o['blocked_until'] - time();
t_ok($left > 86300 && $left <= 86400, "the third term is twenty-four hours ({$left}s)");

// -- Offence 4: permanent ----------------------------------------------------
$serveTerm(); BruteForce::releaseExpired();
$attack(); BruteForce::evaluate();
$o = $state();
t_eq(4, (int) $o['offences'], 'fourth strike');
t_eq(1, (int) $o['blocked'], 'blocked');
t_eq(null, $o['blocked_until'], 'with no deadline, which is what permanent means here');

$b = Database::fetchOne('SELECT * FROM blocked_ips WHERE ip_address=?', [$ip]);
t_eq(1, (int) $b['permanent'], 'and the firewall block is permanent');
t_eq(null, $b['expires_at'], 'with no expiry for the sweep to find');

Firewall::expireBlocks();
t_eq(1, (int) Database::fetchOne(
        'SELECT blocked c FROM brute_force_offenders WHERE ip_address=?', [$ip])['c'],
    'a permanent block is never lifted by the expiry sweep');

// -- Expired blocks are actually released at the firewall --------------------
// Fault 1, pinned directly.
Database::query('DELETE FROM blocked_ips');
$fw = new Firewall();
$fw->blockIP('203.0.113.9', 'test', false, 3600);
Database::query('UPDATE blocked_ips SET expires_at=? WHERE ip_address=?',
    [time() - 60, '203.0.113.9']);
$fw->blockIP('203.0.113.10', 'test permanent', true, 86400);

$res = Firewall::expireBlocks();
t_eq(1, $res['released'], 'an expired block is released');
t_eq(null, Database::fetchOne('SELECT id FROM blocked_ips WHERE ip_address=?', ['203.0.113.9']),
    'and the row goes with it');
t_ok(Database::fetchOne('SELECT id FROM blocked_ips WHERE ip_address=?', ['203.0.113.10']) !== null,
    'a permanent block is left alone');

// -- The strike count outlives the attempts ----------------------------------
// Fault 3. Attempts are evidence and expire in a week; strikes are history.
Database::query('DELETE FROM brute_force_offenders');
Database::setSetting('bf_retention_days', '7');
Database::setSetting('bf_offence_memory_days', '30');

$old = time() - (10 * 86400);        // past the attempts window, inside memory
Database::query(
    'INSERT INTO brute_force_offenders
        (ip_address, service, attempts, first_seen, last_seen, blocked, offences)
     VALUES (?,?,?,?,?,?,?)',
    ['192.0.2.50', 'ssh', 9, $old, $old, 0, 2]);
Database::query(
    'INSERT INTO brute_force_offenders
        (ip_address, service, attempts, first_seen, last_seen, blocked, offences)
     VALUES (?,?,?,?,?,?,?)',
    ['192.0.2.51', 'ssh', 9, $old, $old, 0, 0]);

BruteForce::prune();

t_ok(Database::fetchOne('SELECT ip_address FROM brute_force_offenders WHERE ip_address=?',
        ['192.0.2.50']) !== null,
    'an address with a strike keeps it well past the attempts retention period, '
  . 'or an attacker returning every eighth day never escalates');
t_eq(null, Database::fetchOne('SELECT ip_address FROM brute_force_offenders WHERE ip_address=?',
        ['192.0.2.51']),
    'one that never offended is still pruned on the ordinary clock');

// -- A manual release is the operator vouching for the address ---------------
Database::query('DELETE FROM brute_force_offenders');
Database::query(
    'INSERT INTO brute_force_offenders
        (ip_address, service, attempts, first_seen, last_seen, blocked, offences)
     VALUES (?,?,?,?,?,?,?)',
    ['192.0.2.60', 'ssh', 9, time(), time(), 1, 3]);
BruteForce::release('192.0.2.60');
t_eq(null, Database::fetchOne('SELECT ip_address FROM brute_force_offenders WHERE ip_address=?',
        ['192.0.2.60']),
    'a manual release clears the strike count -- the operator is saying this is not an attacker');

// -- Addresses that must never be blocked, however they behave ---------------
Database::query('DELETE FROM brute_force_attempts');
Database::query('DELETE FROM brute_force_offenders');
foreach (['127.0.0.1', '10.0.0.5', '192.168.1.20'] as $safe) {
    for ($i = 0; $i < 20; $i++) {
        Database::insert('brute_force_attempts', [
            'ip_address' => $safe, 'service' => 'ssh',
            'username' => 'root', 'attempted_at' => time(),
        ]);
    }
}
$r = BruteForce::evaluate();
t_eq(0, $r['blocked'],
    'loopback and private addresses are never blocked, whatever the ladder says -- '
  . 'locking the admin out of the box while defending it is not a trade worth making');
t_ok($r['skipped'] >= 3, 'and they are reported as skipped rather than silently ignored');

// -- The sweep runs on a schedule --------------------------------------------
// A ladder nothing advances is a ladder that does not exist.
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, 'Firewall::expireBlocks()', 'expired blocks are swept on a schedule');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/Firewall.php'",
    'and the scheduler requires Firewall, or the task fatals in cron');

$bf  = t_code($repo . '/backend/lib/BruteForce.php');
$run = substr($bf, strpos($bf, 'function run()'), 900);
$relPos  = strpos($run, 'releaseExpired()');
$evalPos = strpos($run, 'self::evaluate()');
t_ok($relPos !== false && $evalPos !== false && $relPos < $evalPos,
    'terms are released BEFORE evaluating, or a returning address is judged against '
  . 'a block it has already served and never climbs the ladder');

// -- What the operator sees --------------------------------------------------
Database::query('DELETE FROM brute_force_offenders');
Database::query(
    'INSERT INTO brute_force_offenders
        (ip_address, service, attempts, first_seen, last_seen, blocked, offences, blocked_until)
     VALUES (?,?,?,?,?,?,?,?)',
    ['192.0.2.70', 'ssh', 9, time(), time(), 1, 1, time() + 7200]);
Database::query(
    'INSERT INTO brute_force_offenders
        (ip_address, service, attempts, first_seen, last_seen, blocked, offences)
     VALUES (?,?,?,?,?,?,?)',
    ['192.0.2.71', 'ssh', 3, time(), time(), 0, 1]);

$rows = [];
foreach (BruteForce::offenders(50) as $row) { $rows[$row['ip_address']] = $row; }

t_eq('blocked', $rows['192.0.2.70']['state'], 'a serving address reports as blocked');
t_ok($rows['192.0.2.70']['expires_in'] > 7100, 'with the time left on its term');
t_eq('watching', $rows['192.0.2.71']['state'], 'a released one reports as watching');
t_eq('6h', $rows['192.0.2.71']['next_term'],
    'and says what its next offence will cost, so the policy is visible from the list');

$js = file_get_contents($repo . '/frontend/js/app.js');
t_contains($js, 'function bfStatusBadge', 'the table renders a real status');
t_contains($js, 'next_term', 'showing what the next offence costs');
t_ok(strpos($js, "badge-red\">Blocked</span>'\n                : '<span") === false,
    'the old two-state badge is gone');

$stats = BruteForce::stats();
t_eq(['3h', '6h', '24h', 'permanent'], $stats['ladder'],
    'the ladder is reported in terms an operator reads');

// The seam is released, or a later test in the same process inherits it.
FirewallEngine::setRunner(null);
$bp->setValue(null, null);

// The blocks really did reach the firewall rather than only the database.
$blockCmds = array_filter($fwCalls, function ($c) { return strpos($c, '-I ') !== false; });
t_ok(count($blockCmds) >= 4,
    'each rung of the ladder issued a real firewall command, not just a database row');
