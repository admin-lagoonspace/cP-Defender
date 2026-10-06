<?php
/**
 * What happens to an infected file, by severity.
 *
 *   high / critical  disable, then delete outright
 *   medium           disable, quarantine, delete after 5 days
 *   low              disable, quarantine, delete after 7 days
 *
 * and nothing stays in quarantine beyond the global retention period whatever
 * its own deadline says.
 *
 * Previously all three call sites did the same thing — "if auto_quarantine is
 * on, quarantine it" — so a webshell and a suspicious comment were treated
 * exactly alike, and quarantine was kept for 30 days.
 *
 * These tests act on real files on disk, because the whole feature is about
 * destroying files and the only assertion worth making is whether the right
 * one is still there afterwards.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$work = $ctx['sandbox'] . '/policy';
@mkdir($work, 0777, true);

Database::setSetting('auto_quarantine', '1');
Database::setSetting('policy_high_action', 'delete');
Database::setSetting('policy_medium_days', '5');
Database::setSetting('policy_low_days', '7');
Database::setSetting('quarantine_retention_days', '7');

$scanner = new Scanner();

/** An infected file plus the threat row that refers to it. */
function mk(string $dir, string $name, string $severity): array {
    $path = $dir . '/' . $name;
    file_put_contents($path, "<?php /* pretend malware */ eval(base64_decode('aGk=')); ");
    $id = Database::insert('threats', [
        'file_path'   => $path,
        'threat_name' => 'Test.' . $severity,
        'threat_type' => 'test',
        'severity'    => $severity,
        'status'      => 'active',
        'detected_at' => time(),
    ]);
    return [$path, $id];
}

// ── The retention periods ───────────────────────────────────────────────────
t_eq(0, Scanner::policyDaysFor('high'),     'high severity is deleted immediately');
t_eq(0, Scanner::policyDaysFor('critical'), 'and so is critical');
t_eq(5, Scanner::policyDaysFor('medium'),   'medium is held for 5 days');
t_eq(7, Scanner::policyDaysFor('low'),      'low is held for 7 days');

// A per-severity deadline must never outlive the global sweep, or it would
// promise a grace period it does not get.
Database::setSetting('quarantine_retention_days', '3');
t_ok(Scanner::policyDaysFor('low') <= 3,
    'a per-severity period is capped by the global retention');
Database::setSetting('quarantine_retention_days', '7');

// ── High severity: gone, with no copy kept ──────────────────────────────────
[$path, $id] = mk($work, 'high.php', 'high');
t_ok(is_file($path), 'the file exists before the policy runs');

$r = $scanner->applyThreatPolicy($path, $id, 'high');
t_eq('deleted', $r['action'], 'a high-severity file is deleted');
t_ok(!is_file($path), 'and is actually gone from disk');

$row = Database::fetchOne('SELECT * FROM threats WHERE id=?', [$id]);
t_eq('deleted', $row['status'], 'the threat is recorded as deleted');
t_eq('delete', $row['action_taken'], 'with the action taken');

// The record is the only thing left, so it has to say what was destroyed.
t_ok(!empty($row['hash']), 'the hash of the destroyed file is kept');
$ev = Database::fetchOne(
    "SELECT * FROM security_events WHERE type='malware_deleted' AND target=?", [$path]);
t_ok($ev !== null, 'and the deletion is raised as a security event');

// Something left behind for whoever owns the site.
t_ok(is_file($path . '.serverscrub_removed'), 'a note is left where the file was');
$note = file_get_contents($path . '.serverscrub_removed');
t_contains($note, 'DELETED', 'saying it was deleted, not quarantined');
t_contains($note, 'SHA-256', 'and recording the hash');
t_contains($note, 'backups', 'and that restoring means going to backups');

// ── Medium: quarantined with a 5-day deadline ───────────────────────────────
[$path, $id] = mk($work, 'medium.php', 'medium');
$r = $scanner->applyThreatPolicy($path, $id, 'medium');
t_eq('quarantined', $r['action'], 'a medium-severity file is quarantined');
t_eq(5, $r['days'], 'for five days');
t_ok(!is_file($path), 'the original is removed from where it was found');

$row = Database::fetchOne('SELECT * FROM threats WHERE id=?', [$id]);
t_eq('quarantined', $row['status'], 'recorded as quarantined');
t_ok(!empty($row['quarantine_path']), 'with the path it was moved to');
t_ok(is_file($row['quarantine_path']), 'and the file is really there');

$expected = time() + (5 * 86400);
t_ok(abs((int) $row['quarantine_expires_at'] - $expected) < 60,
    'and a deadline five days out');

$mediumQ = $row['quarantine_path'];
$mediumId = $id;

// ── Low: quarantined with a 7-day deadline ──────────────────────────────────
[$path, $id] = mk($work, 'low.php', 'low');
$r = $scanner->applyThreatPolicy($path, $id, 'low');
t_eq('quarantined', $r['action'], 'a low-severity file is quarantined');
t_eq(7, $r['days'], 'for seven days');
$row = Database::fetchOne('SELECT * FROM threats WHERE id=?', [$id]);
t_ok(abs((int) $row['quarantine_expires_at'] - (time() + 7 * 86400)) < 60,
    'with a deadline seven days out');
$lowId = $id;

// ── The sweep deletes what has expired, and only that ───────────────────────
// Wind the medium one back past its deadline; the low one still has days left.
Database::query('UPDATE threats SET quarantine_expires_at=? WHERE id=?',
    [time() - 60, $mediumId]);

$sweep = Scanner::sweepQuarantine();
t_ok($sweep['expired'] >= 1, 'the expired file is swept');
t_ok(!is_file($mediumQ), 'and removed from quarantine');
t_eq('deleted', Database::fetchOne('SELECT status FROM threats WHERE id=?', [$mediumId])['status'],
    'its threat record is closed as deleted');
t_eq('expired', Database::fetchOne('SELECT action_taken FROM threats WHERE id=?', [$mediumId])['action_taken'],
    'and says the deadline is why');

$lowRow = Database::fetchOne('SELECT * FROM threats WHERE id=?', [$lowId]);
t_eq('quarantined', $lowRow['status'], 'a file still within its period is left alone');
t_ok(is_file($lowRow['quarantine_path']), 'and stays in quarantine');

// ── The backstop: anything older than retention, deadline or not ────────────
// Files quarantined before deadlines existed have no expiry recorded. Without
// an age-based rule they would stay for ever, which is the backlog an existing
// install arrives with.
$qdir = Database::storagePath('quarantine') . '/' . date('Y-m-d');
@mkdir($qdir, 0777, true);
$old = $qdir . '/ancient_legacy.quarantine';
file_put_contents($old, 'old infected file with no expiry recorded');
@touch($old, time() - (30 * 86400));
t_ok(is_file($old), 'a legacy quarantined file with no deadline exists');

$sweep = Scanner::sweepQuarantine();
t_ok(!is_file($old),
    'and is removed by age, which is what clears an existing backlog');

// A file inside the retention window is not touched by the backstop.
$fresh = $qdir . '/recent.quarantine';
file_put_contents($fresh, 'quarantined today');
Scanner::sweepQuarantine();
t_ok(is_file($fresh), 'a recently quarantined file is kept');

// ── Disabling the file ──────────────────────────────────────────────────────
// Between detection and the move the file is still executable by the web
// server. Removing every permission bit closes that window.
$d = $work . '/perm.php';
file_put_contents($d, 'x');
@chmod($d, 0644);
// The exact bits are not asserted: Windows does not honour POSIX modes, so
// 0644 comes back as 0666 here. What matters is that a mode is captured and
// that restoring returns the file to it.
$before = @fileperms($d) & 0777;
$mode = Scanner::disableFile($d);
t_eq($before, $mode, 'the previous mode is returned so it can be restored');

// A failure after disabling must not leave the file unreadable AND infected.
Scanner::restoreMode($d, $mode);
t_eq($before, @fileperms($d) & 0777, 'and restoring puts it back');

// ── Switched off means nothing is touched ───────────────────────────────────
Database::setSetting('auto_quarantine', '0');
[$path, $id] = mk($work, 'untouched.php', 'high');
$r = $scanner->applyThreatPolicy($path, $id, 'high');
t_eq('none', $r['action'], 'with auto-quarantine off, nothing is deleted');
t_ok(is_file($path), 'and the file is left exactly where it was');
Database::setSetting('auto_quarantine', '1');

// ── High severity can be given the same grace as the rest ───────────────────
// Deleting with no copy is irreversible, so an operator must be able to turn
// it off without turning off protection.
Database::setSetting('policy_high_action', 'quarantine');
t_ok(Scanner::policyDaysFor('high') > 0,
    'policy_high_action=quarantine stops high severity being deleted outright');
[$path, $id] = mk($work, 'high2.php', 'high');
$r = $scanner->applyThreatPolicy($path, $id, 'high');
t_eq('quarantined', $r['action'], 'and it is quarantined instead');
Database::setSetting('policy_high_action', 'delete');

// ── Every detection path uses the policy ────────────────────────────────────
// There were three copies of "if auto_quarantine is on, quarantine it", which
// is how a webshell and a suspicious comment came to be treated alike.
$sc = t_code($repo . '/backend/lib/Scanner.php');
t_eq(3, substr_count($sc, '$this->applyThreatPolicy('),
    'all three detection paths apply the policy');
t_ok(strpos($sc, "Database::setting('auto_quarantine') === '1'") === false,
    'and none of them still quarantines regardless of severity');

// ── Retention ships at 7 days, and upgrades move to it ──────────────────────
$db = t_code($repo . '/backend/lib/Database.php');
t_contains($db, "('quarantine_retention_days', '7')", 'quarantine is kept for 7 days');
t_contains($db, 'sg_mig_quarantine_7d',
    'and an existing install is migrated off the old 30-day retention');
t_contains($db, "CAST(value AS INTEGER) > 7",
    'only shortening it, never extending a deliberately shorter setting');

$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, 'Scanner::sweepQuarantine()', 'the sweep runs on a schedule');
