<?php
/**
 * Quarantine must not be scanned, and the log must not outlive the files.
 *
 * Reported from a live server: the scanner showed 200 threats, every one of
 * them 16 days old, every one a file inside the quarantine directory, with the
 * account column showing the install directory rather than a customer.
 *
 * Two separate faults produced that:
 *
 *   1. Quarantined files ARE malware, and the walk had nothing to stop it
 *      entering the quarantine directory. The operator had moved quarantine to
 *      /home/.serverscrub/quarantine -- sensible, since /home has the space --
 *      which put it directly inside the default scan path. Every scan then
 *      re-detected every file it had already caught, wrote a fresh threat for
 *      each, and quarantined the quarantined file.
 *
 *   2. pruneQuarantine() deleted files by age and never touched the database,
 *      so rows kept reporting "Quarantined" for files removed days earlier,
 *      and threat records were never pruned at all.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$scanner = new Scanner();
$walk = new ReflectionMethod('Scanner', 'walkFiles');
$walk->setAccessible(true);

// ── The quarantine directory is not walked ──────────────────────────────────
// Arranged exactly as the reporting server had it: quarantine inside the tree
// being scanned.
$root = $ctx['sandbox'] . '/home';
@mkdir($root . '/site/public_html', 0777, true);
file_put_contents($root . '/site/public_html/index.php', '<?php echo 1;');

$quar = $root . '/.serverscrub/quarantine/2026-09-27';
@mkdir($quar, 0777, true);
file_put_contents($quar . '/evil.php_12.quarantine', '<?php eval(base64_decode("aGk="));');

Database::setSetting('quarantine_dir', $root . '/.serverscrub/quarantine');

$found = [];
foreach ($walk->invoke($scanner, $root) as $f) { $found[] = str_replace('\\', '/', $f); }

$sawSite = false; $sawQuar = false;
foreach ($found as $f) {
    if (strpos($f, 'public_html/index.php') !== false) { $sawSite = true; }
    if (strpos($f, '/quarantine/') !== false)          { $sawQuar = true; }
}
t_ok($sawSite, 'ordinary site files are still scanned');
t_ok(!$sawQuar,
    'the quarantine directory is skipped, so quarantined malware is not found again');

// The directory rule must hold on its own. A file inside quarantine that is
// NOT named .quarantine would still be re-detected if only the filename guard
// were doing the work.
file_put_contents($quar . '/plain_name.php', '<?php eval(base64_decode("aGk="));');
$found1b = [];
foreach ($walk->invoke($scanner, $root) as $f) { $found1b[] = str_replace(chr(92), '/', $f); }
$sawPlainInQuar = false;
foreach ($found1b as $f) {
    if (strpos($f, '/quarantine/') !== false && strpos($f, 'plain_name.php') !== false) {
        $sawPlainInQuar = true;
    }
}
t_ok(!$sawPlainInQuar,
    'a normally-named file inside quarantine is skipped too, so the directory '
  . 'rule is doing the work rather than the filename');

// A .quarantine file that has been moved elsewhere is ours too.
file_put_contents($root . '/site/stray_9.quarantine', 'x');
$found2 = [];
foreach ($walk->invoke($scanner, $root) as $f) { $found2[] = str_replace('\\', '/', $f); }
$sawStray = false;
foreach ($found2 as $f) { if (strpos($f, 'stray_9.quarantine') !== false) { $sawStray = true; } }
t_ok(!$sawStray, 'a stray .quarantine file is skipped wherever it sits');

// ── The log stops saying "Quarantined" once the file is gone ────────────────
Database::query('DELETE FROM threats');

$gonePath = $ctx['sandbox'] . '/no-such-quarantine-file.quarantine';
$idGone = Database::insert('threats', [
    'file_path'   => '/home/site/evil.php',
    'threat_name' => 'Test.Gone',
    'threat_type' => 'malware',
    'severity'    => 'medium',
    'status'      => 'quarantined',
    'detected_at' => time() - (16 * 86400),
]);
Database::query('UPDATE threats SET quarantine_path=?, quarantine_expires_at=? WHERE id=?',
    [$gonePath, time() + 86400, $idGone]);   // not expired, but the file is gone

// One whose file is genuinely still there.
$keepDir = $ctx['sandbox'] . '/keepq';
@mkdir($keepDir, 0777, true);
$keepPath = $keepDir . '/still_here.quarantine';
file_put_contents($keepPath, 'x');
$idKeep = Database::insert('threats', [
    'file_path'   => '/home/site/other.php',
    'threat_name' => 'Test.Here',
    'threat_type' => 'malware',
    'severity'    => 'low',
    'status'      => 'quarantined',
    'detected_at' => time() - 3600,
]);
Database::query('UPDATE threats SET quarantine_path=?, quarantine_expires_at=? WHERE id=?',
    [$keepPath, time() + (7 * 86400), $idKeep]);

Database::setSetting('threat_retention_days', '365');   // isolate reconciliation
Scanner::sweepQuarantine();

t_eq('deleted',
    Database::fetchOne('SELECT status FROM threats WHERE id=?', [$idGone])['status'],
    'a row whose quarantined file has gone no longer claims to be quarantined');
t_eq('expired',
    Database::fetchOne('SELECT action_taken FROM threats WHERE id=?', [$idGone])['action_taken'],
    'and records why');
t_eq('quarantined',
    Database::fetchOne('SELECT status FROM threats WHERE id=?', [$idKeep])['status'],
    'a row whose file is still there is left alone');

// ── Rows written before deadlines existed get one ───────────────────────────
Database::query('DELETE FROM threats');
$idOld = Database::insert('threats', [
    'file_path'   => '/home/site/legacy.php',
    'threat_name' => 'Test.Legacy',
    'threat_type' => 'malware',
    'severity'    => 'medium',
    'status'      => 'quarantined',
    'detected_at' => time() - (16 * 86400),
]);
// Deliberately no quarantine_expires_at, as every pre-3.37.0 row has.
t_eq(null, Database::fetchOne(
    'SELECT quarantine_expires_at FROM threats WHERE id=?', [$idOld])['quarantine_expires_at'],
    'the legacy row starts with no deadline');

Scanner::sweepQuarantine();
$after = Database::fetchOne('SELECT * FROM threats WHERE id=?', [$idOld]);
t_ok($after === null || (int) ($after['quarantine_expires_at'] ?? 0) > 0,
    'it is given one derived from when it was detected, so the policy applies');

// ── Dealt-with records are retired; active ones are not ─────────────────────
Database::query('DELETE FROM threats');
Database::setSetting('threat_retention_days', '7');

$idStale = Database::insert('threats', [
    'file_path' => '/home/a.php', 'threat_name' => 'Old', 'threat_type' => 'malware',
    'severity' => 'low', 'status' => 'deleted', 'detected_at' => time() - (16 * 86400),
]);
Database::query('UPDATE threats SET resolved_at=? WHERE id=?',
    [time() - (16 * 86400), $idStale]);

$idActive = Database::insert('threats', [
    'file_path' => '/home/b.php', 'threat_name' => 'Unresolved', 'threat_type' => 'malware',
    'severity' => 'high', 'status' => 'active', 'detected_at' => time() - (40 * 86400),
]);

$idRecent = Database::insert('threats', [
    'file_path' => '/home/c.php', 'threat_name' => 'Recent', 'threat_type' => 'malware',
    'severity' => 'low', 'status' => 'deleted', 'detected_at' => time() - 3600,
]);
Database::query('UPDATE threats SET resolved_at=? WHERE id=?', [time() - 3600, $idRecent]);

Scanner::sweepQuarantine();

t_eq(null, Database::fetchOne('SELECT id FROM threats WHERE id=?', [$idStale]),
    'a resolved record past the retention window is retired');
t_ok(Database::fetchOne('SELECT id FROM threats WHERE id=?', [$idActive]) !== null,
    'an ACTIVE threat is kept however old it is — that is what the log is for');
t_ok(Database::fetchOne('SELECT id FROM threats WHERE id=?', [$idRecent]) !== null,
    'and a recently resolved one is kept');

// ── Ordering: newest first ──────────────────────────────────────────────────
// Asked directly, and worth pinning: a log that silently reversed would be
// read upside down without anyone noticing.
$api = t_code($repo . '/backend/api/index.php');
t_contains($api, 'FROM threats $sqlWhere ORDER BY detected_at DESC',
    'the threat list is newest first');

$db = t_code($repo . '/backend/lib/Database.php');
t_contains($db, "'threat_retention_days',   '7'", 'resolved records are kept for 7 days');
