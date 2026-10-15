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


// ── Our own folders are skipped by name, not only by configured path ────────
// The resolved-path check is the precise one, but it trusts quarantine_dir to
// still point where the files are. On the reporting server the setting said
// /home/.sentinel-gate/quarantine while the product had been renamed, and a
// setting left behind is exactly when the path check stops protecting
// anything. The names cost nothing to skip: they are ours.
Database::setSetting('quarantine_dir', $ctx['sandbox'] . '/somewhere-else');

$legacy = $root . '/.sentinel-gate/quarantine/2026-09-27';
@mkdir($legacy, 0777, true);
file_put_contents($legacy . '/old_one.php', '<?php eval(base64_decode("aGk="));');

$modern = $root . '/.serverscrub/cache';
@mkdir($modern, 0777, true);
file_put_contents($modern . '/temp.php', '<?php echo 1;');

$found3 = [];
foreach ($walk->invoke($scanner, $root) as $f) { $found3[] = str_replace(chr(92), '/', $f); }

$sawLegacy = false; $sawModern = false;
foreach ($found3 as $f) {
    if (strpos($f, '.sentinel-gate') !== false) { $sawLegacy = true; }
    if (strpos($f, '.serverscrub')   !== false) { $sawModern = true; }
}
t_ok(!$sawLegacy,
    'the legacy .sentinel-gate directory is skipped even when quarantine_dir points elsewhere');
t_ok(!$sawModern, 'and the current .serverscrub directory');

// Customer files are still scanned -- the skip must be our folders, not a
// blanket rule on dot-directories.
$dotCustomer = $root . '/site/.well-known';
@mkdir($dotCustomer, 0777, true);
file_put_contents($dotCustomer . '/acme.php', '<?php echo 1;');
$found4 = [];
foreach ($walk->invoke($scanner, $root) as $f) { $found4[] = str_replace(chr(92), '/', $f); }
$sawCustomerDot = false;
foreach ($found4 as $f) { if (strpos($f, '.well-known/acme.php') !== false) { $sawCustomerDot = true; } }
t_ok($sawCustomerDot, 'a customer dot-directory is still scanned');

$sc = t_code($repo . '/backend/lib/Scanner.php');
t_contains($sc, "'.serverscrub', '.sentinel-gate'",
    'both our directory names are in the skip list');

// ── The sweep is runnable on demand ─────────────────────────────────────────
// It only ran from the nightly scheduler, so a backlog could not be cleared
// without waiting -- and `quarantine prune` deletes files without touching the
// records, which is why running that left the log untouched.
$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, "case 'sweep':", 'there is a CLI for the full sweep');
t_contains($cli, 'Scanner::sweepQuarantine()', 'which runs it');
t_contains($cli, 'Records reconciled', 'and reports what it reconciled');


// ── Quarantine directories the product used to use ──────────────────────────
// The default quarantine path is derived from the product name, so the rename
// changed where the product LOOKED without moving one file. The reporting
// server showed `files: 0` at /home/.serverscrub/quarantine while holding two
// hundred files at /home/.sentinel-gate/quarantine. The sweep follows each
// row's recorded path and so still expires those, but a file whose record has
// been retired has nothing left to find it, and pruneQuarantine walked only
// the configured directory -- so the old location leaked for ever.
Database::query('DELETE FROM threats');

$legacyQ = $ctx['sandbox'] . '/legacy-vol/.sentinel-gate/quarantine/2026-09-27';
@mkdir($legacyQ, 0777, true);

$oldFile  = $legacyQ . '/orphan_7.quarantine';          // ours, and ancient
$newFile  = $legacyQ . '/fresh_8.quarantine';           // ours, but recent
$notOurs  = $legacyQ . '/operator-notes.txt';           // not ours at all
file_put_contents($oldFile, 'x');
file_put_contents($newFile, 'x');
file_put_contents($notOurs, 'keep me');
touch($oldFile, time() - (30 * 86400));
touch($notOurs, time() - (30 * 86400));                 // old, but still not ours

$activeQ = $ctx['sandbox'] . '/active-quarantine';
@mkdir($activeQ, 0777, true);
Database::setSetting('quarantine_dir', $activeQ);

// The helper must find it by name without being told, and must never return
// the live directory -- pruning that twice would double-count.
$found = array_map(function ($p) { return str_replace(chr(92), '/', $p); },
    Scanner::legacyQuarantineDirs());

// The sandbox volume is not one of the real system candidates, so point the
// search at it the way a real server's layout does: via the candidate list.
// Here we assert the invariants that hold regardless of layout.
$activeReal = str_replace(chr(92), '/', realpath($activeQ));
t_ok(!in_array($activeReal, $found, true),
    'the live quarantine directory is never reported as a previous one');
t_eq(count($found), count(array_unique($found)),
    'previous locations are de-duplicated by resolved path');
// Asserted once rather than per directory: how many candidates exist depends
// on the machine, and a loop of assertions made the suite's own count drift
// between runs, which is the kind of noise that hides a real regression.
$allExist = true;
foreach ($found as $d) { if (!is_dir($d)) { $allExist = false; } }
t_ok($allExist, 'every reported previous location exists on disk');

// ── The prune reaches them, and only takes what is ours ─────────────────────
// Driven directly, since the candidate list is absolute system paths.
$prune = new ReflectionMethod('Scanner', 'pruneQuarantine');
$legacyFn = new ReflectionMethod('Scanner', 'legacyQuarantineDirs');
t_ok($legacyFn->isPublic(), 'legacyQuarantineDirs is callable by the CLI');

// Simulate the real arrangement: make the legacy tree the one the product
// would find, by making it the configured dir's predecessor.
$sc = t_code($repo . '/backend/lib/Scanner.php');
$pq = substr($sc, strpos($sc, 'function pruneQuarantine'), 3000);
t_contains($pq, 'self::legacyQuarantineDirs()',
    'pruneQuarantine also walks directories quarantine used to live in');
t_contains($pq, "substr(\$entry->getFilename(), -11) !== '.quarantine'",
    'and in those it removes only files it can name as ours');
t_contains($pq, 'legacy_removed', 'reporting how many came from an old location');

$lq = substr($sc, strpos($sc, 'function legacyQuarantineDirs'), 1600);
t_contains($lq, "'.sentinel-gate'", 'the pre-rename name is among the candidates');
t_contains($lq, "'/usr/local/sentinel-gate/quarantine'",
    'as is the pre-rename install directory');
t_contains($lq, '$real === $active', 'and the live directory is excluded');

// ── Behaviour: the old location is actually swept ───────────────────────────
// Driven through a real candidate rather than asserted structurally.
// SG_ROOT . '/quarantine' is the pre-3.x default and is in the candidate list,
// so creating it while quarantine_dir points elsewhere reproduces exactly the
// reporting server's shape: files in a directory the product no longer uses.
$rootQ = SG_ROOT . '/quarantine/2026-09-27';
@mkdir($rootQ, 0777, true);
$rOld     = $rootQ . '/stale_1.quarantine';
$rFresh   = $rootQ . '/recent_2.quarantine';
$rForeign = $rootQ . '/operator-notes.txt';
file_put_contents($rOld, 'x');
file_put_contents($rFresh, 'x');
file_put_contents($rForeign, 'keep me');
touch($rOld, time() - (30 * 86400));
touch($rForeign, time() - (30 * 86400));   // old, but not ours

Database::setSetting('quarantine_dir', $activeQ);
Database::setSetting('quarantine_retention_days', '7');

$res = Scanner::pruneQuarantine();

t_ok(!is_file($rOld),
    'a stale file in a directory quarantine no longer uses is removed, '
  . 'which is what leaked for ever before');
t_ok(is_file($rFresh), 'a recent one there is kept');
t_ok(is_file($rForeign),
    'a file that is not ours is left alone, however old -- an inferred '
  . 'directory gets only files we can name');
t_ok((int) ($res['legacy_removed'] ?? 0) >= 1,
    'and the result says the removal came from a previous location');

// The age rule on the live directory, unchanged.
Database::setSetting('quarantine_dir', $legacyQ);
Scanner::pruneQuarantine();
t_ok(!is_file($oldFile), 'a quarantined file past the retention period is removed');
t_ok(is_file($newFile),  'one still inside it is kept');

// ── status must not describe the wrong directory ────────────────────────────
Database::setSetting('quarantine_dir', $activeQ);
$usage = Scanner::quarantineUsage();
t_eq(0, $usage['files'], 'the live directory is empty, as it was on the server');
t_ok(array_key_exists('legacy_dirs', $usage),
    'and status reports previous locations alongside it, so "files: 0" cannot mislead');
t_ok(array_key_exists('legacy_files', $usage), 'with a file count');

$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, 'legacy_removed', 'the sweep CLI reports what it took from an old location');
t_contains($cli, 'status|sweep|prune', 'and the usage string lists sweep, which it omitted');
