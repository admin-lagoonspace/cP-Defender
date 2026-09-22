<?php
/**
 * Where quarantine lives, and how big it is allowed to get.
 *
 * Reported: "we are dumping everything in quarantine in /root somewhere and my
 * root space is now totally full".
 *
 * QUARANTINE_DIR defaulted to SG_ROOT . '/quarantine', i.e.
 * /usr/local/sentinel-gate/quarantine -- on the root filesystem. Quarantine
 * MOVES infected files there, so on a hosting server, where customer data is a
 * separate and far larger volume, a busy scan fills / and takes the machine
 * down. A security tool must not be the cause of the outage.
 *
 * Three things were wrong, not one:
 *   1. the default location was on the wrong volume
 *   2. nothing ever removed anything, so it grew without limit
 *   3. nothing checked free space before writing
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The default must not be under the install directory ──────────────────────
$cfg = t_code($repo . '/backend/config/config.php');
t_ok(strpos($cfg, "define('QUARANTINE_DIR', SG_ROOT . '/quarantine')") === false,
    'quarantine no longer defaults to a directory under SG_ROOT');
t_contains($cfg, "'/home'", 'the default prefers /home, where the scanned files already live');
t_contains($cfg, 'is_writable($sgVolume)',
    'the volume is checked for writability before being chosen');
t_contains($cfg, "!defined('QUARANTINE_DIR')",
    'an explicit QUARANTINE_DIR still wins');

// ── The setting always overrides ─────────────────────────────────────────────
$alt = $ctx['sandbox'] . '/elsewhere';
@mkdir($alt, 0777, true);
Database::setSetting('quarantine_dir', $alt);
t_eq($alt, Database::storagePath('quarantine'),
    'quarantine_dir overrides the compiled default');

// ── Retention: it must not grow for ever ─────────────────────────────────────
$qdir = $ctx['sandbox'] . '/quar';
@mkdir($qdir . '/2020-01-01', 0777, true);
Database::setSetting('quarantine_dir', $qdir);

$oldFile = $qdir . '/2020-01-01/ancient.quarantine';
file_put_contents($oldFile, str_repeat('x', 2048));
touch($oldFile, time() - (60 * 86400));

$newFile = $qdir . '/2020-01-01/recent.quarantine';
file_put_contents($newFile, 'fresh');

$r = Scanner::pruneQuarantine(30);
t_eq(1, $r['removed'], 'a file older than the window is removed');
t_eq(1, $r['kept'],    'a recent file is kept');
t_ok($r['bytes'] >= 2048, 'the freed bytes are reported');
t_ok(!file_exists($oldFile), 'the old file is gone');
t_ok(file_exists($newFile),  'the recent file survives');

// Retention 0 means "keep everything" and must not delete anything.
$keepAll = $qdir . '/2020-01-01/keepme.quarantine';
file_put_contents($keepAll, 'x');
touch($keepAll, time() - (999 * 86400));
$none = Scanner::pruneQuarantine(0);
t_eq(0, $none['removed'], 'retention 0 disables pruning entirely');
t_ok(file_exists($keepAll), 'and nothing is deleted');

t_contains(t_code($repo . '/backend/lib/Database.php'), 'quarantine_retention_days',
    'a retention default is seeded for new installs');

// ── Free-space guard ─────────────────────────────────────────────────────────
// Quarantining must refuse rather than fill the volume it writes to. Asserted
// from the code: a disk cannot be filled inside a test to prove it.
$sc = t_code($repo . '/backend/lib/Scanner.php');
t_contains($sc, 'disk_free_space(', 'free space is checked before quarantining');
t_contains($sc, 'Refusing to quarantine',
    'quarantine refuses rather than filling the volume');
$guardPos = strpos($sc, 'disk_free_space(');
$renamePos = strpos($sc, '@rename($filePath, $dest)');
t_ok($guardPos !== false && $renamePos !== false && $guardPos < $renamePos,
    'the space check happens BEFORE the file is written');

// ── Usage reporting ──────────────────────────────────────────────────────────
$usage = Scanner::quarantineUsage();
t_eq($qdir, $usage['dir'], 'usage reports the directory in force');
t_ok($usage['files'] >= 1, 'it counts the files held');
t_ok(isset($usage['human']), 'and reports a readable size');
t_eq(false, $usage['on_root'],
    'a quarantine outside /usr/local is not flagged as being on root');

Database::setSetting('quarantine_dir', '/usr/local/sentinel-gate/quarantine');
t_eq(true, Scanner::quarantineUsage()['on_root'],
    'a quarantine under /usr/local IS flagged as being on the root partition');
Database::setSetting('quarantine_dir', $qdir);

// ── Relocation moves files, never deletes them ───────────────────────────────
$dest = $ctx['sandbox'] . '/newvolume/quarantine';
$moveMe = $qdir . '/2020-01-01/moveme.quarantine';
file_put_contents($moveMe, 'payload-bytes');

$m = Scanner::moveQuarantine($dest);
t_eq(true, $m['success'] ?? false, 'relocation succeeds');
t_ok($m['moved'] >= 1, 'files were moved (' . $m['moved'] . ')');
t_ok(is_file($dest . '/2020-01-01/moveme.quarantine'), 'the file is at the new location');
t_eq('payload-bytes', file_get_contents($dest . '/2020-01-01/moveme.quarantine'),
    'its contents are intact');
t_ok(!file_exists($moveMe), 'and it is no longer at the old location');
t_eq($dest, Database::setting('quarantine_dir'),
    'the setting now points at the new location');

$same = Scanner::moveQuarantine($dest);
t_eq(false, $same['success'], 'moving to the current location is refused');

$rel = Scanner::moveQuarantine('relative/path');
t_eq(false, $rel['success'], 'a relative destination is refused');
t_contains($rel['error'], 'absolute', 'and says an absolute path is required');

// ── Scheduled cleanup ────────────────────────────────────────────────────────
// Without this the retention setting is decorative: nothing would ever apply it.
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "'quarclean' => [", 'quarantine cleanup is scheduled');
t_contains($sched, 'Scanner::pruneQuarantine', 'the task actually prunes');
t_contains($sched, 'scan_*.log', 'old per-scan logs are pruned too');

// ── The installer moves existing installs off root ───────────────────────────
$install = file_get_contents($repo . '/install.sh');
t_contains($install, '_SG_QUAR_NEW', 'the installer chooses a non-root quarantine');
t_contains($install, '--remove-source-files', 'existing files are moved, not copied and left');
$migPos   = strpos($install, 'Move quarantine off the root partition');
$guardPos = strpos($install, 'INSTALL-ONLY SECTIONS (skipped');
t_ok($migPos !== false && $guardPos !== false && $migPos < $guardPos,
    'the migration runs on --register-only, the path update.sh takes');

// The one thing this must never do is delete a quarantined file.
$mig = substr($install, $migPos, $guardPos - $migPos);
t_ok(strpos($mig, 'rm -rf "$_SG_QUAR_OLD"') === false,
    'the migration never deletes the old quarantine tree wholesale');

// ── The CLI can see and fix this without a database editor ───────────────────
$cli = t_code($repo . '/backend/cli/sentinel.php');
t_contains($cli, "case 'quarantine'", 'there is a quarantine command');
t_contains($cli, 'Scanner::quarantineUsage', 'it can report usage');
t_contains($cli, 'Scanner::pruneQuarantine', 'it can prune');
t_contains($cli, 'Scanner::moveQuarantine',  'it can relocate');
