<?php
/**
 * The scanner no longer stands down for JetBackup or rsync.
 *
 * Asked for: "i want to disable this feature of pausing scanning while
 * backup jetbackup process and rsync process are active, this is limiting
 * server scanning".
 *
 * The gate was not a pause. waitOutBackup() sleeps in thirty-second steps up
 * to scan_backup_max_wait -- four hours -- and then returns false, which
 * ABANDONS the rest of the sweep. So on a server whose backup window overlaps
 * the scan window the trade was never "a slower scan": it was no scan until
 * the next scheduled run a day later. Contention makes both jobs slower and
 * loses neither, which is the better side of that trade.
 *
 * Three things had to change together, and the middle one is why turning the
 * setting off by hand would not have worked:
 *
 *   - the seeded default, for new installs;
 *   - the SCHEDULER, which checked backupRunning() directly and deferred
 *     whatever the setting said -- so scan_pause_on_backup governed the two
 *     callers that barely matter and not the nightly sweep, the only scan on
 *     which coverage actually depends;
 *   - a one-time migration, because INSERT OR IGNORE never revisits a row
 *     that already exists, so every running server would have kept the gate.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The default, as the product actually behaves ───────────────────────────
//
// Read through the live DB rather than grepped out of the seed list: the seed
// and the code fallback disagreeing is exactly how a setting comes to depend
// on whether a row happens to exist.
t_eq('0', Database::setting('scan_pause_on_backup'),
     'a fresh install does not hold scans for backups');

$src = (string) file_get_contents($repo . '/backend/lib/Scanner.php');

// Both readers must fall back to the same value the seed uses. They did not:
// each defaulted to '1' while the seed now says '0', so an install missing
// the row behaved the opposite way to one that had it.
t_eq(2, preg_match_all("/setting\('scan_pause_on_backup', '0'\)/", $src),
     'both readers in Scanner fall back to off, matching the seed');
t_ok(strpos($src, "setting('scan_pause_on_backup', '1')") === false,
     'and no reader still falls back to on');

// ── The scheduler obeys the setting ────────────────────────────────────────
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "if (setting('scan_pause_on_backup', '0') === '1') {",
     'THE ONE THAT MATTERED: the scheduled sweep checks the setting before '
   . 'deferring. It used to call backupRunning() unconditionally, so the '
   . 'setting could be off and the nightly scan still would not run');

// The deferral itself is kept, for anyone who turns the gate back on.
t_contains($sched, 'scan deferred',
     'and the deferral still exists for an operator who wants it');

// ── The refusal and the wait are still there, just not armed ───────────────
//
// Deleting them would make this irreversible. The setting has to be a switch,
// not a scar.
t_contains($src, 'A backup is running (',
     'startScan() can still refuse — the gate is disabled, not removed');
t_contains($src, 'backup still running after',
     'and the wait cap survives for the same reason');

// ── An existing install is actually changed ────────────────────────────────
$dbsrc = (string) file_get_contents($repo . '/backend/lib/Database.php');
t_contains($dbsrc, "UPDATE settings SET value = '0'\n                        WHERE key = 'scan_pause_on_backup'",
     'the migration UPDATEs the existing row — INSERT OR IGNORE would not '
   . 'touch it, and every server already running has one');
t_contains($dbsrc, "'scan_backup_gate_off_4312', '1'",
     'keyed on its own marker, so it runs once and an operator who turns the '
   . 'gate back on afterwards keeps it');
t_contains($dbsrc, "WHERE key = 'scan_paused_for_backup'",
     'and the "paused for backup" flag is cleared, or the dashboard reports '
   . 'a pause that can no longer end');

// Behaviour, not text: a database that predates this must come out with the
// gate off. Built with raw PDO so it genuinely has the old value before
// migrate() ever sees it -- a DB created through Database::get() would
// already carry the marker and the UPDATE would be a no-op.
$old = $ctx['sandbox'] . '/oldinstall';
@mkdir($old . '/database', 0700, true);
$raw = new PDO('sqlite:' . $old . '/database/serverscrub.db');
$raw->exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)");
$raw->exec("INSERT INTO settings (key, value) VALUES ('scan_pause_on_backup', '1')");
$raw->exec("INSERT INTO settings (key, value) VALUES ('scan_paused_for_backup', '1')");
$raw = null;

$probe = $ctx['sandbox'] . '/probe.php';
file_put_contents($probe, '<?php
define("SG_API", true);
define("SG_ROOT", ' . var_export($old, true) . ');
define("SG_INSTALL_MARKER", SG_ROOT . "/installed-at");
define("INSTALL_MODE", "cpanel");
require ' . var_export($repo . '/backend/config/config.php', true) . ';
require ' . var_export($repo . '/backend/lib/Database.php', true) . ';
echo Database::setting("scan_pause_on_backup", "missing"), "|",
     Database::setting("scan_paused_for_backup", "missing"), "\n";
');

$out = [];
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($probe) . ' 2>&1', $out, $code);
$line = trim(implode('', $out));

t_eq(0, $code, 'the upgrade of an old database runs cleanly: ' . $line);
t_eq('0|0', $line,
     'UPGRADED INSTALL: a database that had the gate on comes out with it '
   . 'off, and with no stale pause flag left to display');
