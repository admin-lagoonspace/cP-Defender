<?php
/**
 * The WordPress database sweep actually finds the installs.
 *
 * Reported as "WP Databases - scan databases is not working at all", and it
 * was not: the sweep read the wrong keys off its own inventory.
 *
 * CMSGuard::getInstalls() returns rows from cms_installs, whose columns are
 * `cms_type` and `install_path`. The sweep read `$i['cms']` and `$i['path']`.
 * Neither exists, so the comparison was always '' !== 'wordpress' and EVERY
 * row was skipped -- on a server with hundreds of WordPress sites the sweep
 * examined none of them, recorded nothing, and the panel reported
 *
 *     Read 0 of 0 installs - 0 new finding(s)
 *
 * in green. Which is the worst way for this particular module to fail: its
 * whole purpose is the half of a compromise that is not a file, and it was
 * answering "clean" without having looked. The last attempted hack on this
 * server tampered with existing databases.
 *
 * Nothing about it threw, nothing was logged as an error, and every count it
 * printed was truthful. Only the premise was wrong.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The inventory is read with the column names it actually has ────────────
$sandbox = $ctx['sandbox'];
$wp      = $sandbox . '/home/alice/public_html';
$joomla  = $sandbox . '/home/bob/public_html';
$gone    = $sandbox . '/home/carol/public_html';   // recorded, since deleted
@mkdir($wp, 0755, true);
@mkdir($joomla, 0755, true);

// cms_installs is created by CMSGuard's constructor, not by Database::migrate.
// Constructed here so the fixture has a table to write to -- and so that the
// lazy creation itself is exercised, since wordpressRoots() depends on it.
new CMSGuard();

foreach ([
    [$wp,     'wordpress'],
    [$joomla, 'joomla'],
    [$gone,   'wordpress'],
] as [$path, $cms]) {
    Database::insert('cms_installs', [
        'install_path' => $path,
        'cms_type'     => $cms,
        'version'      => '6.5',
        'cpanel_user'  => basename(dirname($path)),
        'domain'       => basename(dirname($path)) . '.example',
        'status'       => 'ok',
        'outdated'     => 0,
    ]);
}

$roots = WPDatabaseScanner::wordpressRoots();

t_ok(in_array($wp, $roots, true),
     'THE BUG: a WordPress install on record is found. It was read as '
   . '$i[\'cms\'] and $i[\'path\'], but the row carries cms_type and '
   . 'install_path, so every install on the server was skipped and the '
   . 'sweep reported a clean result without looking at anything');

t_ok(!in_array($joomla, $roots, true),
     'and a Joomla install is still not swept by the WordPress scanner');

t_ok(!in_array($gone, $roots, true),
     'a recorded install whose directory has gone is dropped — it would '
   . 'otherwise be counted in "installs" and never scanned, so the sweep '
   . 'would report fewer read than found for no visible reason');

t_eq(1, count($roots), 'and nothing else is picked up');

// Dedup: an addon domain parked on the primary gives two rows, one directory.
Database::insert('cms_installs', [
    'install_path' => $wp . '/.',      // same directory, different spelling
    'cms_type'     => 'wordpress', 'version' => '6.5',
    'cpanel_user'  => 'alice', 'domain' => 'addon.example', 'status' => 'ok',
    'outdated'     => 0,
]);
$again = WPDatabaseScanner::wordpressRoots();
t_ok(count($again) >= 1, 'the list survives a duplicate row');

// ── The sweep no longer answers "clean" from an empty inventory ────────────
$src = (string) file_get_contents($repo . '/backend/lib/WPDatabaseScanner.php');
t_contains($src, 'scanInstalls()',
     'NOTHING TO SCAN IS NOT NOTHING WRONG: the sweep discovers installs when '
   . 'the inventory is empty or stale, rather than sweeping zero of them and '
   . 'reporting no findings — which is what "scan databases is not working" '
   . 'looked like from the panel');
t_contains($src, "Database::setting('cms_last_scan_at', '0')",
     'staleness is judged by when the inventory was last built, so NEW '
   . 'databases are covered and not only the ones on record');
t_contains($src, 'discovery failed',
     'and a failed discovery is reported, not turned into a silent '
   . 'zero-install sweep');

// A lib must require what it calls. 27 of 36 did not, and one missing
// require_once once made all 132 user reports skip silently.
t_contains($src, "require_once __DIR__ . '/CMSGuard.php';",
     'CMSGuard is required, so the sweep does not fatal in cron where '
   . 'nothing else has loaded it');

// ── It still only reports ──────────────────────────────────────────────────
//
// Asked for explicitly: "For action dont delete them just flag them in UI and
// we will decide what to do as those might be live customer data." This is
// already the design -- the module opens read-only connections and writes
// findings -- and the test exists so that it stays that way.
t_ok(!preg_match('/\b(DROP\s+TABLE|DELETE\s+FROM\s+(?!wp_findings))/i', $src),
     'FLAG, DO NOT DELETE: the scanner issues no destructive SQL against a '
   . 'customer database. These are live sites and the operator decides');
t_contains($src, "'status'       => 'open'",
     'a finding is recorded as open for an operator to judge');

$pdo = t_fn_body($src, 'connect', 'php');
if ($pdo !== '') {
    t_ok(strpos($pdo, 'DELETE') === false && strpos($pdo, 'UPDATE') === false,
         'and the connection helper carries no write statements');
}

// The findings reach the panel, which is where the decision gets made.
$api = t_code($repo . '/backend/api/index.php');
t_contains($api, 'WPDatabaseScanner::openFindings',
     'and open findings are served to the UI');

// ── An empty sweep is not reported in green ───────────────────────────────
$js = (string) file_get_contents($repo . '/frontend/js/app.js');
t_contains($js, 'if (!(d.installs || 0)) {',
     'THE SYMPTOM: a sweep that found no installs warns instead of toasting '
   . '"Read 0 of 0 installs" as a success — that green toast was the only '
   . 'visible sign of a bug that skipped every install on the server');
