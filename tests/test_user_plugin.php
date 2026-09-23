<?php
/**
 * The cPanel-user plugin: its data path, and the boundary it must not cross.
 *
 * Requested: the plugin should appear in the Security section of cPanel for
 * every user, not only in WHM. Two things stood in the way. The menu entry was
 * gated on a feature that was only ever enabled in /var/cpanel/features/default
 * -- so accounts on a reseller's own feature list, which is most accounts on a
 * reseller box, never saw it. And the page behind it was a redirect to the WHM
 * dashboard, which authenticates against WHM, so a cPanel user who did reach it
 * landed on a login they could never pass.
 *
 * The page now reads a report written into the user's own home. That choice is
 * what these tests mostly guard: root writes into a directory the user
 * controls, so every write has to refuse to follow anything it did not create.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// -- Username validation gates every filesystem path below -------------------
foreach (['alice', 'bob99', 'a-b_c', 'x'] as $ok) {
    t_ok(UserReport::validUsername($ok), "'$ok' is accepted");
}
foreach (['../root', '/etc', 'a/b', '', 'Alice', '-lead', 'a b', str_repeat('x', 65)] as $bad) {
    t_ok(!UserReport::validUsername($bad),
        "'" . substr($bad, 0, 12) . "' is rejected as a username");
}

// -- A report is built from this user's rows only ----------------------------
$home = $ctx['sandbox'] . '/home/alice';
@mkdir($home . '/public_html', 0777, true);

Database::query(
    "INSERT INTO threats (file_path, threat_name, threat_type, severity, status, cpanel_user, detected_at)
     VALUES (?,?,?,?,?,?,?)",
    [$home . '/public_html/bad.php', 'PHP.Suspect', 'webshell', 'critical', 'active', 'alice', time()]
);
Database::query(
    "INSERT INTO threats (file_path, threat_name, threat_type, severity, status, cpanel_user, detected_at)
     VALUES (?,?,?,?,?,?,?)",
    [$ctx['sandbox'] . '/home/mallory/x.php', 'PHP.Other', 'webshell', 'high', 'active', 'mallory', time()]
);

// The home is passed explicitly: this machine has no cPanel account named
// alice, so homeDir() cannot resolve one, and that is not what is under
// test here.
$report = UserReport::build('alice', $home);
t_eq('alice', $report['user'], 'the report names the user it was built for');
t_eq(1, count($report['threats']), 'only this user\'s threats are included');
t_contains(json_encode($report), 'bad.php', 'their own threat is present');
t_ok(strpos(json_encode($report), 'mallory') === false,
    'no trace of another account appears anywhere in the report');

// The whole point of the summary tiles is that they are not zero when
// something is wrong.
t_eq(1, $report['summary']['threats_active'], 'the active-threat count is right');

// -- Paths are relative to the home, not absolute ----------------------------
t_eq('public_html/bad.php', $report['threats'][0]['relative_path'] ?? '',
    'the path is shown relative to the account home');

// -- The page itself ---------------------------------------------------------
$page = $repo . '/cpanel/sentinel_gate/index.php';
t_ok(is_file($page), 'the cPanel user page ships as a real file in the repo');

$src = t_code($page);
// It must not reach for the server-wide database or API: both are root-owned
// and shared, and this page runs as an ordinary hosting customer.
foreach (['SG_DB', 'Database::', 'sentinel.db', 'backend/api', 'PDO'] as $forbidden) {
    t_ok(strpos($src, $forbidden) === false,
        "the user page does not reference $forbidden");
}
t_contains($src, 'report.json', 'it reads the per-user report');
t_contains($src, 'htmlspecialchars', 'and escapes what it renders');

// Redirecting to the WHM dashboard is what made this useless before.
t_ok(strpos($src, "header('Location:") === false,
    'the page renders in place rather than redirecting to the WHM dashboard');

// -- Registration: visible for every user ------------------------------------
$install = file_get_contents($repo . '/install.sh');
t_contains($install, '"group_id": "security"', 'the entry is registered in the Security group');
t_contains($install, 'group=security', 'and in the dynamicui group of the same name');

// The feature gate hid it from every account not on the default feature list.
$jsonBlock = substr($install, strpos($install, '"id":       "sentinel_gate"'), 400);
t_ok(strpos($jsonBlock, '"feature"') === false,
    'the menu entry is no longer gated on a feature list');

$dynBlock = substr($install, strpos($install, 'itemdesc=Sentinel Gate Security'), 200);
t_ok(strpos($dynBlock, 'feature=') === false,
    'the dynamicui entry is not gated either');

// Both themes, or half the server's users see nothing.
t_contains($install, 'for CPANEL_THEME in paper_lantern jupiter',
    'the plugin is installed for both cPanel themes');

// The page has to be copied in, not generated as a redirect.
t_contains($install, 'cpanel/sentinel_gate/index.php',
    'the installer copies the real page');

// -- It must be packaged, or the installer copies nothing --------------------
$rel = file_get_contents($repo . '/scripts/make-release.sh');
t_contains($rel, 'backend frontend whm cpanel',
    'the cpanel/ directory is included in the release archive');

// -- Reports have to be produced, or every user sees "no report yet" ---------
$sched = t_code($repo . '/backend/cron/scheduler.php');
t_contains($sched, "'userreports' => [", 'report generation is scheduled');
t_contains($sched, 'UserReport::writeAll', 'the task writes the reports');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/UserReport.php'",
    'and the scheduler requires the class, or cron fatals');

$sel = substr($sched, strpos($sched, "'userreports' => ["), 300);
preg_match("/'schedule' => setting\('user_reports_schedule', '([a-z]+)'\)/", $sel, $m);
t_ok(in_array($m[1] ?? '', ['off', 'hourly', 'daily', 'weekly'], true),
    'its default interval is one the scheduler implements (' . ($m[1] ?? '?') . ')');

t_contains($install, 'UserReport::writeAll',
    'the installer generates reports immediately, so the plugin is not empty on day one');

$cli = t_code($repo . '/backend/cli/sentinel.php');
t_contains($cli, "case 'user-reports'", 'an operator can rebuild them on demand');

// -- Root writing into a directory the user controls -------------------------
// This is the sharp edge of the whole design. Everything under ~ belongs to a
// hostile party for the purposes of this class: a symlink at ~/.sentinel-gate,
// or at report.json, would have root write through it to whatever it points
// at. The runtime behaviour cannot be exercised here -- creating a symlink on
// this Windows host requires a privilege the build does not have -- so these
// assert the guards are present in the source. They are stated as code
// assertions deliberately rather than dressed up as behavioural ones.
$ur = t_code($repo . '/backend/lib/UserReport.php');

t_contains($ur, 'is_link($dir)',
    'a symlinked .sentinel-gate directory is detected');
t_contains($ur, 'refusing to write through it',
    'and refused rather than followed');
t_contains($ur, 'is_link($home)',
    'a symlinked home directory is detected too');
t_contains($ur, '@rename($tmp, $path)',
    'the report is renamed into place, so a planted report.json is replaced '
  . 'rather than opened and written through');

// The ownership check: a home owned by someone other than the named user is a
// sign the account has been tampered with, and writing there as root would
// compound it.
t_contains($ur, 'fileowner($home)', 'the home directory owner is checked');
t_contains($ur, 'posix_getpwnam', 'against the account database, not a guess');

// mkdir must not create parents: /home/<user> itself is never created here.
t_contains($ur, '@mkdir($dir, 0700, false)',
    'the report directory is created without creating parents');

// A missing module table must not abort the hourly task for every account.
t_contains($ur, 'no such table', 'a table a module has not created yet is tolerated');
t_contains($ur, 'self::safeFetch(', 'every query goes through that guard');
t_eq(1, substr_count($ur, 'Database::fetchAll('),
    'exactly one call to fetchAll exists -- the one inside safeFetch');

// -- Least privilege in what the report carries ------------------------------
// The file lands in a hosting customer's home. Anything in it is disclosed to
// them, so it must contain their findings and nothing about the server.
t_ok(strpos($ur, 'SELECT * FROM') === false,
    'no query selects whole rows, which would leak columns added later');
foreach (['settings', 'license', 'blocked_ips', 'firewall_rules'] as $table) {
    t_ok(!preg_match('/FROM\s+' . $table . '\b/i', $ur),
        "the report does not read the $table table");
}
