<?php
/**
 * A cPanel user asking for a scan of their own account.
 *
 * Requested: every cPanel user should reach a limited version of this product
 * from the Security section of cPanel, the way cPGuard offered, and be able to
 * scan their own account rather than emailing their host.
 *
 * The whole difficulty is the boundary. The page runs as the customer and must
 * not reach the database (0700 root) or the API (admin role), so the request
 * crosses as a file in the customer's own home -- which means root reads a
 * path a hostile user controls and can rearrange between one call and the
 * next. These tests mostly guard that, and the limits that stop a button
 * every customer can press from becoming a way to flatten the server.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The request file ────────────────────────────────────────────────────────

$home = $ctx['sandbox'] . '/home/scanner';
@mkdir($home . '/.serverscrub', 0700, true);

// homeDir() resolves through passwd, which a sandbox has no entry for, so the
// path helpers are exercised directly against a stubbed home below.
t_ok(UserScanRequest::requestPath('../root') === null,
     'a traversal attempt never becomes a path');
t_ok(UserScanRequest::requestPath('') === null, 'nor does an empty username');

// ── Limits: enforced as root, not in the page ───────────────────────────────

// The allowance moved from a single cooldown plus a per-tick cap to a rolling
// window of two scans per twelve hours. It is covered in full by
// test_user_scan_window.php; this file keeps to the request file, the
// privilege boundary and the page.
t_eq(2, UserScanRequest::perWindow(), 'two scans per window');
t_eq(12 * 3600, UserScanRequest::windowSeconds(), 'and the window is twelve hours');
t_ok(!UserScanRequest::atLimit('alice'), 'a fresh account is not at its limit');

// ── Status, which is what the page renders ──────────────────────────────────

$st = UserScanRequest::statusFor('alice');
t_ok($st['enabled'], 'the feature reports as enabled by default');
t_eq(0, $st['retry_in'], 'with no wait while the allowance is unspent');
t_eq(2, $st['per_window'], 'and the allowance is reported');

$n = time();
Database::setSetting('user_scan_starts_alice', json_encode([$n - 3600, $n - 60]));
$st = UserScanRequest::statusFor('alice');
t_ok($st['retry_in'] > 0, 'a spent allowance reports a wait');
t_ok($st['retry_in'] <= 12 * 3600, 'that never exceeds the window');
t_eq(2, $st['used'], 'and says how much has been used');
Database::query("DELETE FROM settings WHERE key = 'user_scan_starts_alice'");

Database::setSetting('user_scan_enabled', '0');
t_ok(!UserScanRequest::enabled(), 'the operator can switch the whole feature off');
$off = UserScanRequest::process();
t_eq([], $off['started'], 'and nothing is started while it is off');
Database::setSetting('user_scan_enabled', '1');

// ── The page ────────────────────────────────────────────────────────────────

$page = (string) file_get_contents($repo . '/cpanel/serverscrub/index.live.php');

t_contains($page, "name=\"scan_now\"", 'the page offers a scan button');
t_contains($page, "REQUEST_METHOD'] ?? 'GET') === 'POST'",
     'which acts on POST only, so a link cannot trigger a scan');
t_contains($page, 'scan-request.json', 'and writes the request file');
t_contains($page, '@rename(',
     'written aside and moved into place, so the privileged side never reads '
   . 'a half-written file and throws the request away as malformed');

// The page must still not reach anything privileged. This is the rule the
// original user-plugin test exists to enforce, and a new button is exactly
// how it would get broken.
// Each entry is a CODE reference, not a word. 'Scanner' alone used to be in
// this list to catch the Scanner class, and it failed the moment the page
// gained a "Scanner logs" tab -- an assertion matching prose rather than the
// thing it is guarding.
foreach (['SG_DB', 'Database::', 'serverscrub.db', 'backend/api',
          'new PDO', 'Scanner::', 'new Scanner'] as $forbidden) {
    t_ok(strpos($page, $forbidden) === false,
         'the page still cannot reach ' . $forbidden
       . ' — it runs as the customer, and the database is 0700 root');
}

// It writes only inside the caller's own home.
t_ok(strpos($page, "rtrim(\$home, '/') . '/.serverscrub'") !== false,
     'the request is written inside the caller\'s own home directory');
t_ok(strpos($page, '$_POST[\'path\']') === false
     && strpos($page, '$_GET[\'user\']') === false,
     'and nothing about WHERE to scan comes from the request');

// ── The path scanned comes from passwd, never from the file ─────────────────
//
// This is the one that matters. A request file naming /root would otherwise be
// a request to scan /root, as root, on a customer's say-so.
$src  = (string) file_get_contents($repo . '/backend/lib/UserScanRequest.php');
$proc = t_fn_body($src, 'process', 'php');

t_contains($proc, 'UserReport::homeDir($user)',
     'THE PRIVILEGE BOUNDARY: the scan path is derived from the account, as '
   . 'root');
t_ok(strpos($proc, "\$req['path']") === false && strpos($proc, "\$req['dir']") === false,
     'and never read out of the request file');

// These checks live in readStamp(), which read() and readCancel() both go
// through. That is the point of it being one function: a cancel request is
// root being asked to stop a job on the say-so of a file in a directory the
// customer controls, and it needs every check a scan request needs. A second
// copy of them would be the one that eventually falls behind.
$read = t_fn_body($src, 'readStamp', 'php');
t_contains($read, 'is_link($path)',
     'the request file is never followed as a symlink — root opening a path a '
   . 'hostile user can replace between calls');
t_contains($read, 'fileowner($path)',
     'and must be owned by the account it claims to come from, or one '
   . 'customer could plant a request in another\'s directory');
t_contains($read, 'MAX_BYTES', 'the read is bounded');

t_contains(t_fn_body($src, 'read', 'php'), 'self::readStamp(',
     'the scan request goes through those checks');
t_contains(t_fn_body($src, 'readCancel', 'php'), 'self::readStamp(',
     'and so does the cancel request — the same file in the same '
   . 'customer-controlled directory, asking root to do something');

// Ordering, so the cap cannot starve anyone.
t_contains($proc, 'usort(',
     'pending requests are served oldest first — directory order would let an '
   . 'account early in the alphabet starve one late in it every time the cap '
   . 'bites');

// A declined request is kept, not thrown away.
t_contains($proc, "'reason' => 'at limit'",
     'a request from an account that has spent its allowance is reported');
$coolAt  = strpos($proc, "'at limit'");
$clearAt = strpos($proc, 'self::clear($user);');
t_ok($coolAt !== false && ($clearAt === false || $clearAt > $coolAt),
     'and is NOT cleared, or the customer\'s click would vanish silently and '
   . 'they would simply click again');

// ── It only exists where cPanel does ────────────────────────────────────────

$install = (string) file_get_contents($repo . '/install.sh');
t_contains($install, 'if [[ ! -d /usr/local/cpanel ]]; then',
     'the whole cPanel integration is skipped where cPanel is not installed');
t_contains($install, 'group=>security', 'and the menu entry sits in the Security group');
t_contains($install, 'features=any',
     'visible to every cPanel account, not only those on the default feature list');

// ── A queued request has to explain itself ──────────────────────────────────
//
// It said: "Your scan is waiting to run. Scans are started a few at a time."
// That tells a customer nothing they can act on and nothing that distinguishes
// a working queue from a broken one, so a feature that was working correctly
// produced "is this thing on?" Every reason for a wait lives on the privileged
// side, so the privileged side now records it.

Database::query("DELETE FROM settings WHERE key LIKE 'user_scan_note_%'");
t_ok(UserScanRequest::noteFor('nobody') === null, 'no note when nothing has happened');

$src2 = (string) file_get_contents($repo . '/backend/lib/UserScanRequest.php');
$proc2 = t_fn_body($src2, 'process', 'php');

t_contains($proc2, "self::note(\$user, 'at_limit', 0)",
     'an account that has spent its allowance records that, so the page can '
   . 'say so rather than just "waiting"');
t_contains($proc2, "self::note(\$user, 'blocked', 0, \$e->getMessage())",
     'THE REASON THAT MATTERED MOST: a refused start records WHY — "a backup '
   . 'is running" is something a customer can understand, an unexplained wait '
   . 'is not');
t_ok(strpos($proc2, 'waiting_turn') === false,
     'and nothing records a queue position any more — there is no queue');
t_contains($proc2, "Database::setSetting('user_scan_last_check'",
     'and the time of the last check, which the page cannot know on its own');

$st2 = UserScanRequest::statusFor('alice');
foreach (['last_check_at', 'per_window', 'used', 'note'] as $k) {
    t_ok(array_key_exists($k, $st2), 'status carries ' . $k);
}

// ── The page ────────────────────────────────────────────────────────────────

$page2 = (string) file_get_contents($repo . '/cpanel/serverscrub/index.live.php');

t_contains($page2, 'Requested <?= e(ago($reqAt)) ?>',
     'the page says WHEN the request was made');
t_contains($page2, "'/.serverscrub/scan-request.json'",
     'THE STALENESS TRAP: it reads the request time from the customer\'s own '
   . 'file rather than the report, which is rewritten only every quarter '
   . 'hour — otherwise somebody who clicks and reloads is told nothing was '
   . 'requested');
t_contains($page2, 'It usually starts within a minute',
     'it tells the customer how long, now that a dedicated cron picks requests '
   . 'up every minute rather than the 15-minute scheduler');
t_ok(strpos($page2, 'ahead of you in the queue') === false,
     'and says nothing about a queue, because there no longer is one');
t_contains($page2, 'could not start it yet', 'and surfaces a blocking reason');
t_contains($page2, 'you do not need to ask again',
     'telling the customer not to retry, which is what they would otherwise do');
t_contains($page2, 'has not started, and will not',
     'THE SILENT STALL: if the minute-by-minute pickup is not running, the '
   . 'scan never starts — so the page says exactly that, as the FIRST thing '
   . 'it says');
t_ok(strpos($page2, '$stale = $lastCheck <= 0') !== false,
     'and the reassurance is suppressed rather than printed above the '
   . 'warning. The card used to say "It usually starts within a minute" and '
   . 'then, in the next sentence, that nothing had looked at the request for '
   . 'eight hours — telling the customer their scan was fine and then that it '
   . 'was stuck');
t_contains($page2, 'time() - $lastCheck) > 300',
     'warned only when the check is genuinely stale, not on every page view');
t_contains($page2, 'Nothing is wrong',
     'with a plain fallback when there is no recorded reason, because silence '
   . 'reads as failure');

// A note older than the request describes the PREVIOUS request.
t_contains($page2, "(int) (\$note['at'] ?? 0) < \$reqAt",
     'a note from before this request is ignored, or a customer would be shown '
   . 'the reason their LAST scan waited');

// ── The tabbed panel ────────────────────────────────────────────────────────
//
// Asked for: the same shape cPGuard gives a cPanel user — a branded header, a
// dashboard, and tabs for the scanner, its logs, CMS threats, the WAF and
// attacks.
//
// The tabs are SERVER-SIDE. The page already runs PHP and already renders the
// panels, so a ?tab= link survives a reload, a bookmark, the back button and a
// browser with scripting off. Client-side tabs would buy nothing here and
// could only fail.

t_contains($page2, "\$TABS = [", 'the panels are a whitelist');
foreach (['home', 'scanner', 'logs', 'cms', 'waf', 'attacks', 'files'] as $t) {
    t_contains($page2, "'" . $t . "'", 'there is a ' . $t . ' panel');
}
t_contains($page2, "if (!isset(\$TABS[\$tab])) { \$tab = 'home'; }",
     'THE INJECTION GUARD: an unknown tab falls back to home rather than '
   . 'reaching a template branch or being echoed into the nav');

// There IS script on the page now: a scan that takes minutes has to show
// itself moving, and the alternative was a card that said "Queued" until the
// customer reloaded by hand. What matters is that it stays an enhancement.
t_contains($page2, '<form method="post"',
     'THE NO-JS FLOOR: every control is a real form submit, so the page works '
   . 'with scripting off — the script only re-reads what the server already '
   . 'rendered');
t_ok(strpos($page2, 'onclick=') === false,
     'and nothing is wired through inline handlers');

$js = substr($page2, (int) strpos($page2, '<script'));
t_contains($js, "getAttribute('data-poll')",
     'the poller asks the SERVER whether to keep going, rather than deciding '
   . 'for itself when a scan has finished');
t_contains($js, 'document.hidden',
     'and stops re-reading while the tab is in the background');
t_contains($js, 'armed',
     'one timer only — coming back to the tab would otherwise start a second '
   . 'chain alongside the first');

// cPanel's session lives in the URL PATH, so links must stay relative.
t_contains($page2, "basename((string) (\$_SERVER['SCRIPT_NAME']",
     'links are relative, so cPanel\'s /cpsessNNN/ prefix is preserved');
t_contains($page2, 'rawurlencode($t)', 'and the tab name is encoded into the query');

// The dropdown has to work without script and without hover, or a touch user
// cannot reach the scanner at all.
t_contains($page2, '.ss-drop:focus-within .ss-menu',
     'the Virus scanner menu opens on keyboard focus as well as hover');
t_contains($page2, 'class="ss-drop', 'the menu exists');
$dropAt = strpos($page2, 'class="ss-drop');
$parentLink = substr($page2, $dropAt, 300);
t_contains($parentLink, "\$link('scanner')",
     'and its PARENT is itself a link to the scanner — on a touch device, '
   . 'where there is no hover, the menu is a shortcut rather than the only '
   . 'way in');

// Per-account data, which is the whole constraint this page lives under.
t_contains($page2, "\$report['waf']", 'the WAF panel reads the report');
t_contains($page2, "\$report['attacks']", 'as does the attacks panel');
t_contains($page2, "\$report['scans']", 'and the scanner logs');
t_contains($page2, 'Only events that name one of your own domains',
     'and the attacks panel says plainly that it shows only this account\'s '
   . 'domains, rather than implying the customer is seeing the whole server');

// ── The report has to carry it, or the panels are empty ─────────────────────
$ur = (string) file_get_contents($repo . '/backend/lib/UserReport.php');
t_contains($ur, 'public static function domainsFor',
     'the privileged side resolves the account\'s domains — a WAF event is '
   . 'keyed on a HOST, which is the only thing tying it to a customer');
t_contains($ur, "preg_match('/^DNS\d*=(.+)\$/'",
     'read from the account\'s own cPanel file, DNS= and DNS1..n');
t_contains($ur, "preg_match('/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\$/', \$d)",
     'and every value validated as a hostname — this feeds SQL placeholders '
   . 'and a page, from a file cPanel writes rather than us');

t_contains($ur, 'private static function inClause',
     'THE EMPTY-IN TRAP: an account with no domains gets no query at all. '
   . '"host IN ()" is a syntax error and "IN (NULL)" matches nothing while '
   . 'looking like it worked');
$ucBody = t_fn_body($ur, 'inClause', 'php');
t_contains($ucBody, 'if ($values === []) { return null; }', 'which is what null means here');
