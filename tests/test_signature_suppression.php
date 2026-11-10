<?php
/**
 * Switching off ONE signature, instead of switching off ClamAV.
 *
 * On 10 Nov a single third-party ClamAV signature matched 154,323 customer
 * files on the production server — README.md and CHANGELOG.md inside
 * node_modules and vendor trees, because the rule hunts long hex strings and a
 * changelog is full of git SHAs:
 *
 *     {HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL
 *
 * The only lever the product offered was turning ClamAV off. On a server with
 * 132 accounts that is the choice between one bad signature and no antivirus,
 * and it is not a choice anybody should have to make.
 *
 * Three things have to be true of the fix, and the third is the one that is
 * easy to get wrong:
 *
 *   1. it excludes the RULE, not the files and not the engine;
 *   2. it survives a signature update, because freshclam replaces the whole
 *      database and a feed rewrites its own directory, so anything written
 *      there expires silently at the next update;
 *   3. it is never invisible. A suppressed signature is a hole in the defence,
 *      and a hole nobody can see is indistinguishable from a scanner that has
 *      stopped working — which is the failure this product keeps shipping.
 *
 * Fixtures are inert; see t_inert_payload() in tests/assert.php.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

require_once $repo . '/backend/lib/SignatureSuppressions.php';

$SIG   = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL';
$OTHER = '{HEX}php.cmdshell.gifheader.400.UNOFFICIAL';

$job = Database::insert('scan_jobs', [
    'scan_type' => 'quick', 'status' => 'running', 'started_at' => time(),
    'scan_path' => '/home', 'requested_by' => '@schedule',
]);

// ── It excludes the rule ──────────────────────────────────────────────────

SignatureSuppressions::reset();
t_eq(null, SignatureSuppressions::match($SIG),
     'nothing is suppressed to begin with');

$r = SignatureSuppressions::add($SIG, '154,252 markdown files in node_modules', 'cli:root');
t_ok(!empty($r['success']), 'the signature can be suppressed by name');
t_ok(SignatureSuppressions::match($SIG) !== null, 'and is then matched');
t_eq(null, SignatureSuppressions::match($OTHER),
     'THE OTHER SIGNATURES STILL APPLY: suppressing one rule is not turning '
   . 'the scanner off, which was the only lever before this');

// ── A detection for it is not recorded, and IS counted ────────────────────

$path = $sandbox . '/home/kbroadlines/public_html/node_modules/x/README.md';
@mkdir(dirname($path), 0777, true);
file_put_contents($path, t_inert_payload('a changelog full of git SHAs'));

$id = ThreatStore::record([
    'scan_job_id' => $job, 'file_path' => $path, 'threat_name' => $SIG,
    'threat_type' => 'malware', 'severity' => 'high', 'status' => 'active',
]);
t_eq(null, $id,
     'a suppressed signature produces NO FINDING: nothing to quarantine, '
   . 'nothing to report, nothing to act on');
t_eq(0, (int) Database::fetchOne(
        'SELECT COUNT(*) c FROM threats WHERE threat_name=?', [$SIG])['c'],
     'and no row is written, so the next scan has nothing to act on either');

SignatureSuppressions::flush();
$sum = SignatureSuppressions::summary();
t_eq(1, (int) $sum['count'], 'the suppression is listed');
t_eq(1, (int) $sum['hits'],
     'AND THE MATCH IS COUNTED. This is the number that makes the hole '
   . 'visible: "this signature has hidden 154,252 files since you switched it '
   . 'off" is a fact an operator can weigh, and silence is not');
t_ok((int) $sum['last_hit_at'] > 0, 'with when it last hid something');

// A finding for a different signature is unaffected.
$id2 = ThreatStore::record([
    'scan_job_id' => $job, 'file_path' => $path . '.other', 'threat_name' => $OTHER,
    'threat_type' => 'malware', 'severity' => 'high', 'status' => 'active',
]);
t_ok($id2 !== null,
     'an unsuppressed signature is recorded exactly as before — the one '
   . 'finding in that run which might have been real is still a finding');

// ── Counting is batched, so 154,323 matches is not 154,323 writes ─────────

SignatureSuppressions::reset();
$sup = SignatureSuppressions::match($SIG);
for ($i = 0; $i < 250; $i++) { SignatureSuppressions::noteHit((int) $sup['id']); }
SignatureSuppressions::flush();
$after = (int) Database::fetchOne(
    'SELECT hits FROM signature_suppressions WHERE id=?', [(int) $sup['id']])['hits'];
t_eq(251, $after,
     'every match is counted, in groups: 154,323 matches is 1,544 writes '
   . 'rather than 154,323, and the count is still right');

// ── Prefix form, and the limits on it ────────────────────────────────────

$r = SignatureSuppressions::add('{HEX}linux.ransom.*', 'the whole family', 'cli:root');
t_ok(!empty($r['success']), 'a trailing * suppresses a family of signatures');
t_ok(!empty($r['prefix']), 'and is recorded as a prefix');
SignatureSuppressions::reset();
t_ok(SignatureSuppressions::match('{HEX}linux.ransom.something.else.UNOFFICIAL') !== null,
     'which matches the family');
t_eq(null, SignatureSuppressions::match('{HEX}linux.ransomware-ish.UNOFFICIAL'),
     'and only from the prefix given, not from anything that looks similar');

t_ok(empty(SignatureSuppressions::add('{HEX}*', 'far too broad', 'cli:root')['success']),
     'A SHORT PREFIX IS REFUSED: "{HEX}*" would switch off a whole class of '
   . 'signatures from six characters, and a suppression made by accident is a '
   . 'hole nobody knows about');
t_ok(empty(SignatureSuppressions::add('', '', 'cli:root')['success']),
     'an empty name is refused');
t_ok(empty(SignatureSuppressions::add("bad\nname", '', 'cli:root')['success']),
     'and so is anything that is not shaped like a signature name');
$dupe = SignatureSuppressions::add($SIG, 'again', 'cli:root');
t_ok(empty($dupe['success']) && !empty($dupe['existing']),
     'suppressing the same signature twice reports the existing one rather '
   . 'than making a second');

// ── Reversible, and the reversal is recorded ─────────────────────────────

$before = SignatureSuppressions::summary()['count'];
$rm = SignatureSuppressions::remove((int) $sup['id']);
t_ok(!empty($rm['success']), 'a suppression can be removed');
t_eq($before - 1, (int) SignatureSuppressions::summary()['count'], 'and the list shrinks');

// Both of them: the prefix added above covers this name as well, and a
// signature is only reporting again when NOTHING suppresses it.
foreach (SignatureSuppressions::all() as $row) {
    SignatureSuppressions::remove((int) $row['id']);
}
SignatureSuppressions::reset();
t_eq(null, SignatureSuppressions::match($SIG),
     'and with nothing left suppressing it, the signature reports again');

$ev = Database::fetchAll(
    "SELECT type, description FROM security_events WHERE type IN "
  . "('signature_suppressed','signature_unsuppressed') ORDER BY id");
t_ok(count($ev) >= 2,
     'BOTH DIRECTIONS ARE SECURITY EVENTS: switching a signature off is a '
   . 'change to the defence, and so is switching it back on');
t_contains((string) $ev[0]['description'], 'Matches will be counted and not recorded',
     'and the event says what the suppression does');
$last = end($ev);
t_contains((string) $last['description'], 'it had matched',
     'while removing one records how much it had been hiding');

// ── It survives a signature update, because it is not in the signatures ──

$src = t_code($repo . '/backend/lib/SignatureSuppressions.php');
t_contains($src, 'CREATE TABLE IF NOT EXISTS signature_suppressions',
     'the suppression lives in our own database');
t_ok(strpos($src, 'SIG_DIR') === false
     && strpos($src, 'file_put_contents') === false,
     'and NOTHING in it writes to a signature file or directory: freshclam '
   . 'replaces the whole database and a third-party feed rewrites its own '
   . 'directory, so a suppression stored there would expire at the next '
   . 'update — silently, which is the worst kind of expiry for a safety '
   . 'measure');

$ts = t_code($repo . '/backend/lib/ThreatStore.php');
$rec = t_fn_body($ts, 'record', 'php');
t_contains($rec, 'SignatureSuppressions::match(',
     'the check is in ThreatStore::record() — the one place every detection '
   . 'source passes through, so the scan, the realtime daemon and the '
   . 'WordPress heuristics all honour it');
$supPos = strpos($rec, 'SignatureSuppressions::match(');
// The LAST insert: record() has an early one for a pathless finding, which is
// recorded deliberately rather than lost, and the ordering that matters is
// against the insert on the ordinary path.
$insPos = strrpos($rec, "Database::insert('threats'");
t_ok($supPos !== false && $insPos !== false && $supPos < $insPos,
     'and before the row is written, which is what makes it a suppression '
   . 'rather than a filter on the report');
t_contains($rec, 'SignatureSuppressions::noteHit(',
     'with the match counted on the way past');

// ── It is visible: CLI, API and the panel ────────────────────────────────

$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, "case 'signatures': {", 'there is a CLI command');
t_contains($cli, 'Suppressed signatures: ', 'that lists them');
t_contains($cli, 'is a hole in the defence',
     'and says what the list means, rather than printing names');
t_contains($cli, 'quarantine restore --signature=',
     'and after suppressing one it points at the files it has already taken, '
   . 'because suppressing the signature does not bring them back');

$api = t_code($repo . '/backend/api/index.php');
t_contains($api, "case 'suppressions':", 'the panel can read the list');
t_contains($api, "case 'suppress':", 'and add one');
t_contains($api, "case 'unsuppress':", 'and remove one');
t_contains($api, "Auth::requireRole('admin', \$user)",
     'and both writes need an admin');

$html = (string) file_get_contents($repo . '/frontend/index.html');
t_contains($html, 'id="sigsup-tbody"',
     'THE PANEL SHOWS THE HOLE: there is a card for it on the Scanner page');
t_contains($html, 'Suppressed signatures', 'with a title that says what it is');
t_contains($html, 'one signature everywhere',
     'and explains the blast radius, because this is the bluntest of the three '
   . 'instruments and is not interchangeable with a verdict');

$js = (string) file_get_contents($repo . '/frontend/js/app.js');
$fn = t_fn_body($js, 'loadSuppressions', 'js');
t_ok($fn !== '', 'and a loader that fills it');
t_contains($fn, 'could not be read',
     'A FAILED READ IS NOT AN EMPTY LIST: "no signatures are suppressed" and '
   . '"I could not find out" must not render the same, and the dangerous one '
   . 'is the one that would otherwise look safe');
t_contains($fn, 'file(s) hidden since',
     'the header carries what the suppressions have hidden, so the cost is on '
   . 'screen next to the list');
$loader = t_fn_body($js, 'openPage', 'js');
t_contains($loader, 'loadSuppressions()',
     'and the Scanner page actually calls it — a card nothing fills reads as '
   . '"nothing is suppressed"');
