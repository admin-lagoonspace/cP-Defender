<?php
/**
 * The Threats count leads somewhere.
 *
 * Both scan logs showed a number and nothing behind it. A customer could be
 * told a scan found three things in their account and had no way whatever to
 * learn which files, or what had become of them; an operator had the same
 * problem with more rows to search. The threats table is server-wide and
 * ordered by time, so answering "which three" meant reading past every other
 * finding from that night.
 *
 * "Detected" and "detected, quarantined, and here is where the copy went" are
 * very different things to be told about your own website, and only one of
 * them is actionable.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$api  = t_code($repo . '/backend/api/index.php');
$ur   = t_code($repo . '/backend/lib/UserReport.php');
$js   = (string) file_get_contents($repo . '/frontend/js/app.js');
$html = (string) file_get_contents($repo . '/frontend/index.html');
$page = t_code($repo . '/cpanel/serverscrub/index.live.php');
$raw  = (string) file_get_contents($repo . '/cpanel/serverscrub/index.live.php');

// ── Root: one scan's findings, by job ──────────────────────────────────────
t_contains($api, "if (isset(\$q['job_id']) && ctype_digit((string) \$q['job_id'])) {",
     'the API can return the findings of ONE scan, and only for a job id '
   . 'that is digits — it is interpolated into a query');
t_contains($api, "\$sqlWhere = 'WHERE scan_job_id = ?';",
     'matched on the scan that found them');

// The status filter must NOT survive here. "What happened to it" is half the
// question; a scan that found two and cleaned both would otherwise show none.
$threatsRoute = substr($api, (int) strpos($api, "'threats' => (function"), 1400);
$jobPos = strpos($threatsRoute, "scan_job_id = ?");
$stPos  = strpos($threatsRoute, "WHERE status = ?");
t_ok($jobPos !== false && ($stPos === false || $stPos < $jobPos),
     'THE HIDDEN OUTCOME: the job filter REPLACES the status filter rather '
   . 'than adding to it — a quarantined or deleted finding is exactly what '
   . 'the reader is asking about');

// ── Root UI: a link only where there is something behind it ────────────────
t_contains($js, 'function threatCountCell(j) {',
     'the count is rendered through one function');
t_contains($js, "if (!n) { return '<span style=\"color:var(--green)\">0</span>'; }",
     'THE EMPTY PROMISE: zero stays plain text. A link that opens an empty '
   . 'dialog is worse than no link — it costs a click and returns nothing');
t_contains($js, 'onclick="showScanThreats(',
     'and a non-zero count opens the detail');

// Asked for explicitly: inside the app, not a new tab or window.
t_contains($js, "openModal('scan-threats-modal');",
     'IN THE APP: it opens the in-page dialog');
t_ok(!preg_match('/showScanThreats[\s\S]{0,900}window\.open/', $js),
     'and never a new window — the reader is partway through a log, and '
   . 'losing that position to see three filenames is a bad trade');

t_contains($js, "const WHAT = {",
     'the outcome is put into words');
t_contains($js, "active:      ['Still on disk — no action taken', 'var(--red)'],",
     'including the one that matters most: found, and still there');
t_contains($js, "+ '<div class=\"mono\" style=\"font-size:.8rem;word-break:break-all;margin-bottom:8px\">'",
     'THE TRUNCATED PATH: the full path wraps rather than being cut — the '
   . 'reader\'s next step is to go and look at that file');

// ── The dialog must actually be visible ────────────────────────────────────
//
// Every other modal's styling is a hand-written list of id selectors, in five
// separate rules. A new dialog missing from all five renders as unstyled
// inline markup: in the DOM, correctly populated, and not on screen. That is
// precisely what happened the first time this was built.
t_contains($html, 'id="scan-threats-modal" class="wem-modal hidden"',
     'THE INVISIBLE DIALOG: the new modal carries a CLASS, not a sixth entry '
   . 'in five id lists');
t_contains($html, '  .wem-modal {
    position: fixed; inset: 0; z-index: 9000;',
     'and that class is styled, so the next dialog is not invisible on '
   . 'arrival either');
t_contains($html, '.wem-modal.hidden { display: none; }',
     'with the hidden state on the class too');

// ── Customer page: no JavaScript required ──────────────────────────────────
//
// This page is server-rendered deliberately. A dialog that needs a fetch and
// a script would be the only thing on it that can fail.
t_contains($raw, '.sscrub .ss-dlg:target { display:flex; }',
     'NO SCRIPT NEEDED: the customer dialog opens on :target, so it works '
   . 'with scripting switched off, and the back button closes it');
t_contains($page, 'href="#sst-<?= $jdid ?>"',
     'the count is an ordinary anchor');
t_contains($page, '<div class="ss-dlg" id="sst-<?= $jid ?>"',
     'pointing at a dialog rendered beside the table');
t_ok(strpos($page, 'fetch(\'?card=threats') === false,
     'and nothing is fetched — the data is already in the report the page '
   . 'was built from, so there is nothing to ask for and nothing to fail');

// Only scans with findings get a dialog; the rest would be empty shells.
t_contains($page, 'if (!$finds) { continue; }',
     'a scan that found nothing in this account gets no dialog');

// ── The privacy property, which is the whole reason this is not trivial ────
//
// A /home sweep covers every account on the server. Its findings are not this
// customer's to see, and its COUNT is not about them either.
t_contains($ur, "AND (cpanel_user = ? OR file_path LIKE ?)",
     'THE CROSS-ACCOUNT LEAK: the per-scan findings are scoped to this '
   . 'account, exactly as the threats list already is — a /home scan covers '
   . 'every customer, and listing it unfiltered would hand one customer the '
   . 'paths and filenames inside another customer\'s site');
t_contains($ur, "\$scans[\$i]['threats_found'] = count(\$byScan[\$jid] ?? []);",
     'THE NUMBER ABOUT SOMEBODY ELSE: the count is recomputed from this '
   . 'account\'s own findings. scan_jobs.threats_found is server-wide, so a '
   . 'nightly sweep that found three webshells in three OTHER accounts '
   . 'showed this customer "3" on their own page');

// Bounded. This is written into every account's home on a schedule.
t_contains($ur, 'LIMIT 200',
     'BOUNDED: the query is capped — one bad night can produce thousands of '
   . 'findings, and this file is written into every home');
t_contains($ur, 'if (count($byScan[$jid]) >= 50) { continue; }',
     'and so is any single scan');

// Relative paths, because the customer thinks in their own tree.
t_contains($ur, "\$t['relative_path'] = (strpos((string) \$t['file_path'], \$prefix) === 0)",
     'paths are shown relative to the home directory, which is how the '
   . 'account owner reads their own file tree');

// Deleted rows must NOT be hidden here, unlike the Detected-threats card.
$perScan = substr($ur, (int) strpos($ur, '$byScan = [];'), 1800);
t_ok(strpos($perScan, "status != 'deleted'") === false,
     'and a deleted finding is still listed — hiding it would make a scan '
   . 'that found two and removed both read as a scan that found nothing');

// ── The link and the dialog cannot disagree ────────────────────────────────
//
// They did, on the live server. The link was rendered from the scan row's
// threats_found; the dialog was rendered from the report's scan_threats map.
// On a report written before 4.29.0 the map is absent and the count is not,
// so the page offered a link to a #fragment with no element behind it.
// Clicking it set the URL, matched no :target, and did nothing at all --
// which is exactly what it looked like.
//
// A dead anchor is worse than a plain number: it looks clickable, consumes
// the click, and leaves the reader thinking the page is broken.
t_contains($page, '$allFinds = $report[\'scan_threats\'] ?? null;',
     'THE DEAD ANCHOR: the findings map is read BEFORE the table, so the '
   . 'cell can see whether a dialog will exist');
t_contains($page, 'if ($found > 0 && !empty($jfinds)):',
     'and a link is offered only when that scan has findings to show');
t_contains($page, '<span class="red" title="Detail for this scan is not in the current report yet">',
     'while a count with no stored detail stays plain text and says why on '
   . 'hover, rather than linking to nothing');

// null vs [] carry different meanings and must not be conflated: "this report
// predates the feature" is not "this scan found nothing here".
t_contains($page, '$jfinds = is_array($allFinds) ? ($allFinds[$jdid] ?? []) : null;',
     'an older report (no map at all) is distinguished from a scan with no '
   . 'findings in this account');
t_contains($page, 'if (is_array($jfinds)) { $found = count($jfinds); }',
     'and where the map exists the count comes FROM it, so the number and '
   . 'the list are the same fact rather than two that can drift');

// The dialog loop must read the same variable, or the hoist achieved nothing.
t_contains($page, '$finds = is_array($allFinds) ? ($allFinds[$jid] ?? []) : [];',
     'the dialog loop reads that same map');
t_ok(substr_count($page, "\$report['scan_threats']") === 1,
     'which is read in exactly one place — two reads is how the cell and the '
   . 'dialog came to disagree in the first place');

// ── RUN IT. Every test above this line reads source code. ──────────────────
//
// That is why this shipped: the per-scan findings query used inClause() as if
// it returned ['sql' => ..., 'params' => ...]. It returns [placeholders,
// values] positionally, and the placeholders are bare "?,?,?" with no IN()
// around them. So build() raised two "Undefined array key" warnings and then
//
//     TypeError: array_merge(): Argument #1 must be of type array, null given
//
// writeAll() catches Throwable per account and counts it as a skip, so the
// CLI reported "0 written, 132 skipped" and every customer's report.json
// froze at whatever was last written before 4.29.0. The page kept serving the
// stale file, so the threats link never appeared.
//
// A dozen assertions matched the source exactly as written and every one of
// them passed, because the source was exactly what I wrote. Only calling the
// function finds a call that cannot run.
$job = Database::insert('scan_jobs', [
    'scan_type'   => 'full',  'status'      => 'done',
    'started_at'  => time() - 3600, 'finished_at' => time() - 60,
    'scan_path'   => '/home', 'threats_found' => 2,
    'requested_by' => '@schedule',
]);
Database::insert('threats', [
    'scan_job_id' => $job, 'file_path' => '/home/sgdetail/public_html/shell.php',
    'threat_name' => 'PHP.Webshell.Generic', 'threat_type' => 'webshell',
    'severity'    => 'critical', 'status' => 'quarantined',
    'detected_at' => time() - 1800, 'action_taken' => 'moved to quarantine',
]);
// Another account's finding from the SAME scan. A /home sweep covers every
// customer, and this one must not reach sgdetail's report.
Database::insert('threats', [
    'scan_job_id' => $job, 'file_path' => '/home/someoneelse/public_html/x.php',
    'threat_name' => 'PHP.Backdoor.Obfuscated', 'threat_type' => 'backdoor',
    'severity'    => 'high', 'status' => 'deleted',
    'detected_at' => time() - 1700, 'action_taken' => 'deleted',
]);

$built = null;
$threw = null;
try {
    $built = UserReport::build('sgdetail', '/home/sgdetail');
} catch (Throwable $e) {
    $threw = get_class($e) . ': ' . $e->getMessage();
}
t_ok($threw === null,
     'THE TEST THAT WAS MISSING: build() actually runs. It threw a TypeError '
   . 'for every account on the server and nothing above this line noticed — '
   . ($threw ?? 'no exception'));

t_ok(is_array($built) && isset($built['scan_threats']),
     'and returns the per-scan findings map');

$mine = $built['scan_threats'][$job] ?? null;
t_ok(is_array($mine) && count($mine) === 1,
     'THE SCOPING, AS BEHAVIOUR: the scan found two things and exactly one '
   . 'of them is in this account — asserting the SQL text could never have '
   . 'shown that');
t_ok(is_array($mine) && strpos((string) ($mine[0]['file_path'] ?? ''), '/home/sgdetail/') === 0,
     'and it is the right one');

// The count on the row must agree with the list, since the page links from
// one and renders the other.
$row = null;
foreach (($built['scans'] ?? []) as $sc) {
    if ((int) ($sc['id'] ?? 0) === (int) $job) { $row = $sc; break; }
}
t_ok($row !== null && (int) $row['threats_found'] === 1,
     'the scan row reports 1, not the server-wide 2 — the number and the '
   . 'list are the same fact');

// writeFor() json_encodes this. A value json_encode refuses is another way
// to produce a skip, and it would be just as silent.
t_ok(json_encode($built, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) !== false,
     'and the whole report encodes to JSON, which is what writeFor() does '
   . 'before writing — a refusal there is another silent skip');
