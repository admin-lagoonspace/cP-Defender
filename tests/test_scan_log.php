<?php
/**
 * The scan log, on both sides, says what is happening and who asked for it.
 *
 * Two complaints, one cause.
 *
 *   "i started a manual scan which does not appear in scanner logs"
 *   "i need scanner logs for both user and root"
 *
 * The customer's Scanner logs table was rendered entirely out of report.json,
 * which the privileged side rebuilds HOURLY. A customer could press "Scan my
 * account", watch the Home card count files in real time, switch to the log --
 * and find no row for the scan they were at that moment running. For up to an
 * hour. The one event a log is certain to be asked about is the one that just
 * happened, and that was precisely the event it could not show.
 *
 * And on the root side there was no scan log AT ALL. The WHM page showed the
 * scan running at this instant and the threats found; nothing about any scan
 * before it. "Did last night's sweep finish?" had no answer short of opening
 * the database. The customer-facing plugin had a history the server's own
 * administrator did not.
 *
 * The fixes are different because the two sides can see different things. The
 * customer page cannot read the database (0700 root), so it merges in the one
 * current thing it CAN read -- its own scan-status.json -- and the privileged
 * side rebuilds the reports when the set of running scans changes. The root
 * page just queries.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$page = t_code($repo . '/cpanel/serverscrub/index.live.php');
$api  = t_code($repo . '/backend/api/index.php');
$cron = t_code($repo . '/backend/cron/user-scans.php');
$js   = (string) file_get_contents($repo . '/frontend/js/app.js');
$html = (string) file_get_contents($repo . '/frontend/index.html');

// ── Customer side: the running scan is in its own log ───────────────────────
t_contains($page, '$logRows = $scanRows;',
     'THE STALE LOG: the table is built from the report PLUS whatever is live, '
   . 'rather than from the hourly report alone');
t_contains($page, "\$liveJob = (int) (\$live['job'] ?? 0);",
     'the live job is identified by its id');
t_contains($page, 'array_unshift($logRows,',
     'and a scan the report has not caught up with yet is put at the top');

// Dedup matters more than it looks: the moment the hourly rebuild runs, the
// running scan is in report.json too, and a blind prepend shows it twice --
// once stale, once live, with different file counts. That reads as two scans.
t_contains($page, "if ((int) (\$r['id'] ?? 0) !== \$liveJob) { continue; }",
     'THE DOUBLE ROW: a job already in the report is UPDATED in place, not '
   . 'prepended as a second row with a different file count beside it');
t_contains($page, "'triggered_by'  => 'you',",
     'and it is attributed to this account');

// That attribution is a fact, not a guess, and the reason is worth keeping:
// scan-status.json is written only for scans this account requested.
$sc = t_code($repo . '/backend/lib/Scanner.php');
$pub = t_fn_body($sc, 'publishUserStatus', 'php');
t_contains($pub, "if (\$user === '' || \$user[0] === '@') { return null; }",
     'WHY THAT IS SAFE: publishUserStatus() writes nothing for a scan nobody '
   . 'asked for and nothing for a scheduler, operator or CLI scan — so a '
   . 'status file in a home can only describe that account\'s own request');

// ── The log refreshes itself while a scan runs ──────────────────────────────
t_contains($page, 'id="ss-logs" data-poll=',
     'the log is a live region, so a scan that is running changes the table '
   . 'without the reader pressing anything');
t_contains($page, "\$CARDS = ['scan' => \$renderScanCard, 'logs' => \$renderLogsCard];",
     'and it can be fetched on its own, like the scan card');
t_contains($page, "var REGIONS = { 'ss-scan': 'scan', 'ss-logs': 'logs' };",
     'the poller knows both regions');
t_contains($page, "if (el && el.getAttribute('data-poll') === '1') { out.push(id); }",
     'ONLY WHAT IS ON SCREEN: a region absent from the page is not fetched — '
   . 'the two live regions are on different tabs, and polling the one the '
   . 'reader is not looking at is a request for nothing');

// ── 'done' is the status this product writes ────────────────────────────────
t_contains($page, "\$scls     = \$status === 'done' ? 'green'",
     'THE GREY SUCCESS: a finished scan is green. The check was for '
   . "'completed', which this product has never written, so a clean scan was "
   . 'rendered in the same grey as "cancelled" and "error"');
t_ok(strpos($page, "\$status === 'completed'") === false,
     'and the status that never existed is gone');

// ── The privileged side refreshes reports when a scan starts or ends ────────
//
// The merge above covers the customer's OWN scan. It cannot cover the nightly
// sweep of /home, which is in their log too and which they have no status file
// for.
t_contains($cron, "\"SELECT id FROM scan_jobs WHERE status IN ('running','pending','cancelling')\"",
     'the watcher tracks EVERY live scan, not only customer-requested ones — '
   . 'a root scan of /home covers every account and belongs in every log');
t_contains($cron, 'if ($prevLive !== null && $nowLive !== $prevLive) {',
     'ON CHANGE: reports are rebuilt when a scan starts or ends, not every '
   . 'pass — this is a few queries and a file per account, cheap at the edges '
   . 'of a scan and wasteful every five seconds');
t_contains($cron, 'static $prevLive = null;',
     'and the first pass only records');

// The first-pass rule is the whole point of the null check: the minute cron is
// a fresh process every time and has nothing to compare against.
$passBody = substr($cron, (int) strpos($cron, 'static $prevLive'));
$passBody = substr($passBody, 0, 600);
t_ok(strpos($passBody, 'if ($prevLive !== null') !== false,
     'THE MINUTE CRON: without it a one-shot run reads its own startup as a '
   . 'change and rebuilds every report on the server every minute');
t_contains($cron, 'sort($nowLive);',
     'the sets are compared in a fixed order, so a different row order is not '
   . 'mistaken for a scan starting');

// ── Root side: there is a scan log, and it names the account ────────────────
t_contains($api, "'jobs' => (function () use (\$q) {",
     'THE MISSING HISTORY: GET scanner/jobs exists — the server\'s own '
   . 'administrator could previously see the scan running this second and '
   . 'nothing at all about the ones before it');
t_contains($api, 'requested_by, ignore_backup',
     'and it returns who asked');
t_contains($api, "\$limit = max(1, min(200, (int) (\$q['limit'] ?? 50)));",
     'BOUNDED: the row count is clamped, so a limit from the query string '
   . 'cannot ask this server for every scan it has ever run');

t_contains($js, 'async function loadScanJobs() {',
     'the UI loads it');
t_contains($js, 'loadScanJobs(),',
     'the Scanner page loads it on open');
t_contains($html, 'id="scanlog-body"',
     'and there is a table for it to fill');

t_contains($html, '<th>Started by</th>',
     'with the column that was asked for');

// Root may see the name. The customer page may not, and that difference is the
// security property, not a presentational choice.
t_contains($js, "return [by + ' (cPanel user)', 'var(--txt1)'];",
     'ROOT SEES THE NAME: on this side the account that asked is shown '
   . 'outright, which is the useful answer for whoever runs the server');

$ur = t_code($repo . '/backend/lib/UserReport.php');
t_contains($ur, "unset(\$scans[\$i]['requested_by']);",
     'AND THE CUSTOMER DOES NOT: the raw name is stripped before the report '
   . 'is written into a home -- a /home scan appears in every account log, '
   . 'and the name on it is usually somebody else as');

t_contains($js, "if (by === '@schedule') return ['Scheduled scan'",
     'the markers read as words rather than as the tokens the database holds');
t_contains($js, "if (by === '')          return ['",
     'HONEST ABOUT THE PAST: rows from before this was recorded say so rather '
   . 'than guessing "scheduled", which would be wrong for every scan an '
   . 'operator ever started by hand');

// A running scan has no finished_at. Measuring against it leaves the one row
// anybody is actually watching as the one row with no duration on it.
t_contains($js, '? Math.floor(Date.now() / 1000) : 0);',
     'a running scan elapsed time is measured against now');

// The log has to gain the scan at BOTH ends of it: when it starts, so the
// operator can see what the server is doing, and when it stops, so they can
// see how it went. Opening the page is not the only moment either happens.
t_ok(substr_count($js, 'loadScanJobs()') >= 4,
     'the log is refreshed when a scan starts and when it finishes, not only '
   . 'when the page is opened');
