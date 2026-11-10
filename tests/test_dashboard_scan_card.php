<?php
/**
 * One card, two numbers, contradicting each other.
 *
 * Observed live in the container after a full scan that found the seeded EICAR
 * file — the same card, at the same moment:
 *
 *     SCANNER STATUS
 *     Threats Found
 *     ⚠️ 1 Active Threat
 *     Last scan: 12s ago · 0 new threats
 *
 *     SCAN COVERAGE   Coverage 98.7%
 *     1,339 Scanned   1,339 Clean   0 Quarantined   0 Deleted
 *
 * with the threat listed in the panel directly beneath it. Four false claims:
 *
 *   - `· 0 new threats` was a literal in app.js. `lastJob.threats_found`
 *     existed and was used at four other call sites in the same file.
 *   - `1,339 Clean` was the last scan's file count minus two ALL-TIME threat
 *     counts, so a file that is open as a threat right now counted as clean.
 *   - `0 Deleted` was a literal.
 *   - `Coverage 98.7%` was `total > 0 ? 98.7 : 0`. Nothing in this product has
 *     ever measured coverage.
 *
 * And `const threats = sc?.active || 0` followed by `if (threats > 0) … else
 * '✅ Protected'` painted undefined, a failed fetch and a genuine zero the same
 * green. Nothing must look like success.
 *
 * The two headline figures DO measure different things, and that is not the
 * fault: "Active Threats" is what is open now across every scan;
 * `threats_found` is what the last scan found. Both can be true at once. So
 * each says which it is, and neither is a constant.
 *
 * Same class as `action = 'block'` on 148,551 WAF events and
 * `MODE.textContent = 'On'`: a value presented as fact that does not come from
 * the data.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// ── The server side: one scan's numbers, and all-time numbers, separately ──

$scanner = new Scanner();

$empty = $scanner->getStats();
t_eq(null, $empty['last_scan_stats'],
     'with no scan ever run the per-scan figures are null, not zero: "no scan" '
   . 'and "a scan that found nothing" are different answers and the card has '
   . 'to be able to tell them apart');

// The earlier scan goes in first: scan_jobs rows are created in time order on
// a real server, and getStats() takes the newest job by id.
$old = Database::insert('scan_jobs', [
    'scan_type'    => 'quick', 'status' => 'done',
    'started_at'   => time() - 90000, 'finished_at' => time() - 86400,
    'scan_path'    => '/home', 'files_scanned' => 120, 'threats_found' => 1,
    'requested_by' => '@schedule',
]);
// Its finding is still open. This is what made the all-time and the per-scan
// numbers diverge on the real card.
Database::insert('threats', [
    'scan_job_id' => $old, 'file_path' => '/home/acct1/public_html/old.php',
    'threat_name' => 'PHP.Backdoor.Obfuscated', 'threat_type' => 'backdoor',
    'severity'    => 'critical', 'status' => 'active', 'detected_at' => time() - 86000,
]);

$job = Database::insert('scan_jobs', [
    'scan_type'    => 'full', 'status' => 'done',
    'started_at'   => time() - 300, 'finished_at' => time() - 12,
    'scan_path'    => '/home', 'files_scanned' => 1339, 'threats_found' => 3,
    'requested_by' => '@schedule',
]);
// Three findings from that scan, in the three states they end up in.
foreach ([['/home/acct3/public_html/suspicious.php', 'active'],
          ['/home/acct4/public_html/shell.php',      'quarantined'],
          ['/home/acct5/public_html/x.php',          'deleted']] as $i => $t) {
    Database::insert('threats', [
        'scan_job_id' => $job, 'file_path' => $t[0],
        'threat_name' => 'EICAR-Test-File', 'threat_type' => 'malware',
        'severity'    => 'high', 'status' => $t[1], 'detected_at' => time() - 20 + $i,
    ]);
}

$s = $scanner->getStats();

t_eq(2, $s['active'], 'two threats are open in total — one from each scan');
$ls = $s['last_scan_stats'];
t_eq($job, $ls['job_id'], 'the per-scan figures are for the newest scan');
t_eq(1339, $ls['files_scanned'], 'with the file count that scan recorded');
t_eq(3, $ls['threats_found'],
     'THE FIGURE THAT WAS A LITERAL ZERO: what the last scan actually found, '
   . 'which the job row has recorded all along');
t_eq(1336, $ls['clean'],
     'and "clean" is the files that scan examined with no finding — 1339 − 3. '
   . 'It used to be the file count minus all-time threat counts, which '
   . 'reported every examined file as clean while one of them was an open '
   . 'threat');
t_eq(1, $ls['quarantined'], 'quarantined counts that scan\'s own findings');
t_eq(1, $ls['deleted'],
     'and so does deleted, which was the literal 0 on the card');
t_eq(1, $ls['still_active'],
     'the one finding from that scan that is still open — not the two open '
   . 'server-wide, which is the figure above it on the card');
t_eq(1, $s['deleted'],
     'the all-time deleted count exists at all now: app.js read sc.deleted, '
   . 'getStats() never returned it, and undefined became 0 in a subtraction');

// ── The card: no constants, and "could not read" is not green ─────────────

$js   = (string) file_get_contents($repo . '/frontend/js/app.js');
// Sliced to the function that renders the card, not a fixed character window:
// a window runs into whatever function grew above it, which has happened in
// this suite before.
$card = t_fn_body($js, 'refreshDashboard', 'js');
t_ok($card !== '', 'the dashboard renderer was found');

t_ok(strpos($card, '0 new threats') === false,
     'the literal "0 new threats" is gone from the card');
t_contains($card, 'found by that scan',
     'and the figure is labelled as what the LAST SCAN found, so it cannot be '
   . 'read as a contradiction of the open-threat count above it');
t_contains($card, 'threats_found',
     'read from the job, which is where it has always been recorded');

t_ok(strpos($card, '98.7') === false,
     'the fabricated 98.7% coverage is gone: the product counts the files it '
   . 'examined, not how many exist, so there is no percentage to print');

t_contains($card, 'Number.isFinite(sc?.active)',
     'the threat count is tested for being a number rather than for being '
   . 'truthy: `sc?.active || 0` made undefined, a failed fetch and a real zero '
   . 'the same value');
t_contains($card, "scanStatus.textContent = 'Unknown'",
     'A THIRD STATE: a card that could not read the threat count says so '
   . 'instead of showing a green "Protected"');
t_ok(strpos($card, 'badge-gray') !== false,
     'and is not badged green while it is unknown');

t_ok(strpos($card, 'fmtNum(total - (sc?.quarantined') === false,
     '"Clean" is no longer one scan\'s file count minus two all-time counts');
t_contains($card, 'ls.clean',
     'it comes from the per-scan figures the server now returns');
t_contains($card, "dash('fs-del',     ls ? ls.deleted : null)",
     'and so does "Deleted", which was a literal zero');
t_contains($card, 'Last scan: never',
     'a server that has never been scanned says so, rather than leaving the '
   . 'previous text in place');
