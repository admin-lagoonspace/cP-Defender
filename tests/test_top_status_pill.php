<?php
/**
 * The topbar badge that could not be wrong, because nothing ever set it.
 *
 * `frontend/index.html` carried this, on every page:
 *
 *     <div class="status-pill" id="top-status">
 *       <div class="status-dot"></div>
 *       <span>Protected</span>
 *     </div>
 *
 * and `grep top-status frontend/js/app.js` returned NOTHING. Static markup, a
 * green dot, and the word Protected, from the moment the page loaded until it
 * was closed. Both of these were then observed in a browser:
 *
 *   - a fresh pre-scan install: the scanner card correctly read grey "Not yet
 *     scanned" while the pill directly above it read Protected;
 *   - the API answering 500: the card correctly read "API unreachable" and the
 *     pill still read Protected, in green, on the same screen.
 *
 * This is the same class as `MODE.textContent = 'On'`, `action = 'block'` on
 * 148,551 WAF events, `Coverage 98.7%` and "944 Java Attack / Disabled" — all
 * four of which were removed from this product. This one survived every pass
 * because it lived in the HTML and not in the JavaScript, so reading app.js
 * could never surface it. A badge that is always green is not a status; it is
 * a decoration that looks like a status.
 *
 * It is driven from the same two figures as the scanner card now — the
 * open-threat count, and whether any scan has ever finished — by the same
 * code, so the two cannot disagree. Four states, and the green one has to be
 * earned.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$html = (string) file_get_contents($repo . '/frontend/index.html');
$js   = (string) file_get_contents($repo . '/frontend/js/app.js');
$css  = (string) file_get_contents($repo . '/frontend/css/app.css');

// ── The markup makes no claim ──────────────────────────────────────────────

$pill = substr($html, (int) strpos($html, 'id="top-status"') - 400, 900);
t_ok(strpos($pill, '<span>Protected</span>') === false,
     'THE LITERAL IS GONE: the pill no longer ships with the word "Protected" '
   . 'baked into the page');
t_contains($pill, 'Checking…',
     'what it ships with is what is true before the first answer arrives — and '
   . 'what stays on screen if the script never runs at all');
t_contains($pill, 'sp-unknown',
     'and it ships in the grey unknown state, not in a state that asserts '
   . 'anything');
t_contains($pill, 'id="top-status-text"',
     'the text node has an id, so updating it does not depend on the shape of '
   . 'the markup around it');

// ── Something actually drives it ───────────────────────────────────────────

t_ok(substr_count($js, "getElementById('top-status')") >= 1,
     'app.js reaches the pill at all, which is the whole of this finding: '
   . '`grep top-status app.js` used to return nothing');

$fn = t_fn_body($js, 'topStatusFor', 'js');
t_ok($fn !== '', 'there is one function that decides the pill\'s state');
t_contains($fn, 'Number.isFinite(sc?.active)',
     'the threat count is tested for being a NUMBER, not for being truthy: '
   . '`sc?.active || 0` is what made undefined, a failed fetch and a real zero '
   . 'the same value on the card below it');
t_contains($fn, "sc?.last_scan?.finished_at",
     'and it asks whether a scan has ever finished, which is the question the '
   . 'static badge never asked');

// ── All four states exist, and the green one is reachable last ─────────────

t_contains($fn, "'unknown', 'Status unknown'",
     'STATE 1 — the count could not be read: it says so');
t_contains($fn, "'never', 'Not yet scanned'",
     'STATE 2 — nothing has been scanned: zero open threats across zero scans '
   . 'is not a clean bill of health');
t_contains($fn, "' threat' + (threats > 1 ? 's' : '') + ' open'",
     'STATE 3 — open threats, with the count');
t_contains($fn, "'clean', 'No open threats'",
     'STATE 4 — a scan ran and nothing is open');
t_contains($js, "setTopStatus('down', 'API unreachable'",
     'STATE 5 — and the API not answering is its own state, in the dashboard\'s '
   . 'own failure branch, which is where the pill used to sit in green saying '
   . '"Protected" beside the words "API unreachable"');

$neverPos = strpos($fn, "'never', 'Not yet scanned'");
$cleanPos = strpos($fn, "'clean', 'No open threats'");
$unkPos   = strpos($fn, "'unknown', 'Status unknown'");
t_ok($unkPos < $neverPos && $neverPos < $cleanPos,
     'the order is unknown, then never-scanned, then green: green is only '
   . 'reachable when a scan has finished AND the count was readable, which is '
   . 'the same branch order as the card');

// ── The card and the pill share one source ────────────────────────────────

$dash = t_fn_body($js, 'refreshDashboard', 'js');
t_contains($dash, 'applyTopStatus(sc)',
     'the dashboard drives the pill from the payload it already has, rather '
   . 'than issuing a second request or keeping a second opinion');
$page = t_fn_body($js, 'openPage', 'js');
t_contains($page, 'refreshTopStatus()',
     'and every page switch refreshes it, because the pill is in the topbar '
   . 'and the dashboard is the only page that would otherwise supply it');

$rt = t_fn_body($js, 'refreshTopStatus', 'js');
t_contains($rt, '15000',
     'throttled, so a nav bar being clicked does not become a request per '
   . 'click on a server with 132 accounts');
t_contains($rt, "setTopStatus('down'",
     'and a refresh that fails says the API is unreachable rather than leaving '
   . 'the last good answer on screen');

// ── Green is a CSS state, not the default ─────────────────────────────────

$pillCss = substr($css, (int) strpos($css, '.status-pill {'), 1600);
t_ok(strpos($pillCss, '.status-pill {
  display: flex; align-items: center; gap: 7px;
  font-size: .75rem; font-weight: 600; color: var(--green2);
}') === false,
     'the DEFAULT pill is no longer green: an unstyled or un-updated pill must '
   . 'not look like a clean bill of health');
t_contains($pillCss, '.status-pill.sp-clean      { color: var(--green2); }',
     'green is a state class, applied from data');
t_ok(strpos($pillCss, '.status-pill.sp-unknown .status-dot { background: var(--txt3); }') !== false,
     'and the unknown state is grey');
$clean = substr($pillCss, (int) strpos($pillCss, '.sp-clean .status-dot'), 200);
t_contains($clean, 'animation: pulse-dot',
     'only the earned state pulses — the "being watched and all is well" '
   . 'animation used to run on a badge that was watching nothing');

// ── Every state the JS applies has to exist in the CSS and the HTML ────────
//
// The realistic way this breaks now is not a wrong decision but a mismatch:
// setTopStatus() writes `status-pill sp-<state>`, and a state nobody styled
// renders with the default — which is grey, so it would FAIL SAFE rather than
// look green, but "threats open" shown in grey is still a quiet lie. These
// four assertions are what a browser would otherwise have to find.
preg_match_all("/return \['(\w+)',/", $fn, $states);
$applied = array_unique(array_merge($states[1] ?? [], ['down']));
// Sixth state added in 4.37.11: 'partial', an incomplete last scan (quick
// scan bounds). It is styled in app.css; the loop below checks that.
t_eq(6, count($applied),
     'six states are applied by the code (unknown, never, threat, partial, '
   . 'clean, down) — if a seventh is added, this count is what notices');

foreach ($applied as $state) {
    // 'never' deliberately shares the grey unknown styling: "nothing has been
    // scanned" and "the count could not be read" are both "no claim", and one
    // grey is clearer than two.
    $cls = ($state === 'never') ? 'sp-unknown' : 'sp-' . $state;
    t_ok(strpos($css, '.status-pill.' . $cls) !== false,
         'the ' . $state . ' state resolves to a style that exists (.'
       . $cls . '): a state class nobody wrote would render with the default');
}

foreach (['top-status', 'top-status-text'] as $id) {
    t_contains($html, 'id="' . $id . '"',
               'setTopStatus() writes to #' . $id . ', and the markup has it');
}

// setTopStatus() must not be able to reintroduce the defect by being called
// with a hardcoded word.
$setter = t_fn_body($js, 'setTopStatus', 'js');
t_ok(strpos($setter, "'Protected'") === false,
     'and the setter itself contains no literal status text — every word it '
   . 'writes comes from the state it was given');

/* ══ "PROTECTED" ONLY FROM A SCAN THAT ACTUALLY FINISHED ═══════════════════
 *
 * Spec 2026-11-26. Green meant "the newest job row has no open threats",
 * whatever happened to that job. The updater cancels running scans on every
 * release ("cancelled (stopped by the 4.37.12 update)"), so after each update
 * the pill read "No open threats / The last scan finished and nothing is
 * open" about a scan that had not finished. And once the scheduler resumed it,
 * the newest row was `running` with no finished_at, so a server scanned every
 * night for months read "Not yet scanned".
 *
 * Also: a customer's one-account scan finishing is not a server scan. Of 132
 * accounts it looked at one, so it must not refresh the server's green.
 *
 * The decision is now Scanner::protectionStatus(), fed by getStats(), so it is
 * tested here by BEHAVIOUR against seeded scan_jobs rows, not by source text.
 */

$now = time();
$day = 86400;
$seed = function (array $rows) use (&$now) {   // one clock: seeding and judging read the same $now
    Database::query('DELETE FROM scan_jobs');
    foreach ($rows as $r) {
        Database::insert('scan_jobs', $r + ['scan_type' => 'quick', 'scan_path' => '/home',
                                            'requested_by' => '@schedule', 'files_scanned' => 10]);
    }
    $s = (new Scanner())->getStats($now);
    // A backend without the decision fails each assertion below, not one crash.
    $s['protection'] = ($s['protection'] ?? null)
        ?: ['state' => '(missing)', 'text' => '', 'title' => '', 'badge' => ''];
    return $s;
};
$done = function (int $agoSecs, array $extra = []) use ($now) {
    return $extra + ['status' => 'done', 'started_at' => $now - $agoSecs - 600,
                     'finished_at' => $now - $agoSecs];
};
$upd = ['status' => 'cancelled', 'started_at' => $now - 900, 'finished_at' => $now - 600,
        'stop_reason' => 'stopped by the 4.37.12 update'];

// 1. Update-cancelled newest job, a complete scan 1 day ago: green, and says so.
$s = $seed([$done($day), $upd]);
t_eq('clean', $s['protection']['state'],
     'CASE 1: a routine update-cancel after a complete scan yesterday stays green; '
   . 'amber after every release would teach the operator to ignore amber');
t_contains($s['protection']['title'], 'A later scan was cancelled (stopped by the 4.37.12 update)',
     'and the title admits the later scan did not finish');
t_ok(strpos($s['protection']['title'], 'The last scan finished and nothing is open') === false,
     'the old sentence is not shown: the last scan did NOT finish');
t_eq($day, $s['last_done_scan']['age_secs'] ?? null,
     'getStats() returns the complete scan with its age computed by the server');
t_eq('cancelled', $s['last_finished_scan']['status'] ?? null,
     'and the newest finished job, whatever its status');
t_eq('cancelled', $s['last_scan']['status'] ?? null,
     'last_scan keeps its old meaning, so its other callers are unchanged');

// 2. Same, but resumed: the newest job is running.
$s = $seed([$done($day), $upd, ['status' => 'running', 'started_at' => $now - 60]]);
t_eq('clean', $s['protection']['state'],
     'CASE 2: a resumed scan running does not turn a scanned server into "Not yet scanned"');
t_contains($s['protection']['title'], 'A scan is running now',
     'and the title says one is running');

// 3. Did not finish, no complete scan within 8 days: amber, never green.
foreach (['failed', 'interrupted', 'cancelled'] as $st) {
    $s = $seed([$done(10 * $day),
                ['status' => $st, 'started_at' => $now - 900, 'finished_at' => $now - 600,
                 'stop_reason' => 'worker pid 4242 is gone']]);
    t_eq('partial', $s['protection']['state'],
         "CASE 3 ($st): a scan that did not finish, with nothing complete in 8 days, is amber");
    t_eq('Last scan did not finish', $s['protection']['text'], "and the pill says so ($st)");
    t_eq('Not finished', $s['protection']['badge'], "and the card badge says so ($st)");
    t_contains($s['protection']['title'], $st . ' (worker pid 4242 is gone)',
               "the title gives the status and the reason ($st)");
    t_contains($s['protection']['title'], '10 days ago',
               "and the age of the last complete scan ($st)");
}
$s = $seed([['status' => 'failed', 'started_at' => $now - 900, 'finished_at' => $now - 600]]);
t_contains($s['protection']['title'], 'No complete server scan on record',
     'a failed first scan says there is no complete scan, rather than inventing one');

// 4. The only complete scan is 9 days old.
$s = $seed([$done(9 * $day)]);
t_eq('partial', $s['protection']['state'], 'CASE 4: a complete scan 9 days old is amber, not green');
t_eq('Last complete scan 9 days ago', $s['protection']['text'], 'and says how old');
$s = $seed([$done(691200)]);
t_eq('clean', $s['protection']['state'], 'exactly 8 days is still inside the window');

// 5. Incomplete wins over a recent complete scan (4.37.11 behaviour kept).
$s = $seed([$done($day),
            ['status' => 'incomplete', 'started_at' => $now - 900, 'finished_at' => $now - 600]]);
t_eq('partial', $s['protection']['state'], 'CASE 5: a capped newest scan is amber');
t_eq('Last scan incomplete', $s['protection']['text'], 'with the 4.37.11 words');

// 6. Nothing, or only a running first scan.
$s = $seed([]);
t_eq('never', $s['protection']['state'], 'CASE 6: no jobs at all is "never"');
t_eq(null, $s['last_done_scan'], 'last_done_scan is null, not an empty row');
$s = $seed([['status' => 'running', 'started_at' => $now - 60]]);
t_eq('never', $s['protection']['state'], 'a running first scan is still "never"');
t_eq('First scan in progress.', $s['protection']['title'], 'but the title says it is in progress');

// 7. Open threats beat every other state. getStats() counts the threats
// table, not the job, so one active row is enough whatever scan_jobs holds.
foreach ([[$done($day)], [], [$done($day), $upd]] as $i => $rows) {
    Database::query('DELETE FROM threats');
    $s = $seed($rows);
    Database::insert('threats', ['scan_job_id' => $s['last_scan']['id'] ?? null, 'file_path' => '/home/a/x.php',
                                 'status' => 'active']);
    $s = (new Scanner())->getStats($now);
    t_eq('threat', $s['protection']['state'] ?? null, "CASE 7.$i: an open threat is red whatever the scans did");
}
Database::query('DELETE FROM threats');

// THE SCOPE RULE. A customer's one-account scan is the newest finished job;
// the last server-wide scan is 10 days old. Green would be a false clean.
$s = $seed([$done(10 * $day),
            $done(3600, ['requested_by' => 'alice', 'scan_path' => '/home/alice'])]);
t_ok($s['protection']['state'] !== 'clean',
     'SCOPE: a customer finishing a scan of their own account must not make the whole '
   . 'server read Protected when the last server-wide scan is 10 days old');
t_eq('Last complete scan 10 days ago', $s['protection']['text'],
     'it reads amber with the age of the last SERVER scan, not the customer\'s');
t_eq(10 * $day, $s['last_done_scan']['age_secs'] ?? null,
     'last_done_scan skips the customer scan and reports the server-wide one');
$s = $seed([$done(3600, ['requested_by' => 'alice', 'scan_path' => '/home/alice'])]);
t_eq('No complete server scan', $s['protection']['text'],
     'only a customer scan on record is amber "No complete server scan", not green');

$homes = ['/home/alice', '/home/bob'];
t_ok(Scanner::isServerWideJob(['requested_by' => '@operator', 'scan_path' => '/home/alice,/home/bob'], $homes),
     'an operator quick scan over every account home is server-wide');
t_ok(!Scanner::isServerWideJob(['requested_by' => '@operator', 'scan_path' => '/home/alice'], $homes),
     'an operator scan of SOME accounts is not');
t_ok(Scanner::isServerWideJob(['requested_by' => '@schedule', 'scan_path' => '/home'], $homes),
     'a scheduled scan of /home is');
t_ok(Scanner::isServerWideJob(['requested_by' => '', 'scan_path' => '/'], $homes),
     'a CLI full scan of / is');
t_ok(Scanner::isServerWideJob(['requested_by' => '@cli', 'scan_path' => '/home'], $homes),
     'a `serverscrub scan` from the CLI (tagged @cli) over /home is server-wide; '
   . 'excluding it showed a false amber after an admin scanned everything');
t_ok(!Scanner::isServerWideJob(['requested_by' => '@cli', 'scan_path' => '/home/alice'], $homes),
     'but a CLI scan of one account is not');
t_ok(!Scanner::isServerWideJob(['requested_by' => 'alice', 'scan_path' => '/home'], $homes),
     'a customer request is never server-wide, whatever path it names');
$more = ['/home/alice', '/home/bob', '/home/carol'];
t_ok(!Scanner::isServerWideJob(['requested_by' => '@schedule', 'scan_path' => '/home/alice,/home/bob'], $more),
     'a sweep that predates a new account no longer covers the server');

// Failure behaviour, by the pure function.
t_eq('partial', Scanner::protectionStatus(0, null, ['id' => 2, 'status' => 'done', 'finished_at' => $now],
        ['id' => 2, 'finished_at' => $now + 3600, 'age_secs' => -3600], $now)['state'],
     'a complete scan "finished" in the future does not count as recent');

// ── The page side: green only from the explicit clean branch ──────────────

t_contains($fn, 'const p = sc?.protection;', 'the pill renders the server\'s decision');
$a = (int) strpos($fn, 'if (!p ||');
$b = (int) strpos($fn, 'const title');
$noP = ($a > 0 && $b > $a) ? substr($fn, $a, $b - $a) : '';
t_ok($noP !== '' && strpos($noP, "'clean'") === false,
     'CASE 8: a payload WITHOUT the decision (old backend, failed fetch) can reach '
   . 'threat, never or amber, but no green branch');
t_contains($noP, "'partial', 'No complete scan on record'", 'and its amber says why');
t_contains($dash, 'topStatusFor(sc)',
     'CASE 9: the card renders the same function the pill does, so they cannot disagree');
t_ok(strpos($dash, "lastJob.status === 'incomplete'") === false
   && strpos($dash, '} else if (!lastJob?.finished_at) {') === false,
     'and no longer keeps its own cascade on the newest job row, which is what made '
   . 'a running scan read "Not yet scanned"');
