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
