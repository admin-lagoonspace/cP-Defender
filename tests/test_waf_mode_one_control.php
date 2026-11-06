<?php
/**
 * There is one WAF mode, one place that sets it, and the panel shows it.
 *
 * Reported: "at the top i selected enforcement rule and clicked apply but
 * right below it WAF engine does not update it still shows as detection only.
 * wonder if both are even working and are cpnnected".
 *
 * They were not connected. Three separate defects, stacked:
 *
 *  1. TWO IMPLEMENTATIONS, TWO FILES. The page header's Apply Mode called
 *     WAF::setMode(), which rewrote the VENDOR config
 *     (modsec_vendor_configs/modsecurity.conf). The WAF Engine card's selector
 *     called WAFInstaller::setMode(), which writes serverscrub-waf.conf --
 *     the file we own, included after the vendor's, and therefore the one
 *     whose SecRuleEngine decides. Editing the vendor file changed nothing a
 *     request would ever notice.
 *
 *  2. IT COULD NOT FAIL. The edit sat behind `is_readable`, so on a server
 *     where that path does not exist -- most of them -- the whole block was
 *     skipped and the method returned success anyway. No write check, no
 *     `apachectl -t`, no check that the reload worked.
 *
 *  3. THE MODE TILE WAS A STRING LITERAL. `textContent = 'On'`. It read
 *     nothing, so it said On beside an engine reading detectiononly, and
 *     would have said On with ModSecurity not installed at all.
 *
 * Which answers the operator's follow-up -- "if we dont block WAF attacks
 * then whats the use of having it there". Detection only is the right
 * DEFAULT for a new install, for the week it takes to review false
 * positives. It is not a resting place, and this server sat in it through
 * 148,551 events not by choice but because the control that would have
 * changed it did nothing and said it had worked.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$src = (string) file_get_contents($repo . '/backend/lib/WAF.php');
$js  = (string) file_get_contents($repo . '/frontend/js/app.js');
$html = (string) file_get_contents($repo . '/frontend/index.html');

// ── One implementation ─────────────────────────────────────────────────────
$set = t_fn_body($src, 'setMode', 'php');

t_contains($set, 'WAFInstaller::setMode',
     'ONE IMPLEMENTATION: WAF::setMode delegates rather than writing its own '
   . 'copy of the config. Two writers for one setting is how the header and '
   . 'the card came to disagree in public');

t_ok(strpos($set, 'preg_replace') === false,
     'and it no longer rewrites the vendor config — a file whose '
   . 'SecRuleEngine our own include overrides, so editing it changed nothing '
   . 'a request would notice');

t_ok(strpos($set, "return ['success' => true, 'mode' => \$mode];") !== false
     && strpos($set, "if (empty(\$r['success'])) { return \$r; }") !== false,
     'A FAILURE IS REPORTED AS A FAILURE: the old version returned success '
   . 'unconditionally, which is why pressing Apply Mode on a server where '
   . 'that path does not exist reported that it had worked');

// The delegate is the one that validates before reloading. Checked here
// because that is the property being relied on by delegating to it.
$inst = (string) file_get_contents($repo . '/backend/lib/WAFInstaller.php');
$isetm = t_fn_body($inst, 'setMode', 'php');
t_contains($isetm, 'validateApache',
     'and the implementation it delegates to runs apachectl -t first — a bad '
   . 'config reloaded into Apache takes the whole server down, not just the '
   . 'WAF');
t_contains($isetm, "if (!\$v['ok'])",
     'and refuses to reload when the check fails');

// ── The status reports the mode that actually applies ──────────────────────
$get = t_fn_body($src, 'getMode', 'php');
t_contains($get, 'WAFInstaller::currentMode()',
     'OUR CONFIG IS READ FIRST: it is included after the vendor\'s and wins, '
   . 'so reading only the vendor file reported a mode that had been '
   . 'overridden');
t_contains($get, "return 'unknown';",
     'and an unreadable config is "unknown", never "On" — a status that '
   . 'assumes it is protecting you is the one assumption this must not make');

// ── The tile reads something ───────────────────────────────────────────────
t_ok(strpos($js, "getElementById('waf-stat-mode').textContent     = 'On'") === false,
     'THE HARD-CODED TILE IS GONE: it was the literal word "On", so it said '
   . 'On beside an engine in detectiononly, and would have said On with '
   . 'ModSecurity not installed');
t_contains($js, "setText('waf-stat-mode', wafModeLabel(d.mode))",
     'and now shows the mode the server reported');

t_contains($js, 'function wafModeLabel(',
     'one spelling of the mode for the whole page');
t_contains($js, "return 'Unknown';",
     'including Unknown, which is shown rather than smoothed into On');

// ── Both controls are the same control ─────────────────────────────────────
$hdr = t_fn_body($js, 'setWAFMode', 'js');
t_contains($hdr, 'setWafEngineMode(',
     'THE HEADER BUTTON AND THE CARD SELECTOR NOW DO THE SAME THING — '
   . 'the reported bug was pressing one and watching the other not change');
t_ok(strpos($hdr, 'API.wafSetMode') === false,
     'the header no longer calls the second endpoint');

$eng = t_fn_body($js, 'setWafEngineMode', 'js');
t_contains($eng, 'await loadWafEngine();',
     'applying a mode re-reads the engine');
t_contains($eng, 'loadWAF()',
     'AND the stats row, so the Mode tile cannot keep showing the old value '
   . '— refreshing only the card is how a failed change looked exactly like '
   . 'a successful one');
t_contains($eng, 'res && res.success',
     'and the toast reflects what the server said, not what was asked for');

// Blocking is still confirmed: a false positive in blocking mode turns away
// real visitors, and that is a decision, not a click.
t_contains($eng, "mode === 'on' && !confirm(",
     'switching to blocking is still confirmed — now from the header button '
   . 'too, which previously applied it with no warning at all');

// ── The selectors agree with the engine, and with each other ───────────────
$load = t_fn_body($js, 'loadWafEngine', 'js');
t_contains($load, "getElementById('waf-mode-sel')",
     'the header selector is set from the engine\'s reported mode, instead of '
   . 'sitting on whatever it was left on after a change that did not take');
t_contains($load, 'wafModeLabel(d.mode)',
     'and the Mode row uses the same label as the tile');

// The header's options read as choices. "Enforcement Mode" looked like a
// heading, which is part of how a mode change gets made without noticing it
// has not taken.
t_contains($html, '<option value="On">Blocking (enforce rules)</option>',
     'the header options are worded like the card\'s, as choices rather than '
   . 'a heading');
t_ok(strpos($html, '<option value="On">Enforcement Mode</option>') === false,
     'and the heading-shaped label is gone');

// ── A way to check from outside the panel ──────────────────────────────────
$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, "case 'waf': {",
     'the mode can be read and set from the shell — when a control cannot be '
   . 'trusted, a path that shows its working is what settles it');
t_contains($cli, 'WAFInstaller::currentMode()',
     'reading back from the config Apache actually loads');
t_contains($cli, "'applied'   => \$now === \$want",
     'AND IT READS BACK AFTER WRITING: reporting the requested value is '
   . 'precisely the mistake the panel made');
t_contains($cli, 'WARNING: Apache reloaded but the config still reads',
     'a write that did not take exits non-zero and says so');
t_contains($cli, "require_once \$BASE . '/lib/WAFInstaller.php';",
     'and the CLI requires the class it calls');
