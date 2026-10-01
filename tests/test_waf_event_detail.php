<?php
/**
 * WAF event detail, and the data it renders.
 *
 * Requested: clicking a WAF log row should open a dialog with the full detail.
 * The table truncates the message and the URI -- the two fields that say what
 * was actually attempted -- so a row could be read but not understood.
 *
 * Two defects were visible in the same screenshot and are fixed here too.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$waf  = t_code($repo . '/backend/lib/WAF.php');
$js   = file_get_contents($repo . '/frontend/js/app.js');
$html = file_get_contents($repo . '/frontend/index.html');

// -- The source IP was never parsed, so every row showed a blank ------------
// ModSecurity section A is "[time] uniqueId clientIp clientPort serverIp
// serverPort". The old pattern looked for an IP immediately after the closing
// bracket, where the unique id actually is, so it never matched -- the table
// listed attacks with no way to act on their source.
t_contains($waf, 'server_ip', 'the server address is captured as well');
t_ok(strpos($waf, "'/\] (\d+\.\d+\.\d+\.\d+) /'") === false,
    'the pattern that never matched is gone');
t_contains($waf, '[0-9a-fA-F:.]', 'and the replacement accepts IPv6 too');

// The regex is the fix, so assert it against a real line rather than its shape.
$line = '[01/Oct/2026:16:21:03 +0000] aYx9QwAAQgEAAFt2 203.0.113.77 54321 198.51.100.10 443';
$re   = '/^\[[^\]]*\]\s+\S+\s+([0-9a-fA-F:.]+)\s+\d+\s+([0-9a-fA-F:.]+)\s+\d+/';
t_ok(strpos($waf, '^\[[^\]]*\]\s+\S+\s+([0-9a-fA-F:.]+)') !== false,
    'the shipped pattern is the one tested here');
t_eq(1, preg_match($re, $line, $m), 'a real section-A line is matched');
t_eq('203.0.113.77', $m[1], 'and the CLIENT address is what is taken');
t_eq('198.51.100.10', $m[2], 'with the server address kept separate');

$v6 = '[01/Oct/2026:16:21:03 +0000] aYx9Qw 2001:db8::1 54321 2001:db8::2 443';
t_eq(1, preg_match($re, $v6, $m6), 'an IPv6 client is matched');
t_eq('2001:db8::1', $m6[1], 'and parsed correctly');

// The old pattern must genuinely have failed, or this was never the bug.
t_eq(0, preg_match('/\] (\d+\.\d+\.\d+\.\d+) /', $line),
    'the previous pattern does not match a real line, which is why IPs were blank');

// -- user_agent had a column and nothing ever filled it ---------------------
t_contains($waf, '^User-Agent:', 'the user agent is parsed');
t_contains($waf, "'user_agent' => mb_substr", 'and stored, bounded in length');

// -- Attacker-controlled data must not be interpolated raw ------------------
// Every field here arrives in an HTTP request from whoever is attacking the
// server: the URI, the rule message quoting what matched, the user agent. The
// renderer built innerHTML from them unescaped, so a request crafted to carry
// markup would run as script in the dashboard of whoever read the log.
// Anchored on the WAF loader: other pages render tables with the same
// phrasing, and the first match in the file is one of those.
$wafFn  = strpos($js, 'async function loadWAFEvents');
$render = substr($js, $wafFn, 2200);
foreach (['rule_id', 'rule_msg', 'ip_address', 'uri'] as $f) {
    t_contains($render, 'esc(e.' . $f . ')', "the {$f} column is escaped");
}
t_ok(strpos($render, '${e.uri}') === false,
    'no field is interpolated raw any more');
t_ok(strpos($render, '${e.rule_msg}') === false,
    'including the rule message, which quotes the matched request data');

// The dialog uses textContent, not innerHTML, for the same reason.
$show = substr($js, strpos($js, 'function showWafEvent(id)'), 2200);
t_contains($show, 'el.textContent =',
    'the dialog sets text, so markup in an event cannot execute');
t_ok(substr_count($show, '.innerHTML') <= 1,
    'the only innerHTML in the dialog is the severity badge, which is our own markup');

// -- The dialog itself -------------------------------------------------------
t_contains($html, 'id="waf-event-modal"', 'the dialog exists');
t_contains($html, 'role="dialog"', 'announced as a dialog');
t_contains($html, 'aria-modal="true"', 'and as modal');
t_contains($render, 'onclick="showWafEvent(', 'rows open it when clicked');
t_contains($render, 'onkeydown=', 'and can be opened from the keyboard');
t_contains($render, 'tabindex="0"', 'so the rows are reachable by tab');

// The point of the dialog is the fields the table has to truncate.
t_contains($html, 'id="wem-uri"', 'the full URI is shown');
t_contains($html, 'id="wem-msg"', 'and the full rule message');
t_contains($html, 'white-space: pre-wrap', 'wrapped rather than cut off');

// Acting on what you are looking at.
t_contains($js, 'function blockWafEventIp', 'the source address can be blocked from the dialog');
t_contains($js, 'API.fwBlockIP(', 'through the real firewall method');
t_contains($js, 'function lookupWafEventIp', 'or checked for reputation');
t_contains($js, 'function copyWafEvent', 'and the details copied');
t_contains($js, 'function fallbackCopy',
    'with a fallback, since the clipboard API needs a secure context');

// Rows ingested before the parser could read an IP have none, and those two
// buttons would do nothing.
t_contains($show, "el.disabled = !e.ip_address",
    'blocking and lookup are disabled when the event has no source address');

// Clicking the backdrop closes it, but clicking inside must not.
t_contains($html, 'if(event.target===this)closeModal',
    'the backdrop closes the dialog without swallowing clicks inside it');
