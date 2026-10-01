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
t_contains($waf, 'FILTER_VALIDATE_IP',
    'addresses are identified by validating tokens, not by counting fields');

// Why that matters, and why this is no longer asserted as a regex shape: the
// number of fields on the line varies. With mod_unique_id it is
//   [time] uniqueId clientIp clientPort serverIp serverPort
// and without it the id is simply absent. Both previous attempts here were
// positional and each missed one of those layouts. tests/test_waf_parse.php
// runs the real ingester over logs in both and checks what reaches the
// database, which is the only assertion that could have caught either bug.
t_ok(strpos($waf, 'preg_split') !== false,
    'the line is tokenised rather than matched positionally');
t_contains($waf, "\$ips[0]", 'the first valid address is taken as the client');
t_contains($waf, "\$ips[1]", 'and the second as the server');

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
