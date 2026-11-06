<?php
/**
 * A Refresh button shows that it is working.
 *
 * Reported against the malware scanner: "for scanner logs refresh button does
 * not seem to work. when user clicks it we should be displaying our loding
 * icon while page refreshes in background".
 *
 * It did work. loadScanJobs() ran and re-rendered the table -- but it was
 * wired as a bare onclick, so there was no disabled state, no icon and no
 * confirmation, and between two scans the table comes back IDENTICAL. A click
 * that repaints the same rows is indistinguishable from a click that did
 * nothing, so the button read as broken. Which, as a button, it was.
 *
 * doRefresh() already existed and already did all of this -- 20 of the 23
 * refresh controls used it. The scanner log was one of the three that did not.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$html = (string) file_get_contents($repo . '/frontend/index.html');
$js   = (string) file_get_contents($repo . '/frontend/js/app.js');
$css  = (string) file_get_contents($repo . '/frontend/css/app.css');

// ── The button that was reported ───────────────────────────────────────────
t_contains($html, 'onclick="doRefresh(this, loadScanJobs)"',
     'THE REPORTED BUTTON: the scanner log refresh goes through doRefresh, so '
   . 'it disables itself, shows the icon and confirms when it is done');
t_ok(strpos($html, 'onclick="loadScanJobs()"') === false,
     'and the bare call that gave no feedback at all is gone');

// ── Every refresh control, not just that one ───────────────────────────────
//
// Fixing the one that was reported and leaving its neighbours is how the same
// complaint arrives again next week about a different card.
//
// Scoped to load*() handlers on purpose, because that is the category: a
// function that re-reads data into a card. Two buttons that look similar are
// deliberately NOT in it --
//
//   finishUpdate()   reloads the whole page after an update. There is no card
//                    to show a spinner on, and the page is about to go away.
//   reloadFirewall() reloads rules INTO iptables. It is a server action that
//                    already reports its own result; dressing it as a view
//                    refresh would both double-toast and misdescribe it.
if (preg_match_all('/onclick="(load[A-Za-z]+)\(\)"[^>]*>\s*(?:&#\d+;|[^<]{0,4})\s*(?:Refresh|Reload)/i',
                   $html, $m, PREG_SET_ORDER)) {
    foreach ($m as $hit) {
        t_ok(false, 'refresh control still wired bare: ' . $hit[1] . '()');
    }
} else {
    t_ok(true, 'no Refresh or Reload control is still wired as a bare call '
             . 'with no loading state');
}

// ── The loading icon itself ────────────────────────────────────────────────
//
// The ask was an icon, not a word. The old implementation swapped the label
// for "Refreshing" and nothing moved, which on a fast local request is a
// flicker nobody sees.
t_contains($js, 'class="btn-spin"',
     'THE LOADING ICON: the button shows a spinner while the card reloads');
t_contains($css, '.btn-spin {',
     'and the class exists in the stylesheet — a button that reads '
   . 'class="btn-spin" with no rule behind it shows nothing at all');
t_contains($css, 'animation: update-spin',
     'reusing the existing keyframes rather than declaring a second identical '
   . 'animation');
t_contains($css, 'border: 2px solid currentColor',
     'drawn in the button\'s own colour, so it is visible on a ghost button '
   . 'in either theme');
t_contains($css, 'prefers-reduced-motion',
     'and someone who has asked for less motion gets a static ring — the '
   . 'button is disabled and relabelled too, so it still reads as busy');

// The word stays with the icon: an icon alone does not say what is happening.
t_contains($js, 'Refreshing',
     'the label stays alongside the icon');

// ── What doRefresh actually guarantees ─────────────────────────────────────
$body = t_fn_body($js, 'doRefresh', 'js');

t_contains($body, 'btn.disabled = true',
     'the button is disabled while in flight, so an impatient second click '
   . 'does not fire a second request');
t_contains($body, 'if (elapsed < 350)',
     'A FAST REFRESH IS STILL SEEN TO HAPPEN: a request that returns in 40ms '
   . 'is held to 350ms, because an icon that appears and vanishes within one '
   . 'frame is the same as no icon — and this is a local request against a '
   . 'table that usually comes back unchanged');
t_contains($body, 'btn.innerHTML = original',
     'and the original label is restored afterwards, not a guess at it');
t_contains($body, 'toast(',
     'with a confirmation, since the card itself may legitimately come back '
   . 'identical');
t_contains($body, "catch (e)",
     'a failed refresh says so rather than silently restoring the label, '
   . 'which would look exactly like a successful one');
t_contains($body, 'Last refreshed',
     'and the button records when it last succeeded');
