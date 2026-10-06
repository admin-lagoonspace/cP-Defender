<?php
/**
 * The splash must always lift.
 *
 * 4.1.0 shipped with the splash covering a perfectly working app. The call
 * that removes it was inserted into the wrong function -- it landed after a
 * `return` in reltime(), where it was unreachable -- so openPage() never
 * dismissed it. On a server with a session, which is every cPanel install, the
 * first thing the user saw was a logo that never went away. Nothing errored;
 * the app was running fine behind a cover that never lifted.
 *
 * The browser check at the time only exercised the UNAUTHENTICATED path, where
 * a separate timer happened to dismiss it. The broken path was the one nobody
 * looked at.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$js   = file_get_contents($repo . '/frontend/js/app.js');
$html = file_get_contents($repo . '/frontend/index.html');

// ── The render path dismisses it ────────────────────────────────────────────
$start = strpos($js, 'function openPage(name)');
t_ok($start !== false, 'openPage exists');

// Bounded by the next top-level function, so "inside openPage" means inside it.
$end = strpos($js, "\nfunction ", $start + 10);
$body = substr($js, $start, $end - $start);
t_contains($body, 'dismissSplash()',
    'openPage dismisses the splash once the page is drawn');

// ── And it is reachable ─────────────────────────────────────────────────────
// This is the exact accident: a call placed after a return runs never, and no
// syntax check or bracket count notices.
$lines = explode("\n", $body);
$seenReturn = false;
$unreachable = false;
$depth = 0;
foreach ($lines as $ln) {
    $t = trim($ln);
    if ($seenReturn && strpos($t, 'dismissSplash()') !== false) { $unreachable = true; }
    if (preg_match('/^return\b/', $t)) { $seenReturn = true; }
    if (strpos($t, '}') !== false) { $seenReturn = false; }   // new block
}
t_ok(!$unreachable, 'the call is not stranded after a return');

// Nowhere else in the file either.
$all = explode("\n", $js);
$bad = [];
for ($i = 1; $i < count($all); $i++) {
    if (strpos($all[$i], 'dismissSplash()') === false) { continue; }
    $prev = trim($all[$i - 1]);
    if (preg_match('/^return\b/', $prev)) { $bad[] = $i + 1; }
}
t_eq(0, count($bad),
    'no dismissSplash call sits directly after a return'
    . ($bad ? ' — line(s) ' . implode(', ', $bad) : ''));

// ── The failsafe ────────────────────────────────────────────────────────────
// A cover that can stick is worse than no cover. These remove it whether or
// not anything on the render path remembered to.
t_contains($js, "window.addEventListener('load'",
    'the splash is also removed when the window finishes loading');
t_contains($js, 'setTimeout(dismissSplash',
    'and on a timer, so no single broken path can strand the user');
$fs = substr($js, strpos($js, 'let _splashGone'), 900);
t_contains($fs, 'A cover that can stick is worse than no cover',
    'the reason is recorded where the timers are');

// Both failsafes must be scheduled OUTSIDE any function, or they never arm.
$loadIdx = strpos($js, "window.addEventListener('load', () => setTimeout(dismissSplash");
$fnIdx   = strpos($js, 'function dismissSplash()');
t_ok($loadIdx !== false && $fnIdx !== false && $loadIdx < $fnIdx,
    'the failsafes are at module scope, not nested inside something');

// ── Dismissal is idempotent ─────────────────────────────────────────────────
// Three paths can call it; the second and third must be harmless.
t_contains($js, 'if (_splashGone) return;', 'dismissing twice is a no-op');

// ── The unauthenticated path keeps its own dismissal ────────────────────────
t_contains($html, 'dismissSplash',
    'the login path dismisses it too, since no page is coming');
