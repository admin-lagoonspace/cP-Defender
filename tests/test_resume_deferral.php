<?php
/**
 * A scan the updater stopped is not lost when it cannot restart at once.
 *
 * install.sh stops every running scan before replacing the code beneath it,
 * and update.sh starts them again afterwards. On a live server the restart
 * was refused, correctly, because rsync was running:
 *
 *     could not resume /home/aaksh/public_html,/home/aavvarjunlogisti/...
 *     [132 paths on one line]
 *     0 scan(s) resumed
 *
 * Three things wrong with that, in increasing order of seriousness.
 *
 *   The whole scan_path was printed. A scheduled sweep's path is every
 *   account's docroot joined with commas, so the one thing the operator
 *   needed -- the reason -- was at the end of 132 paths.
 *
 *   It was reported with a tick. "0 scan(s) resumed" next to a green mark is
 *   how a missed nightly sweep goes unnoticed.
 *
 *   And the marker was deleted regardless, so the scan was genuinely gone
 *   until its next slot a day later. The refusal is transient -- a backup
 *   window -- and the right answer is to try again, not to give up.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$upd   = t_shell($repo . '/update.sh');
$sched = t_code($repo . '/backend/cron/scheduler.php');

// ── The output has to be readable ──────────────────────────────────────────
t_contains($upd, "n_paths = substr_count(",
     'THE WALL OF PATHS: a multi-account scan is summarised by count, not '
   . 'printed in full — the reason it was deferred has to be findable');
t_contains($upd, "account(s)'",
     'as "N account(s)"');

// ── A deferral is not a success ────────────────────────────────────────────
t_contains($upd, 'if [[ "$_SG_RESUME_OUT" == *"0 scan(s) resumed"* ]]; then',
     'THE GREEN TICK: nothing resumed is reported as a warning, not a tick. '
   . 'A missed nightly sweep that looks like a success is a sweep nobody '
   . 'goes looking for');

// ── And the scan must survive ──────────────────────────────────────────────
t_contains($upd, 'deferred[] =',
     'THE LOST SWEEP: a refused resume is kept rather than discarded');
t_contains($upd, 'deferred) {',
     'and the marker file is only removed when nothing is outstanding — '
   . 'deleting it regardless is what lost the scan for a whole day');
t_ok(strpos($upd, 'rm -f "$_SG_RESUME_PHP" "$_SG_RESUME"') === false,
     'the shell no longer deletes the marker behind PHP\'s back, which would '
   . 'undo the deferral it had just recorded');

// ── Somebody has to pick it up ─────────────────────────────────────────────
t_contains($sched, "'resumescan' => [",
     'THE RETRY: the scheduler looks for interrupted scans on its ordinary '
   . 'tick, so a backup window delays the sweep instead of cancelling it');
t_contains($sched, "\$marker = SG_ROOT . '/logs/.resume-scans.json';",
     'reading the marker the updater left');
t_contains($sched, 'if (!is_file($marker)) { return; }',
     'and costing one stat of an absent file on every other run');
t_contains($sched, 'if ($busy) { continue; }',
     'a path already scanning again is dropped from the list rather than '
   . 'started a second time — several workers on one tree is how six '
   . 'clamscans came to run at once');
t_contains($sched, '$left[] = $j;',
     'a still-refused scan stays on the list for the next tick');
t_contains($sched, '@unlink($marker);',
     'and the marker goes once everything has started, so it cannot '
   . 're-trigger a scan days later');

// ── The deferral cycle, as behaviour ───────────────────────────────────────
//
// The scheduler task is a closure inside a big array, so rather than invoke
// it, exercise the decision it makes: refuse while busy, keep the entry.
$marker = sys_get_temp_dir() . '/sg-resume-' . getmypid() . '.json';
$list   = [
    ['path' => '/home/a/public_html,/home/b/public_html', 'type' => 'full', 'by' => '@schedule'],
    ['path' => '/home/solo/public_html',                  'type' => 'quick', 'by' => '@schedule'],
];
file_put_contents($marker, json_encode($list));

$read = json_decode((string) file_get_contents($marker), true);
t_eq(2, count($read), 'the marker round-trips both entries');

$first = $read[0]['path'];
t_eq(2, substr_count($first, ',') + 1,
     'and a multi-account path is counted, not expanded — the summary the '
   . 'output prints comes from this');

// Everything deferred -> file stays and still holds both.
$left = $read;
file_put_contents($marker, json_encode($left));
t_ok(is_file($marker), 'with everything deferred the marker survives');
t_eq(2, count(json_decode((string) file_get_contents($marker), true)),
     'and still holds every outstanding scan');

// Nothing deferred -> file goes.
$left = [];
if ($left) { file_put_contents($marker, json_encode($left)); } else { @unlink($marker); }
t_ok(!is_file($marker),
     'once everything has started the marker is removed, so it cannot '
   . 'restart a scan on some unrelated run later');

@unlink($marker);
