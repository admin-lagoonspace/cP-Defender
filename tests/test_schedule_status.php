<?php
/**
 * Telling an operator whether the scheduler is actually running.
 *
 * I told the user to grep logs/scheduler.log. No such file exists: slog()
 * writes to stdout and cron redirects it into logs/cron.log, one file holding
 * every task's output interleaved. There was no way at all to answer "is my
 * nightly scan running?" short of reading the settings table by hand -- which
 * is a poor state for the question an operator asks when something is wrong.
 *
 * The first draft of the status command kept its own copy of the task table.
 * It was wrong before it shipped: one setting key misspelled
 * (fwprobe_schedule for fw_probe_schedule), one task that does not exist
 * (cleanup), and five real tasks missing. So the report is built from the
 * scheduler's own $tasks, and this test pins that it cannot drift again.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$sched = $repo . '/backend/cron/scheduler.php';
$src   = t_code($sched);

// -- The report is built from the real task table ----------------------------
t_contains($src, "elseif (\$argv[\$i] === '--status')", 'the scheduler takes --status');

$statusBlock = substr($src, strpos($src, 'if ($status) {'), 1600);
t_contains($statusBlock, 'foreach ($tasks as $name => $t)',
    'the report iterates the scheduler\'s own task table, so it cannot drift from it');
t_contains($statusBlock, "lastRun(\$name)", 'reading each task\'s real last-run time');
t_ok(strpos($statusBlock, '_schedule') === false,
    'and it does not hardcode setting keys, which is how the first draft got them wrong');

// -- It runs before anything else, and without a licence ---------------------
// A diagnostic that refuses to answer while something is wrong is no use.
t_contains($src, 'if (!$status && !License::protectionAllowed())',
    'the licence gate lets a read-only status report through');

$gatePos   = strpos($src, 'License::protectionAllowed()');
$statusPos = strpos($src, 'if ($status) {');
$runPos    = strpos($src, '$outcome = $t[\'run\']();');
t_ok($statusPos !== false && $runPos !== false && $statusPos < $runPos,
    'the report is printed before any task is executed, so asking for status '
  . 'never starts a scan as a side effect');
t_contains($statusBlock, 'exit(0)', 'and it exits rather than falling through into the run loop');

// -- Behaviour: every task the scheduler knows about is reported -------------
$php = PHP_BINARY;
$out = [];
@exec(escapeshellarg($php) . ' ' . escapeshellarg($sched) . ' --status 2>&1', $out);
$text = implode("\n", $out);

t_contains($text, 'TASK', 'the report has a header');

// Each task name in $tasks must appear in the output.
preg_match_all("/^    '([a-z]+)' => \[\$/m", file_get_contents($sched), $m);
$taskNames = $m[1];
t_ok(count($taskNames) >= 10, 'the scheduler defines a real set of tasks ('
    . count($taskNames) . ')');

$missing = [];
foreach ($taskNames as $n) {
    if (strpos($text, $n) === false) { $missing[] = $n; }
}
t_eq(0, count($missing), 'every scheduled task appears in the report'
    . ($missing ? ' -- missing: ' . implode(', ', $missing) : ''));

// -- A task that has never run says so, loudly -------------------------------
// This is the state the reporting server was in, and the state that needed a
// name: the nightly scan had been deferred-and-marked-run every night.
t_contains($text, 'NEVER RUN', 'a task that has never run is called out');

// -- An overdue task is distinguished from a healthy one ---------------------
// Asserted on the source rather than by driving the subprocess: scheduler.php
// resolves SG_ROOT from its own location, so a child process reads the real
// database rather than this sandbox, and there is no env override worth adding
// to production code purely to make this one assertion behavioural.
t_contains($statusBlock, "['every' => 900, 'hourly' => 3600,",
    'each schedule carries its own period');
t_contains($statusBlock, "'daily' => 86400, 'weekly' => 604800]",
    'including daily and weekly');
t_contains($statusBlock, '($now - $last) > ($limit * 2)',
    'and a task silent for twice its own period is reported as overdue -- which '
  . 'is exactly the symptom a nightly scan that never runs would show');
t_contains($statusBlock, "'OVERDUE'", 'by that name');
t_contains($statusBlock, "'NEVER RUN'", 'and one that has never run by its own');
t_contains($statusBlock, "'disabled'", 'while a task switched off is not called broken');

// -- The operator is pointed at the file that exists -------------------------
t_contains($text, 'cron.log',
    'the report names the log file cron actually writes, not an invented one');
t_ok(strpos($text, 'scheduler.log') === false,
    'and never mentions scheduler.log, which does not exist');

// -- The CLI exposes it without keeping a second copy ------------------------
$cli = t_code($repo . '/backend/cli/serverscrub.php');
t_contains($cli, "case 'schedule':", 'the CLI has a schedule command');
t_contains($cli, '--status', 'which delegates to the scheduler');
t_contains($cli, 'cron/scheduler.php', 'by running it');
t_ok(strpos($cli, "'scan_schedule'") === false,
    'and does not keep its own copy of the task table');

$help = file_get_contents($repo . '/backend/cli/serverscrub.php');
t_contains($help, 'schedule                     Show every scheduled task',
    'and it is listed in the help');

// -- get.sh must not install a stale version ---------------------------------
// Reported: the install command published 4.3.0 and the server ended up on
// 4.2.0. raw.githubusercontent.com serves through a CDN with a short TTL, so
// for a few minutes after a release it keeps handing out the previous
// latest.json -- and the installer believed it.
$get = file_get_contents($repo . '/get.sh');
t_contains($get, 'fetch_manifest()', 'the manifest has its own fetch');
t_contains($get, '_=$(date +%s)', 'which makes each request a cache miss');
t_ok(strpos($get, 'fetch "${BASE}/latest.json"') === false,
    'and no manifest read goes through the plain cached fetch');
t_contains($get, 'fetch_manifest "${BASE}/latest.json"',
    'the primary manifest read is cache-busted');

// The zip must NOT be cache-busted: it is content-addressed by the sha256 in
// the manifest, so a stale copy is caught by the checksum rather than by a
// query string, and busting it would defeat mirroring.
t_ok(strpos($get, 'fetch_to') !== false, 'the archive still uses the ordinary fetch');
$ft = substr($get, strpos($get, 'fetch_to() {'), 240);
t_ok(strpos($ft, 'date +%s') === false,
    'the archive download is not cache-busted -- its checksum is what guards it');
