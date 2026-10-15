<?php
/**
 * The scan types, the nightly schedule, and stopping a scan you did not start.
 *
 * Four faults reported together from a live server.
 *
 *   1. The nightly scan never ran. The scheduler marks a task as run whenever
 *      its closure returns normally -- and the scan task returns normally when
 *      it defers for a backup. On a server whose JetBackup window covers the
 *      02:00 scan time, every nightly scan was deferred AND recorded as having
 *      run, so a 'daily' task was not due again for 24 hours. For ever.
 *
 *   2. Quick, Full and Custom scanned byte-for-byte the same tree. scan_type
 *      was written to the database and never read again. Three options that do
 *      the same thing are worse than one, because the operator believes they
 *      chose something.
 *
 *   3. Custom offered a free-text directory box. On a shared server an
 *      operator thinks in accounts, not paths.
 *
 *   4. The Stop button lived inside a progress card that only appeared for a
 *      scan THIS browser tab had started. A scan started by cron, by another
 *      admin, or before a page reload could not be stopped from the interface
 *      at all.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

// -- 1. A deferred task stays due --------------------------------------------
$sched = t_code($repo . '/backend/cron/scheduler.php');

t_contains($sched, '$outcome = $t[\'run\']();',
    'the scheduler looks at what a task returned');
t_contains($sched, 'if ($outcome === false) {',
    'and a task that returns false is not marked as run');

// The ordering is the whole fix: markRun must be unreachable for a deferral.
$loop     = substr($sched, strpos($sched, '$outcome = $t['), 420);
$deferPos = strpos($loop, '$outcome === false');
$markPos  = strpos($loop, 'markRun($name)');
t_ok($deferPos !== false && $markPos !== false && $deferPos < $markPos,
    'the deferral check comes BEFORE markRun, or the task is recorded as run anyway');

// And the scan task has to actually use it.
$scanTask = substr($sched, strpos($sched, "'scan' => ["), 2200);
t_contains($scanTask, 'scan deferred',
    'the scan task still defers while a backup runs');
$deferLine = strpos($scanTask, 'scan deferred');
$afterDefer = substr($scanTask, $deferLine, 120);
t_contains($afterDefer, 'return false',
    'and returns false, so the nightly scan stays due instead of being skipped '
  . 'for a day every time a backup overlaps the scan window');

// Contention is transient too: a scan already running at 02:00 must not cost
// the server its nightly scan.
t_ok(substr_count($scanTask, 'return false') >= 2,
    'a scan that could not start because one was already running also stays due');

// A missing path is NOT transient and must not spam the log every tick.
t_contains($scanTask, 'no usable scan paths',
    'a misconfigured path is still reported');

// -- 2. The scan types resolve to different things ---------------------------
$home = $ctx['sandbox'] . '/srv';
@mkdir($home . '/alice/public_html', 0777, true);
@mkdir($home . '/alice/mail',        0777, true);
@mkdir($home . '/bob/public_html',   0777, true);
@mkdir($home . '/carol',             0777, true);   // no web root
@mkdir($home . '/.serverscrub',      0777, true);   // ours, not an account

Database::setSetting('scan_paths', $home);

$accts = [];
foreach (Scanner::listAccounts() as $a) { $accts[$a['user']] = $a; }

t_ok(isset($accts['alice']) && isset($accts['bob']) && isset($accts['carol']),
    'every account under the scan root is listed');
t_ok(!isset($accts['.serverscrub']),
    'our own directory is not offered as an account');
t_eq(true,  $accts['alice']['has_web'], 'an account with a web root says so');
t_eq(false, $accts['carol']['has_web'], 'and one without says so too');
t_eq($home . '/alice/public_html', $accts['alice']['docroot'], 'with its document root');

// Quick: web roots only.
$q = Scanner::resolveScanPaths('quick', $home);
sort($q['paths']);
t_eq([$home . '/alice/public_html', $home . '/bob/public_html'], $q['paths'],
    'a quick scan walks the web roots, where public code runs');
t_ok(strpos($q['note'], 'web root') !== false, 'and says what it chose');

// Full: everything.
$f = Scanner::resolveScanPaths('full', $home);
t_eq([$home], $f['paths'], 'a full scan walks the configured roots entire');

// They must genuinely differ, which is the entire complaint.
t_ok($q['paths'] !== $f['paths'],
    'quick and full resolve to different paths -- before this they were identical, '
  . 'so the three options in the dropdown did nothing at all');

// Custom: the chosen accounts.
$c = Scanner::resolveScanPaths('custom', $home . '/alice,' . $home . '/carol');
sort($c['paths']);
t_eq([$home . '/alice', $home . '/carol'], $c['paths'],
    'a custom scan walks exactly the accounts picked');

// A path that does not exist is dropped rather than handed to the worker.
$c2 = Scanner::resolveScanPaths('custom', $home . '/alice,' . $home . '/nobody');
t_eq([$home . '/alice'], $c2['paths'], 'a non-existent account is dropped');

// Selecting nothing must not become "scan everything".
$c3 = Scanner::resolveScanPaths('custom', '');
t_eq([], $c3['paths'],
    'a custom scan with nothing selected resolves to nothing, not to the whole server');

// -- Quick must degrade honestly ---------------------------------------------
// A server with no public_html anywhere must still scan something, and must
// not pretend a full scan was a quick one.
$bare = $ctx['sandbox'] . '/bare';
@mkdir($bare . '/dave', 0777, true);
Database::setSetting('scan_paths', $bare);
$qb = Scanner::resolveScanPaths('quick', $bare);
t_eq([$bare], $qb['paths'], 'with no web roots a quick scan falls back to the full root');
t_contains($qb['note'], 'no web roots found',
    'and says so, rather than silently scanning everything under the word "quick"');

Database::setSetting('scan_paths', $home);

// -- startScan refuses to start a scan with no target ------------------------
$threw = false;
try {
    (new Scanner())->startScan('', 'custom');
} catch (Throwable $e) {
    $threw = true;
    t_contains($e->getMessage(), 'Nothing to scan', 'and explains why');
}
t_ok($threw, 'starting a custom scan with nothing selected is refused');

// -- 3. The picker is a checkbox list of accounts ----------------------------
$html = file_get_contents($repo . '/frontend/index.html');
$js   = file_get_contents($repo . '/frontend/js/app.js');

// A dialog, not an inline card. The first attempt put the picker in a panel
// below the toolbar; it also never appeared, because every function that would
// have shown it called g() at module scope and threw.
t_contains($html, 'id="scan-accounts-modal"', 'the account picker is a dialog');
t_contains($html, 'role="dialog"', 'marked up as one');
t_contains($html, 'id="scan-accounts-list"', 'with a list to fill');
t_contains($html, 'Custom (choose accounts)',
    'and the dropdown no longer offers a free-text path');
t_ok(strpos($html, 'id="scan-path-input"') === false
     || strpos($html, 'Custom Path</option>') === false,
    'the old custom-path option is gone');
t_contains($html, 'onchange="onScanTypeChange()"',
    'choosing a type shows or hides the picker');

t_contains($js, 'class="scan-acct"', 'each account is a checkbox');
t_contains($js, 'function scanAccountsAll', 'with select-all and clear');
t_contains($js, 'function scanAccountsSelected', 'and the selection is read back');
t_contains($js, 'Select at least one account',
    'starting a custom scan with nothing ticked is refused in the UI too');

$api = t_code($repo . '/backend/api/index.php');
t_contains($api, "'accounts' =>", 'the account list has an API route');
t_contains($api, 'None of those accounts exist',
    'and an account name that is not real is rejected');
// The request names accounts; the server resolves them. A path in the request
// body must not be able to send the scanner somewhere of its own choosing.
t_contains($api, 'Scanner::listAccounts()',
    'account names are resolved against the real account list, not trusted as paths');

$apijs = file_get_contents($repo . '/frontend/js/api.js');
t_contains($apijs, 'scanAccounts:', 'the client can fetch accounts');
t_contains($apijs, 'accounts }', 'and sends the selection with the scan');

// -- 4. A running scan can be stopped from any page load ---------------------
t_contains($api, "'active' =>", 'the API reports the scan in progress');
t_contains($js, 'async function adoptRunningScan',
    'the page adopts a scan it did not start');
t_contains($js, 'function followScan',
    'sharing one progress loop between a started scan and an adopted one');
t_contains($js, 'adoptRunningScan()',
    'and it runs when the Scanner page is opened');

// The Stop button must be reachable, which means the progress card has to be
// shown for an adopted scan too.
$adopt = substr($js, strpos($js, 'async function adoptRunningScan'), 900);
t_contains($adopt, "card.style.display = ''",
    'the progress card is shown, which is what the Stop button lives in');
t_contains($adopt, 'followScan(job.id)', 'and the scan is followed to completion');

t_contains($html, 'onclick="stopScan(State.scanJobId)"', 'the Stop button is wired');


// -- The picker is a dialog, and it actually opens ----------------------------
// It shipped as an inline card and never appeared at all: onScanTypeChange(),
// loadScanAccounts() and adoptRunningScan() all called g() at module scope,
// where g() did not exist -- it was declared as a `const g` inside two other
// functions. Each call threw ReferenceError inside an event handler, with
// nothing logged and nothing shown. Bracket balance passed, handler resolution
// passed, and three features did nothing.
t_contains($js, 'function g(id)', 'g() is defined at module scope');
$gPos = strpos($js, 'function g(id)');
t_ok($gPos !== false && substr($js, $gPos - 1, 1) === "\n",
    'at column zero, not nested inside another function');

t_contains($js, 'function openScanAccounts', 'choosing Custom opens the dialog');
$onChange = substr($js, strpos($js, 'function onScanTypeChange'), 260);
t_contains($onChange, 'openScanAccounts()',
    'the type dropdown opens it rather than toggling a hidden panel');

t_contains($js, "openModal('scan-accounts-modal')", 'the dialog is opened');
t_contains($js, "closeModal('scan-accounts-modal')", 'and closed');

// Selecting nothing must not be startable from the dialog.
t_contains($js, 'function startScanFromPicker', 'the dialog starts the scan itself');
t_contains($js, 'go.disabled = (n === 0)',
    'and its button is disabled until something is ticked');

// Pressing Start Scan with Custom chosen but nothing picked reopens the
// dialog: the operator plainly meant to choose.
$ss = substr($js, strpos($js, 'async function startScan()'), 1200);
t_contains($ss, 'openScanAccounts()',
    'Start Scan with nothing selected reopens the picker instead of failing');

// Filtering must not silently discard an existing selection.
t_contains($js, 'const picked = new Set(scanAccountsSelected())',
    'the current selection survives a filter change');
t_contains($js, "picked.has(a.user) ? 'checked' : ''", 'by re-checking those boxes');

// The modal must be styled, or it renders as an unpositioned block.
t_contains($html, '#scan-accounts-modal .wem-box',
    'the dialog reuses the existing modal styling');
t_contains($html, '#scan-accounts-modal.hidden', 'and is hidden by default');
