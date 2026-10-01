<?php
/**
 * Rootkit scanning: scheduled nightly, and its tools installed with the product.
 *
 * Reported: the Rootkit Scanner page shows rkhunter and chkrootkit as "Not
 * installed", and there should be a schedule for nightly scans like the
 * malware scanner has.
 *
 * The schedule already existed and was fully wired — settings, save, and a
 * scheduler task — but shipped unseeded, so it fell back to the code default
 * of weekly. The tools were the real gap: the installer never installed them,
 * and the page offered two tools it had done nothing to provide.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$install = file_get_contents($repo . '/install.sh');
$sched   = t_code($repo . '/backend/cron/scheduler.php');
$db      = t_code($repo . '/backend/lib/Database.php');

// -- The installer provides the tools it offers ------------------------------
t_contains($install, 'Rootkit scanning tools', 'the installer has a step for them');
t_contains($install, 'rkhunter chkrootkit', 'and installs both');

// It must not be nested inside the cPanel-only Apache restart block, which is
// where it first landed -- standalone installs would have been skipped.
$rkPos     = strpos($install, '# ── Rootkit scanning tools');
$apachePos = strpos($install, '# ── Apache restart (cpanel mode)');
t_ok($rkPos !== false && $apachePos !== false && $rkPos < $apachePos,
    'the step runs before the cPanel-only Apache section, at top level');
$line = substr($install, $rkPos, 40);
t_ok($line[0] === '#', 'and is not indented inside another conditional');

// -- EPEL is handled carefully, because cPanel cautions against it -----------
// Enabling EPEL globally on a cPanel server can shadow packages cPanel
// manages. It is added disabled and enabled for one transaction only.
t_contains($install, '--enablerepo=epel',
    'EPEL is enabled for this transaction only');
t_contains($install, "sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/epel.repo",
    'and the repository is left disabled afterwards');
$epelPos  = strpos($install, 'epel-release');
$checkPos = strpos($install, 'if [[ ! -f /etc/yum.repos.d/epel.repo ]]');
t_ok($checkPos !== false && $checkPos < $epelPos,
    'EPEL is only added when it is not already present');

// Trying the configured repositories first means a host that already has these
// packages is left alone entirely.
$rkBlock  = substr($install, $rkPos, 6000);
$plainPos = strpos($rkBlock, 'install -y -q rkhunter chkrootkit');
// The command, not the word: '--enablerepo=epel' also appears in the
// comment at the top of the block, which is before everything.
$epelTry  = strpos($rkBlock, 'install -y -q --enablerepo=epel');
t_ok($plainPos !== false && $epelTry !== false && $plainPos < $epelTry,
    'the configured repositories are tried before reaching for EPEL');

// -- Failure must not break the install -------------------------------------
// RootkitEngine is built in and needs neither tool.
t_contains($rkBlock, 'built-in rootkit engine needs neither tool',
    'a failed install explains that scanning still works');
t_ok(substr_count($rkBlock, '|| true') >= 3,
    'no package command can abort the installer');

// -- Declining is supported --------------------------------------------------
t_contains($install, '--no-rootkit-tools', 'an operator can decline the tools');
t_contains($install, 'SKIP_ROOTKIT_TOOLS=false', 'with the flag defaulting to off');

// -- rkhunter needs its property database before its first scan -------------
// Without it every system binary looks modified and the first scan is a wall
// of warnings that means nothing.
t_contains($rkBlock, 'rkhunter --propupd', 'rkhunter is initialised');
t_contains($rkBlock, 'nohup', 'in the background, so a large server does not stall the install');

// -- The schedule ------------------------------------------------------------
t_contains($sched, "'rootkit' => [", 'rootkit scanning is a scheduled task');
t_contains($sched, "setting('rootkit_schedule'", 'on a configurable schedule');
t_contains($sched, 'RootkitEngine::scan()',
    'falling back to the built-in engine when the tools are absent');
t_contains($sched, "require_once SG_ROOT . '/backend/lib/RootkitEngine.php'",
    'and the scheduler requires that class, or the task fatals in cron');
t_contains($sched, "Database::setSetting('rootkit_last_run'",
    'the run is recorded, so a scheduled scan is not invisible');

// Seeded, so it does not fall back to the code default of weekly. A rootkit
// that lands on Monday should not wait until Sunday to be noticed.
t_contains($db, "'rootkit_schedule',        'daily'", 'nightly by default');
t_contains($db, "'rootkit_time',            '03:00'", 'at a time after the backup window');

// The settings page has to be able to change it.
$js   = file_get_contents($repo . '/frontend/js/app.js');
$html = file_get_contents($repo . '/frontend/index.html');
t_contains($html, 'id="set-rootkit-schedule"', 'the schedule control exists');
t_contains($js, 'rootkit_schedule:', 'and is saved');
t_contains($js, "set('set-rootkit-schedule'", 'and loaded back');
t_contains($js, "txt('rootkit-last-run'", 'with the last run shown');

// -- A missing tool must say what to do about it ----------------------------
t_contains($js, 'could not be installed on this server',
    'missing tools are explained rather than just flagged');
t_contains($js, 'install-rootkit-tools', 'with the command to retry');
t_contains($html, 'id="rk-tools-note"', 'and somewhere to say it');

$cli = t_code($repo . '/backend/cli/sentinel.php');
t_contains($cli, "case 'install-rootkit-tools'", 'that command exists');
t_contains($cli, '--enablerepo=epel', 'and treats EPEL the same way the installer does');
t_contains($cli, "sed -i 's/^enabled=1/enabled=0/'", 'leaving it disabled too');
