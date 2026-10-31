#!/usr/bin/env php
<?php
/**
 * ServerScrub — pick up customer scan requests.
 *
 * WHY THIS IS SEPARATE FROM THE SCHEDULER
 *
 * A cPanel user presses "Scan my account" and the page writes a request file
 * into their own home; it cannot start a scan itself, because it runs as the
 * customer and the database is 0700 root. Something privileged has to notice.
 *
 * That used to be the 15-minute scheduler, which meant a customer could press
 * the button and watch nothing happen for a quarter of an hour. Long enough
 * to press it again, then open a ticket.
 *
 * So this runs every minute and does one thing. It is deliberately cheap: a
 * glob over /var/cpanel/users and a stat of one path per account. On the
 * common tick there are no requests and it exits having touched nothing.
 *
 * It does NOT scan. It asks Scanner::startScan(), which enforces
 * scan_max_concurrent -- so a minute interval cannot pile work onto a busy
 * server. The worst a flood of requests can do is get refused quickly and
 * politely.
 *
 * A backup is NOT a reason to refuse one of these. The scheduled server-wide
 * sweep still stands down for JetBackup or rsync, because nothing is waiting
 * on it; a customer who has just pressed the button is waiting, and one
 * account's quick scan is a far smaller claim on the disks.
 */

if (PHP_SAPI !== 'cli') { fwrite(STDERR, "user-scans: CLI only\n"); exit(2); }

require_once __DIR__ . '/../config/config.php';
require_once SG_ROOT . '/backend/lib/Database.php';
require_once SG_ROOT . '/backend/lib/Logger.php';
require_once SG_ROOT . '/backend/lib/License.php';
require_once SG_ROOT . '/backend/lib/Scanner.php';
require_once SG_ROOT . '/backend/lib/Firewall.php';
require_once SG_ROOT . '/backend/lib/UserReport.php';
require_once SG_ROOT . '/backend/lib/UserScanRequest.php';

// A licensing fault must not turn into a scan nobody authorised.
if (!License::protectionAllowed()) { exit(0); }

// One at a time. At a minute interval an overrun would otherwise stack, and
// each instance would try to start the same request.
//
// The kernel holds the lock for the life of the process, so a run that is
// killed cannot leave a stale one behind.
if (!is_dir(SG_TMP)) { @mkdir(SG_TMP, 0750, true); }
$lock = @fopen(SG_TMP . '/user-scans.lock', 'c');
if ($lock === false) {
    Logger::warn('user-scans: could not open its lock file; exiting');
    exit(0);
}
if (!@flock($lock, LOCK_EX | LOCK_NB)) {
    // Not an error: the previous minute is still working.
    exit(0);
}
$GLOBALS['__sg_user_scan_lock'] = $lock;

$r = UserScanRequest::process();

// Silent on the common tick. A cron that logs "nothing to do" every minute
// buries the lines that matter in its own noise.
foreach ($r['started'] as $s) {
    Logger::info("user-scans: started job {$s['job']} for {$s['user']}");
}
foreach ($r['errors'] as $e) {
    Logger::warn("user-scans: could not start for {$e['user']} - {$e['error']}");
}

exit(0);
