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

/**
 * --watch: stay resident and look every few seconds.
 *
 * "It starts within a minute" was still a minute of a customer staring at
 * "Queued" -- and that was the GOOD case, since it assumed a cron entry one
 * live server turned out not to have at all. A cron is the wrong mechanism
 * for something a person is sitting in front of: a minute is its floor, and
 * whether it runs depends on a file in /etc/cron.d an administrator can tidy
 * away.
 *
 * So the normal path is a systemd service running this with --watch, which
 * picks a request up in about five seconds. The cron entry stays as a
 * fallback for hosts without systemd, and the scheduler stays as a floor
 * under both. All three go through the same lock inside process(), so running
 * all three at once is harmless.
 *
 * Each pass is a fresh look at the database, so a settings change takes
 * effect without a restart.
 */
$watch    = false;
$interval = 5;
$maxLife  = 3600;
foreach (array_slice($argv, 1) as $a) {
    if ($a === '--watch') {
        $watch = true;
    } elseif (strpos($a, '--interval=') === 0) {
        $interval = max(2, min(60, (int) substr($a, 11)));
    } elseif (strpos($a, '--max-life=') === 0) {
        // Recycled rather than trusted to run for weeks. systemd restarts it.
        $maxLife = max(5, min(86400, (int) substr($a, 11)));
    }
}


// The lock is taken inside UserScanRequest::process(), not here.
//
// It has to be: the scheduler calls process() as well, hourly, so that a
// server whose minute cron is missing or broken still picks requests up. Two
// scripts each holding their OWN lock would not exclude each other at all.
// One lock, in the one function both go through.

/**
 * One pass. This used to be the whole script.
 */
$sg_pass = function (): void {
    // Checked every pass, not once at startup.
    //
    // In --watch mode this process outlives any single answer: a licence that
    // expires must stop scans starting without waiting for a restart, and one
    // that is renewed -- or a transient lookup failure -- must not leave the
    // service dead. Checking at startup also meant the process exited
    // immediately on an unlicensed box and systemd restarted it every five
    // seconds, forever.
    if (!License::protectionAllowed()) { return; }

    $r = UserScanRequest::process();

    // Silent on the common tick. A log line saying "nothing to do" every
    // minute buries the lines that matter in its own noise -- and at a
    // five-second interval it would bury them twelve times faster.
    foreach ($r['started'] as $s) {
        Logger::info("user-scans: started job {$s['job']} for {$s['user']}");
    }
    foreach ($r['errors'] as $e) {
        Logger::warn("user-scans: could not start for {$e['user']} - {$e['error']}");
    }
    foreach ($r['cancelled'] ?? [] as $c) {
        Logger::info("user-scans: {$c['user']} cancelled job {$c['job']}");
    }

    // Republish every live customer scan.
    //
    // The worker publishes as it goes, which is what makes the page move.
    // This is the safety net for when it cannot: a worker killed outright
    // never writes a final state, and the customer's page would show a scan
    // running forever. The stale-job reaper marks those 'interrupted'; this
    // is what carries that answer into their home.
    foreach (Database::fetchAll(
        "SELECT id FROM scan_jobs
          WHERE requested_by <> '' AND status IN ('running','pending','cancelling')") as $row) {
        Scanner::publishUserStatus((int) $row['id']);
    }
};

if (!$watch) {
    $sg_pass();
    exit(0);
}

// ── Resident mode ───────────────────────────────────────────────────────────
//
// Stopping has to be prompt: systemd sends SIGTERM and kills after its
// timeout, and being killed mid-pass could leave a request neither started
// nor cleared.
$sg_stop = false;
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    $h = function () use (&$sg_stop) { $sg_stop = true; };
    pcntl_signal(SIGTERM, $h);
    pcntl_signal(SIGINT,  $h);
}

Logger::info("user-scans: watching for scan requests every {$interval}s");
$started = time();

while (!$sg_stop) {
    try {
        $sg_pass();
    } catch (Throwable $e) {
        // One bad pass must not end the watcher. If it did, the failure mode
        // is the one this file exists to prevent: nothing picking requests
        // up, and no sign of it on the customer's page.
        Logger::error('user-scans: pass failed - ' . $e->getMessage());
        sleep(10);
    }

    // Recycled rather than trusted to run forever; systemd restarts it.
    if ((time() - $started) >= $maxLife) {
        Logger::info('user-scans: recycling after ' . (time() - $started) . 's');
        break;
    }

    for ($i = 0; $i < $interval && !$sg_stop; $i++) { sleep(1); }
}

exit(0);
