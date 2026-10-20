#!/usr/bin/env php
<?php
/**
 * ServerScrub — task scheduler
 *
 * Runs every 15 minutes from cron and decides which scheduled tasks are due,
 * based on the user's settings.
 *
 * Why a dispatcher rather than one cron line per task: the schedules are
 * user-configurable from Settings, and rewriting /etc/cron.d whenever someone
 * changes a dropdown needs root at runtime, races with the file being read, and
 * silently diverges from the UI if any single write fails. Here the crontab is
 * fixed and dumb, the settings are the single source of truth, and a change
 * takes effect on the next tick with nothing to keep in sync.
 *
 * Usage:  php backend/cron/scheduler.php [--force <task>] [--dry-run] [--status]
 *
 * Settings consumed (all have defaults, so an upgrade needs no migration):
 *   scan_schedule        off | hourly | daily | weekly     (default daily)
 *   scan_time            HH:MM  — for daily/weekly         (default 02:00)
 *   scan_day             0-6, Sunday=0 — for weekly        (default 0)
 *   scan_type            quick | full                      (default full)
 *   scan_paths           comma-separated                   (default /home)
 *   sig_update_schedule  off | daily | weekly              (default weekly)
 *   sig_update_day       0-6 — for weekly                  (default 0)
 *   iprep_schedule       off | hourly | daily | weekly     (default daily)
 */

if (PHP_SAPI !== 'cli') { fwrite(STDERR, "scheduler: CLI only\n"); exit(2); }

require_once __DIR__ . '/../config/config.php';
require_once SG_ROOT . '/backend/lib/Database.php';
require_once SG_ROOT . '/backend/lib/Logger.php';
require_once SG_ROOT . '/backend/lib/Heuristics.php';
require_once SG_ROOT . '/backend/lib/UpdateChecker.php';
require_once SG_ROOT . '/backend/lib/Updater.php';
require_once SG_ROOT . '/backend/lib/Scanner.php';
require_once SG_ROOT . '/backend/lib/IPReputation.php';
// Used by the iprep task to check this server's own addresses. Calling a
// class the scheduler never required is a fatal error at 03:00, in cron,
// where nobody is looking.
require_once SG_ROOT . '/backend/lib/BlocklistRegistry.php';
require_once SG_ROOT . '/backend/lib/License.php';
// Newly scheduled modules. Omitting these is a fatal on the first cron run,
// which nothing would have reported until a panel stayed empty for a week.
require_once SG_ROOT . '/backend/lib/CMSGuard.php';
require_once SG_ROOT . '/backend/lib/WPDatabaseScanner.php';
require_once SG_ROOT . '/backend/lib/BotShield.php';
require_once SG_ROOT . '/backend/lib/RootkitScanner.php';
require_once SG_ROOT . '/backend/lib/RootkitEngine.php';
require_once SG_ROOT . '/backend/lib/FileIntegrity.php';
// Feeds the cPanel user plugin: it can read nothing else, because the
// database is root-only and must stay that way.
require_once SG_ROOT . '/backend/lib/UserReport.php';
// The rtguard task starts the monitor once backups finish; without this
// require the task fatals in cron and nothing ever resumes.
require_once SG_ROOT . '/backend/lib/RealTimeMonitor.php';
// The wafingest task reads ModSecurity events into waf_events.
require_once SG_ROOT . '/backend/lib/WAF.php';
// The bruteforce task reads auth logs and blocks repeat offenders.
require_once SG_ROOT . '/backend/lib/Schedule.php';
require_once SG_ROOT . '/backend/lib/BruteForce.php';
require_once SG_ROOT . '/backend/lib/NetworkGuard.php';
// The fwprobe task measures iptables and CSF off the request path.
require_once SG_ROOT . '/backend/lib/Firewall.php';

$force  = null;
$dryRun = false;
$status = false;
for ($i = 1; $i < $argc; $i++) {
    if ($argv[$i] === '--force' && isset($argv[$i + 1])) { $force = $argv[++$i]; }
    elseif ($argv[$i] === '--dry-run') { $dryRun = true; }
    elseif ($argv[$i] === '--status')  { $status = true; }
}

function slog(string $m): void {
    echo '[' . gmdate('Y-m-d\TH:i:s\Z') . "] $m\n";
}

// Keep the flag the Python daemon reads fresh — this is the most frequent PHP
// entry point, so it is the most reliable place to do it.
License::publishFlag();

// --status is a read-only diagnostic, so it answers even on an unlicensed
// server. "Is my nightly scan running?" is exactly the question an operator
// asks when something is wrong, and refusing to say because of the licence
// state would hide the licence state itself.
if (!$status && !License::protectionAllowed()) {
    $s = License::status();
    slog("skipped: license {$s['status']} — {$s['message']}");
    exit(0);
}

$now = time();

function setting(string $k, string $default): string {
    $v = (string)Database::setting($k, $default);
    return $v === '' ? $default : $v;
}

function lastRun(string $task): int  { return (int)Database::setting("last_run_$task", 0); }
function markRun(string $task): void { Database::setSetting("last_run_$task", (string)time()); }

/**
 * Is a task due?
 *
 * Uses "has enough time elapsed" rather than "does the clock read HH:MM right
 * now". A wall-clock match only fires if a tick lands exactly in that window —
 * a reboot, a slow run or a missed tick would skip the day entirely and nobody
 * would notice until an incident. Elapsed-time means a missed window runs late
 * instead of not at all.
 */
function isDue(string $task, string $schedule, int $now,
               string $atTime = '02:00', int $onDay = 0): bool {
    // The decision itself lives in Schedule, where it can be tested. This
    // wrapper only supplies the task's last-run time.
    return Schedule::isDue($schedule, lastRun($task), $now, $atTime, $onDay);
}

// ── Tasks ─────────────────────────────────────────────────────────────────────
$tasks = [
    'scan' => [
        'schedule' => setting('scan_schedule', 'daily'),
        'time'     => setting('scan_time', '02:00'),
        'day'      => (int)setting('scan_day', '0'),
        'run'      => function () {
            $paths = array_filter(array_map('trim', explode(',', setting('scan_paths', '/home'))));
            $type  = setting('scan_type', 'full');
            $sc    = new Scanner();

            // Do not start a scheduled scan into a backup window. startScan()
            // refuses anyway; catching it here keeps the log readable and
            // leaves the scan to the next tick.
            $busy = Scanner::backupRunning();
            if ($busy) {
                slog('  backup in progress (' . implode(', ', $busy) . ') - scan deferred');
                return false;      // still due: try again on the next tick
            }

            $usable = array_values(array_filter($paths, 'is_dir'));
            foreach (array_diff($paths, $usable) as $missing) {
                slog("  skip missing path: $missing");
            }
            if (!$usable) {
                // Marked as run deliberately: this is a misconfiguration that
                // will not fix itself, and retrying every fifteen minutes
                // would bury the log line that says so.
                slog('  no usable scan paths — check scan_paths');
                return true;
            }

            // ONE job covering every path. This loop used to call startScan()
            // per path, and startScan() spawns a detached worker immediately --
            // so three configured paths meant three workers and three clamscan
            // processes running at once, every scheduled run, by design.
            try {
                $job = $sc->startScan(implode(',', $usable), $type);
                slog("  started $type scan of " . implode(', ', $usable) . " (job $job)");
            } catch (Throwable $e) {
                // Declining to stack a second scan is the correct outcome, not
                // a failure worth alarming about -- but it is also not a run,
                // so the nightly scan stays due rather than being skipped for
                // a day because one was already in progress at 02:00.
                slog('  ' . $e->getMessage());
                return false;
            }
            return true;
        },
    ],

    'sigs' => [
        'schedule' => setting('sig_update_schedule', 'weekly'),
        'time'     => setting('sig_update_time', '01:00'),
        'day'      => (int)setting('sig_update_day', '0'),
        'run'      => function () {
            $r = (new Scanner())->updateSignatures();
            $ok = is_array($r) ? ($r['success'] ?? false) : (bool)$r;
            slog('  signature update ' . ($ok ? 'completed' : 'FAILED'));
            Database::setSetting('sig_last_update', (string)time());
            Database::setSetting('sig_last_result', $ok ? 'ok' : 'failed');
        },
    ],

    'iprep' => [
        'schedule' => setting('iprep_schedule', 'daily'),
        'time'     => setting('iprep_time', '03:00'),
        'day'      => (int)setting('iprep_day', '0'),
        'run'      => function () {
            // Re-check the addresses that have actually attacked this server
            // recently. Re-checking the whole historical table would grow
            // without bound and mostly re-confirm stale entries.
            $rep  = new IPReputation();
            $rows = Database::fetchAll(
                "SELECT DISTINCT source_ip FROM security_events
                  WHERE timestamp > ? AND source_ip IS NOT NULL AND source_ip != ''
                  ORDER BY timestamp DESC LIMIT 200",
                [time() - 7 * 86400]
            );
            $n = 0;
            foreach ($rows as $r) {
                $ip = $r['source_ip'] ?? '';
                if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) { continue; }
                try { $rep->check($ip); $n++; } catch (Throwable $e) { /* one bad IP must not stop the sweep */ }
            }
            slog("  refreshed reputation for $n address(es)");
            Database::setSetting('iprep_last_run', (string)time());
            Database::setSetting('iprep_last_count', (string)$n);

            // The server's OWN addresses, which nothing checked. Attacker IPs
            // and the server's IPs are different questions, and this is the one
            // that costs money: a mail IP quietly landing on a blocklist is
            // only noticed when customers report undelivered mail.
            $listed = 0;
            foreach (BlocklistRegistry::serverIps() as $mine) {
                try {
                    $r = BlocklistRegistry::checkAll($mine);
                } catch (Throwable $e) {
                    continue;
                }
                if ((int)($r['listed'] ?? 0) > 0) {
                    $listed++;
                    slog("  WARNING: server IP $mine is listed on "
                       . (int)$r['listed'] . ' blocklist(s)');
                    Logger::event('ip_reputation', 'high', $mine, 'server',
                        'This server address is listed on ' . (int)$r['listed'] . ' blocklist(s)');
                }
            }
            Database::setSetting('iprep_server_last_run', (string)time());
            Database::setSetting('iprep_server_listed', (string)$listed);
        },
    ],

    // ── Modules that were never scheduled ────────────────────────────────────
    // CMS Guard, Bot Shield, rootkit and file integrity all read their panels
    // from database tables, and NOTHING wrote to those tables unless the user
    // happened to press a button. So every one of them showed zero for ever and
    // read as broken. Building the module and then never running it is the
    // single most common fault in this codebase.

    'cmsguard' => [
        'schedule' => setting('cmsguard_schedule', 'daily'),
        'time'     => setting('cmsguard_time', '04:00'),
        'day'      => (int)setting('cmsguard_day', '0'),
        'run'      => function () {
            $found = (new CMSGuard())->scanInstalls();
            slog('  CMS discovery found ' . count($found) . ' install(s)');
        },
    ],

    // The database half of a WordPress compromise.
    //
    // Scheduled at 03:30, half an hour before CMS discovery, so a nightly run
    // reads the install list that discovery left and the two never contend for
    // the disk. Weekly, not daily: it opens a database connection per install
    // and this is the most expensive task in the file, so it runs often enough
    // to catch a new compromise within days and rarely enough not to be a
    // standing load on a shared server.
    //
    // The sweep carries its own wall-clock budget and resumes where it
    // stopped, so an install count that grows past what fits in one night
    // degrades into "every site every few nights" rather than "the first 200
    // sites every night and the rest never".
    'wpdbscan' => [
        'schedule' => setting('wpdbscan_schedule', 'weekly'),
        'time'     => setting('wpdbscan_time', '03:30'),
        'day'      => (int)setting('wpdbscan_day', '0'),
        'run'      => function () {
            $r = WPDatabaseScanner::sweep(null, (int)setting('wpdbscan_budget', '1800'));
            slog(sprintf('  WordPress database sweep: %d of %d installs, '
                       . '%d new findings%s',
                         $r['scanned'], $r['installs'], $r['findings'],
                         $r['complete'] ? '' : ' (budget reached, resumes next run)'));
            // Errors are logged, not swallowed. A sweep that could not read
            // half the installs and a server with nothing wrong produce the
            // same finding count.
            foreach (array_slice($r['errors'], 0, 10) as $e) {
                slog('  ! ' . $e);
            }
            if (count($r['errors']) > 10) {
                slog(sprintf('  ! and %d more', count($r['errors']) - 10));
            }
        },
    ],

    // Check for a new version, and install it.
    //
    // There was already a daily update CHECK, installed by install.sh as its
    // own cron entry, which cached a notice and did nothing else. So a server
    // sat on a known-vulnerable version indefinitely while the dashboard
    // displayed a tidy "update available" badge that nobody was looking at.
    // For a security product that is the wrong default: the thing most likely
    // to be out of date is the thing supposed to be watching everything else.
    //
    // Two steps, in this order, and the order matters:
    //
    //   1. reconcile() reads the state file the LAST run left behind and
    //      records whether it worked. It has to happen here rather than in the
    //      updater, because the updater rsyncs over its own code and cannot be
    //      relied on to write its own obituary.
    //   2. shouldApply() decides, and refuses with a stated reason -- not
    //      while a scan or backup is running, not a major version, not after
    //      repeated failures.
    'autoupdate' => [
        'schedule' => setting('autoupdate_schedule', 'daily'),
        'time'     => setting('autoupdate_time', '04:30'),
        'day'      => (int)setting('autoupdate_day', '0'),
        'run'      => function () {
            $rec = Updater::reconcile();
            if (!empty($rec['changed'])) {
                slog('  previous update finished: ' . $rec['status']
                     . (isset($rec['failures'])
                        ? ' (consecutive failures: ' . $rec['failures'] . ')' : ''));
            }

            $st = UpdateChecker::checkForUpdates();
            slog(sprintf('  current v%s, latest v%s',
                 $st['current_version'] ?? '?', $st['latest_version'] ?? '?'));

            // A channel that cannot be reached is reported, never treated as
            // "up to date". An unreachable update server and a patched server
            // look identical otherwise, and only one of them is safe.
            $err = Database::setting('update_check_error', '');
            if ($err !== '') {
                slog('  ! ' . $err);
                return;
            }

            $d = Updater::shouldApply($st);
            if (!$d['go']) {
                slog('  not updating: ' . $d['reason']);
                return;
            }

            slog('  ' . $d['reason']);
            $r = Updater::launch(true);
            slog($r['success']
                ? '  updater launched (pid ' . ($r['pid'] ?? 0) . '); '
                  . 'result recorded on the next run'
                : '  ! could not launch: ' . ($r['error'] ?? 'unknown'));
        },
    ],

    // Port scans and connection floods.
    //
    // Every 15 minutes, which is the scheduler's own tick -- a scan is over in
    // seconds, so this samples rather than watches. That is a deliberate
    // trade: a continuous watcher means a daemon reading /proc/net in a loop
    // on a shared host, and an unbounded read of kernel connection state is
    // itself a performance incident. This server has already had one of those
    // this month.
    //
    // A sample is enough: a scanner that touches enough closed ports to matter
    // is still mid-scan or still in TIME_WAIT when the sample lands, and a
    // flood by definition persists.
    //
    // It records; BruteForce escalates and releases. One blocking path.
    'netguard' => [
        'schedule' => setting('netguard_schedule', 'every'),
        'time'     => setting('netguard_time', '00:00'),
        'day'      => (int)setting('netguard_day', '0'),
        'run'      => function () {
            $r = NetworkGuard::run();
            foreach (['scan' => 'port-scan', 'flood' => 'flood'] as $k => $label) {
                if (!empty($r[$k]['skipped'])) {
                    slog("  $label: " . $r[$k]['skipped']);
                }
            }
            if (!empty($r['scan']['scanners'])) {
                slog(sprintf('  port scans: %d address(es) probing closed ports',
                     $r['scan']['scanners']));
            }
            if (!empty($r['flood']['offenders'])) {
                slog(sprintf('  connection floods: %d address(es) over %d concurrent',
                     $r['flood']['offenders'], NetworkGuard::floodLimit()));
            }
            if (!empty($r['blocked'])) {
                slog(sprintf('  %d address(es) blocked through the brute-force ladder',
                     $r['blocked']));
            }
        },
    ],

    'botshield' => [
        // Hourly: log lines age out, and a bot seen only in yesterday's rotated
        // access log cannot be acted on at all.
        'schedule' => setting('botshield_schedule', 'hourly'),
        'time'     => setting('botshield_time', '00:00'),
        'day'      => (int)setting('botshield_day', '0'),
        'run'      => function () {
            $r = (new BotShield())->runAnalysis();
            slog('  bot analysis: ' . (int)($r['blocked'] ?? 0) . ' blocked, '
                 . (int)($r['skipped'] ?? 0) . ' already known');
        },
    ],

    'rootkit' => [
        'schedule' => setting('rootkit_schedule', 'weekly'),
        'time'     => setting('rootkit_time', '05:00'),
        'day'      => (int)setting('rootkit_day', '0'),
        'run'      => function () {
            // runScan() refuses when rkhunter/chkrootkit are absent, which is
            // the normal case on a clean box. The built-in engine has no such
            // dependency, so fall back to it rather than silently doing nothing.
            $rs = new RootkitScanner();
            $r  = $rs->runScan();
            if (isset($r['error'])) {
                slog('  rkhunter/chkrootkit unavailable — using built-in engine');
                $r = RootkitEngine::scan();
            }
            $n = is_array($r['findings'] ?? null)
                ? count($r['findings'])
                : (int)($r['findings'] ?? 0);
            // Recorded so the settings page can show when this last ran and
            // what it found. Without it a scheduled scan is invisible: it
            // either runs or does not, and the operator cannot tell which.
            Database::setSetting('rootkit_last_run', (string)time());
            Database::setSetting('rootkit_last_findings', (string)$n);
            slog('  rootkit scan: ' . $n . ' finding(s)');
        },
    ],

    'integrity' => [
        'schedule' => setting('integrity_schedule', 'daily'),
        'time'     => setting('integrity_time', '06:00'),
        'day'      => (int)setting('integrity_day', '0'),
        'run'      => function () {
            // runCheck('') walks every watched path.
            $r = (new FileIntegrity())->runCheck('');
            slog('  integrity check: ' . (int)($r['changed'] ?? 0) . ' change(s)');
        },
    ],

    // Per-user reports for the cPanel-side plugin.
    //
    // Runs on its own schedule rather than being appended to each scan: the
    // scan, CMS and integrity tasks all contribute to a report, and rebuilding
    // it three times in one night writes into every customer's home three
    // times for no benefit. Hourly is cheap -- it is a few queries and one
    // small file per account -- and means a user sees a finding within the
    // hour rather than at the next scan.
    'userreports' => [
        'schedule' => setting('user_reports_schedule', 'hourly'),
        'time'     => setting('user_reports_time', '00:00'),
        'day'      => (int)setting('user_reports_day', '0'),
        'run'      => function () {
            $r = UserReport::writeAll();
            slog('  per-user reports: ' . $r['written'] . ' written, '
               . $r['skipped'] . ' skipped');
        },
    ],

    // Bring real-time monitoring back once the backups are done.
    //
    // The daemon suspends its own scanning while a backup runs, but a daemon
    // that is STOPPED cannot do that for itself -- and a monitor that went
    // down during a backup window otherwise stays down until somebody notices
    // and presses Start. This probes for JetBackup and rsync directly and
    // starts the monitor once they have gone.
    // Read new ModSecurity events into waf_events.
    //
    // This had no scheduled run at all: ingestModSecLog() was reachable only
    // from an API route nothing calls, so waf_events stayed empty for ever and
    // the WAF page reported no attacks on a server certainly receiving some.
    // Cheap now that it reads only what has been appended since last time.
    // Read authentication logs, and block addresses that keep failing.
    //
    // Every tick: an attack that lasts ten minutes is over before an hourly
    // task would notice, and reading is incremental so the cost is small.
    // Measure the things the firewall page shows that cost a process spawn.
    //
    // Off the request path deliberately: iptables can sit on the xtables lock,
    // and cpsrvd serialises requests, so one slow call stalls every page. The
    // page now reads what this leaves behind.
    'fwprobe' => [
        'schedule' => setting('fw_probe_schedule', 'every'),
        'time'     => '00:00',
        'day'      => 0,
        'run'      => function () {
            $r = Firewall::refreshProbes();
            slog('  firewall probes: iptables=' . $r['iptables_rules']
               . ' csf=' . (($r['csf_status']['installed'] ?? false) ? 'installed' : 'absent'));
        },
    ],

    'bruteforce' => [
        'schedule' => setting('bf_schedule', 'every'),
        'time'     => '00:00',
        'day'      => 0,
        'run'      => function () {
            $r = BruteForce::run();
            if (!$r['enabled']) { slog('  brute force: disabled'); return; }
            slog('  brute force: ' . $r['collected'] . ' failure(s), '
               . $r['offenders'] . ' offender(s), ' . $r['blocked'] . ' blocked, '
               . (int) ($r['released'] ?? 0) . ' released');

            // Blocks placed by anything else -- the operator, another module --
            // carry a deadline too, and until 4.2.0 nothing anywhere acted on
            // one. Swept here rather than in its own task: it is cheap, and a
            // task that exists only to call one function is a task that gets
            // forgotten when the schedule is edited.
            $e = Firewall::expireBlocks();
            if ($e['released'] > 0 || $e['failed'] > 0) {
                slog('  firewall: ' . $e['released'] . ' expired block(s) released'
                   . ($e['failed'] > 0 ? ', ' . $e['failed'] . ' failed' : ''));
            }
        },
    ],

    'wafingest' => [
        'schedule' => setting('waf_ingest_schedule', 'every'),
        'time'     => '00:00',
        'day'      => 0,
        'run'      => function () {
            $w  = new WAF();
            $n  = $w->ingestModSecLog();
            $st = $w->ingestStatus();
            slog($st['log_found']
                ? "  WAF: ingested {$n} event(s) from {$st['log_path']}"
                : '  WAF: no ModSecurity audit log found - nothing to ingest');
        },
    ],

    'rtguard' => [
        'schedule' => setting('rt_autostart_schedule', 'every'),
        'time'     => '00:00',
        'day'      => 0,
        'run'      => function () {
            $m = new RealTimeMonitor();
            $r = $m->autoResume();
            slog('  real-time guard: ' . ($r['reason'] ?? '?')
               . (!empty($r['acted']) ? ' (monitor started)' : ''));
        },
    ],

    'quarclean' => [
        // Quarantine only ever grew: nothing removed anything, so a server
        // scanning nightly keeps every infected file it has ever seen until the
        // disk is gone. That is what filled a live server's root partition.
        'schedule' => setting('quarantine_clean_schedule', 'daily'),
        'time'     => setting('quarantine_clean_time', '04:30'),
        'day'      => (int)setting('quarantine_clean_day', '0'),
        'run'      => function () {
            // sweepQuarantine() applies the per-severity deadlines first and
            // then falls back to pruneQuarantine() for the age-based backstop,
            // which is what clears files quarantined before deadlines existed.
            $r = Scanner::sweepQuarantine();
            slog('  quarantine: ' . (int)$r['expired'] . ' expired by policy, '
                 . (int)$r['aged_out'] . ' by age, ' . (int)$r['kept'] . ' kept');

            // Per-scan logs are one file per scan and were never pruned either.
            $logs = defined('SG_LOGS') ? SG_LOGS : null;
            if ($logs && is_dir($logs)) {
                $cut = time() - 7 * 86400;
                $n = 0;
                foreach (glob($logs . '/scan_*.log') ?: [] as $f) {
                    if (@filemtime($f) < $cut && @unlink($f)) { $n++; }
                }
                if ($n) { slog("  removed {$n} old scan log(s)"); }
            }
        },
    ],
];

// ── Dispatch ──────────────────────────────────────────────────────────────────
$ran = 0;
// ---- --status: what is scheduled, and when it last ran ---------------------
//
// Built from $tasks itself rather than a second list kept somewhere else. A
// copy of this table in the CLI was wrong within minutes of being written --
// one setting key misspelled, one task that does not exist, five missing --
// and a status report that lies is worse than no status report.
if ($status) {
    printf("%-12s %-9s %-7s %-22s %s\n", 'TASK', 'SCHEDULE', 'AT', 'LAST RUN', 'STATUS');
    foreach ($tasks as $name => $t) {
        $sched = (string) $t['schedule'];
        $last  = lastRun($name);

        if ($sched === 'off' || $sched === 'disabled' || $sched === '') {
            $state = 'disabled';
        } elseif ($last === 0) {
            $state = 'NEVER RUN';
        } else {
            $limit = ['every' => 900, 'hourly' => 3600,
                      'daily' => 86400, 'weekly' => 604800][$sched] ?? 86400;
            // Twice its own period with no run means it is not happening,
            // which is the question this command exists to answer.
            $state = ($now - $last) > ($limit * 2) ? 'OVERDUE' : 'ok';
        }

        printf("%-12s %-9s %-7s %-22s %s\n",
               $name, $sched, (string) ($t['time'] ?? '-'),
               $last ? gmdate('Y-m-d H:i:s', $last) . 'Z' : '-',
               $state);
    }
    echo PHP_EOL;
    echo 'Scheduler output goes to: ' . SG_LOGS . '/cron.log' . PHP_EOL;
    $live = Scanner::liveScans();
    echo 'Scans running now:        ' . count($live)
       . ($live ? ' (job ' . implode(', ', array_column($live, 'id')) . ')' : '')
       . PHP_EOL;
    exit(0);
}

foreach ($tasks as $name => $t) {
    $due = $force === $name
        ? true
        : ($force === null && isDue($name, $t['schedule'], $now, $t['time'], $t['day']));

    if (!$due) { continue; }

    if ($dryRun) { slog("DUE (dry run): $name [{$t['schedule']}]"); $ran++; continue; }

    slog("running: $name [{$t['schedule']}]");
    try {
        // A task that returns false did NOT do its work and must stay due.
        //
        // This is what stopped the nightly malware scan from ever running. The
        // scan task defers while a backup is in progress -- correctly, since
        // two processes reading the whole filesystem at once is the problem it
        // exists to avoid -- and then returned normally, so markRun() recorded
        // it as having run. A 'daily' task is not due again for 24 hours, so
        // on a server whose JetBackup window covers 02:00 the scan was
        // deferred and marked done every single night, for ever. The deferral
        // was right; counting it as a run was not.
        $outcome = $t['run']();
        if ($outcome === false) {
            slog("  deferred: $name stays due");
            continue;
        }
        markRun($name);
        $ran++;
    } catch (Throwable $e) {
        // One failing task must not prevent the others from running.
        slog("  ERROR in $name: " . $e->getMessage());
        Logger::error("scheduler[$name]: " . $e->getMessage());
    }
}

if ($ran === 0) { exit(0); }   // silent when idle — keeps the cron log readable
slog("done — $ran task(s)");
