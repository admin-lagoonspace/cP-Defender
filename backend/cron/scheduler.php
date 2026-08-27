#!/usr/bin/env php
<?php
/**
 * Sentinel Gate — task scheduler
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
 * Usage:  php backend/cron/scheduler.php [--force <task>] [--dry-run]
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
require_once SG_ROOT . '/backend/lib/Scanner.php';
require_once SG_ROOT . '/backend/lib/IPReputation.php';
require_once SG_ROOT . '/backend/lib/License.php';
// Newly scheduled modules. Omitting these is a fatal on the first cron run,
// which nothing would have reported until a panel stayed empty for a week.
require_once SG_ROOT . '/backend/lib/CMSGuard.php';
require_once SG_ROOT . '/backend/lib/BotShield.php';
require_once SG_ROOT . '/backend/lib/RootkitScanner.php';
require_once SG_ROOT . '/backend/lib/RootkitEngine.php';
require_once SG_ROOT . '/backend/lib/FileIntegrity.php';

$force  = null;
$dryRun = false;
for ($i = 1; $i < $argc; $i++) {
    if ($argv[$i] === '--force' && isset($argv[$i + 1])) { $force = $argv[++$i]; }
    elseif ($argv[$i] === '--dry-run') { $dryRun = true; }
}

function slog(string $m): void {
    echo '[' . gmdate('Y-m-d\TH:i:s\Z') . "] $m\n";
}

// Keep the flag the Python daemon reads fresh — this is the most frequent PHP
// entry point, so it is the most reliable place to do it.
License::publishFlag();

if (!License::protectionAllowed()) {
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
    if ($schedule === 'off') { return false; }

    $last = lastRun($task);
    if ($last === 0) { return true; }          // never run — run now

    $elapsed = $now - $last;

    switch ($schedule) {
        case 'hourly':
            return $elapsed >= 3600 - 300;      // 5 min slack for tick jitter

        case 'daily':
            if ($elapsed < 86400 - 300) { return false; }
            return pastTimeOfDay($atTime, $now, $last);

        case 'weekly':
            if ($elapsed < 604800 - 300) { return false; }
            if ((int)date('w', $now) !== $onDay) { return false; }
            return pastTimeOfDay($atTime, $now, $last);
    }
    return false;
}

/** True once today has passed the configured time and we have not run since. */
function pastTimeOfDay(string $hhmm, int $now, int $last): bool {
    [$h, $m] = array_pad(explode(':', $hhmm, 2), 2, '0');
    $target  = mktime((int)$h, (int)$m, 0, (int)date('n', $now), (int)date('j', $now), (int)date('Y', $now));
    if ($now < $target) { return false; }
    return $last < $target;
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
            foreach ($paths as $p) {
                if (!is_dir($p)) { slog("  skip missing path: $p"); continue; }
                $job = $sc->startScan($p, $type);
                slog("  started $type scan of $p (job $job)");
            }
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
            $n = (int)($r['findings'] ?? (is_array($r['findings'] ?? null) ? count($r['findings']) : 0));
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
];

// ── Dispatch ──────────────────────────────────────────────────────────────────
$ran = 0;
foreach ($tasks as $name => $t) {
    $due = $force === $name
        ? true
        : ($force === null && isDue($name, $t['schedule'], $now, $t['time'], $t['day']));

    if (!$due) { continue; }

    if ($dryRun) { slog("DUE (dry run): $name [{$t['schedule']}]"); $ran++; continue; }

    slog("running: $name [{$t['schedule']}]");
    try {
        $t['run']();
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
