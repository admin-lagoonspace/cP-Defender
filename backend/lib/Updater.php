<?php
/**
 * ServerScrub — Automatic update policy
 *
 * WHAT THIS IS FOR
 * ----------------
 * update.sh already knows how to apply a release safely: it verifies the
 * SHA-256, backs the install up, rsyncs, restarts the services and rolls back
 * if the new version fails to answer. What it does not do is decide WHETHER to
 * run. That decision is this class, and it is the whole of the risk, because
 * automatic updates on a shared host replace the security software of 118
 * paying customers without anyone watching.
 *
 * SO THE DEFAULTS ARE DELIBERATE
 * ------------------------------
 *   - Patch and minor versions apply automatically. A MAJOR bump never does.
 *     X is reserved in this product's own versioning scheme for a breaking
 *     change; applying one unattended is how a security tool becomes the
 *     outage.
 *   - Never while a scan is running. update.sh rsyncs over the install
 *     directory with --delete, which would pull the scanner's own code out
 *     from under a worker mid-walk.
 *   - Never while a backup is running. The same reasoning, plus JetBackup
 *     holds files open.
 *   - After a failure it backs off, and after three it stops trying and says
 *     so. A daily retry of an update that cannot work is a daily rsync over
 *     the install directory of a production server.
 *
 * A note on how it is launched: the updater replaces the very PHP that is
 * running it, so it is always started detached. A synchronous call is killed
 * partway through and leaves a half-applied install with nothing to report it.
 */

class Updater
{
    /** Where update.sh writes its progress. Outside SG_ROOT on purpose. */
    public const STATE_FILE = '/var/lib/serverscrub/update-state.json';

    /** A run older than this is assumed dead rather than in progress. */
    private const STALE_AFTER = 900;

    /** Give up after this many consecutive failures and tell the operator. */
    private const MAX_FAILURES = 3;

    // ── Settings ────────────────────────────────────────────────────────────

    /** Is unattended updating switched on? Default yes. */
    public static function autoEnabled(): bool
    {
        return Database::setting('auto_update', '1') === '1';
    }

    /**
     * May a major version be applied unattended? Default NO.
     *
     * Kept as a separate setting rather than folded into auto_update, because
     * "keep me patched" and "install anything the vendor ships" are different
     * appetites and the second one should be opt-in.
     */
    public static function autoMajorEnabled(): bool
    {
        return Database::setting('auto_update_major', '0') === '1';
    }

    // ── State ───────────────────────────────────────────────────────────────

    /**
     * What the updater is doing, if anything.
     *
     * @return array{running:bool,status:string,phase:string,percent:int,
     *               message:string,from_version:string,to_version:string,
     *               updated_at:int}
     */
    public static function state(): array
    {
        $blank = [
            'running' => false, 'status' => 'idle', 'phase' => 'idle',
            'percent' => 0, 'message' => '', 'from_version' => '',
            'to_version' => '', 'updated_at' => 0,
        ];
        if (!is_readable(self::STATE_FILE)) return $blank;

        $j = json_decode((string)@file_get_contents(self::STATE_FILE), true);
        if (!is_array($j)) return $blank;

        $age     = time() - (int)($j['updated_at'] ?? 0);
        $status  = (string)($j['status'] ?? 'idle');
        // A state file that says "running" but has not been touched for fifteen
        // minutes is a crashed updater, not a slow one. Reporting it as running
        // for ever would block every later attempt.
        $running = $status === 'running' && $age < self::STALE_AFTER;

        return [
            'running'      => $running,
            'status'       => $running ? 'running'
                              : ($status === 'running' ? 'stalled' : $status),
            'phase'        => (string)($j['phase']   ?? ''),
            'percent'      => (int)($j['percent']    ?? 0),
            'message'      => (string)($j['message'] ?? ''),
            'from_version' => (string)($j['from_version'] ?? ''),
            'to_version'   => (string)($j['to_version']   ?? ''),
            'updated_at'   => (int)($j['updated_at'] ?? 0),
        ];
    }

    /** Consecutive failed attempts. */
    public static function failureCount(): int
    {
        return (int)Database::setting('auto_update_failures', '0');
    }

    // ── The decision ────────────────────────────────────────────────────────

    /**
     * Should an update be applied right now, and if not, why not?
     *
     * Returns a REASON in every case, including the yes. The reason is written
     * to the cron log, and "skipped" with no explanation is indistinguishable
     * from "the task never ran" — which is how several modules in this product
     * sat broken for months.
     *
     * @return array{go:bool,reason:string,from?:string,to?:string}
     */
    public static function shouldApply(?array $status = null): array
    {
        if (!self::autoEnabled()) {
            return ['go' => false, 'reason' => 'automatic updates are switched off'];
        }

        $st = self::state();
        if ($st['running']) {
            return ['go' => false,
                    'reason' => 'an update is already running (' . $st['phase'] . ')'];
        }

        $fails = self::failureCount();
        if ($fails >= self::MAX_FAILURES) {
            return ['go' => false, 'reason' => sprintf(
                '%d consecutive failures — automatic updates paused until someone '
              . 'looks at %s and clears the counter', $fails, SG_LOGS . '/update.log')];
        }

        // Back off after a failure instead of retrying on the next tick. Each
        // attempt rsyncs over the install directory of a live server.
        $lastFail = (int)Database::setting('auto_update_last_fail', '0');
        if ($fails > 0 && $lastFail > 0) {
            $wait = 3600 * (2 ** ($fails - 1));   // 1h, 2h, 4h
            if (time() - $lastFail < $wait) {
                return ['go' => false, 'reason' => sprintf(
                    'backing off after %d failure(s) — next attempt in %d minute(s)',
                    $fails, (int)ceil(($wait - (time() - $lastFail)) / 60))];
            }
        }

        $status = $status ?? UpdateChecker::getCachedStatus();
        if (empty($status['update_available'])) {
            return ['go' => false, 'reason' => 'already on the latest version ('
                                             . ($status['current_version'] ?? '?') . ')'];
        }

        $from = (string)($status['current_version'] ?? '');
        $to   = (string)($status['latest_version']  ?? '');
        if ($to === '' || version_compare($to, $from, '<=')) {
            return ['go' => false, 'reason' => 'no newer version to apply'];
        }

        // A major bump is not applied unattended unless asked for.
        if (self::majorBump($from, $to) && !self::autoMajorEnabled()) {
            return ['go' => false, 'reason' => sprintf(
                'v%s is a major update and major updates are not applied '
              . 'automatically — apply it yourself when you are ready', $to)];
        }

        // Do not pull the floor out from under work in progress. update.sh
        // rsyncs over the install directory with --delete.
        $scan = Scanner::activeScan();
        if ($scan !== null) {
            return ['go' => false, 'reason' => 'a scan is running (job '
                                             . ($scan['id'] ?? '?') . ')'];
        }

        $backup = Scanner::backupRunning();
        if (!empty($backup['running'])) {
            return ['go' => false, 'reason' => 'a backup is running ('
                                             . ($backup['what'] ?? 'backup') . ')'];
        }

        return ['go' => true, 'reason' => "applying v$to over v$from",
                'from' => $from, 'to' => $to];
    }

    /** Is going from $from to $to a change of major version? */
    public static function majorBump(string $from, string $to): bool
    {
        $a = (int)explode('.', $from)[0];
        $b = (int)explode('.', $to)[0];
        return $b > $a;
    }

    // ── Doing it ────────────────────────────────────────────────────────────

    /**
     * Launch update.sh, detached.
     *
     * Detached is not an optimisation. The script rsyncs over SG_ROOT, which
     * includes the PHP that called it; a foreground run is killed partway
     * through and leaves a half-applied install and no record of why.
     *
     * Returns as soon as the child is started. Progress is in state().
     *
     * @param bool $auto true when this came from cron, which is recorded so
     *                   the log can tell an unattended update from a click.
     * @return array{success:bool,error?:string,pid?:int,data?:array}
     */
    public static function launch(bool $auto = false): array
    {
        $st = self::state();
        if ($st['running']) {
            return ['success' => false, 'error' => 'An update is already running',
                    'data' => $st];
        }

        $script = SG_ROOT . '/update.sh';
        if (!is_file($script)) {
            return ['success' => false,
                    'error' => 'update.sh is missing from ' . SG_ROOT];
        }
        if (!self::canRunShell()) {
            return ['success' => false, 'error' =>
                'This PHP cannot start a background process (shell functions are '
              . 'disabled), so the updater cannot be launched from the panel. '
              . 'Run: bash ' . $script . ' --yes'];
        }

        @mkdir(dirname(self::STATE_FILE), 0755, true);

        // Seed the state before starting, so the panel has something to poll
        // in the second before the script writes its own first update.
        @file_put_contents(self::STATE_FILE, json_encode([
            'status'  => 'running',
            'phase'   => 'starting',
            'percent' => 1,
            'message' => $auto ? 'Automatic update starting' : 'Update starting',
            'from_version' => defined('SG_VERSION') ? SG_VERSION : '',
            'to_version'   => (string)Database::setting('update_latest_ver', ''),
            'updated_at'   => time(),
        ]));

        Database::setSetting('auto_update_last_attempt', (string)time());
        Database::setSetting('update_last_trigger', $auto ? 'auto' : 'manual');

        $log = SG_LOGS . '/update.log';
        // setsid so it survives this request or cron run ending; </dev/null so
        // it can never block on input even if a prompt slips through.
        $cmd = sprintf('setsid nohup bash %s --yes </dev/null >> %s 2>&1 & echo $!',
                       escapeshellarg($script), escapeshellarg($log));
        $pid = (int)trim((string)@shell_exec($cmd));

        Logger::info(sprintf('%s update launched (pid %d): %s',
            $auto ? 'Automatic' : 'Manual', $pid,
            Database::setting('update_latest_ver', 'unknown version')));

        return ['success' => true, 'pid' => $pid, 'data' => self::state()];
    }

    /**
     * Record how the last run turned out.
     *
     * Called on the NEXT tick rather than by the updater itself, because the
     * updater is replaced mid-run and cannot reliably write its own obituary.
     * The state file is what it leaves behind.
     */
    public static function reconcile(): array
    {
        $st = self::state();
        $seen = Database::setting('auto_update_seen_at', '0');

        // Nothing new to account for.
        if ($st['updated_at'] === 0 || (string)$st['updated_at'] === $seen) {
            return ['changed' => false, 'status' => $st['status']];
        }
        if ($st['running']) return ['changed' => false, 'status' => 'running'];

        Database::setSetting('auto_update_seen_at', (string)$st['updated_at']);

        if ($st['status'] === 'success') {
            Database::setSetting('auto_update_failures', '0');
            Database::setSetting('auto_update_last_ok',  (string)time());
            Logger::info(sprintf('Update completed: v%s -> v%s',
                $st['from_version'] ?: '?', $st['to_version'] ?: '?'));
            return ['changed' => true, 'status' => 'success'];
        }

        // failed, rolled_back or stalled — all of them count against the
        // backoff, because all three mean the attempt did not land.
        $n = self::failureCount() + 1;
        Database::setSetting('auto_update_failures',  (string)$n);
        Database::setSetting('auto_update_last_fail', (string)time());
        Logger::error(sprintf('Update %s at phase "%s": %s (failure %d of %d '
                            . 'before automatic updates pause)',
            $st['status'], $st['phase'] ?: '?', $st['message'] ?: 'no detail',
            $n, self::MAX_FAILURES));

        return ['changed' => true, 'status' => $st['status'], 'failures' => $n];
    }

    /** Let the operator resume automatic updates after fixing whatever broke. */
    public static function clearFailures(): void
    {
        Database::setSetting('auto_update_failures',  '0');
        Database::setSetting('auto_update_last_fail', '0');
        Logger::info('Automatic update failure counter cleared by operator');
    }

    /**
     * Everything the panel needs in one call.
     */
    public static function status(): array
    {
        $check = UpdateChecker::getCachedStatus();
        $st    = self::state();
        $dec   = self::shouldApply($check);

        return [
            'current_version'  => $check['current_version']  ?? '',
            'latest_version'   => $check['latest_version']   ?? '',
            'update_available' => (bool)($check['update_available'] ?? false),
            'checked_at'       => (int)($check['checked_at'] ?? 0),
            'release_url'      => $check['release_url'] ?? '',
            'auto_enabled'     => self::autoEnabled(),
            'auto_major'       => self::autoMajorEnabled(),
            'auto_time'        => Database::setting('autoupdate_time', '04:30'),
            'failures'         => self::failureCount(),
            'paused'           => self::failureCount() >= self::MAX_FAILURES,
            'last_ok'          => (int)Database::setting('auto_update_last_ok', '0'),
            'last_attempt'     => (int)Database::setting('auto_update_last_attempt', '0'),
            'last_trigger'     => Database::setting('update_last_trigger', ''),
            'run'              => $st,
            // Shown verbatim in the panel. "Will not update" with no reason is
            // the thing this field exists to prevent.
            'next_action'      => $dec['go'] ? 'will apply on the next check'
                                             : $dec['reason'],
            'can_launch'       => self::canRunShell(),
        ];
    }

    /**
     * Can this PHP start a detached process at all?
     *
     * Hardened hosts disable shell_exec, and PHPHardening in this very product
     * offers to do it. Without this check the panel reports a launched update
     * that never started.
     */
    public static function canRunShell(): bool
    {
        if (!function_exists('shell_exec')) return false;
        $disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
        return !in_array('shell_exec', $disabled, true);
    }
}
