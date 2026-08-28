<?php
/**
 * Sentinel Gate — Real-Time Monitor Manager
 * Controls the Python inotify daemon from the PHP API
 */

class RealTimeMonitor {

    private string $daemonScript;
    private string $pidFile;
    private string $logFile;
    private string $serviceFile;

    /**
     * How shell commands are run. Injectable so the status logic can be tested
     * without systemd: the previous code called exec() directly, which made
     * every branch of it unreachable from a test and is why "Active" could be
     * displayed beside empty counters for so long without anyone noticing.
     *
     * @var callable(string):array{0:string[],1:int}
     */
    private $exec;

    public function __construct(?array $paths = null, ?callable $exec = null) {
        $this->daemonScript = $paths['daemon']  ?? SG_ROOT . '/backend/daemon/monitor.py';
        $this->pidFile      = $paths['pid']     ?? '/var/run/sentinel-gate-monitor.pid';
        $this->logFile      = $paths['log']     ?? SG_LOGS . '/monitor.log';
        $this->serviceFile  = $paths['service'] ?? '/etc/systemd/system/sentinel-gate-monitor.service';

        $this->exec = $exec ?? function (string $cmd): array {
            $out = [];
            $code = 0;
            exec($cmd, $out, $code);
            return [$out, $code];
        };
    }

    /** @return array{0:string[],1:int} */
    private function run(string $cmd): array {
        return ($this->exec)($cmd);
    }

    // ── Status ──────────────────────────────────────────────────────────────

    /**
     * Is the daemon actually running?
     *
     * The PID file is written by the daemon itself and lives in /var/run, which
     * is tmpfs: it disappears on reboot, and a crash can leave it behind
     * pointing at a PID that no longer exists or has been reused. Systemd is
     * the authority on a service it manages, so it is consulted whenever the
     * PID file does not give a clear answer. Reporting "stopped" for a running
     * monitor is exactly as harmful as the reverse.
     */
    public function isRunning(): bool {
        if (file_exists($this->pidFile)) {
            $pid = (int) trim((string) @file_get_contents($this->pidFile));
            if ($pid > 0 && file_exists("/proc/$pid")) {
                return true;
            }
        }
        return $this->isServiceActive();
    }

    /**
     * Is the unit running right now, AND staying up?
     *
     * `is-active` alone is not enough. A daemon that crashes on its first line
     * and is relaunched by Restart=on-failure cycles through active/activating
     * for as long as systemd keeps trying, so `is-active` answers "active"
     * about a process that has never worked. That is precisely what happened:
     * the daemon died on a Python 3.8 argument under 3.6, systemd restarted it
     * in a loop, and the dashboard reported "Monitor started".
     *
     * SubState separates them: `running` is up, `auto-restart` is being
     * resurrected.
     */
    public function isServiceActive(): bool {
        $d = $this->serviceDetail();
        return $d['active'] === 'active' && $d['sub'] === 'running';
    }

    /**
     * ActiveState, SubState and the restart count.
     *
     * @return array{active:string,sub:string,restarts:int}
     */
    public function serviceDetail(): array {
        if (!file_exists($this->serviceFile)) {
            return ['active' => 'not-installed', 'sub' => '', 'restarts' => 0];
        }
        [$out, ] = $this->run(
            'systemctl show sentinel-gate-monitor -p ActiveState -p SubState -p NRestarts 2>/dev/null');

        $vals = [];
        foreach ($out as $line) {
            $parts = explode('=', trim($line), 2);
            if (count($parts) === 2) { $vals[$parts[0]] = $parts[1]; }
        }
        return [
            'active'   => $vals['ActiveState'] ?? 'unknown',
            'sub'      => $vals['SubState'] ?? '',
            'restarts' => (int)($vals['NRestarts'] ?? 0),
        ];
    }

    /** The last lines the daemon logged — what a failed start must report. */
    public function recentLog(int $lines = 12): string {
        if (is_readable($this->logFile)) {
            [$out, ] = $this->run('tail -n ' . (int)$lines . ' ' . escapeshellarg($this->logFile));
            if ($out) { return trim(implode("\n", $out)); }
        }
        [$out, ] = $this->run(
            'journalctl -u sentinel-gate-monitor -n ' . (int)$lines . ' --no-pager 2>/dev/null');
        return trim(implode("\n", $out));
    }

    public function getStatus(): array {
        $detail       = $this->serviceDetail();
        $running      = $this->isRunning();
        // Running may be true on systemd's word alone, with no PID file present
        // — reading it unconditionally warned on every request in that case.
        $pid = null;
        if ($running && is_readable($this->pidFile)) {
            $pid = (int) trim((string) @file_get_contents($this->pidFile)) ?: null;
        }
        $filesChecked = (int) (Database::setting('rt_files_checked') ?? 0);
        $threatsFound = (int) (Database::setting('rt_threats_found') ?? 0);
        $lastActivity = Database::setting('rt_last_activity');
        $engine       = $this->detectEngine();

        // Count real-time detections (last 24h)
        $since      = time() - 86400;
        $rt24h      = Database::fetchOne(
            "SELECT COUNT(*) as c FROM threats WHERE threat_type='realtime_detection' AND detected_at >= ?",
            [$since]
        )['c'] ?? 0;

        // Total real-time detections ever
        $rtTotal = Database::fetchOne(
            "SELECT COUNT(*) as c FROM threats WHERE threat_type='realtime_detection'"
        )['c'] ?? 0;

        // Watch paths
        $paths = Database::setting('scan_paths', '/home');

        // A daemon can be "running" and yet doing nothing — wrong watch paths,
        // an exception in its loop, inotify watches exhausted. It stamps
        // rt_last_activity as it works, so silence is measurable and worth
        // surfacing rather than showing a green badge and empty counters.
        $age   = $lastActivity !== null ? max(0, time() - (int) $lastActivity) : null;
        $stale = $running && ($age === null || $age > 3600);

        return [
            'running'           => $running,
            'pid'               => $pid,
            'engine'            => $engine,
            'watch_paths'       => array_map('trim', explode(',', $paths)),
            'files_checked'     => $filesChecked,
            'threats_found'     => $threatsFound,
            'detections_24h'    => (int) $rt24h,
            'detections_all'    => (int) $rtTotal,
            'last_activity'     => $lastActivity !== null ? (int) $lastActivity : null,
            'last_activity_age' => $age,
            'stale'             => $stale,
            'log_file'          => $this->logFile,
            // What the daemon reports as ACTUALLY in effect, which is not
            // necessarily what the settings say: it re-reads them on a cycle,
            // and a value out of range is clamped rather than obeyed.
            'profile'           => Database::setting('rt_profile', 'balanced'),
            'effective_profile' => Database::setting('rt_effective_profile'),
            'effective_rate'    => (int) (Database::setting('rt_effective_files_per_sec', '0') ?? 0),
            'watch_count'       => (int) (Database::setting('rt_watch_count', '0') ?? 0),
            'watch_capped'      => Database::setting('rt_watch_capped', '0') === '1',
            // A crash loop is the state that looked like success. Report it.
            'restarts'          => $detail['restarts'],
            'crash_looping'     => $detail['sub'] === 'auto-restart',
            'service_installed' => file_exists($this->serviceFile),
            'service_enabled'   => $this->isServiceEnabled(),
            'service_active'    => $this->isServiceActive(),
        ];
    }

    // ── Start / Stop ─────────────────────────────────────────────────────────

    public function start(): array {
        if ($this->isRunning()) {
            return ['success' => true, 'message' => 'Monitor already running'];
        }

        if (!file_exists($this->daemonScript)) {
            return ['success' => false, 'error' => 'Daemon script not found: ' . $this->daemonScript];
        }

        // Prefer systemd whenever the unit file is present
        if (file_exists($this->serviceFile)) {
            [$out, $code] = $this->run('systemctl start sentinel-gate-monitor 2>&1');

            if ($code === 0) {
                // Exit 0 means the process was LAUNCHED, not that it survived.
                // A daemon that dies immediately gets relaunched by
                // Restart=on-failure, and returning success here is how
                // "Monitor started" came to be shown over something that had
                // already crashed. Wait, then confirm it is still up.
                $detail = ['active' => '', 'sub' => '', 'restarts' => 0];
                for ($i = 0; $i < 8; $i++) {
                    usleep(400000);
                    $detail = $this->serviceDetail();
                    if ($detail['active'] === 'active' && $detail['sub'] === 'running') {
                        Database::setSetting('rt_monitor_status', 'running');
                        Logger::info('Real-time monitor started via systemd');
                        return ['success' => true, 'method' => 'systemd'];
                    }
                    if ($detail['sub'] === 'auto-restart' || $detail['active'] === 'failed') {
                        break;   // crashing; waiting longer will not help
                    }
                }

                $log = $this->recentLog();
                Logger::error('Monitor did not stay running: '
                              . $detail['active'] . '/' . $detail['sub']);
                return [
                    'success' => false,
                    'error'   => 'The service started but did not stay running ('
                               . $detail['active'] . '/' . $detail['sub']
                               . ($detail['restarts'] > 0
                                  ? ', ' . $detail['restarts'] . ' restarts' : '')
                               . '). Last log lines: ' . ($log !== '' ? $log : 'none'),
                    'detail'  => $detail,
                ];
            }

            return ['success' => false,
                    'error'   => 'systemctl start failed: ' . trim(implode(' ', $out))];
        }

        // Fallback: direct background launch
        $logFile = escapeshellarg($this->logFile);
        $script  = escapeshellarg($this->daemonScript);
        $cmd = "SG_ROOT=" . escapeshellarg(SG_ROOT) .
               " /usr/bin/python3 $script >> $logFile 2>&1 &";
        exec($cmd, $out, $code);

        usleep(500000); // 0.5s — let it start
        $started = $this->isRunning();

        if ($started) {
            Database::setSetting('rt_monitor_status', 'running');
            Logger::info("Real-time monitor started (direct)");
        }

        return [
            'success' => $started,
            'method'  => 'direct',
            'error'   => $started ? null : 'Daemon failed to start — check ' . $this->logFile,
        ];
    }

    public function stop(): array {
        // Prefer systemd whenever the unit file is present (installed),
        // regardless of whether auto-start is enabled.
        if (file_exists($this->serviceFile)) {
            exec('systemctl stop sentinel-gate-monitor 2>&1', $out, $code);
            Database::setSetting('rt_monitor_status', 'stopped');
            Logger::info("Real-time monitor stopped via systemd");
            return ['success' => $code === 0, 'output' => implode("\n", $out)];
        }

        // Kill by PID
        if (!file_exists($this->pidFile)) {
            return ['success' => true, 'message' => 'Not running'];
        }
        $pid = (int) trim(file_get_contents($this->pidFile));
        if ($pid > 0) {
            exec("kill -TERM $pid 2>&1", $out, $code);
            sleep(1);
            if ($this->isRunning()) {
                exec("kill -KILL $pid 2>&1");
            }
        }
        @unlink($this->pidFile);
        Database::setSetting('rt_monitor_status', 'stopped');
        Logger::info("Real-time monitor stopped");
        return ['success' => true];
    }

    public function restart(): array {
        $this->stop();
        sleep(1);
        return $this->start();
    }

    // ── Watch Paths ───────────────────────────────────────────────────────────

    public function addWatchPath(string $path): array {
        if (!is_dir($path)) {
            return ['success' => false, 'error' => "Path does not exist: $path"];
        }
        $current = Database::setting('scan_paths', '/home');
        $paths   = array_map('trim', explode(',', $current));
        if (in_array($path, $paths)) {
            return ['success' => true, 'message' => 'Path already watched'];
        }
        $paths[] = $path;
        Database::setSetting('scan_paths', implode(',', $paths));

        // Restart daemon to pick up new path
        if ($this->isRunning()) $this->restart();

        return ['success' => true, 'paths' => $paths];
    }

    public function removeWatchPath(string $path): array {
        $current = Database::setting('scan_paths', '/home');
        $paths   = array_filter(
            array_map('trim', explode(',', $current)),
            fn($p) => $p !== $path
        );
        Database::setSetting('scan_paths', implode(',', $paths));
        if ($this->isRunning()) $this->restart();
        return ['success' => true, 'paths' => array_values($paths)];
    }

    // ── Systemd ───────────────────────────────────────────────────────────────

    public function installService(): array {
        $service = $this->buildServiceUnit();
        if (!file_put_contents($this->serviceFile, $service)) {
            return ['success' => false, 'error' => 'Cannot write service file — run as root'];
        }
        exec('systemctl daemon-reload 2>&1', $o1);
        exec('systemctl enable sentinel-gate-monitor 2>&1', $o2);
        Logger::info("systemd service installed and enabled");
        return ['success' => true, 'output' => implode("\n", array_merge($o1, $o2))];
    }

    private function buildServiceUnit(): string {
        $root    = SG_ROOT;
        $script  = $this->daemonScript;
        $logFile = $this->logFile;
        return <<<UNIT
[Unit]
Description=Sentinel Gate Real-Time File Monitor
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Environment="SG_ROOT={$root}"
ExecStart=/usr/bin/python3 {$script}
Restart=on-failure
RestartSec=10
StandardOutput=append:{$logFile}
StandardError=append:{$logFile}
KillSignal=SIGTERM
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
UNIT;
    }

    /**
     * Enabled means "starts at boot". It does NOT mean running — a unit can be
     * enabled and dead. getStatus() used to report this as `service_active`,
     * so the dashboard displayed "Active" for a monitor that was not running,
     * beside counters that stayed empty because nothing was watching anything.
     */
    public function isServiceEnabled(): bool {
        if (!file_exists($this->serviceFile)) { return false; }
        [$out, ] = $this->run('systemctl is-enabled sentinel-gate-monitor 2>/dev/null');
        return trim($out[0] ?? '') === 'enabled';
    }

    /**
     * Detailed systemd service status — installed, enabled, active-state,
     * uptime, PID, memory.  Works whether running or not.
     */
    public function getServiceStatus(): array {
        $installed = file_exists($this->serviceFile);
        $enabled   = $installed && $this->isServiceEnabled();

        if (!$installed) {
            return [
                'installed'    => false,
                'enabled'      => false,
                'active'       => false,
                'active_state' => 'not-installed',
                'sub_state'    => '',
                'since'        => null,
                'main_pid'     => null,
                'memory_mb'    => null,
                'description'  => 'Service unit not installed',
            ];
        }

        // `systemctl show` returns KEY=VALUE lines — fast, machine-readable
        exec('systemctl show sentinel-gate-monitor ' .
             '--no-pager 2>/dev/null', $out);
        $props = [];
        foreach ($out as $line) {
            [$k, $v] = array_pad(explode('=', $line, 2), 2, '');
            $props[$k] = $v;
        }

        $activeState = $props['ActiveState']  ?? 'unknown';
        $subState    = $props['SubState']     ?? '';
        $mainPid     = (int) ($props['MainPID']     ?? 0);
        $memBytes    = (int) ($props['MemoryCurrent'] ?? 0);

        // ActiveEnterTimestamp is microseconds since epoch
        $since = null;
        $ts = $props['ActiveEnterTimestamp'] ?? '';
        if ($ts && $ts !== '0') {
            $since = (int) (substr($ts, 0, -6) ?: '0'); // strip µs
        }

        return [
            'installed'    => true,
            'enabled'      => $enabled,
            'active'       => $activeState === 'active',
            'active_state' => $activeState,
            'sub_state'    => $subState,
            'since'        => $since ?: null,
            'main_pid'     => $mainPid ?: null,
            'memory_mb'    => $memBytes > 0 ? round($memBytes / 1048576, 1) : null,
            'description'  => $props['Description'] ?? 'Sentinel Gate Monitor',
            'unit_file'    => $this->serviceFile,
        ];
    }

    public function enableService(): array {
        if (!file_exists($this->serviceFile)) {
            return ['success' => false, 'error' => 'Service not installed — install it first'];
        }
        exec('systemctl enable sentinel-gate-monitor 2>&1', $out, $code);
        Logger::info("Monitor service enabled");
        return ['success' => $code === 0, 'output' => implode("\n", $out)];
    }

    public function disableService(): array {
        exec('systemctl disable sentinel-gate-monitor 2>&1', $out, $code);
        Logger::info("Monitor service disabled");
        return ['success' => $code === 0, 'output' => implode("\n", $out)];
    }

    /**
     * Pull recent journal entries for the unit.
     * Returns plain-text lines newest-first.
     */
    public function getServiceLogs(int $lines = 50): array {
        exec(
            "journalctl -u sentinel-gate-monitor -n {$lines} " .
            "--no-pager --output=short-iso 2>/dev/null",
            $out, $code
        );
        if ($code !== 0 || empty($out)) {
            // Journald may not be available — fall back to daemon log tail
            return $this->getRecentLogs($lines);
        }
        return array_reverse($out); // newest first
    }

    // ── Recent Detections ─────────────────────────────────────────────────────

    public function getRecentDetections(int $limit = 50): array {
        return Database::fetchAll(
            "SELECT * FROM threats WHERE threat_type='realtime_detection' ORDER BY detected_at DESC LIMIT ?",
            [$limit]
        );
    }

    public function getRecentLogs(int $lines = 100): array {
        if (!file_exists($this->logFile)) return [];
        $all = file($this->logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        return array_slice(array_reverse($all), 0, $lines);
    }

    // ── Engine detection ──────────────────────────────────────────────────────

    private function detectEngine(): string {
        [$out, $code] = $this->run('/usr/bin/python3 -c "import inotify_simple; print(\'inotify\')" 2>/dev/null');
        return ($code === 0 && trim($out[0] ?? '') === 'inotify') ? 'inotify' : 'polling';
    }

    // ── Stats summary for dashboard ───────────────────────────────────────────

    public function getDashboardStats(): array {
        $status = $this->getStatus();
        return [
            'enabled'        => $status['running'],
            'running'        => $status['running'],
            'stale'          => $status['stale'],
            'engine'         => $status['engine'],
            'watch_paths'    => $status['watch_paths'],
            'files_checked'  => $status['files_checked'],
            'detections_24h' => $status['detections_24h'],
            'detections_all' => $status['detections_all'],
            'last_activity'  => $status['last_activity'],
        ];
    }
}
