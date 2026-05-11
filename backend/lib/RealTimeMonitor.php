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

    public function __construct() {
        $this->daemonScript = SG_ROOT . '/backend/daemon/monitor.py';
        $this->pidFile      = '/var/run/sentinel-gate-monitor.pid';
        $this->logFile      = SG_LOGS . '/monitor.log';
        $this->serviceFile  = '/etc/systemd/system/sentinel-gate-monitor.service';
    }

    // ── Status ──────────────────────────────────────────────────────────────

    public function isRunning(): bool {
        if (!file_exists($this->pidFile)) return false;
        $pid = (int) trim(file_get_contents($this->pidFile));
        if ($pid <= 0) return false;
        return file_exists("/proc/$pid");
    }

    public function getStatus(): array {
        $running      = $this->isRunning();
        $pid          = $running ? (int) trim(file_get_contents($this->pidFile)) : null;
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

        return [
            'running'       => $running,
            'pid'           => $pid,
            'engine'        => $engine,
            'watch_paths'   => array_map('trim', explode(',', $paths)),
            'files_checked' => $filesChecked,
            'threats_found' => $threatsFound,
            'detections_24h'=> (int) $rt24h,
            'detections_all'=> (int) $rtTotal,
            'last_activity' => $lastActivity,
            'log_file'      => $this->logFile,
            'service_active'=> $this->isServiceEnabled(),
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
            exec('systemctl start sentinel-gate-monitor 2>&1', $out, $code);
            if ($code === 0) {
                Database::setSetting('rt_monitor_status', 'running');
                Logger::info("Real-time monitor started via systemd");
                return ['success' => true, 'method' => 'systemd'];
            }
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

    private function isServiceEnabled(): bool {
        if (!file_exists($this->serviceFile)) return false;
        exec('systemctl is-enabled sentinel-gate-monitor 2>/dev/null', $out);
        return ($out[0] ?? '') === 'enabled';
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
        exec('/usr/bin/python3 -c "import inotify_simple; print(\'inotify\')" 2>/dev/null', $out, $code);
        return ($code === 0 && ($out[0] ?? '') === 'inotify') ? 'inotify' : 'polling';
    }

    // ── Stats summary for dashboard ───────────────────────────────────────────

    public function getDashboardStats(): array {
        $status = $this->getStatus();
        return [
            'enabled'        => $status['running'],
            'engine'         => $status['engine'],
            'watch_paths'    => $status['watch_paths'],
            'files_checked'  => $status['files_checked'],
            'detections_24h' => $status['detections_24h'],
            'detections_all' => $status['detections_all'],
        ];
    }
}
