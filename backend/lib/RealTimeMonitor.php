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

        // Prefer systemd
        if ($this->isServiceEnabled()) {
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
        // Systemd path
        if ($this->isServiceEnabled()) {
            exec('systemctl stop sentinel-gate-monitor 2>&1', $out, $code);
            Database::setSetting('rt_monitor_status', 'stopped');
            Logger::info("Real-time monitor stopped via systemd");
            return ['success' => true];
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
