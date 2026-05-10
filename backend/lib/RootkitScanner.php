<?php
/**
 * Sentinel Gate — Rootkit Scanner Module
 * Executes rkhunter and/or chkrootkit and stores parsed results
 */

class RootkitScanner {

    public function __construct() {
        $this->ensureSchema();
    }

    private function ensureSchema(): void {
        Database::get()->exec("
            CREATE TABLE IF NOT EXISTS rootkit_scans (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                tool           TEXT NOT NULL,
                status         TEXT NOT NULL DEFAULT 'running',
                started_at     INTEGER,
                finished_at    INTEGER,
                warnings_count INTEGER NOT NULL DEFAULT 0,
                clean_count    INTEGER NOT NULL DEFAULT 0,
                infected_count INTEGER NOT NULL DEFAULT 0,
                raw_output     TEXT
            );

            CREATE TABLE IF NOT EXISTS rootkit_findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL REFERENCES rootkit_scans(id),
                finding_type TEXT NOT NULL,
                category    TEXT,
                description TEXT,
                severity    TEXT NOT NULL DEFAULT 'medium'
            );
        ");
    }

    // ── Availability ──────────────────────────────────────────────────────────

    public function isRkhunterAvailable(): bool {
        if (file_exists('/usr/bin/rkhunter')) return true;
        exec('which rkhunter 2>/dev/null', $out, $code);
        return $code === 0 && !empty($out[0]);
    }

    public function isChkrootkitAvailable(): bool {
        return file_exists('/usr/sbin/chkrootkit');
    }

    // ── Status ────────────────────────────────────────────────────────────────

    public function getStatus(): array {
        $lastScan = Database::fetchOne(
            "SELECT * FROM rootkit_scans ORDER BY id DESC LIMIT 1"
        );

        $lastResult = null;
        if ($lastScan) {
            $lastResult = [
                'warnings_count' => (int) $lastScan['warnings_count'],
                'clean_count'    => (int) $lastScan['clean_count'],
                'infected_count' => (int) $lastScan['infected_count'],
                'scan_type'      => $lastScan['tool'],
                'status'         => $lastScan['status'],
            ];
        }

        return [
            'rkhunter_available'    => $this->isRkhunterAvailable(),
            'chkrootkit_available'  => $this->isChkrootkitAvailable(),
            'last_scan'             => $lastScan,
            'last_result'           => $lastResult,
        ];
    }

    // ── Run Scan ──────────────────────────────────────────────────────────────

    public function runScan(string $tool = 'rkhunter'): array {
        if ($tool === 'chkrootkit' && !$this->isChkrootkitAvailable()) {
            return ['error' => 'chkrootkit is not installed'];
        }
        if ($tool === 'rkhunter' && !$this->isRkhunterAvailable()) {
            return ['error' => 'rkhunter is not installed'];
        }

        $startedAt = time();
        $scanId    = Database::insert('rootkit_scans', [
            'tool'       => $tool,
            'status'     => 'running',
            'started_at' => $startedAt,
        ]);

        $rawLines = [];
        if ($tool === 'rkhunter') {
            exec('rkhunter --check --skip-keypress --report-warnings-only 2>&1', $rawLines, $code);
        } else {
            exec('chkrootkit 2>&1', $rawLines, $code);
        }

        $rawOutput = implode("\n", $rawLines);
        $findings  = ($tool === 'rkhunter')
            ? $this->parseRkhunter($rawLines, $scanId)
            : $this->parseChkrootkit($rawLines, $scanId);

        $warningsCount = 0;
        $cleanCount    = 0;
        $infectedCount = 0;

        foreach ($findings as $f) {
            match ($f['finding_type']) {
                'warning'  => $warningsCount++,
                'infected' => $infectedCount++,
                'clean'    => $cleanCount++,
                default    => null,
            };
        }

        $status = ($infectedCount > 0) ? 'infected'
                : (($warningsCount > 0) ? 'warnings' : 'clean');

        Database::query(
            "UPDATE rootkit_scans
             SET status=?, finished_at=?, warnings_count=?, clean_count=?, infected_count=?, raw_output=?
             WHERE id=?",
            [$status, time(), $warningsCount, $cleanCount, $infectedCount, $rawOutput, $scanId]
        );

        Logger::info("RootkitScanner: $tool scan complete — $warningsCount warnings, $infectedCount infected, $cleanCount clean");

        return [
            'scan_id'        => $scanId,
            'tool'           => $tool,
            'status'         => $status,
            'warnings_count' => $warningsCount,
            'clean_count'    => $cleanCount,
            'infected_count' => $infectedCount,
            'findings'       => $findings,
        ];
    }

    public function getScans(int $limit = 10): array {
        return Database::fetchAll(
            "SELECT * FROM rootkit_scans ORDER BY id DESC LIMIT ?", [$limit]
        );
    }

    public function getFindings(int $scanId): array {
        return Database::fetchAll(
            "SELECT * FROM rootkit_findings WHERE scan_id = ? ORDER BY id ASC", [$scanId]
        );
    }

    // ── Parsers ───────────────────────────────────────────────────────────────

    private function parseRkhunter(array $lines, int $scanId): array {
        $findings = [];
        $category = 'general';

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') continue;

            // Section marker
            if (stripos($line, 'Rootkit check results') !== false ||
                preg_match('/^-+\s*(.+?)\s*-+$/', $line, $sm)) {
                $category = isset($sm[1]) ? trim($sm[1]) : 'rootkit';
                continue;
            }

            // Explicit warning lines
            if (preg_match('/^Warning:\s*(.+)$/i', $line, $m)) {
                $findings[] = $this->storeFinding($scanId, 'warning', $category, $m[1], 'high');
                continue;
            }

            // Check result lines: "  Checking ... [ Warning ]" or "[ OK ]"
            if (preg_match('/\[\s*(Warning|OK)\s*\]/', $line, $m)) {
                $type        = strtolower($m[1]) === 'ok' ? 'clean' : 'warning';
                $severity    = $type === 'warning' ? 'medium' : 'low';
                $description = preg_replace('/\[.*?\]/', '', $line);
                $description = trim(preg_replace('/\s+/', ' ', $description));
                $findings[]  = $this->storeFinding($scanId, $type, $category, $description, $severity);
            }
        }

        return $findings;
    }

    private function parseChkrootkit(array $lines, int $scanId): array {
        $findings = [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') continue;

            if (stripos($line, 'not tested') !== false) {
                continue; // skip untested checks
            }

            if (stripos($line, 'INFECTED') !== false) {
                $findings[] = $this->storeFinding($scanId, 'infected', 'chkrootkit', $line, 'critical');
                continue;
            }

            if (stripos($line, 'not infected') !== false) {
                $findings[] = $this->storeFinding($scanId, 'clean', 'chkrootkit', $line, 'low');
            }
        }

        return $findings;
    }

    private function storeFinding(
        int $scanId,
        string $type,
        string $category,
        string $description,
        string $severity
    ): array {
        $id = Database::insert('rootkit_findings', [
            'scan_id'      => $scanId,
            'finding_type' => $type,
            'category'     => $category,
            'description'  => $description,
            'severity'     => $severity,
        ]);

        return [
            'id'           => $id,
            'scan_id'      => $scanId,
            'finding_type' => $type,
            'category'     => $category,
            'description'  => $description,
            'severity'     => $severity,
        ];
    }
}
