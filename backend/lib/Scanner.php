<?php
/**
 * Sentinel Gate — Malware Scanner Module
 * ClamAV + custom signature-based scanning
 */

class Scanner {

    private array $customSignatures = [];
    private array $phpPatterns      = [];

    public function __construct() {
        $this->loadSignatures();
        $this->phpPatterns = [
            // Obfuscation
            'base64_decode_exec'    => '/base64_decode\s*\(.*\)\s*;?\s*\)?\s*;?\s*eval\s*\(/i',
            'eval_base64'           => '/eval\s*\(\s*base64_decode\s*\(/i',
            'eval_gzinflate'        => '/eval\s*\(\s*gzinflate\s*\(/i',
            'eval_str_rot13'        => '/eval\s*\(\s*str_rot13\s*\(/i',
            'preg_replace_eval'     => '/preg_replace\s*\(\s*[\'"].*\/e[\'"],/i',
            'assert_base64'         => '/assert\s*\(\s*base64_decode\s*\(/i',
            'hex_decode_exec'       => '/\\\\x[0-9a-f]{2}.*eval/i',
            'gzuncompress_eval'     => '/eval\s*\(\s*gzuncompress\s*\(/i',
            // Shells
            'c99_shell'             => '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[.{0,30}\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'system_shell'          => '/\$_(?:GET|POST|REQUEST)\s*\[.{0,30}\]\s*;\s*(?:system|exec|passthru|shell_exec)/i',
            'backdoor_connect'      => '/fsockopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'stdin_exec'            => '/proc_open.*STDIN.*STDOUT.*STDERR/is',
            'reverse_shell'         => '/(?:bash|sh)\s*-i\s*>&?\s*\/dev\/tcp/i',
            // Crypto miners
            'xmrig_pattern'         => '/stratum\+tcp:\/\/|xmrig|moneropool|minergate\.com/i',
            'coin_hive'             => '/CoinHive\.Anonymous|coinhive\.min\.js/i',
            // Injections
            'spam_mailer'           => '/\$(?:to|from|subject|body|message)\s*=.*(?:@gmail|@yahoo|@hotmail).*;.*mail\s*\(/is',
            'seo_spam_hidden'       => '/<div\s+style=["\']display\s*:\s*none["\'][^>]*>.*(?:viagra|cialis|pharmacy|casino|poker)/is',
            // Encoded payloads
            'long_base64'           => '/[\'"][A-Za-z0-9+\/]{500,}={0,2}[\'"]/',
            'hex_string_long'       => '/[\'"][0-9a-f]{200,}[\'"]/i',
            'char_code_obf'         => '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)/i',
        ];
    }

    private function loadSignatures(): void {
        $sigFile = SIG_DIR . '/custom.sig';
        if (file_exists($sigFile)) {
            $lines = file($sigFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (str_starts_with($line, '#')) continue;
                $parts = explode(':', $line, 3);
                if (count($parts) === 3) {
                    $this->customSignatures[] = [
                        'name'    => $parts[0],
                        'type'    => $parts[1],
                        'pattern' => $parts[2],
                    ];
                }
            }
        }
    }

    /**
     * CPU limit → Linux nice value (0–19).
     * 100 % CPU → nice 0 (normal),  10 % CPU → nice 19 (lowest priority).
     */
    private static function getCpuNice(): int {
        $pct = max(10, min(100, (int) (Database::setting('cpu_limit_percent') ?? 50)));
        return (int) round(19 * (1.0 - $pct / 100.0));
    }

    /**
     * Build the nice/ionice prefix for external commands.
     * Uses idle I/O class (-c3) so scans never starve interactive I/O.
     */
    private static function nicePrefix(): string {
        $nice = self::getCpuNice();
        // ionice may not be available on all systems; ignore if missing
        return "nice -n{$nice} ionice -c3 2>/dev/null || nice -n{$nice}";
    }

    /**
     * Start a new scan job
     */
    public function startScan(string $path = '/home', string $type = 'quick'): int {
        $jobId = Database::insert('scan_jobs', [
            'scan_type'  => $type,
            'status'     => 'running',
            'started_at' => time(),
            'scan_path'  => $path,
        ]);

        // Write job file so cron can pick it up
        if (!is_dir(SG_TMP)) mkdir(SG_TMP, 0750, true);
        file_put_contents(SG_TMP . '/current_job.json', json_encode([
            'id'   => $jobId,
            'path' => $path,
            'type' => $type,
        ]));

        // Launch async via background process with CPU throttling
        $nice = self::getCpuNice();
        $cmd  = sprintf(
            'nice -n%d %s %s/backend/cron/scan.php --job-id=%d --path=%s > %s/scan_%d.log 2>&1 &',
            $nice,
            escapeshellarg(self::phpBinary()),
            SG_ROOT,
            $jobId,
            escapeshellarg($path),
            SG_LOGS,
            $jobId
        );
        exec($cmd);

        return $jobId;
    }

    /**
     * Run ClamAV scan on a path (synchronous, used by cron)
     */
    /**
     * Resolve the clamscan binary.
     *
     * The CLAMSCAN_BIN constant is /usr/bin/clamscan, but cPanel ships ClamAV at
     * /usr/local/cpanel/3rdparty/bin/clamscan. The installer detects the real
     * location and stores it in the clamscan_path setting — which this used to
     * ignore, so on every cPanel server ClamAV was installed and then silently
     * never used, with scans quietly falling back to the pattern engine.
     */
    public static function clamscanBin(): ?string {
        $stored = (string)Database::setting('clamscan_path', '');
        if ($stored !== '' && is_executable($stored)) { return $stored; }
        if (is_executable(CLAMSCAN_BIN)) { return CLAMSCAN_BIN; }
        foreach (['/usr/bin/clamscan', '/usr/local/bin/clamscan',
                  '/usr/local/cpanel/3rdparty/bin/clamscan', '/opt/clamav/bin/clamscan'] as $p) {
            if (is_executable($p)) { return $p; }
        }
        return null;
    }

    /**
     * A PHP binary that certainly exists.
     *
     * The scan worker was launched with a bare `php`, which relies on PATH. The
     * API runs under cpsrvd, whose environment is not a login shell, and on
     * cPanel the `php` that PATH resolves to may not be an EasyApache build at
     * all. PHP_BINARY is whatever is running this code right now, so it is the
     * one interpreter guaranteed to work.
     */
    public static function phpBinary(): string
    {
        // PHP_BINARY is whatever is executing right now -- and under cpsrvd that
        // is php-cgi, which REFUSES to run a script handed to it on the command
        // line ("Security Alert! The PHP CGI cannot be accessed directly")
        // unless REDIRECT_STATUS is set. So the background scan was launched
        // with an interpreter that exited immediately, the job row stayed at
        // zero, and the scan appeared to do nothing at all.
        //
        // Fixing the bare `php` in 3.20.0 replaced "might not be on PATH" with
        // "is definitely the wrong SAPI". A CLI binary is what a worker needs.
        $candidates = [];

        if (defined('PHP_BINARY') && PHP_BINARY !== '') {
            $base = basename(PHP_BINARY);
            if (strpos($base, 'cgi') === false && strpos($base, 'fpm') === false) {
                $candidates[] = PHP_BINARY;              // already a CLI binary
            } else {
                // The CLI build usually sits beside the CGI one.
                $candidates[] = preg_replace('/-?(cgi|fpm)$/', '', PHP_BINARY);
                $candidates[] = dirname(PHP_BINARY) . '/php';
            }
        }

        $candidates = array_merge($candidates, [
            '/usr/local/cpanel/3rdparty/bin/php',
            '/opt/cpanel/ea-php83/root/usr/bin/php',
            '/opt/cpanel/ea-php82/root/usr/bin/php',
            '/opt/cpanel/ea-php81/root/usr/bin/php',
            '/usr/bin/php',
            '/usr/local/bin/php',
        ]);

        foreach ($candidates as $cand) {
            if ($cand !== '' && is_executable($cand) && self::isCliBinary($cand)) {
                return $cand;
            }
        }
        return 'php';
    }

    /**
     * Does this binary run scripts as CLI?
     *
     * Asked rather than assumed from the filename: /usr/bin/php is a CGI build
     * on some cPanel servers, and a worker launched with it dies on the first
     * line with no output anyone reads.
     */
    private static function isCliBinary(string $bin): bool
    {
        $out = [];
        @exec(escapeshellarg($bin) . ' -r "echo PHP_SAPI;" 2>/dev/null', $out);
        return trim($out[0] ?? '') === 'cli';
    }

    /** True when a signature database exists — clamscan is unusable without one. */
    public static function clamSignaturesPresent(): bool {
        foreach (['/var/lib/clamav', '/usr/local/share/clamav', '/usr/share/clamav',
                  '/usr/local/cpanel/3rdparty/share/clamav'] as $d) {
            foreach (['main.cvd', 'main.cld', 'daily.cvd', 'daily.cld'] as $f) {
                if (is_file($d . '/' . $f)) { return true; }
            }
        }
        return false;
    }

    /**
     * Write progress to the job row.
     *
     * files_scanned was only written once, at the very end of the scan, and
     * even then it was countFiles() re-walking the directory afterwards rather
     * than a count of what had been examined. So the UI read 0 for the entire
     * duration of a scan and the dashboard stayed empty — reported as "I ran a
     * scan and nothing updated".
     *
     * Cheap enough to call every batch: one UPDATE against a single row.
     */
    public static function recordProgress(int $jobId, int $filesScanned, int $threatsFound): void
    {
        if ($jobId <= 0) { return; }
        Database::query(
            'UPDATE scan_jobs SET files_scanned = ?, threats_found = ? WHERE id = ?',
            [$filesScanned, $threatsFound, $jobId]
        );
    }

    /** Directories that are never worth scanning. */
    private const SCAN_SKIP_DIRS = [
        'node_modules', '.git', '.svn', 'cache', '.cache', 'proc', 'sys', 'dev',
    ];

    /**
     * Every regular file under $path, lazily.
     *
     * A generator so a scan of /home does not build a list of every file on the
     * server in memory before examining any of them.
     *
     * @return Generator<string>
     */
    private function walkFiles(string $path): Generator
    {
        if (is_file($path)) { yield $path; return; }
        if (!is_dir($path)) { return; }

        $dirIt = new RecursiveDirectoryIterator(
            $path,
            FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO
        );
        $filter = new RecursiveCallbackFilterIterator($dirIt, function ($current) {
            if ($current->isLink()) { return false; }   // symlink loops
            if ($current->isDir()) {
                return !in_array(strtolower($current->getFilename()), self::SCAN_SKIP_DIRS, true);
            }
            return true;
        });

        foreach (new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::LEAVES_ONLY) as $file) {
            if ($file->isFile()) { yield $file->getPathname(); }
        }
    }

    /**
     * Hand one batch of paths to clamscan.
     *
     * --file-list keeps the command line bounded: passing thousands of paths as
     * arguments hits ARG_MAX and fails outright on a large account.
     *
     * @param string[] $files
     * @return array<int,array<string,mixed>>
     */
    private function scanBatch(string $bin, array $files, int $jobId): array
    {
        if (!$files) { return []; }

        $listFile = tempnam(sys_get_temp_dir(), 'sg-scan-');
        if ($listFile === false) { return []; }
        file_put_contents($listFile, implode("\n", $files) . "\n");

        $nice = self::getCpuNice();
        $cmd  = sprintf(
            'nice -n%d ionice -c3 %s --infected --no-summary --max-filesize=50M --max-scansize=200M --file-list=%s 2>&1',
            $nice,
            escapeshellarg($bin),
            escapeshellarg($listFile)
        );

        $output = [];
        exec($cmd, $output);
        @unlink($listFile);

        $threats = [];
        foreach ($output as $line) {
            if (preg_match('/^(.+):\s+(.+)\s+FOUND$/', $line, $m)) {
                $threats[] = $this->recordThreat($m[1], $m[2], $jobId);
            }
        }
        return $threats;
    }

    /** Persist one ClamAV detection and report it. */
    private function recordThreat(string $filePath, string $threatName, int $jobId): array
    {
        $threatId = Database::insert('threats', [
            'scan_job_id'  => $jobId,
            'file_path'    => $filePath,
            'threat_name'  => $threatName,
            'threat_type'  => $this->classifyThreat($threatName),
            'severity'     => $this->getSeverity($threatName),
            'hash'         => file_exists($filePath) ? hash_file('sha256', $filePath) : null,
            'size'         => file_exists($filePath) ? filesize($filePath) : 0,
            'status'       => 'active',
            'cpanel_user'  => self::getCpanelUser($filePath),
        ]);

        Logger::event('malware_detected', $this->getSeverity($threatName), '',
                      $filePath, "Malware detected: {$threatName}");

        if (Database::setting('auto_quarantine') === '1') {
            $this->quarantine($filePath, $threatId);
        }

        return ['id' => $threatId, 'file' => $filePath, 'name' => $threatName];
    }

    public function runClamScan(string $path, int $jobId): array {
        $bin = self::clamscanBin();
        // No binary, or a binary with no signature database — clamscan would
        // either be missing or error out on every file. The pattern engine needs
        // no database, so it is the correct fallback in both cases.
        if ($bin === null || !self::clamSignaturesPresent()) {
            return $this->runPatternScan($path, $jobId);
        }

        // Batched rather than one recursive invocation. A single clamscan over
        // /home reports nothing until it finishes — which for a real account is
        // many minutes of a UI showing "Files: 0" and a progress bar that could
        // not move. Batching gives a real, rising count.
        $batchSize = max(25, min(1000, (int) (Database::setting('scan_batch_size', '200') ?? 200)));

        $threats = [];
        $batch   = [];
        $scanned = 0;

        foreach ($this->walkFiles($path) as $file) {
            $batch[] = $file;
            if (count($batch) < $batchSize) { continue; }

            $threats = array_merge($threats, $this->scanBatch($bin, $batch, $jobId));
            $scanned += count($batch);
            $batch = [];
            self::recordProgress($jobId, $scanned, count($threats));
        }

        if ($batch) {
            $threats = array_merge($threats, $this->scanBatch($bin, $batch, $jobId));
            $scanned += count($batch);
        }

        self::recordProgress($jobId, $scanned, count($threats));
        return $threats;
    }

    /** Retained for callers that want the old one-shot behaviour. */
    private function runClamScanLegacy(string $path, int $jobId, string $bin): array {
        $nice = self::getCpuNice();
        $cmd  = sprintf(
            'nice -n%d ionice -c3 %s --recursive --infected --no-summary --max-filesize=50M --max-scansize=200M %s 2>&1',
            $nice,
            escapeshellarg($bin),
            escapeshellarg($path)
        );

        $output = [];
        exec($cmd, $output, $exitCode);

        $threats = [];
        foreach ($output as $line) {
            // ClamAV format: /path/to/file: ThreatName FOUND
            if (preg_match('/^(.+):\s+(.+)\s+FOUND$/', $line, $m)) {
                $filePath   = $m[1];
                $threatName = $m[2];
                $threatId   = Database::insert('threats', [
                    'scan_job_id'  => $jobId,
                    'file_path'    => $filePath,
                    'threat_name'  => $threatName,
                    'threat_type'  => $this->classifyThreat($threatName),
                    'severity'     => $this->getSeverity($threatName),
                    'hash'         => file_exists($filePath) ? hash_file('sha256', $filePath) : null,
                    'size'         => file_exists($filePath) ? filesize($filePath) : 0,
                    'status'       => 'active',
                    'cpanel_user'  => self::getCpanelUser($filePath),
                ]);
                $threats[] = ['id' => $threatId, 'file' => $filePath, 'name' => $threatName];

                // Record it on the Security Events timeline too. That page had
                // exactly two writers in the whole product — a failed login and
                // one firewall path — so it was empty on every server no matter
                // what the scanner found.
                Logger::event(
                    'malware_detected',
                    $this->getSeverity($threatName),
                    '',
                    $filePath,
                    "Malware detected: {$threatName}"
                );

                // Auto-quarantine if enabled
                if (Database::setting('auto_quarantine') === '1') {
                    $this->quarantine($filePath, $threatId);
                }
            }
        }

        return $threats;
    }

    /**
     * Pattern-based PHP scanner (fallback when ClamAV not installed)
     */
    public function runPatternScan(string $path, int $jobId): array {
        $threats = [];
        $files   = $this->getPhpFiles($path);
        $scanned = 0;

        foreach ($files as $file) {
            // Counted before the size check: the file WAS examined and skipped,
            // and a progress counter that stalls on a directory of large files
            // looks identical to a dead scan.
            $scanned++;
            if ($scanned % 100 === 0) {
                self::recordProgress($jobId, $scanned, count($threats));
            }

            if (filesize($file) > SCAN_MAX_SIZE) continue;

            $content = @file_get_contents($file);
            if ($content === false) continue;

            foreach ($this->phpPatterns as $sigName => $pattern) {
                if (preg_match($pattern, $content)) {
                    $threatId = Database::insert('threats', [
                        'scan_job_id' => $jobId,
                        'file_path'   => $file,
                        'threat_name' => "SG.PHP.$sigName",
                        'threat_type' => $this->classifySigName($sigName),
                        'severity'    => $this->getSeverityFromSig($sigName),
                        'hash'        => hash_file('sha256', $file),
                        'size'        => filesize($file),
                        'status'      => 'active',
                        'cpanel_user' => self::getCpanelUser($file),
                    ]);
                    $threats[] = ['id' => $threatId, 'file' => $file, 'name' => $sigName];

                    // Auto-quarantine
                    if (Database::setting('auto_quarantine') === '1') {
                        $this->quarantine($file, $threatId);
                    }
                    break; // One match per file is enough
                }
            }

            // Also check custom signatures
            foreach ($this->customSignatures as $sig) {
                if ($sig['type'] === 'regex' && preg_match($sig['pattern'], $content)) {
                    Database::insert('threats', [
                        'scan_job_id' => $jobId,
                        'file_path'   => $file,
                        'threat_name' => $sig['name'],
                        'threat_type' => 'custom',
                        'severity'    => 'high',
                        'hash'        => hash_file('sha256', $file),
                        'size'        => filesize($file),
                        'status'      => 'active',
                    ]);
                }
            }
        }


        self::recordProgress($jobId, $scanned, count($threats));
        return $threats;
    }

    private function getPhpFiles(string $path): array {
        $files = [];
        $ext   = ['php', 'php3', 'php4', 'php5', 'phtml', 'php7', 'phps'];
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($it as $file) {
                if ($file->isFile() && in_array(strtolower($file->getExtension()), $ext)) {
                    $files[] = $file->getPathname();
                }
            }
        } catch (Exception $e) {
            Logger::error("Scanner: cannot read $path — " . $e->getMessage());
        }
        return $files;
    }

    /**
     * Move an infected file into quarantine.
     *
     * Returns a RESULT, not a bool. The route used to send ['success' => false]
     * with nothing else, so every failure reached the user as "there seems to be
     * some issue accessing files" with nothing to act on.
     *
     * The failure itself was rename(): it cannot cross a filesystem boundary. On
     * a hosting server /home is very often a separate volume from /usr/local, so
     * quarantine failed with EXDEV on precisely the files it exists to handle.
     * copy+unlink does work across devices, and is tried only after rename has
     * had its chance, because rename is atomic and cheaper.
     *
     * @return array{success:bool,error?:string,dest?:string}
     */
    public function quarantine(string $filePath, int $threatId): array {
        if (!file_exists($filePath)) {
            return ['success' => false,
                    'error' => 'The file is no longer on disk: ' . $filePath];
        }

        $qDir = Database::storagePath('quarantine') . '/' . date('Y-m-d');
        if (!is_dir($qDir) && !@mkdir($qDir, 0700, true) && !is_dir($qDir)) {
            return ['success' => false,
                    'error' => 'Could not create the quarantine directory ' . $qDir
                             . ' (' . self::lastError() . ')'];
        }
        if (!is_writable($qDir)) {
            return ['success' => false,
                    'error' => 'The quarantine directory is not writable: ' . $qDir];
        }

        $dest  = $qDir . '/' . basename($filePath) . '_' . $threatId . '.quarantine';
        $bytes = (int) filesize($filePath);

        // Never fill the volume we are writing to. Quarantine moving files onto
        // the root partition filled / on a live server and took the machine
        // down with it -- a security tool must not be the thing that causes the
        // outage. Refusing to quarantine leaves the file in place and says so,
        // which is recoverable; a full disk is not.
        $free  = @disk_free_space($qDir);
        $total = @disk_total_space($qDir);
        if ($free !== false && $total !== false && $total > 0) {
            $freeAfter = $free - $bytes;
            if ($freeAfter < 0 || ($freeAfter / $total) < 0.05) {
                return ['success' => false,
                        'error' => 'Refusing to quarantine: the volume holding '
                                 . $qDir . ' would drop below 5% free ('
                                 . self::human((int) $free) . ' free, file is '
                                 . self::human($bytes) . '). Free some space, or '
                                 . 'point quarantine_dir at a larger volume.'];
            }
        }

        $moved = @rename($filePath, $dest);

        if (!$moved) {
            // EXDEV, or a directory we may write to but not unlink from. Copy
            // first and remove the original only once the copy is verified:
            // losing a customer file while trying to protect it is a far worse
            // outcome than leaving the malware in place.
            if (!@copy($filePath, $dest)) {
                return ['success' => false,
                        'error' => 'Could not copy the file into quarantine ('
                                 . self::lastError() . '). '
                                 . self::permissionHint($filePath)];
            }
            if ((int) filesize($dest) !== $bytes) {
                @unlink($dest);
                return ['success' => false,
                        'error' => 'The quarantine copy was incomplete; the original '
                                 . 'was left untouched.'];
            }
            if (!@unlink($filePath)) {
                @unlink($dest);
                return ['success' => false,
                        'error' => 'Copied into quarantine but could not remove the '
                                 . 'original (' . self::lastError() . '), so the copy '
                                 . 'was discarded rather than leave the file in two '
                                 . 'places. ' . self::permissionHint($filePath)];
            }
            $moved = true;
        }

        @chmod($dest, 0600);

        // A placeholder so whoever owns the site knows where the file went.
        @file_put_contents($filePath . '.sentinel_removed',
            "File quarantined by Sentinel Gate at " . date('Y-m-d H:i:s') .
            "\nThreat ID: $threatId\nOriginal: $filePath\nQuarantined to: $dest\n");

        Database::query(
            "UPDATE threats SET status='quarantined', action_taken='quarantine', resolved_at=? WHERE id=?",
            [time(), $threatId]
        );
        Logger::info("Quarantined threat {$threatId}: {$filePath} -> {$dest}");
        return ['success' => true, 'dest' => $dest];
    }

    /** Bytes as something a human reads without counting digits. */
    private static function human(int $bytes): string {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $n = (float) $bytes;
        while ($n >= 1024 && $i < count($units) - 1) { $n /= 1024; $i++; }
        return round($n, $n < 10 && $i > 0 ? 1 : 0) . ' ' . $units[$i];
    }

    /**
     * Delete quarantined files older than the retention window.
     *
     * Quarantine grew without limit: nothing ever removed anything, so a server
     * that scans nightly accumulates every infected file it has ever seen until
     * the disk is gone. Retention is a setting (days); 0 disables pruning.
     *
     * @return array{removed:int,bytes:int,kept:int}
     */
    public static function pruneQuarantine(?int $days = null): array {
        $days = $days ?? (int) (Database::setting('quarantine_retention_days', '30') ?? 30);
        $dir  = Database::storagePath('quarantine');

        $removed = 0;
        $freed   = 0;
        $kept    = 0;

        if ($days <= 0 || !is_dir($dir)) {
            return ['removed' => 0, 'bytes' => 0, 'kept' => 0];
        }

        $cutoff = time() - ($days * 86400);
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($it as $entry) {
            if ($entry->isDir()) {
                @rmdir($entry->getPathname());       // only succeeds when empty
                continue;
            }
            if ($entry->getMTime() < $cutoff) {
                $size = $entry->getSize();
                if (@unlink($entry->getPathname())) {
                    $removed++;
                    $freed += $size;
                }
            } else {
                $kept++;
            }
        }

        if ($removed > 0) {
            Logger::info("Quarantine pruned: {$removed} file(s), " . self::human($freed) . " freed");
        }
        return ['removed' => $removed, 'bytes' => $freed, 'kept' => $kept];
    }

    /**
     * Relocate quarantine to another volume.
     *
     * Files are MOVED, never dropped: they are evidence, and one of them may be
     * a customer's only copy of something. If a file cannot be moved it is left
     * where it is and reported, rather than the whole operation being abandoned
     * half-done with no record of what went where.
     *
     * @return array{success:bool,error?:string,moved?:int,failed?:int,from?:string,to?:string}
     */
    public static function moveQuarantine(string $dest): array
    {
        $dest = rtrim(trim($dest), '/');

        // The point is to reject a RELATIVE path, which would resolve against
        // whatever the working directory happens to be. A drive-letter form is
        // accepted so this is reachable from a test on a developer machine; on
        // the servers this runs on only the leading slash ever matches.
        //
        // Written out rather than as a regex: in a single-quoted PHP string the
        // character class [\\/] collapses to [\/], where the backslash escapes
        // the slash and the class matches only "/" -- so the drive-letter form
        // was silently rejected. Two layers of escaping to express one
        // character is not worth it here.
        $absolute = $dest !== '' && (
            $dest[0] === '/'
            || (strlen($dest) > 2 && ctype_alpha($dest[0]) && $dest[1] === ':'
                && ($dest[2] === '/' || $dest[2] === '\\'))
        );
        if (!$absolute) {
            return ['success' => false, 'error' => 'Give an absolute path.'];
        }

        $from = Database::storagePath('quarantine');
        if ($dest === rtrim($from, '/')) {
            return ['success' => false, 'error' => 'Quarantine is already at ' . $dest];
        }

        if (!is_dir($dest) && !@mkdir($dest, 0700, true) && !is_dir($dest)) {
            return ['success' => false,
                    'error' => 'Could not create ' . $dest . ' (' . self::lastError() . ')'];
        }
        if (!is_writable($dest)) {
            return ['success' => false, 'error' => $dest . ' is not writable.'];
        }

        $moved  = 0;
        $failed = 0;
        $errors = [];

        if (is_dir($from)) {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($from, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($it as $entry) {
                $rel    = substr($entry->getPathname(), strlen($from) + 1);
                $target = $dest . '/' . $rel;

                if ($entry->isDir()) {
                    if (!is_dir($target)) { @mkdir($target, 0700, true); }
                    continue;
                }

                // rename first; fall back to copy for a cross-device move,
                // which is the entire reason anyone runs this command.
                if (@rename($entry->getPathname(), $target)) {
                    $moved++;
                    continue;
                }
                if (@copy($entry->getPathname(), $target)
                    && (int) filesize($target) === (int) $entry->getSize()
                    && @unlink($entry->getPathname())) {
                    $moved++;
                    continue;
                }
                @unlink($target);              // discard a partial copy
                $failed++;
                if (count($errors) < 5) {
                    $errors[] = $rel . ': ' . self::lastError();
                }
            }

            // Tidy up the now-empty tree, leaving anything that still holds a file.
            $tidy = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($from, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($tidy as $entry) {
                if ($entry->isDir()) { @rmdir($entry->getPathname()); }
            }
        }

        Database::setSetting('quarantine_dir', $dest);
        Logger::info("Quarantine relocated: {$from} -> {$dest} ({$moved} moved, {$failed} failed)");

        return [
            'success' => $failed === 0,
            'from'    => $from,
            'to'      => $dest,
            'moved'   => $moved,
            'failed'  => $failed,
            'errors'  => $errors,
            'note'    => $failed > 0
                ? 'Files that could not be moved were left where they are; nothing was deleted.'
                : 'New quarantines will be written to ' . $dest,
        ];
    }

    /** How much space quarantine is using, and where. */
    public static function quarantineUsage(): array {
        $dir   = Database::storagePath('quarantine');
        $bytes = 0;
        $files = 0;

        if (is_dir($dir)) {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if ($f->isFile()) { $bytes += $f->getSize(); $files++; }
            }
        }

        $free  = @disk_free_space($dir);
        return [
            'dir'         => $dir,
            'files'       => $files,
            'bytes'       => $bytes,
            'human'       => self::human($bytes),
            'free'        => $free === false ? null : (int) $free,
            'free_human'  => $free === false ? 'unknown' : self::human((int) $free),
            'on_root'     => strpos($dir, '/usr/local') === 0,
            'retention_days' => (int) (Database::setting('quarantine_retention_days', '30') ?? 30),
        ];
    }

    /** The last PHP error message, so a filesystem failure can be reported. */
    private static function lastError(): string {
        $e   = error_get_last();
        $msg = (string) ($e['message'] ?? '');
        // Strip the "function(args): " prefix PHP prepends; it adds nothing here.
        $msg = (string) preg_replace('/^[a-z_]+\\([^)]*\\):\\s*/i', '', $msg);
        return $msg !== '' ? $msg : 'no further detail from the filesystem';
    }

    /**
     * Why a file might refuse to move, in terms someone can act on.
     *
     * The immutable attribute is the one that looks like a permissions problem
     * and is not: root itself cannot unlink such a file, and attackers set it
     * deliberately to make a payload hard to remove.
     */
    private static function permissionHint(string $path): string {
        $bits = [];
        $dir  = dirname($path);
        if (!is_writable($dir)) {
            $bits[] = 'the containing directory ' . $dir . ' is not writable';
        }
        $out = [];
        @exec('lsattr -d ' . escapeshellarg($path) . ' 2>/dev/null', $out);
        if (!empty($out[0])) {
            $flags = explode(' ', trim($out[0]))[0];
            if (strpos($flags, 'i') !== false) {
                $bits[] = 'the file is marked immutable (chattr +i) — clear it with: '
                        . 'chattr -i ' . escapeshellarg($path);
            }
        }
        return $bits ? 'Likely cause: ' . implode('; ', $bits) . '.' : '';
    }

    public function restoreFromQuarantine(int $threatId): bool {
        $threat = Database::fetchOne("SELECT * FROM threats WHERE id = ?", [$threatId]);
        if (!$threat) return false;

        $qDir = Database::storagePath('quarantine') . '/' . date('Y-m-d', $threat['resolved_at'] ?? $threat['detected_at']);
        $src  = $qDir . '/' . basename($threat['file_path']) . '_' . $threatId . '.quarantine';

        if (file_exists($src) && rename($src, $threat['file_path'])) {
            @unlink($threat['file_path'] . '.sentinel_removed');
            Database::query(
                "UPDATE threats SET status='restored', resolved_at=? WHERE id=?",
                [time(), $threatId]
            );
            return true;
        }
        return false;
    }

    /**
     * Delete an infected file.
     *
     * The row used to be marked 'deleted' whether or not unlink() succeeded, so
     * the dashboard could report malware removed while it sat untouched on disk.
     * For a security product that is the worst kind of wrong answer, and the @
     * in front of unlink meant nobody ever saw why it had failed.
     *
     * @return array{success:bool,error?:string,note?:string}
     */
    public function deleteThreat(int $threatId): array {
        $threat = Database::fetchOne("SELECT * FROM threats WHERE id = ?", [$threatId]);
        if (!$threat) {
            return ['success' => false, 'error' => 'Threat ' . $threatId . ' not found.'];
        }

        $path = (string) $threat['file_path'];

        if (!file_exists($path)) {
            // Genuinely handled, so record it — but say so rather than implying
            // this call is what removed it.
            Database::query(
                "UPDATE threats SET status='deleted', action_taken='delete', resolved_at=? WHERE id=?",
                [time(), $threatId]
            );
            return ['success' => true, 'note' => 'The file was already gone.'];
        }

        if (!@unlink($path)) {
            $err = self::lastError();
            Logger::error("Delete failed for threat {$threatId} ({$path}): {$err}");
            return ['success' => false,
                    'error' => 'Could not delete ' . $path . ' (' . $err . '). '
                             . self::permissionHint($path)];
        }

        Database::query(
            "UPDATE threats SET status='deleted', action_taken='delete', resolved_at=? WHERE id=?",
            [time(), $threatId]
        );
        Logger::info("Deleted threat {$threatId}: {$path}");
        return ['success' => true];
    }

    /**
     * Read an infected file for INSPECTION ONLY.
     *
     * Nothing here executes, includes or evaluates the file: it is read with
     * file_get_contents and returned as data. The caller renders it escaped, so
     * a payload containing markup cannot act inside the dashboard either.
     *
     * @return array{success:bool,error?:string,content?:string,size?:int,
     *               truncated?:bool,sha256?:string,path?:string,binary?:bool}
     */
    public function viewThreat(int $threatId, int $maxBytes = 262144): array {
        $threat = Database::fetchOne("SELECT * FROM threats WHERE id = ?", [$threatId]);
        if (!$threat) {
            return ['success' => false, 'error' => 'Threat ' . $threatId . ' not found.'];
        }

        $path = (string) $threat['file_path'];

        // A quarantined file lives under the quarantine directory now.
        if (!file_exists($path) && ($threat['status'] ?? '') === 'quarantined') {
            $stamp     = (int) ($threat['resolved_at'] ?: $threat['detected_at']);
            $candidate = Database::storagePath('quarantine') . '/' . date('Y-m-d', $stamp)
                       . '/' . basename($path) . '_' . $threatId . '.quarantine';
            if (file_exists($candidate)) { $path = $candidate; }
        }

        if (!file_exists($path)) {
            return ['success' => false, 'error' => 'The file is no longer on disk: ' . $path];
        }
        if (!is_readable($path)) {
            return ['success' => false,
                    'error' => 'The file is not readable. ' . self::permissionHint($path)];
        }

        $size = (int) filesize($path);
        $data = (string) @file_get_contents($path, false, null, 0, $maxBytes);

        if ($data === '' && $size > 0) {
            return ['success' => false,
                    'error' => 'Could not read the file (' . self::lastError() . ')'];
        }

        // Binary content is not worth rendering as text and can carry terminal
        // escapes. Describe it instead of dumping it.
        $binary = strpos(substr($data, 0, 8000), chr(0)) !== false;

        return [
            'success'   => true,
            'path'      => $path,
            'size'      => $size,
            'binary'    => $binary,
            'sha256'    => (string) (hash_file('sha256', $path) ?: ''),
            'content'   => $binary ? '' : $data,
            'truncated' => !$binary && $size > $maxBytes,
        ];
    }

    /**
     * Apply one action to many threats.
     *
     * Each is attempted independently: one file that cannot be removed must not
     * stop the rest, and the caller needs to know which ones failed and why
     * rather than a single pass/fail for the whole batch.
     *
     * @param int[] $ids
     * @return array{success:bool,ok:int,failed:int,results:array}
     */
    public function bulkAction(array $ids, string $action): array {
        if (!in_array($action, ['quarantine', 'delete'], true)) {
            return ['success' => false, 'ok' => 0, 'failed' => 0, 'results' => [],
                    'error' => 'Unknown action: ' . $action];
        }

        $results = [];
        $ok      = 0;
        $failed  = 0;

        // Bounded: a runaway selection must not hold the request open for ever.
        foreach (array_slice(array_unique(array_map('intval', $ids)), 0, 500) as $id) {
            if ($id <= 0) { continue; }

            if ($action === 'delete') {
                $r = $this->deleteThreat($id);
            } else {
                $threat = Database::fetchOne("SELECT * FROM threats WHERE id = ?", [$id]);
                $r = $threat
                    ? $this->quarantine((string) $threat['file_path'], $id)
                    : ['success' => false, 'error' => 'Threat ' . $id . ' not found.'];
            }

            if (!empty($r['success'])) { $ok++; } else { $failed++; }
            $results[] = ['id' => $id] + $r;
        }

        return [
            'success' => $failed === 0,
            'ok'      => $ok,
            'failed'  => $failed,
            'results' => $results,
        ];
    }

    public function getScanStatus(int $jobId): array {
        $job = Database::fetchOne("SELECT * FROM scan_jobs WHERE id = ?", [$jobId]);
        if (!$job) return ['error' => 'Job not found'];

        $threats = Database::fetchAll(
            "SELECT * FROM threats WHERE scan_job_id = ? ORDER BY detected_at DESC",
            [$jobId]
        );

        return ['job' => $job, 'threats' => $threats];
    }

    public function getStats(): array {
        $total    = Database::fetchOne("SELECT COUNT(*) as c FROM threats")['c'];
        $active   = Database::fetchOne("SELECT COUNT(*) as c FROM threats WHERE status='active'")['c'];
        $quarant  = Database::fetchOne("SELECT COUNT(*) as c FROM threats WHERE status='quarantined'")['c'];
        $lastScan = Database::fetchOne("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT 1");
        $byType   = Database::fetchAll(
            "SELECT threat_type, COUNT(*) as count FROM threats WHERE status='active' GROUP BY threat_type"
        );

        return [
            'total_threats'  => (int) $total,
            'active'         => (int) $active,
            'quarantined'    => (int) $quarant,
            'last_scan'      => $lastScan,
            'by_type'        => $byType,
            'files_scanned'  => (int) ($lastScan['files_scanned'] ?? 0),
        ];
    }

    /**
     * Determine which cPanel account owns a file path.
     * /home/USERNAME/... → USERNAME
     * Falls back to posix file owner, then 'unknown'.
     */
    public static function getCpanelUser(string $filePath): string {
        // Most common: /home/<user>/...
        if (preg_match('#^/home/([^/]+)/#', $filePath, $m)) {
            return $m[1];
        }
        // /usr/home/<user>/...
        if (preg_match('#^/usr/home/([^/]+)/#', $filePath, $m)) {
            return $m[1];
        }
        // Fallback: file owner via posix
        if (file_exists($filePath) && function_exists('posix_getpwuid')) {
            $info = @posix_getpwuid(@fileowner($filePath));
            if ($info && isset($info['name'])) return $info['name'];
        }
        return 'system';
    }

    private function classifyThreat(string $name): string {
        $n = strtolower($name);
        if (str_contains($n, 'backdoor'))    return 'backdoor';
        if (str_contains($n, 'malware'))     return 'malware';
        if (str_contains($n, 'trojan'))      return 'trojan';
        if (str_contains($n, 'phishing'))    return 'phishing';
        if (str_contains($n, 'miner'))       return 'cryptominer';
        if (str_contains($n, 'shell'))       return 'webshell';
        if (str_contains($n, 'spam'))        return 'spam';
        return 'malware';
    }

    private function classifySigName(string $sig): string {
        if (str_contains($sig, 'shell'))     return 'webshell';
        if (str_contains($sig, 'eval'))      return 'obfuscated';
        if (str_contains($sig, 'miner'))     return 'cryptominer';
        if (str_contains($sig, 'spam'))      return 'spam';
        if (str_contains($sig, 'backdoor'))  return 'backdoor';
        return 'suspicious';
    }

    private function getSeverity(string $name): string {
        $n = strtolower($name);
        if (str_contains($n, 'critical') || str_contains($n, 'backdoor') || str_contains($n, 'shell')) return 'critical';
        if (str_contains($n, 'trojan') || str_contains($n, 'malware')) return 'high';
        if (str_contains($n, 'phishing') || str_contains($n, 'miner')) return 'medium';
        return 'low';
    }

    private function getSeverityFromSig(string $sig): string {
        $critical = ['c99_shell', 'backdoor_connect', 'reverse_shell', 'stdin_exec'];
        $high     = ['eval_base64', 'eval_gzinflate', 'system_shell', 'assert_base64'];
        if (in_array($sig, $critical)) return 'critical';
        if (in_array($sig, $high))     return 'high';
        return 'medium';
    }

    public function updateSignatures(): array {
        // Update ClamAV signatures
        $clamResult = '';
        if (file_exists(FRESHCLAM_BIN)) {
            exec(FRESHCLAM_BIN . ' 2>&1', $out, $code);
            $clamResult = implode("\n", $out);
        }

        Database::setSetting('clam_db_update', (string) time());
        return ['success' => true, 'clam' => $clamResult];
    }
}
