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
    /**
     * How long a job may sit with no worker pid recorded before it is presumed
     * dead. The worker writes its pid as its first act, so this only has to
     * cover process startup.
     */
    private const WORKER_GRACE = 120;

    /**
     * Scan worker processes that are genuinely running, found in /proc.
     *
     * The database is not the authority on what is executing. Workers started
     * before 3.30.1 never recorded a pid, because the column did not exist
     * then -- so after an upgrade there can be a worker happily scanning that
     * no row can identify. /proc is the only honest answer to "what is running
     * right now".
     *
     * @param int|null $jobId restrict to the worker for one job
     * @return int[] pids
     */
    public static function scanWorkerPids(?int $jobId = null): array
    {
        $pids = [];
        if (!is_dir('/proc')) { return $pids; }

        $needle = 'backend/cron/scan.php';
        $self   = getmypid();

        foreach (glob('/proc/[0-9]*') ?: [] as $dir) {
            $pid = (int) basename($dir);
            if ($pid <= 1 || $pid === $self) { continue; }

            $raw = @file_get_contents($dir . '/cmdline');
            if ($raw === false || $raw === '') { continue; }
            $cmd = str_replace("\0", ' ', $raw);

            if (strpos($cmd, $needle) === false) { continue; }
            if ($jobId !== null && strpos($cmd, '--job-id=' . $jobId) === false) { continue; }
            $pids[] = $pid;
        }
        return $pids;
    }

    /** Direct children of the given pids that are clamscan. */
    private static function clamscanChildrenOf(array $parentPids): array
    {
        $kids = [];
        if (!$parentPids || !is_dir('/proc')) { return $kids; }
        $parents = array_flip($parentPids);

        foreach (glob('/proc/[0-9]*') ?: [] as $dir) {
            $pid  = (int) basename($dir);
            $comm = @file_get_contents($dir . '/comm');
            if ($comm === false || strpos(trim($comm), 'clamscan') === false) { continue; }

            $stat = @file_get_contents($dir . '/stat');
            if ($stat === false) { continue; }
            // Field 4 is ppid; the command in field 2 may contain spaces, so
            // parse from the closing parenthesis.
            $tail = substr($stat, strrpos($stat, ')') + 2);
            $f    = explode(' ', $tail);
            if (isset($f[1]) && isset($parents[(int) $f[1]])) {
                $kids[] = $pid;
            }
        }
        return $kids;
    }

    /**
     * Kill scan workers that are running regardless of what the database says,
     * and the clamscan processes they have spawned.
     *
     * Reported as "even if i kill them individually they are spawned
     * immediately". That is the worker doing its job: it forks one clamscan
     * per batch, so killing a clamscan simply ends that batch and the worker
     * starts the next one. The worker is what has to go.
     *
     * Order matters, and is the whole of this method:
     *   1. Note each worker's clamscan children FIRST -- once the worker dies
     *      they are reparented to init and the link is lost.
     *   2. Kill the workers, so nothing can spawn a replacement.
     *   3. Kill the children noted in step 1.
     *
     * Doing it the other way round is what makes clamscan look immortal.
     */
    public static function killRunawayScans(): array
    {
        $workers = self::scanWorkerPids();
        if (!$workers) {
            return ['workers' => [], 'clamscans' => []];
        }

        // Step 1 -- before anything dies.
        $children = self::clamscanChildrenOf($workers);

        // Step 2 -- the workers.
        foreach ($workers as $pid) {
            function_exists('posix_kill') ? @posix_kill($pid, 15)
                                          : @exec('kill -TERM ' . $pid . ' 2>/dev/null');
        }
        usleep(500000);
        foreach ($workers as $pid) {
            if (self::processAlive($pid)) {
                function_exists('posix_kill') ? @posix_kill($pid, 9)
                                              : @exec('kill -KILL ' . $pid . ' 2>/dev/null');
            }
        }

        // Step 3 -- the clamscans they left behind. Only the ones noted above:
        // cPanel runs its own clamscan for mail and it must not be touched.
        $killed = [];
        foreach ($children as $pid) {
            if (!self::processAlive($pid)) { continue; }
            function_exists('posix_kill') ? @posix_kill($pid, 15)
                                          : @exec('kill -TERM ' . $pid . ' 2>/dev/null');
            $killed[] = $pid;
        }
        usleep(300000);
        foreach ($killed as $pid) {
            if (self::processAlive($pid)) {
                function_exists('posix_kill') ? @posix_kill($pid, 9)
                                              : @exec('kill -KILL ' . $pid . ' 2>/dev/null');
            }
        }

        Logger::warn('Killed ' . count($workers) . ' runaway scan worker(s) and '
                   . count($killed) . ' clamscan process(es): workers '
                   . implode(', ', $workers));

        return ['workers' => $workers, 'clamscans' => $killed];
    }

    /** Is the worker recorded on this job still alive? */
    public static function jobWorkerAlive(array $job): bool
    {
        $pid = (int) ($job['worker_pid'] ?? 0);
        if ($pid <= 1) {
            // Nothing recorded. Either it has not started yet, or it died
            // before it could write one -- age is what separates the two.
            $started = (int) ($job['started_at'] ?? 0);
            return $started > 0 && (time() - $started) < self::WORKER_GRACE;
        }
        return self::processAlive($pid);
    }

    /**
     * Close out jobs whose worker is gone.
     *
     * A worker that is killed, or dies on an out-of-memory, never reaches the
     * code that sets a final status -- so its row sits at 'running' for ever.
     * Nothing cleaned these up, so after a few of them the database claimed
     * several scans were in progress when none were.
     */
    public static function reapStaleJobs(): int
    {
        $rows = Database::fetchAll(
            "SELECT * FROM scan_jobs WHERE status IN ('running','pending','cancelling')"
        );
        $n = 0;
        foreach ($rows as $job) {
            if (self::jobWorkerAlive($job)) { continue; }

            // Before declaring it dead, look for the process itself.
            //
            // A job whose worker predates the worker_pid column has no pid to
            // check, and marking it interrupted while it is still running is
            // how a scan becomes invisible: the row stops showing as running,
            // so nothing can find it, while the worker carries on forking a
            // clamscan per batch. Adopt the process instead.
            $found = self::scanWorkerPids((int) $job['id']);
            if ($found) {
                $pid  = $found[0];
                $pgid = self::pgidOf($pid);
                Database::query(
                    'UPDATE scan_jobs SET worker_pid=?, worker_pgid=? WHERE id=?',
                    [$pid, $pgid, (int) $job['id']]
                );
                Logger::info('Scan job ' . $job['id'] . ' had no recorded pid; '
                           . 'adopted the running worker ' . $pid);
                continue;
            }

            Database::query(
                "UPDATE scan_jobs SET status='interrupted', finished_at=? WHERE id=?",
                [time(), (int) $job['id']]
            );
            Logger::warn('Scan job ' . $job['id'] . ' had no live worker - marked interrupted');
            $n++;
        }
        return $n;
    }

    /**
     * How many scans may run at once. One, unless an operator changes it.
     *
     * Clamped to 4, and raising it is not a throughput control. Each clamscan
     * loads the entire ClamAV signature database into its own memory --
     * observed at 650MB to 1.3GB per process -- so a second concurrent scan
     * buys a second copy of that database and two processes contending for the
     * same disks. It does not halve the time; it is how a server ends up with
     * six of them and no CPU left.
     */
    public static function maxConcurrent(): int
    {
        $n = (int) (Database::setting('scan_max_concurrent', '1') ?? 1);
        return max(1, min(4, $n));
    }

    /** Every scan genuinely in progress. Stale rows are cleared first. */
    public static function liveScans(): array
    {
        self::reapStaleJobs();
        return Database::fetchAll(
            "SELECT * FROM scan_jobs WHERE status IN ('running','pending','cancelling')
              ORDER BY id ASC"
        );
    }

    /**
     * The scan genuinely in progress, if any. Stale rows are cleared first, so
     * this never reports a scan that died days ago.
     */
    public static function activeScan(): ?array
    {
        self::reapStaleJobs();
        $row = Database::fetchOne(
            "SELECT * FROM scan_jobs WHERE status IN ('running','pending','cancelling')
              ORDER BY id DESC LIMIT 1"
        );
        return $row ?: null;
    }

    /**
     * Stop every running scan and clean up after it.
     *
     * stopScan() takes one job. When several have stacked up -- which is how
     * six clamscan processes came to be running at once -- stopping them one
     * at a time means finding six job ids first. This is the cleanup path:
     * used by the installer, the CLI, and the dashboard.
     */
    public static function stopAllScans(): array
    {
        $stopped = [];
        $failed  = [];
        foreach (self::liveScans() as $job) {
            $r = self::stopScan((int) $job['id']);
            if (!empty($r['success'])) { $stopped[] = (int) $job['id']; }
            else { $failed[] = (int) $job['id']; }
        }

        // Anything the stopped workers left behind.
        $killed = self::reapOrphanClamscans();

        // And anything still executing that no row accounts for. Without this,
        // a worker the database has lost track of keeps scanning and keeps
        // replacing every clamscan that is killed.
        $runaway = self::killRunawayScans();

        if ($stopped || $killed) {
            Logger::info('Stopped ' . count($stopped) . ' scan(s), killed '
                       . count($killed) . ' leftover clamscan process(es)');
        }
        $totalClam = count($killed) + count($runaway['clamscans']);
        return [
            'success'  => empty($failed),
            'stopped'  => $stopped,
            'failed'   => $failed,
            'killed'   => $totalClam,
            'runaways' => count($runaway['workers']),
            'message'  => 'Stopped ' . count($stopped) . ' scan(s), killed '
                        . count($runaway['workers']) . ' untracked worker(s) and '
                        . $totalClam . ' clamscan process(es)',
        ];
    }

    /**
     * Kill clamscan processes left behind by workers that are gone.
     *
     * Deliberately narrow: ONLY processes whose process group matches a
     * scan_jobs row whose worker is dead. cPanel runs its own clamscan for
     * mail, and a reaper that matched on the process name alone would kill
     * that too -- silently breaking mail scanning on every cPanel server this
     * ships to.
     */
    public static function reapOrphanClamscans(): array
    {
        $killed = [];
        if (!is_dir('/proc')) { return $killed; }

        $deadGroups = [];
        foreach (Database::fetchAll(
            "SELECT worker_pid, worker_pgid FROM scan_jobs
              WHERE worker_pgid IS NOT NULL AND worker_pgid > 1"
        ) as $row) {
            $pgid = (int) $row['worker_pgid'];
            $pid  = (int) $row['worker_pid'];
            // A group whose worker is still alive is a running scan, not an
            // orphan. Leave it entirely alone.
            if ($pid > 1 && self::processAlive($pid)) { continue; }
            $deadGroups[$pgid] = true;
        }
        if (!$deadGroups) { return $killed; }

        foreach (array_keys($deadGroups) as $pgid) {
            foreach (self::clamscanPidsForGroup((int) $pgid) as $pid) {
                if (function_exists('posix_kill')) { @posix_kill($pid, 15); }
                else { @exec('kill -TERM ' . $pid . ' 2>/dev/null'); }
                $killed[] = $pid;
            }
        }
        if ($killed) {
            Logger::warn('Reaped ' . count($killed) . ' orphaned clamscan process(es): '
                       . implode(', ', $killed));
        }
        return $killed;
    }

    /**
     * Start a scan -- at most one at a time.
     *
     * There was no guard here at all. Every call inserted a job and spawned a
     * detached worker, so each one added a clamscan to the server. The UI's
     * Start button, the CLI and the scheduler all landed here, and the
     * scheduler called this once PER CONFIGURED PATH, in a loop, launching
     * them all in parallel.
     *
     * Concurrency is not a tuning question for this particular program: every
     * clamscan process loads the whole ClamAV signature database into its own
     * memory, which is most of a gigabyte each. Six of them is six copies of
     * the same database and six processes competing for the same disks, which
     * is strictly worse than one scan that finishes sooner.
     */
    public function startScan(string $path = '/home', string $type = 'quick'): int {
        $live = self::liveScans();
        $max  = self::maxConcurrent();
        if (count($live) >= $max) {
            $ids = implode(', ', array_map(fn($j) => $j['id'], $live));
            throw new RuntimeException(
                'Already running ' . count($live) . ' of a maximum ' . $max
                . ' scan(s) (job ' . $ids . '). Stop one before starting another,'
                . ' or raise scan_max_concurrent.'
            );
        }

        // Starting a scan into a running backup is the same mistake as not
        // pausing one: two processes reading the whole filesystem at once.
        if ((Database::setting('scan_pause_on_backup', '1') ?? '1') === '1') {
            $backups = self::backupRunning();
            if ($backups) {
                throw new RuntimeException(
                    'A backup is running (' . implode(', ', $backups) . '). '
                    . 'Scanning now would compete with it for the same disks. '
                    . 'The scheduled scan will run once it has finished.'
                );
            }
        }

        // Anything left over from a worker that died takes CPU from the scan
        // about to start.
        self::reapOrphanClamscans();

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

        // Bounded. A single archive can keep clamscan busy for a very long
        // time -- one was found holding 13 minutes of CPU and 1.3GB of RSS on
        // one file -- and while it does, the worker is blocked and the scan
        // makes no progress at all. The batch is abandoned rather than the
        // scan, so one bad file costs this batch and nothing more.
        $timeout = max(60, min(3600,
            (int) (Database::setting('scan_batch_timeout', '600') ?? 600)));

        $cmd  = sprintf(
            'timeout %d nice -n%d ionice -c3 %s --infected --no-summary --max-filesize=50M --max-scansize=200M --file-list=%s 2>&1',
            $timeout,
            $nice,
            escapeshellarg($bin),
            escapeshellarg($listFile)
        );

        $output = [];
        $rc     = 0;
        exec($cmd, $output, $rc);
        @unlink($listFile);

        // 124 is timeout(1) giving up. Any threats clamscan printed before it
        // was cut off are still in $output and are still real, so they are
        // kept -- only the rest of the batch is lost.
        if ($rc === 124) {
            Logger::warn("Scan job {$jobId}: a batch of " . count($files)
                       . " file(s) exceeded {$timeout}s and was abandoned");
        }

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

        $this->applyThreatPolicy($filePath, $threatId, $this->getSeverity($threatName));

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

            // Stop between batches when asked.
            //
            // This is the graceful half of stopping a scan: the signal sent to
            // the process group is the forceful half. Checking here means a
            // stop leaves the database consistent and the partial results
            // recorded, rather than relying on a SIGKILL landing somewhere
            // harmless.
            if (self::isCancelled($jobId)) {
                Logger::info("Scan job {$jobId} cancelled after {$scanned} file(s)");
                self::recordProgress($jobId, $scanned, count($threats));
                return $threats;
            }

            // Stand down while a backup runs. Between batches, so the check is
            // cheap and the scan never stops mid-clamscan.
            if (!self::waitOutBackup($jobId)) {
                self::recordProgress($jobId, $scanned, count($threats));
                return $threats;
            }
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

                // Severity decides what happens: delete outright, or
                // quarantine with a deadline.
                $this->applyThreatPolicy($filePath, $threatId, $this->getSeverity($threatName));
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

                    // Severity decides: delete outright, or quarantine with
                    // a deadline.
                    $this->applyThreatPolicy($file, $threatId,
                                             $this->getSeverityFromSig($sigName));
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
    // ── Threat policy ────────────────────────────────────────────────────────
    //
    // What happens to an infected file depends on how bad it is:
    //
    //   high / critical  disable, then delete outright
    //   medium           disable, quarantine, delete after 5 days
    //   low              disable, quarantine, delete after 7 days
    //
    // and nothing stays in quarantine beyond the global retention period
    // whatever its own deadline says.
    //
    // ON DELETING WITHOUT A COPY: a high-severity detection is removed with no
    // way back, so a false positive destroys a customer's file permanently.
    // That is the configured behaviour and it is what was asked for, but it is
    // the sharpest edge in this product -- so the path, size and SHA-256 are
    // written to the log and to the threat record first. That does not restore
    // the file; it does mean an operator can see exactly what was taken and
    // from where. `policy_high_action` can be set to 'quarantine' to give high
    // severity the same grace as the others.

    /** Days a file of this severity may sit in quarantine. 0 means delete now. */
    public static function policyDaysFor(string $severity): int
    {
        switch (strtolower($severity)) {
            case 'critical':
            case 'high':
                return (Database::setting('policy_high_action', 'delete') ?? 'delete') === 'delete'
                    ? 0
                    : self::policyClamp('policy_medium_days', 5);
            case 'medium':
                return self::policyClamp('policy_medium_days', 5);
            default:
                return self::policyClamp('policy_low_days', 7);
        }
    }

    private static function policyClamp(string $key, int $fallback): int
    {
        $n = (int) (Database::setting($key, (string) $fallback) ?? $fallback);
        // Never longer than the global retention: a per-severity deadline that
        // outlived the sweep would promise a grace period it does not get.
        $max = max(1, (int) (Database::setting('quarantine_retention_days', '7') ?? 7));
        return max(0, min($max, $n));
    }

    /**
     * Make a file inert before acting on it.
     *
     * Between detection and the move there is a window in which the file is
     * still executable by the web server. Removing every permission bit closes
     * it. The previous mode is returned so it can be put back if what follows
     * fails -- leaving a customer with an unreadable file AND the malware still
     * present would be the worst of both.
     */
    public static function disableFile(string $filePath): ?int
    {
        if (!file_exists($filePath)) { return null; }
        $mode = @fileperms($filePath);
        $mode = $mode === false ? null : ($mode & 0777);
        @chmod($filePath, 0000);
        return $mode;
    }

    /** Put back a mode captured by disableFile(). */
    public static function restoreMode(string $filePath, ?int $mode): void
    {
        if ($mode !== null && file_exists($filePath)) { @chmod($filePath, $mode); }
    }

    /**
     * Delete an infected file, recording what was destroyed.
     *
     * The record is the only thing left afterwards, so it is written before
     * the file is removed rather than after.
     */
    public function deleteInfected(string $filePath, int $threatId, string $why,
                                   ?array $meta = null): array
    {
        if (!file_exists($filePath)) {
            Database::query(
                "UPDATE threats SET status='deleted', action_taken='delete', resolved_at=? WHERE id=?",
                [time(), $threatId]
            );
            return ['success' => true, 'already_gone' => true];
        }

        // Taken before the file was made unreadable, where the caller had the
        // chance. Hashing a file after chmod 0000 only works because root can
        // read anything -- relying on that would mean no hash at all whenever
        // this runs as anyone else.
        $size = $meta['size'] ?? (int) @filesize($filePath);
        $hash = $meta['hash'] ?? (@hash_file('sha256', $filePath) ?: '');

        Logger::warn("Deleting infected file (threat {$threatId}, {$why}): {$filePath} "
                   . "[{$size} bytes, sha256 {$hash}]");

        if (!@unlink($filePath)) {
            // A file with no permission bits cannot be unlinked on Windows,
            // and a read-only one resists deletion on some filesystems. Give
            // it back write access and try once more before giving up -- the
            // alternative is leaving the malware in place.
            @chmod($filePath, 0600);
            if (!@unlink($filePath)) {
                return ['success' => false,
                        'error' => 'Could not delete ' . $filePath . ' ('
                                 . self::lastError() . '). ' . self::permissionHint($filePath)];
            }
        }

        // So whoever owns the site knows where the file went, and what it was.
        @file_put_contents($filePath . '.sentinel_removed',
            "File DELETED by Sentinel Gate at " . date('Y-m-d H:i:s') .
            "
Reason: {$why}
Threat ID: {$threatId}
Original: {$filePath}" .
            "
Size: {$size} bytes
SHA-256: {$hash}
" .
            "
This file was removed and not kept. Restore it from your backups
" .
            "if you believe this was a mistake.
");

        Database::query(
            "UPDATE threats SET status='deleted', action_taken='delete',
                                resolved_at=?, hash=COALESCE(NULLIF(hash,''), ?) WHERE id=?",
            [time(), $hash, $threatId]
        );
        Database::insert('security_events', [
            'type'        => 'malware_deleted',
            'severity'    => 'high',
            'target'      => $filePath,
            'description' => 'Infected file deleted (' . $why . '), ' . $size
                           . ' bytes, sha256 ' . substr($hash, 0, 16),
        ]);
        return ['success' => true, 'bytes' => $size, 'sha256' => $hash];
    }

    /**
     * Act on a detected threat according to its severity.
     *
     * This replaced three identical copies of "if auto_quarantine is on,
     * quarantine it", which treated a webshell and a suspicious comment
     * exactly alike.
     */
    public function applyThreatPolicy(string $filePath, int $threatId, string $severity): array
    {
        if ((Database::setting('auto_quarantine', '0') ?? '0') !== '1') {
            return ['action' => 'none', 'reason' => 'auto-quarantine is off'];
        }

        $days = self::policyDaysFor($severity);

        // Recorded while the file is still readable. For a delete this is the
        // only trace that will remain of it.
        $meta = is_file($filePath)
            ? ['size' => (int) @filesize($filePath),
               'hash' => @hash_file('sha256', $filePath) ?: '']
            : null;

        // Inert first, whatever happens next.
        $mode = self::disableFile($filePath);

        if ($days === 0) {
            $r = $this->deleteInfected($filePath, $threatId, $severity . ' severity', $meta);
            if (empty($r['success'])) {
                // Could not delete: put the file back as it was rather than
                // leave it unreadable and still infected.
                self::restoreMode($filePath, $mode);
                return ['action' => 'failed', 'error' => $r['error'] ?? 'delete failed'];
            }
            return ['action' => 'deleted'];
        }

        $r = $this->quarantine($filePath, $threatId);
        if (empty($r['success'])) {
            self::restoreMode($filePath, $mode);
            return ['action' => 'failed', 'error' => $r['error'] ?? 'quarantine failed'];
        }

        $expires = time() + ($days * 86400);
        Database::query(
            'UPDATE threats SET quarantine_path=?, quarantine_expires_at=? WHERE id=?',
            [$r['dest'] ?? '', $expires, $threatId]
        );
        return ['action' => 'quarantined', 'days' => $days, 'expires_at' => $expires];
    }

    /**
     * Delete quarantined files whose time is up.
     *
     * Two rules, and the second is the backstop: a file goes when its own
     * deadline passes, and anything still present beyond the global retention
     * period goes regardless -- including files quarantined before expiry
     * dates were recorded at all, which is what clears the backlog on an
     * existing install.
     */
    public static function sweepQuarantine(): array
    {
        $now     = time();
        $deleted = 0;
        $bytes   = 0;

        // 1. Per-threat deadlines.
        $rows = Database::fetchAll(
            "SELECT id, quarantine_path, quarantine_expires_at
               FROM threats
              WHERE status='quarantined'
                AND quarantine_expires_at IS NOT NULL
                AND quarantine_expires_at > 0
                AND quarantine_expires_at <= CAST(? AS INTEGER)",
            [$now]
        );
        foreach ($rows as $r) {
            $path = (string) ($r['quarantine_path'] ?? '');
            if ($path !== '' && is_file($path)) {
                $bytes += (int) @filesize($path);
                if (@unlink($path)) { $deleted++; }
            }
            Database::query(
                "UPDATE threats SET status='deleted', action_taken='expired', resolved_at=? WHERE id=?",
                [$now, (int) $r['id']]
            );
        }

        // 2. The backstop, by file age. pruneQuarantine already walks the tree
        //    and removes anything past the retention period; it is what clears
        //    files that predate per-threat deadlines.
        $pruned = self::pruneQuarantine();

        if ($deleted > 0 || (int) ($pruned['removed'] ?? 0) > 0) {
            Logger::info('Quarantine sweep: ' . $deleted . ' expired by policy, '
                       . (int) ($pruned['removed'] ?? 0) . ' by retention age');
        }

        return [
            'expired'        => $deleted,
            'expired_bytes'  => $bytes,
            'aged_out'       => (int) ($pruned['removed'] ?? 0),
            'aged_bytes'     => (int) ($pruned['bytes'] ?? 0),
            'kept'           => (int) ($pruned['kept'] ?? 0),
        ];
    }

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
    /**
     * Is a backup running? Cached, because the batch loop asks constantly.
     *
     * The pause added in 3.30.0 lives inside the real-time monitor daemon and
     * suspends ITS scanning. A malware scan is a different process entirely
     * and knew nothing about any of it -- so during a backup the monitor sat
     * politely idle at 1% CPU while clamscan ran flat out at 58% in
     * uninterruptible I/O wait, competing with rsync for the same disks. The
     * quiet half of the product was suspended and the loud half was not.
     */
    public static function backupRunning(): array
    {
        static $cachedAt = 0;
        static $cached   = [];

        if ((time() - $cachedAt) < 30) { return $cached; }

        if (!class_exists('RealTimeMonitor')) {
            $lib = SG_ROOT . '/backend/lib/RealTimeMonitor.php';
            if (is_file($lib)) { require_once $lib; }
        }
        $cached   = class_exists('RealTimeMonitor')
            ? RealTimeMonitor::backupProcesses()
            : [];
        $cachedAt = time();
        return $cached;
    }

    /**
     * Hold the scan while a backup runs.
     *
     * Waiting rather than aborting: the scan resumes and finishes, and a
     * sleeping worker costs one idle process. It holds its lock slot while it
     * waits, which is correct -- a second scan starting because this one is
     * politely asleep would defeat the point.
     *
     * Returns false when the scan should give up: the wait cap was reached, or
     * the job was cancelled while waiting.
     */
    private static function waitOutBackup(int $jobId): bool
    {
        if ((Database::setting('scan_pause_on_backup', '1') ?? '1') !== '1') {
            return true;
        }
        $running = self::backupRunning();
        if (!$running) { return true; }

        $maxWait = max(60, min(86400,
            (int) (Database::setting('scan_backup_max_wait', '14400') ?? 14400)));
        $waited  = 0;
        $logged  = false;

        while ($running) {
            if (self::isCancelled($jobId)) { return false; }
            if ($waited >= $maxWait) {
                Logger::warn("Scan job {$jobId}: backup still running after {$waited}s; "
                           . 'deferring the rest of this scan');
                return false;
            }
            if (!$logged) {
                Logger::info("Scan job {$jobId}: pausing, backup in progress ("
                           . implode(', ', $running) . ')');
                Database::setSetting('scan_paused_for_backup', '1');
                $logged = true;
            }
            sleep(30);
            $waited += 30;
            // Force a fresh look rather than the 30s cache.
            $running = self::backupRunning();
        }

        if ($logged) {
            Logger::info("Scan job {$jobId}: backup finished after {$waited}s, resuming");
            Database::setSetting('scan_paused_for_backup', '0');
        }
        return true;
    }

    /** True once a stop has been requested for this job. */
    public static function isCancelled(int $jobId): bool
    {
        $row = Database::fetchOne('SELECT status FROM scan_jobs WHERE id=?', [$jobId]);
        $status = $row['status'] ?? '';

        // Anything that is not still in progress means stop.
        //
        // This used to accept only 'cancelling' and 'cancelled', which left a
        // gap wide enough to hide a runaway in: reapStaleJobs() marks a job
        // 'interrupted', the worker did not recognise that as a stop, and so
        // it carried on scanning and forking a clamscan per batch -- while the
        // row it belonged to no longer showed as running, so nothing could
        // find it. A deleted row means stop too.
        return $status === '' || !in_array($status, ['running', 'pending'], true);
    }

    /** The scan currently running, if any. */
    public static function runningJob(): ?array
    {
        return Database::fetchOne(
            "SELECT * FROM scan_jobs WHERE status IN ('running','pending','cancelling')
              ORDER BY id DESC LIMIT 1"
        );
    }

    /**
     * Stop a running scan, and the clamscan it has spawned.
     *
     * Reported as "the stop button is not stopping clamscan". It was not: the
     * real-time monitor's Stop button stops the monitor daemon, which never
     * runs clamscan -- it uses its own pattern engine. clamscan belongs to a
     * SCAN, and there was no way to stop a scan at all. Once started it ran to
     * completion whatever the operator did.
     *
     * Stopping is done twice over, because either half alone is unreliable:
     *
     *   1. The job is marked 'cancelling', which the batch loop checks. A scan
     *      that reaches that check exits cleanly with its partial results
     *      recorded.
     *   2. The worker's process GROUP is signalled, which reaches the clamscan
     *      it is currently blocked on. Signalling the worker alone leaves that
     *      clamscan running -- it would finish the batch it was given, which on
     *      a large file can take a while.
     */
    public static function stopScan(?int $jobId = null): array
    {
        $job = $jobId !== null
            ? Database::fetchOne('SELECT * FROM scan_jobs WHERE id=?', [$jobId])
            : self::runningJob();

        if (!$job) {
            return ['success' => false, 'error' => 'No scan is running', 'code' => 404];
        }
        if (in_array($job['status'], ['done', 'error', 'cancelled'], true)) {
            return ['success' => false,
                    'error'   => 'That scan has already finished (' . $job['status'] . ')',
                    'code'    => 409];
        }

        $id = (int) $job['id'];
        Database::query(
            "UPDATE scan_jobs SET status='cancelling' WHERE id=?", [$id]
        );

        $pgid   = (int) ($job['worker_pgid'] ?? 0);
        $pid    = (int) ($job['worker_pid'] ?? 0);
        $signalled = false;

        // Negative PID means "the whole process group" to kill(2), which is how
        // the clamscan children are reached.
        if ($pgid > 1) {
            $signalled = self::signalGroup($pgid, 'TERM');
        } elseif ($pid > 1) {
            // Older rows have no pgid. The worker alone is better than nothing,
            // and the batch check will still stop the loop.
            @exec('kill -TERM ' . $pid . ' 2>/dev/null');
            $signalled = true;
        }

        // Give it a moment to exit on its own before insisting.
        $gone = false;
        for ($i = 0; $i < 10; $i++) {
            usleep(200000);
            if (!self::processAlive($pid)) { $gone = true; break; }
        }
        if (!$gone && $pgid > 1) {
            self::signalGroup($pgid, 'KILL');
            usleep(300000);
            $gone = !self::processAlive($pid);
        }

        Database::query(
            "UPDATE scan_jobs SET status='cancelled', finished_at=? WHERE id=?",
            [time(), $id]
        );

        // Any clamscan left over from this group after a KILL is worth saying
        // out loud rather than reporting a clean stop.
        $stragglers = self::clamscanPidsForGroup($pgid);

        Logger::info("Scan job {$id} stopped by request"
                   . ($signalled ? ' (process group ' . $pgid . ' signalled)' : '')
                   . ($stragglers ? ' - ' . count($stragglers) . ' clamscan process(es) still present' : ''));

        return [
            'success'    => true,
            'job_id'     => $id,
            'signalled'  => $signalled,
            'worker_gone'=> $gone,
            'stragglers' => count($stragglers),
            'message'    => $gone
                ? 'Scan stopped.'
                : 'Scan marked cancelled; the worker did not exit and was killed.',
        ];
    }

    private static function signalGroup(int $pgid, string $sig): bool
    {
        if ($pgid <= 1) { return false; }
        // posix_kill with a negative PID signals the group; the shell fallback
        // exists because posix is not compiled in everywhere.
        if (function_exists('posix_kill')) {
            $map = ['TERM' => 15, 'KILL' => 9];
            return @posix_kill(-$pgid, $map[$sig] ?? 15);
        }
        @exec('kill -' . $sig . ' -- -' . $pgid . ' 2>/dev/null', $o, $rc);
        return $rc === 0;
    }

    /** The process group of a pid, or 0. */
    private static function pgidOf(int $pid): int
    {
        $stat = @file_get_contents('/proc/' . $pid . '/stat');
        if ($stat === false) { return 0; }
        $tail = substr($stat, strrpos($stat, ')') + 2);
        $f    = explode(' ', $tail);
        return isset($f[2]) ? (int) $f[2] : 0;
    }

    private static function processAlive(int $pid): bool
    {
        if ($pid <= 1) { return false; }
        if (is_dir('/proc')) { return is_dir('/proc/' . $pid); }
        if (function_exists('posix_kill')) { return @posix_kill($pid, 0); }
        @exec('kill -0 ' . $pid . ' 2>/dev/null', $o, $rc);
        return $rc === 0;
    }

    /** clamscan processes still in the given process group. */
    private static function clamscanPidsForGroup(int $pgid): array
    {
        $pids = [];
        if ($pgid <= 1 || !is_dir('/proc')) { return $pids; }
        foreach (glob('/proc/[0-9]*') ?: [] as $dir) {
            $pid  = (int) basename($dir);
            $comm = @file_get_contents($dir . '/comm');
            if ($comm === false || strpos(trim($comm), 'clamscan') === false) {
                continue;
            }
            $stat = @file_get_contents($dir . '/stat');
            if ($stat === false) { continue; }
            // Field 5 is the process group id; the command name in field 2 can
            // contain spaces, so parse from the closing parenthesis.
            $tail = substr($stat, strrpos($stat, ')') + 2);
            $f    = explode(' ', $tail);
            if (isset($f[2]) && (int) $f[2] === $pgid) {
                $pids[] = $pid;
            }
        }
        return $pids;
    }

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
