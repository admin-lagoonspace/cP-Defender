<?php
/**
 * Sentinel Gate — CMS Guard Module
 * Discovers and audits WordPress, Joomla, and Drupal installations
 */

class CMSGuard {

    /** Minimum versions considered current — anything below is flagged outdated */
    private array $minVersions = [
        'wordpress' => '6.4',
        'joomla'    => '5.0',
        'drupal'    => '10.0',
    ];

    /** Scan roots used when cPanel userdata is unavailable. */
    private array $scanRoots = [
        '/home',
        '/var/www',
    ];

    /**
     * cPanel's own record of every document root on the box. Each domain, addon
     * domain and subdomain has a file here naming its documentroot, which makes
     * it authoritative — far better than guessing directory layouts.
     */
    private string $cpanelUserdata = '/var/cpanel/userdata';

    /**
     * How far below a document root to look for a CMS.
     *
     * WordPress is very often NOT at the document root: /public_html/blog,
     * /public_html/shop, and addon domains under /public_html/example.com are
     * all routine. The previous code checked the document root and nothing
     * else, so a server full of WordPress sites reported zero.
     */
    private int $maxDepth = 3;

    /**
     * Never descend into these. They are CMS internals or dependency trees:
     * walking them costs a great deal of time and cannot contain a separate
     * installation.
     */
    private const SKIP_DIRS = [
        'wp-content', 'wp-includes', 'wp-admin', 'node_modules', 'vendor',
        'cgi-bin', '.git', '.svn', '.well-known', 'cache', 'tmp', 'temp',
        'administrator', 'libraries', 'core', 'modules', 'sites', 'media',
        'uploads', 'backup', 'backups', '.trash', 'mail', 'etc', 'logs',
    ];

    /** Stop rather than walking a pathological tree forever. */
    private const MAX_DIRS = 20000;

    private int $dirsSeen = 0;

    /**
     * @param string[]|null $scanRoots      override for tests
     * @param string|null   $cpanelUserdata override for tests
     */
    public function __construct(?array $scanRoots = null, ?string $cpanelUserdata = null) {
        if ($scanRoots !== null)      { $this->scanRoots = $scanRoots; }
        if ($cpanelUserdata !== null) { $this->cpanelUserdata = $cpanelUserdata; }

        $depth = (int)(Database::setting('cms_scan_depth', '3') ?? 3);
        if ($depth >= 0 && $depth <= 6) { $this->maxDepth = $depth; }

        $this->ensureSchema();
    }

    private function ensureSchema(): void {
        Database::get()->exec("
            CREATE TABLE IF NOT EXISTS cms_installs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                cms_type     TEXT NOT NULL,
                version      TEXT,
                install_path TEXT NOT NULL UNIQUE,
                cpanel_user  TEXT,
                domain       TEXT,
                issues       TEXT,
                outdated     INTEGER NOT NULL DEFAULT 0,
                last_check   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                status       TEXT NOT NULL DEFAULT 'ok'
            );
        ");
    }

    // ── Scan ──────────────────────────────────────────────────────────────────

    /**
     * Every document root worth searching.
     *
     * cPanel's userdata is consulted first and is authoritative: it lists the
     * document root of every domain, addon domain and subdomain. Globbing
     * /home/<user>/public_html finds only the primary domain of each account,
     * which is why a server hosting several WordPress sites could report none.
     *
     * @return string[]
     */
    public function candidateDocroots(): array {
        $dirs = [];

        foreach (glob($this->cpanelUserdata . '/*/*') ?: [] as $file) {
            // Skip cPanel's own cache/lock siblings; only the plain domain
            // files carry a documentroot.
            if (!is_file($file) || preg_match('/\.(cache|lock|json)$/', $file)) {
                continue;
            }
            $body = @file_get_contents($file);
            if ($body === false) { continue; }
            if (preg_match('/^\s*documentroot:\s*(.+)$/m', $body, $m)) {
                $dir = rtrim(trim($m[1], " \t\"'"), '/');
                if ($dir !== '' && is_dir($dir)) { $dirs[] = $dir; }
            }
        }

        foreach ($this->scanRoots as $root) {
            if (!is_dir($root)) { continue; }
            foreach ([
                glob("$root/*/public_html", GLOB_ONLYDIR),
                glob("$root/html",          GLOB_ONLYDIR),
                glob("$root/*/html",        GLOB_ONLYDIR),
            ] as $set) {
                foreach ($set ?: [] as $dir) { $dirs[] = rtrim($dir, '/'); }
            }
        }

        return array_values(array_unique($dirs));
    }

    /** The CMS record for this exact directory, or null if it is not one. */
    private function detect(string $dir): ?array {
        if ($this->isWordPress($dir)) { return $this->buildWordPressRecord($dir); }
        if ($this->isJoomla($dir))    { return $this->buildJoomlaRecord($dir); }
        if ($this->isDrupal($dir))    { return $this->buildDrupalRecord($dir); }
        return null;
    }

    /**
     * Search $dir and, to $depth levels, the directories beneath it.
     *
     * Descent stops as soon as a CMS matches: everything below a WordPress root
     * belongs to that installation, not to a new one.
     *
     * @return array<int,array<string,mixed>>
     */
    private function findInstallsUnder(string $dir, int $depth): array {
        if ($this->dirsSeen++ > self::MAX_DIRS) { return []; }

        $record = $this->detect($dir);
        if ($record !== null) { return [$record]; }
        if ($depth <= 0) { return []; }

        $found = [];
        foreach (glob($dir . '/*', GLOB_ONLYDIR) ?: [] as $sub) {
            $base = basename($sub);
            if ($base === '' || $base[0] === '.') { continue; }
            if (in_array(strtolower($base), self::SKIP_DIRS, true)) { continue; }
            // A symlink can point back up the tree; following it can loop.
            if (is_link($sub)) { continue; }
            $found = array_merge($found, $this->findInstallsUnder($sub, $depth - 1));
        }
        return $found;
    }

    public function scanInstalls(): array {
        $found = [];
        $this->dirsSeen = 0;

        foreach ($this->candidateDocroots() as $dir) {
            $found = array_merge($found, $this->findInstallsUnder($dir, $this->maxDepth));
        }

        // Two document roots can resolve to the same directory (an addon domain
        // parked on the primary). install_path is UNIQUE, so de-duplicate here
        // rather than letting the insert fail.
        $unique = [];
        foreach ($found as $rec) { $unique[$rec['install_path']] = $rec; }
        $found = array_values($unique);

        // Upsert into DB
        foreach ($found as $install) {
            $existing = Database::fetchOne(
                "SELECT id FROM cms_installs WHERE install_path = ?", [$install['install_path']]
            );
            if ($existing) {
                Database::query(
                    "UPDATE cms_installs
                     SET cms_type=?, version=?, cpanel_user=?, domain=?, issues=?,
                         outdated=?, last_check=strftime('%s','now'), status=?
                     WHERE id=?",
                    [
                        $install['cms_type'], $install['version'],
                        $install['cpanel_user'], $install['domain'],
                        $install['issues'], $install['outdated'],
                        $install['status'], $existing['id'],
                    ]
                );
            } else {
                Database::insert('cms_installs', $install);
            }
        }

        Database::setSetting('cms_last_scan_at', (string) time());
        Logger::info('CMSGuard: scan complete, found ' . count($found) . ' installs');
        return $found;
    }

    public function getInstalls(): array {
        return Database::fetchAll("SELECT * FROM cms_installs ORDER BY last_check DESC");
    }

    public function checkInstall(int $id): array {
        $row = Database::fetchOne("SELECT * FROM cms_installs WHERE id = ?", [$id]);
        if (!$row) return ['error' => 'Install not found'];

        $dir    = $row['install_path'];
        $issues = [];
        $outdated = 0;

        switch ($row['cms_type']) {
            case 'wordpress':
                $issues   = $this->auditWordPress($dir, $row['version']);
                $outdated = $this->isOutdated('wordpress', $row['version']) ? 1 : 0;
                break;
            case 'joomla':
                $issues   = $this->auditJoomla($dir, $row['version']);
                $outdated = $this->isOutdated('joomla', $row['version']) ? 1 : 0;
                break;
            case 'drupal':
                $issues   = $this->auditDrupal($dir, $row['version']);
                $outdated = $this->isOutdated('drupal', $row['version']) ? 1 : 0;
                break;
        }

        $status = count($issues) > 0 ? 'issues' : 'ok';

        Database::query(
            "UPDATE cms_installs SET issues=?, outdated=?, last_check=strftime('%s','now'), status=? WHERE id=?",
            [json_encode($issues), $outdated, $status, $id]
        );

        return array_merge($row, ['issues' => $issues, 'outdated' => $outdated, 'status' => $status]);
    }

    public function getStats(): array {
        $total   = Database::fetchOne("SELECT COUNT(*) as c FROM cms_installs")['c'];
        $wp      = Database::fetchOne("SELECT COUNT(*) as c FROM cms_installs WHERE cms_type='wordpress'")['c'];
        $joomla  = Database::fetchOne("SELECT COUNT(*) as c FROM cms_installs WHERE cms_type='joomla'")['c'];
        $drupal  = Database::fetchOne("SELECT COUNT(*) as c FROM cms_installs WHERE cms_type='drupal'")['c'];
        $outd    = Database::fetchOne("SELECT COUNT(*) as c FROM cms_installs WHERE outdated=1")['c'];
        $issues  = Database::fetchOne("SELECT COUNT(*) as c FROM cms_installs WHERE status='issues'")['c'];

        // "0 installs" and "no scan has ever run" look identical in the UI, and
        // the second is what a fresh install always shows. Report the last scan
        // time so the panel can say which it is instead of implying the server
        // has no CMS on it.
        $last = Database::setting('cms_last_scan_at', '0');

        return [
            'total_installs'       => (int) $total,
            'wordpress'            => (int) $wp,
            'joomla'               => (int) $joomla,
            'drupal'               => (int) $drupal,
            'outdated'             => (int) $outd,
            'installs_with_issues' => (int) $issues,
            'last_scan_at'         => (int) $last,
            'ever_scanned'         => ((int) $last) > 0,
        ];
    }

    public function runScan(): array {
        $installs = $this->scanInstalls();
        $stats    = $this->getStats();
        return array_merge(['installs_found' => count($installs)], $stats);
    }

    // ── Detection Helpers ─────────────────────────────────────────────────────

    private function isWordPress(string $dir): bool {
        return file_exists("$dir/wp-config.php") && file_exists("$dir/wp-includes/version.php");
    }

    private function isJoomla(string $dir): bool {
        return file_exists("$dir/configuration.php") &&
               file_exists("$dir/libraries/cms/version/version.php");
    }

    private function isDrupal(string $dir): bool {
        return file_exists("$dir/core/lib/Drupal.php");
    }

    // ── Record Builders ───────────────────────────────────────────────────────

    private function buildWordPressRecord(string $dir): array {
        $version    = $this->getWPVersion($dir);
        $cpanelUser = $this->extractCpanelUser($dir);
        $domain     = $this->guessDomain($dir, $cpanelUser);
        $issues     = $this->auditWordPress($dir, $version);
        $outdated   = $this->isOutdated('wordpress', $version) ? 1 : 0;

        return [
            'cms_type'    => 'wordpress',
            'version'     => $version,
            'install_path'=> $dir,
            'cpanel_user' => $cpanelUser,
            'domain'      => $domain,
            'issues'      => json_encode($issues),
            'outdated'    => $outdated,
            'status'      => count($issues) > 0 ? 'issues' : 'ok',
        ];
    }

    private function buildJoomlaRecord(string $dir): array {
        $version    = $this->getJoomlaVersion($dir);
        $cpanelUser = $this->extractCpanelUser($dir);
        $domain     = $this->guessDomain($dir, $cpanelUser);
        $issues     = $this->auditJoomla($dir, $version);
        $outdated   = $this->isOutdated('joomla', $version) ? 1 : 0;

        return [
            'cms_type'    => 'joomla',
            'version'     => $version,
            'install_path'=> $dir,
            'cpanel_user' => $cpanelUser,
            'domain'      => $domain,
            'issues'      => json_encode($issues),
            'outdated'    => $outdated,
            'status'      => count($issues) > 0 ? 'issues' : 'ok',
        ];
    }

    private function buildDrupalRecord(string $dir): array {
        $version    = $this->getDrupalVersion($dir);
        $cpanelUser = $this->extractCpanelUser($dir);
        $domain     = $this->guessDomain($dir, $cpanelUser);
        $issues     = $this->auditDrupal($dir, $version);
        $outdated   = $this->isOutdated('drupal', $version) ? 1 : 0;

        return [
            'cms_type'    => 'drupal',
            'version'     => $version,
            'install_path'=> $dir,
            'cpanel_user' => $cpanelUser,
            'domain'      => $domain,
            'issues'      => json_encode($issues),
            'outdated'    => $outdated,
            'status'      => count($issues) > 0 ? 'issues' : 'ok',
        ];
    }

    // ── Version Readers ───────────────────────────────────────────────────────

    private function getWPVersion(string $dir): string {
        $file    = "$dir/wp-includes/version.php";
        $content = @file_get_contents($file);
        if ($content && preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m)) {
            return $m[1];
        }
        return 'unknown';
    }

    private function getJoomlaVersion(string $dir): string {
        $file    = "$dir/libraries/cms/version/version.php";
        $content = @file_get_contents($file);
        if ($content && preg_match('/RELEASE\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m)) {
            return $m[1];
        }
        return 'unknown';
    }

    private function getDrupalVersion(string $dir): string {
        // Try core/lib/Drupal.php constant
        $file    = "$dir/core/lib/Drupal.php";
        $content = @file_get_contents($file);
        if ($content && preg_match('/VERSION\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m)) {
            return $m[1];
        }
        // Fallback: system.info in modules
        $info = @file_get_contents("$dir/modules/system/system.info");
        if ($info && preg_match('/^version\s*=\s*(.+)$/m', $info, $m)) {
            return trim($m[1]);
        }
        return 'unknown';
    }

    // ── Audit Methods ─────────────────────────────────────────────────────────

    private function auditWordPress(string $dir, string $version): array {
        $issues = [];

        if ($this->isOutdated('wordpress', $version)) {
            $issues[] = [
                'type'    => 'outdated',
                'message' => "WordPress $version is outdated (minimum recommended: {$this->minVersions['wordpress']})",
            ];
        }

        if (file_exists("$dir/xmlrpc.php")) {
            $issues[] = [
                'type'    => 'xmlrpc_enabled',
                'message' => 'xmlrpc.php is present and may be exploited for brute-force or DDoS amplification',
            ];
        }

        if (file_exists("$dir/wp-login.php")) {
            $issues[] = [
                'type'    => 'login_exposed',
                'message' => 'wp-login.php is publicly accessible — consider restricting access',
            ];
        }

        // Check for stray PHP files in wp-admin and wp-includes
        foreach (['wp-admin', 'wp-includes'] as $coreDir) {
            $path = "$dir/$coreDir";
            if (!is_dir($path)) continue;
            $phpFiles = glob("$path/*.php") ?: [];
            foreach ($phpFiles as $phpFile) {
                // Known entry-points are fine; anything not matching WordPress's naming
                // convention (lowercase, hyphens) is suspicious
                $base = basename($phpFile);
                if (preg_match('/[A-Z]|[^a-z0-9\-.]/', $base)) {
                    $issues[] = [
                        'type'    => 'suspicious_file',
                        'message' => "Suspicious file in $coreDir: $base",
                        'file'    => $phpFile,
                    ];
                }
            }
        }

        // Check active plugins directory
        $pluginDir = "$dir/wp-content/plugins";
        if (is_dir($pluginDir)) {
            $plugins = array_filter(glob("$pluginDir/*"), 'is_dir');
            // No deep audit here — just count and record them
            // (Future: check plugin versions against WP.org API)
        }

        return $issues;
    }

    private function auditJoomla(string $dir, string $version): array {
        $issues = [];

        if ($this->isOutdated('joomla', $version)) {
            $issues[] = [
                'type'    => 'outdated',
                'message' => "Joomla $version is outdated (minimum recommended: {$this->minVersions['joomla']})",
            ];
        }

        // Joomla: configuration.php should not be web-accessible — check it isn't readable as HTML
        if (!file_exists("$dir/configuration.php")) {
            $issues[] = [
                'type'    => 'missing_config',
                'message' => 'configuration.php not found — install may be incomplete',
            ];
        }

        return $issues;
    }

    private function auditDrupal(string $dir, string $version): array {
        $issues = [];

        if ($this->isOutdated('drupal', $version)) {
            $issues[] = [
                'type'    => 'outdated',
                'message' => "Drupal $version is outdated (minimum recommended: {$this->minVersions['drupal']})",
            ];
        }

        // Check for .txt files that reveal version info
        foreach (['CHANGELOG.txt', 'README.txt', 'INSTALL.txt'] as $f) {
            if (file_exists("$dir/$f")) {
                $issues[] = [
                    'type'    => 'info_disclosure',
                    'message' => "$f is present and may reveal version information to attackers",
                ];
            }
        }

        return $issues;
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    private function isOutdated(string $cms, string $version): bool {
        if ($version === 'unknown') return false;
        $min = $this->minVersions[$cms] ?? '0';
        return version_compare($version, $min, '<');
    }

    private function extractCpanelUser(string $dir): string {
        // /home/USERNAME/public_html → USERNAME
        if (preg_match('|^/home/([^/]+)/|', $dir, $m)) {
            return $m[1];
        }
        return '';
    }

    private function guessDomain(string $dir, string $cpanelUser): string {
        if ($cpanelUser === '') return '';

        // Read cPanel user file for the main domain
        $userFile = "/var/cpanel/users/$cpanelUser";
        $content  = @file_get_contents($userFile);
        if ($content && preg_match('/^DNS=(.+)$/m', $content, $m)) {
            return trim($m[1]);
        }
        return '';
    }
}
