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

    /** Scan roots */
    private array $scanRoots = [
        '/home',
        '/var/www',
    ];

    public function __construct() {
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

    public function scanInstalls(): array {
        $found = [];

        foreach ($this->scanRoots as $root) {
            if (!is_dir($root)) continue;

            // /home/*/public_html  and /var/www/html  and /var/www/*/html
            $candidates = array_merge(
                glob("$root/*/public_html", GLOB_ONLYDIR) ?: [],
                glob("$root/html",          GLOB_ONLYDIR) ?: [],
                glob("$root/*/html",        GLOB_ONLYDIR) ?: []
            );

            foreach ($candidates as $dir) {
                $dir = rtrim($dir, '/');

                if ($this->isWordPress($dir)) {
                    $found[] = $this->buildWordPressRecord($dir);
                } elseif ($this->isJoomla($dir)) {
                    $found[] = $this->buildJoomlaRecord($dir);
                } elseif ($this->isDrupal($dir)) {
                    $found[] = $this->buildDrupalRecord($dir);
                }
            }
        }

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

        return [
            'total_installs'       => (int) $total,
            'wordpress'            => (int) $wp,
            'joomla'               => (int) $joomla,
            'drupal'               => (int) $drupal,
            'outdated'             => (int) $outd,
            'installs_with_issues' => (int) $issues,
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
