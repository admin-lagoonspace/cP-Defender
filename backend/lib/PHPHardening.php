<?php
/**
 * Sentinel Gate — PHP Hardening Module
 * Audits and applies PHP security configuration for the server and per cPanel account
 */

class PHPHardening {

    /** Settings whose recommended value is Off / disabled */
    private array $offSettings = [
        'expose_php', 'display_errors', 'display_startup_errors',
        'allow_url_fopen', 'allow_url_include',
    ];

    /** Recommended disabled functions to add when disable_functions is empty */
    private string $recommendedDisabledFunctions =
        'exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source';

    public function __construct() {
        // No extra DB tables required
    }

    // ── Read Current Settings ─────────────────────────────────────────────────

    public function getCurrentSettings(): array {
        $keys = [
            'expose_php', 'display_errors', 'display_startup_errors',
            'log_errors', 'error_log',
            'allow_url_fopen', 'allow_url_include',
            'disable_functions', 'open_basedir',
            'session.cookie_httponly', 'session.cookie_secure', 'session.use_strict_mode',
            'file_uploads', 'upload_max_filesize',
            'max_execution_time', 'max_input_time',
            'memory_limit', 'post_max_size',
        ];

        // Legacy keys only present in PHP < 5.4
        if (version_compare(PHP_VERSION, '5.4.0', '<')) {
            $keys[] = 'register_globals';
            $keys[] = 'magic_quotes_gpc';
        }

        $settings = [];
        foreach ($keys as $key) {
            $settings[$key] = ini_get($key);
        }

        $settings['php_version']    = PHP_VERSION;
        $settings['php_ini_path']   = php_ini_loaded_file() ?: 'unknown';
        $settings['loaded_inifiles']= php_ini_scanned_files() ?: '';

        return $settings;
    }

    // ── Recommendations ───────────────────────────────────────────────────────

    public function getRecommendations(): array {
        $current = $this->getCurrentSettings();
        $recs    = [];

        // expose_php
        if (strtolower($current['expose_php']) === 'on' || $current['expose_php'] === '1') {
            $recs[] = $this->rec(
                'expose_php', $current['expose_php'], 'Off', 'medium',
                'Hides PHP version from response headers, reducing fingerprinting risk.',
                true
            );
        }

        // display_errors
        if (strtolower($current['display_errors']) === 'on' || $current['display_errors'] === '1') {
            $recs[] = $this->rec(
                'display_errors', $current['display_errors'], 'Off', 'high',
                'Prevents error details from leaking to users — log errors instead.',
                true
            );
        }

        // display_startup_errors
        if (strtolower($current['display_startup_errors']) === 'on' || $current['display_startup_errors'] === '1') {
            $recs[] = $this->rec(
                'display_startup_errors', $current['display_startup_errors'], 'Off', 'medium',
                'Hides PHP startup errors from users.',
                true
            );
        }

        // log_errors — should be On
        if (strtolower($current['log_errors']) !== 'on' && $current['log_errors'] !== '1') {
            $recs[] = $this->rec(
                'log_errors', $current['log_errors'], 'On', 'medium',
                'Errors should be logged to file rather than displayed to users.',
                true
            );
        }

        // allow_url_fopen
        if (strtolower($current['allow_url_fopen']) === 'on' || $current['allow_url_fopen'] === '1') {
            $recs[] = $this->rec(
                'allow_url_fopen', $current['allow_url_fopen'], 'Off', 'high',
                'Prevents remote file inclusion attacks via URL-based file functions.',
                true
            );
        }

        // allow_url_include
        if (strtolower($current['allow_url_include']) === 'on' || $current['allow_url_include'] === '1') {
            $recs[] = $this->rec(
                'allow_url_include', $current['allow_url_include'], 'Off', 'critical',
                'Remote file inclusion is a critical attack vector — must be disabled.',
                true
            );
        }

        // session.cookie_httponly
        if ($current['session.cookie_httponly'] !== '1' && strtolower($current['session.cookie_httponly']) !== 'on') {
            $recs[] = $this->rec(
                'session.cookie_httponly', $current['session.cookie_httponly'], '1', 'high',
                'Prevents XSS-based session theft by blocking JavaScript access to session cookies.',
                true
            );
        }

        // session.cookie_secure — recommend only when on HTTPS
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
                   (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);
        if ($isHttps && $current['session.cookie_secure'] !== '1') {
            $recs[] = $this->rec(
                'session.cookie_secure', $current['session.cookie_secure'], '1', 'medium',
                'Instructs the browser to send session cookies only over HTTPS.',
                true
            );
        }

        // session.use_strict_mode
        if ($current['session.use_strict_mode'] !== '1') {
            $recs[] = $this->rec(
                'session.use_strict_mode', $current['session.use_strict_mode'], '1', 'medium',
                'Prevents session fixation attacks by rejecting uninitialized session IDs.',
                true
            );
        }

        // disable_functions — warn if completely empty
        if (trim($current['disable_functions']) === '') {
            $recs[] = $this->rec(
                'disable_functions', '(empty)', $this->recommendedDisabledFunctions, 'high',
                'Dangerous shell-execution functions are unrestricted — disable them to limit damage from code injection.',
                true
            );
        }

        // open_basedir — warn if not set
        if (trim($current['open_basedir']) === '') {
            $recs[] = $this->rec(
                'open_basedir', '(not set)', '/home:/tmp:/usr/share/php', 'medium',
                'open_basedir restricts PHP file access to specific directories, limiting path traversal attacks.',
                false   // Requires per-account tuning — flag for awareness but mark as manual
            );
        }

        return $recs;
    }

    // ── Apply Hardening (server-level php.ini) ────────────────────────────────

    public function applyHardening(array $settings): array {
        $phpIni = php_ini_loaded_file();
        if (!$phpIni || !is_writable($phpIni)) {
            Logger::error("PHPHardening::applyHardening — php.ini not writable: $phpIni");
            return [
                'applied'          => [],
                'failed'           => array_keys($settings),
                'restart_needed'   => false,
                'error'            => "php.ini ($phpIni) is not writable",
            ];
        }

        $applied        = [];
        $failed         = [];
        $restartNeeded  = false;

        foreach ($settings as $key => $value) {
            $escaped = escapeshellarg($value);
            $keyEsc  = preg_quote($key, '/');

            // Try to update existing directive; insert if absent
            $checkCmd = "grep -cP '^\\s*{$keyEsc}\\s*=' " . escapeshellarg($phpIni) . " 2>/dev/null";
            exec($checkCmd, $grepOut, $grepCode);
            $exists = isset($grepOut[0]) && (int)$grepOut[0] > 0;

            if ($exists) {
                $cmd = sprintf(
                    "sed -i 's/^\\s*%s\\s*=.*/%s = %s/' %s 2>/dev/null",
                    preg_quote($key, '/'),
                    $key,
                    addslashes($value),
                    escapeshellarg($phpIni)
                );
            } else {
                $cmd = sprintf(
                    "echo '%s = %s' >> %s 2>/dev/null",
                    $key,
                    $value,
                    escapeshellarg($phpIni)
                );
            }

            exec($cmd, $cmdOut, $code);

            if ($code === 0) {
                $applied[]     = $key;
                $restartNeeded = true;
            } else {
                $failed[] = $key;
                Logger::error("PHPHardening: failed to set $key in $phpIni");
            }
        }

        if (!empty($applied)) {
            Logger::info('PHPHardening: applied ' . implode(', ', $applied) . " in $phpIni");
        }

        return [
            'applied'        => $applied,
            'failed'         => $failed,
            'restart_needed' => $restartNeeded,
        ];
    }

    // ── cPanel Account Helpers ────────────────────────────────────────────────

    public function getCpanelAccounts(): array {
        $accounts = [];

        // Try whmapi1 first (authoritative)
        if (file_exists(WHMAPI_BINARY)) {
            exec(WHMAPI_BINARY . ' listaccts --output=json 2>/dev/null', $out, $code);
            $json = implode('', $out);
            $data = @json_decode($json, true);
            if ($data && isset($data['data']['acct'])) {
                foreach ($data['data']['acct'] as $acct) {
                    $accounts[] = [
                        'user'      => $acct['user']   ?? '',
                        'domain'    => $acct['domain']  ?? '',
                        'php_version'=> $acct['phpversion'] ?? 'system',
                        'home'      => "/home/{$acct['user']}",
                    ];
                }
                return $accounts;
            }
        }

        // Fallback: parse /etc/trueuserdomains
        $mapFile = '/etc/trueuserdomains';
        if (file_exists($mapFile)) {
            $lines = @file($mapFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            foreach ($lines as $line) {
                // Format: domain: user
                if (preg_match('/^([^:]+):\s*(\S+)$/', $line, $m)) {
                    $user   = $m[2];
                    $domain = $m[1];

                    // Read php version from /var/cpanel/users/$user
                    $phpVersion = 'system';
                    $userFile   = "/var/cpanel/users/$user";
                    $uf         = @file_get_contents($userFile);
                    if ($uf && preg_match('/PHPVERSION=(.+)/', $uf, $pv)) {
                        $phpVersion = trim($pv[1]);
                    }

                    $accounts[] = [
                        'user'        => $user,
                        'domain'      => trim($domain),
                        'php_version' => $phpVersion,
                        'home'        => "/home/$user",
                    ];
                }
            }
        }

        return $accounts;
    }

    public function getAccountPHPSettings(string $account): array {
        $settings  = [];
        $home      = "/home/$account";
        $htaccess  = "$home/public_html/.htaccess";
        $phpIniLoc = "$home/public_html/php.ini";

        // Read php_value / php_flag from .htaccess
        $ht = @file_get_contents($htaccess);
        if ($ht) {
            preg_match_all('/^php_(?:value|flag)\s+(\S+)\s+(.+)$/im', $ht, $matches, PREG_SET_ORDER);
            foreach ($matches as $m) {
                $settings[$m[1]] = trim($m[2]);
            }
        }

        // Also check local php.ini
        $pi = @file_get_contents($phpIniLoc);
        if ($pi) {
            preg_match_all('/^\s*([^=;\s][^=\s]*)\s*=\s*(.+)$/m', $pi, $matches, PREG_SET_ORDER);
            foreach ($matches as $m) {
                $key = trim($m[1]);
                if (str_starts_with($key, ';')) continue;
                $settings[$key] = trim($m[2]);
            }
        }

        return [
            'account'  => $account,
            'htaccess' => $htaccess,
            'php_ini'  => $phpIniLoc,
            'settings' => $settings,
        ];
    }

    public function applyAccountHardening(string $account, array $settings): array {
        $htaccess = "/home/$account/public_html/.htaccess";
        $applied  = [];
        $failed   = [];

        if (!file_exists(dirname($htaccess))) {
            return ['applied' => [], 'failed' => array_keys($settings), 'error' => 'public_html not found'];
        }

        $currentContent = @file_get_contents($htaccess) ?: '';

        foreach ($settings as $key => $value) {
            // Determine directive type: boolean settings use php_flag, others php_value
            $boolSettings = [
                'display_errors', 'display_startup_errors', 'expose_php', 'log_errors',
                'allow_url_fopen', 'allow_url_include', 'file_uploads',
                'session.cookie_httponly', 'session.cookie_secure', 'session.use_strict_mode',
            ];
            $directive = in_array($key, $boolSettings) ? 'php_flag' : 'php_value';
            $line      = "$directive $key $value";

            // Replace existing directive or append
            $keyEsc = preg_quote($key, '/');
            $pattern = "/^php_(?:value|flag)\s+$keyEsc\s+.+$/im";
            if (preg_match($pattern, $currentContent)) {
                $currentContent = preg_replace($pattern, $line, $currentContent);
            } else {
                $currentContent .= "\n$line";
            }

            $applied[] = $key;
        }

        $result = @file_put_contents($htaccess, $currentContent);
        if ($result === false) {
            Logger::error("PHPHardening::applyAccountHardening — cannot write $htaccess");
            return ['applied' => [], 'failed' => array_keys($settings)];
        }

        Logger::info("PHPHardening: applied " . implode(', ', $applied) . " to $htaccess");
        return ['applied' => $applied, 'failed' => $failed];
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    public function getStats(): array {
        $recs    = $this->getRecommendations();
        $current = $this->getCurrentSettings();

        $bySeverity = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($recs as $r) {
            $sev = $r['severity'] ?? 'low';
            if (isset($bySeverity[$sev])) $bySeverity[$sev]++;
        }

        // Count hardened settings (recommendations that are already satisfied)
        $allRecs = $this->buildAllRecommendationChecks($current);
        $hardened = 0;
        foreach ($allRecs as $check) {
            if ($check['satisfied']) $hardened++;
        }

        // Accounts checked via cPanel (count without deep scanning)
        $accountsChecked = 0;
        if (file_exists('/etc/trueuserdomains')) {
            $lines = @file('/etc/trueuserdomains', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            $accountsChecked = count($lines);
        }

        return [
            'total_recommendations'  => count($recs),
            'recommendations_by_severity' => $bySeverity,
            'accounts_checked'       => $accountsChecked,
            'hardened_settings'      => $hardened,
            'php_version'            => PHP_VERSION,
        ];
    }

    // ── Private Helpers ───────────────────────────────────────────────────────

    private function rec(
        string $setting,
        string $current,
        string $recommended,
        string $severity,
        string $description,
        bool   $canApply
    ): array {
        return [
            'setting'           => $setting,
            'current_value'     => $current,
            'recommended_value' => $recommended,
            'severity'          => $severity,
            'description'       => $description,
            'can_apply'         => $canApply,
        ];
    }

    /**
     * Build a list of all hardening checks with a 'satisfied' flag
     * (used by getStats to count how many are already correctly configured).
     */
    private function buildAllRecommendationChecks(array $current): array {
        $checks = [];

        $onOffSettings = [
            'expose_php'            => ['expected' => 'off', 'severity' => 'medium'],
            'display_errors'        => ['expected' => 'off', 'severity' => 'high'],
            'display_startup_errors'=> ['expected' => 'off', 'severity' => 'medium'],
            'allow_url_fopen'       => ['expected' => 'off', 'severity' => 'high'],
            'allow_url_include'     => ['expected' => 'off', 'severity' => 'critical'],
            'log_errors'            => ['expected' => 'on',  'severity' => 'medium'],
        ];

        foreach ($onOffSettings as $key => $meta) {
            $val   = strtolower($current[$key] ?? '');
            $isOn  = $val === 'on' || $val === '1';
            $checks[] = [
                'setting'   => $key,
                'satisfied' => ($meta['expected'] === 'on') ? $isOn : !$isOn,
            ];
        }

        // session settings
        $checks[] = ['setting' => 'session.cookie_httponly', 'satisfied' => $current['session.cookie_httponly'] === '1'];
        $checks[] = ['setting' => 'session.use_strict_mode', 'satisfied' => $current['session.use_strict_mode'] === '1'];

        // disable_functions
        $checks[] = ['setting' => 'disable_functions', 'satisfied' => trim($current['disable_functions'] ?? '') !== ''];

        return $checks;
    }
}
