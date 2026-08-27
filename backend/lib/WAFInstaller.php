<?php
/**
 * Sentinel Gate — ModSecurity + OWASP CRS provisioning
 *
 * Installs and configures the WAF engine so the operator does not have to.
 * WAF.php reads ModSecurity's configuration and audit log; without ModSecurity
 * present it reports status and nothing else, which made the WAF page look
 * complete while providing no protection.
 *
 * ── WHY MODSECURITY RATHER THAN OUR OWN FILTER ───────────────────────────────
 * Request filtering has to sit in the request path. Writing our own would mean
 * either an Apache module (C, and a crash takes the web server with it) or a PHP
 * auto_prepend_file, which only sees PHP requests and adds latency to every one.
 * ModSecurity is already in that path, is battle-tested, and OWASP CRS is a
 * maintained ruleset we would otherwise have to reproduce and keep current.
 *
 * ── SAFETY ───────────────────────────────────────────────────────────────────
 * A WAF that blocks legitimate traffic is worse than none, because the operator
 * finds out from customers. So a fresh install is deployed in DetectionOnly and
 * must be switched to blocking deliberately, after the audit log has been
 * reviewed. Apache config is validated BEFORE any reload — an invalid include
 * would otherwise take the web server down on restart, taking every hosted site
 * with it.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class WAFInstaller
{
    const CRS_VERSION = '4.7.0';
    const CRS_URL     = 'https://github.com/coreruleset/coreruleset/archive/refs/tags/v%s.tar.gz';
    const SG_CONF_DIR = '/etc/sentinel-gate/waf';

    // ── Status ───────────────────────────────────────────────────────────────

    public static function status(): array
    {
        $modsec = self::modsecPresent();
        $crs    = self::crsPath();
        return [
            'modsecurity_installed' => $modsec,
            'modsecurity_version'   => $modsec ? self::modsecVersion() : null,
            'crs_installed'         => $crs !== null,
            'crs_path'              => $crs,
            'crs_version'           => $crs ? self::crsVersion($crs) : null,
            'mode'                  => self::currentMode(),
            'apache'                => self::apacheFlavour(),
            'package_manager'       => self::pkgManager(),
            'can_install'           => self::pkgManager() !== null,
            'managed_by_us'         => is_file(self::SG_CONF_DIR . '/sentinel-waf.conf'),
        ];
    }

    private static function modsecPresent(): bool
    {
        // cPanel/EA4 ships it as ea-apache24-mod_security2; the module file is
        // the reliable signal because the package name differs per platform.
        foreach ([
            '/etc/apache2/modules/mod_security2.so',
            '/usr/lib64/httpd/modules/mod_security2.so',
            '/usr/lib/apache2/modules/mod_security2.so',
        ] as $p) {
            if (file_exists($p)) { return true; }
        }
        $o = (string)@shell_exec('httpd -M 2>/dev/null || apache2ctl -M 2>/dev/null');
        return stripos($o, 'security2_module') !== false;
    }

    private static function modsecVersion(): ?string
    {
        foreach (['/etc/apache2/conf.d/modsec/modsecurity.conf',
                  '/etc/httpd/conf.d/mod_security.conf'] as $f) {
            if (is_readable($f)) {
                if (preg_match('/ModSecurity\s+v?([\d.]+)/i', (string)@file_get_contents($f), $m)) {
                    return $m[1];
                }
            }
        }
        $o = (string)@shell_exec('rpm -q --qf "%{VERSION}" ea-apache24-mod_security2 2>/dev/null');
        return $o !== '' ? trim($o) : 'installed';
    }

    private static function crsPath(): ?string
    {
        foreach ([
            '/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/crs-setup.conf',
            '/etc/httpd/modsecurity.d/owasp-crs/crs-setup.conf',
            self::SG_CONF_DIR . '/coreruleset/crs-setup.conf',
        ] as $p) {
            if (is_file($p)) { return dirname($p); }
        }
        return null;
    }

    private static function crsVersion(string $dir): string
    {
        $f = $dir . '/crs-setup.conf';
        if (is_readable($f) && preg_match('/OWASP_CRS.*?ver.*?([\d.]+)/i',
                (string)@file_get_contents($f), $m)) {
            return $m[1];
        }
        return is_file($dir . '/.crs-version')
            ? trim((string)@file_get_contents($dir . '/.crs-version'))
            : 'unknown';
    }

    public static function currentMode(): string
    {
        $f = self::SG_CONF_DIR . '/sentinel-waf.conf';
        if (is_readable($f)) {
            $c = (string)@file_get_contents($f);
            if (preg_match('/^\s*SecRuleEngine\s+(\w+)/mi', $c, $m)) {
                return strtolower($m[1]);   // on | detectiononly | off
            }
        }
        return 'unknown';
    }

    private static function apacheFlavour(): ?string
    {
        if (is_dir('/etc/apache2/conf.d'))  { return 'ea4';      }  // cPanel
        if (is_dir('/etc/httpd/conf.d'))    { return 'httpd';    }  // RHEL
        if (is_dir('/etc/apache2/conf-available')) { return 'debian'; }
        return null;
    }

    private static function pkgManager(): ?string
    {
        foreach (['dnf', 'yum', 'apt-get'] as $p) {
            if (trim((string)@shell_exec('command -v ' . $p . ' 2>/dev/null')) !== '') { return $p; }
        }
        return null;
    }

    // ── Install ──────────────────────────────────────────────────────────────

    /**
     * @return array{success:bool,steps:array,error?:string}
     */
    public static function install(): array
    {
        $steps = [];
        $ok = static function (string $m) use (&$steps) { $steps[] = ['ok' => true,  'message' => $m]; };
        $no = static function (string $m) use (&$steps) { $steps[] = ['ok' => false, 'message' => $m]; };

        $pm = self::pkgManager();
        if ($pm === null) {
            return ['success' => false, 'steps' => $steps,
                    'error' => 'No supported package manager (dnf/yum/apt-get) found.'];
        }

        // 1. ModSecurity
        if (self::modsecPresent()) {
            $ok('ModSecurity already installed — leaving it alone');
        } else {
            $pkg = self::apacheFlavour() === 'ea4' ? 'ea-apache24-mod_security2'
                 : ($pm === 'apt-get' ? 'libapache2-mod-security2' : 'mod_security');
            @exec(sprintf('%s install -y %s 2>&1', $pm, escapeshellarg($pkg)), $o, $c);
            if ($c !== 0 || !self::modsecPresent()) {
                return ['success' => false, 'steps' => $steps,
                        'error' => 'Could not install ' . $pkg . ': ' . implode(' ', array_slice($o, -3))];
            }
            $ok('Installed ' . $pkg);
        }

        // 2. OWASP CRS
        $crs = self::crsPath();
        if ($crs !== null) {
            $ok('OWASP CRS already present at ' . $crs);
        } else {
            $r = self::installCrs();
            if (!$r['success']) {
                return ['success' => false, 'steps' => $steps, 'error' => $r['error']];
            }
            $ok('Installed OWASP CRS ' . self::CRS_VERSION);
            $crs = self::crsPath();
        }

        // 3. Our config — DetectionOnly to begin with
        $r = self::writeConfig('DetectionOnly', $crs);
        if (!$r['success']) {
            return ['success' => false, 'steps' => $steps, 'error' => $r['error']];
        }
        $ok('Wrote Sentinel Gate WAF config (DetectionOnly)');

        // 4. Validate BEFORE reloading. A bad include would otherwise take
        //    Apache down on restart, and with it every site on the server.
        $v = self::validateApache();
        if (!$v['ok']) {
            self::disableConfig();
            return ['success' => false, 'steps' => $steps,
                    'error' => 'Apache rejected the configuration, so it was removed and '
                             . 'nothing was reloaded: ' . $v['output']];
        }
        $ok('Apache configuration validated');

        self::reloadApache();
        $ok('Apache reloaded — WAF active in DetectionOnly');

        Database::setSetting('waf_managed', '1');
        Database::setSetting('waf_mode', 'detectiononly');
        return ['success' => true, 'steps' => $steps,
                'note' => 'Running in DetectionOnly: attacks are logged, not blocked. '
                        . 'Review the audit log, then switch to blocking.'];
    }

    private static function installCrs(): array
    {
        $dir = self::SG_CONF_DIR;
        @mkdir($dir, 0750, true);
        $tgz = $dir . '/crs.tar.gz';
        $url = sprintf(self::CRS_URL, self::CRS_VERSION);

        @exec(sprintf('curl -fsSL --max-time 120 -o %s %s 2>&1',
              escapeshellarg($tgz), escapeshellarg($url)), $o, $c);
        if ($c !== 0 || !is_file($tgz) || filesize($tgz) < 10000) {
            return ['success' => false, 'error' => 'Could not download OWASP CRS: ' . implode(' ', $o)];
        }

        @exec(sprintf('tar -xzf %s -C %s 2>&1', escapeshellarg($tgz), escapeshellarg($dir)), $o2, $c2);
        if ($c2 !== 0) {
            return ['success' => false, 'error' => 'Could not extract CRS: ' . implode(' ', $o2)];
        }
        @unlink($tgz);

        $extracted = glob($dir . '/coreruleset-*');
        if (!$extracted) { return ['success' => false, 'error' => 'CRS archive had unexpected contents']; }
        $target = $dir . '/coreruleset';
        @exec('rm -rf ' . escapeshellarg($target));
        @rename($extracted[0], $target);

        // crs-setup.conf.example must be copied to crs-setup.conf — CRS ships
        // the example so a package upgrade cannot overwrite local edits.
        if (is_file($target . '/crs-setup.conf.example') && !is_file($target . '/crs-setup.conf')) {
            @copy($target . '/crs-setup.conf.example', $target . '/crs-setup.conf');
        }
        @file_put_contents($target . '/.crs-version', self::CRS_VERSION);
        return ['success' => true];
    }

    /** Write our include, and reference it from Apache. */
    private static function writeConfig(string $mode, ?string $crsDir): array
    {
        @mkdir(self::SG_CONF_DIR, 0750, true);
        $conf = self::SG_CONF_DIR . '/sentinel-waf.conf';

        $rules = '';
        if ($crsDir) {
            $rules = "IncludeOptional " . $crsDir . "/crs-setup.conf\n"
                   . "IncludeOptional " . $crsDir . "/rules/*.conf\n";
        }

        $body = <<<CONF
# Sentinel Gate — WAF configuration
# Generated automatically. Change the mode from the dashboard, not here:
# edits are overwritten whenever the mode is changed.

<IfModule security2_module>
    SecRuleEngine {$mode}
    SecRequestBodyAccess On
    SecResponseBodyAccess Off

    # 13 MB: large enough for ordinary uploads, bounded so a request body
    # cannot be used to exhaust memory.
    SecRequestBodyLimit 13107200
    SecRequestBodyNoFilesLimit 131072
    SecRequestBodyLimitAction Reject

    SecAuditEngine RelevantOnly
    SecAuditLogRelevantStatus "^(?:5|4(?!04))"
    SecAuditLogParts ABIJDEFHZ
    SecAuditLogType Serial
    SecAuditLog /var/log/modsec_audit.log

    SecTmpDir /tmp
    SecDataDir /tmp
    SecDebugLog /var/log/modsec_debug.log
    SecDebugLogLevel 0

    # The dashboard itself must never be filtered: a false positive would lock
    # the operator out of the tool needed to turn the WAF off.
    <LocationMatch "^/sentinel-gate">
        SecRuleEngine Off
    </LocationMatch>

{$rules}
</IfModule>
CONF;
        if (@file_put_contents($conf, $body) === false) {
            return ['success' => false, 'error' => 'Could not write ' . $conf];
        }
        @chmod($conf, 0644);

        $incDir = [
            'ea4'    => '/etc/apache2/conf.d',
            'httpd'  => '/etc/httpd/conf.d',
            'debian' => '/etc/apache2/conf-enabled',
        ][self::apacheFlavour()] ?? null;
        if ($incDir === null || !is_dir($incDir)) {
            return ['success' => false, 'error' => 'Could not locate the Apache config directory'];
        }
        $inc = $incDir . '/zz-sentinel-gate-waf.conf';
        // zz- prefix so our settings load last and win over earlier includes.
        if (@file_put_contents($inc, "IncludeOptional {$conf}\n") === false) {
            return ['success' => false, 'error' => 'Could not write ' . $inc];
        }
        @chmod($inc, 0644);
        Database::setSetting('waf_include_path', $inc);
        return ['success' => true];
    }

    private static function disableConfig(): void
    {
        $inc = (string)Database::setting('waf_include_path', '');
        if ($inc !== '' && is_file($inc)) { @unlink($inc); }
    }

    /** Change enforcement mode: on | detectiononly | off. */
    public static function setMode(string $mode): array
    {
        $map = ['on' => 'On', 'detectiononly' => 'DetectionOnly', 'off' => 'Off'];
        $m = $map[strtolower($mode)] ?? null;
        if ($m === null) { return ['success' => false, 'error' => 'Invalid mode']; }

        $r = self::writeConfig($m, self::crsPath());
        if (!$r['success']) { return $r; }

        $v = self::validateApache();
        if (!$v['ok']) {
            return ['success' => false, 'error' => 'Apache rejected the change: ' . $v['output']];
        }
        self::reloadApache();
        Database::setSetting('waf_mode', strtolower($mode));
        Logger::info('WAF mode set to ' . $m);
        return ['success' => true, 'mode' => strtolower($mode)];
    }

    /** Syntax check only — never reloads. */
    public static function validateApache(): array
    {
        foreach (['/usr/sbin/apachectl', '/usr/sbin/httpd', 'apachectl', 'apache2ctl'] as $bin) {
            @exec(escapeshellarg($bin) . ' -t 2>&1', $o, $c);
            if (!empty($o)) {
                return ['ok' => $c === 0, 'output' => implode("\n", array_slice($o, -5))];
            }
            $o = [];
        }
        // No validator available: report it rather than claiming success.
        return ['ok' => false, 'output' => 'Could not run an Apache syntax check'];
    }

    private static function reloadApache(): void
    {
        foreach (['/scripts/restartsrv_httpd', '/usr/sbin/apachectl graceful',
                  '/usr/sbin/apache2ctl graceful', 'systemctl reload httpd',
                  'systemctl reload apache2'] as $cmd) {
            @exec($cmd . ' 2>&1', $o, $c);
            if ($c === 0) { return; }
            $o = [];
        }
    }

    /** Remove everything we installed. Used by the uninstaller. */
    public static function remove(): void
    {
        self::disableConfig();
        @unlink(self::SG_CONF_DIR . '/sentinel-waf.conf');
        self::reloadApache();
    }
}
