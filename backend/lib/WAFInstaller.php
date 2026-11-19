<?php

/* Pulls in what it calls, rather than trusting the caller to have done it.
 * UserReport did not, and `serverscrub user-reports` died with
 * Class "UserScanRequest" not found on all 132 accounts -- silently,
 * because writeAll() catches Throwable per account. require_once is
 * idempotent and safe across the cycles these classes form. */
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';
// Rendered into the config writeConfig() generates. Requires only
// Database and Logger, so no cycle.
require_once __DIR__ . '/WAFExclusions.php';

/**
 * ServerScrub — ModSecurity + OWASP CRS provisioning
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
    /**
     * Command runner, replaceable by tests.
     *
     * Every write path in this class ends in a shell command against nft,
     * iptables, csf or apachectl. None of those exist on a development machine,
     * so none of this code could be executed before it reached a customer's
     * server -- which is exactly how the write paths came to be the last
     * untested part of the product. Injecting the runner makes the decision
     * logic testable without pretending the tools are present.
     *
     * @var (callable(string):array{out:string,code:int})|null
     */
    private static $runner = null;

    /** @param (callable(string):array{out:string,code:int})|null $runner */
    public static function setRunner(?callable $runner): void
    {
        self::$runner = $runner;
    }

    /** Run a command through the injected runner when one is set. */
    private static function sh(string $cmd): array
    {
        if (self::$runner !== null) {
            return (self::$runner)($cmd);
        }
        $out = [];
        $code = 0;
        @exec($cmd . ' 2>&1', $out, $code);
        return ['out' => implode("\n", $out), 'code' => $code];
    }

    const CRS_VERSION = '4.7.0';
    const CRS_URL     = 'https://github.com/coreruleset/coreruleset/archive/refs/tags/v%s.tar.gz';
    const SG_CONF_DIR = '/etc/serverscrub/waf';

    /**
     * Where our WAF config is written. Overridable so the write paths can be
     * exercised without writing into /etc on a developer's machine — the reason
     * these paths had never been run before reaching a customer.
     */
    private static ?string $confDir = null;

    /**
     * Where the Apache include is dropped. Overridable for the same reason as
     * confDir(): the write path is otherwise unreachable without a real Apache.
     */
    private static ?string $includeDir = null;

    /**
     * Where the OWASP CRS tree is, when it is not where crsPath() would look.
     *
     * Same reason as confDir() and includeDir(): without it, the only code
     * path that reads real rule files could not be pointed at a tree a test
     * controls.
     */
    private static ?string $crsPathOverride = null;

    public static function setCrsPath(?string $dir): void { self::$crsPathOverride = $dir; }

    public static function setConfDir(?string $dir): void { self::$confDir = $dir; }
    public static function setIncludeDir(?string $dir): void { self::$includeDir = $dir; }
    public static function confDir(): string { return self::$confDir ?? self::SG_CONF_DIR; }

    // ── Status ───────────────────────────────────────────────────────────────

    public static function status(): array
    {
        $modsec = self::modsecPresent();
        $crs    = self::crsPath();
        // Our config file is only read by Apache if the include that points at
        // it exists. currentMode() parses the config and knows nothing about
        // that, so a mode of "on" with the include gone is a blocking WAF
        // filtering exactly no requests -- which install()'s failure path
        // produces, because disableConfig() unlinks the include and leaves the
        // config. Reported so the panel can qualify the mode instead of
        // claiming protection the server is not delivering.
        $inc = self::includePath();

        /* WHAT IS ACTUALLY LOADED, not what is merely present.
         *
         * crs_installed was `crsPath() !== null`, which tests only that a
         * DIRECTORY exists. An empty CRS tree -- the state f1844fb existed to
         * clean up -- therefore read as installed, `ready` became true, and
         * the panel asserted "ModSecurity is installed and logging matches"
         * with nothing on the server to match against. That is the same shape
         * as setMode() reporting success for a config Apache had rejected,
         * which took 132 accounts down for two minutes on 7 Nov: a protection
         * claim with nothing behind it.
         *
         * A rule engine with no rules is not a rule engine. The claim this
         * card makes now follows from the rule FILES. */
        $ruleFiles   = $crs !== null ? self::crsRuleFileCount($crs) : 0;
        $rulesLoaded = $ruleFiles > 0;
        $ready       = $modsec && $rulesLoaded;

        return [
            'modsecurity_installed' => $modsec,
            'modsecurity_version'   => $modsec ? self::modsecVersion() : null,
            'crs_installed'         => $crs !== null && $rulesLoaded,
            'crs_tree_present'      => $crs !== null,
            'crs_rule_files'        => $ruleFiles,
            'rules_loaded'          => $rulesLoaded,
            'ready'                 => $ready,
            'claim'                 => self::engineClaim(
                                           $modsec, $crs, $ruleFiles,
                                           self::currentMode(),
                                           is_file(self::confDir() . '/serverscrub-waf.conf'),
                                           $inc !== null && is_file($inc)),
            'crs_path'              => $crs,
            'crs_version'           => $crs ? self::crsVersion($crs) : null,
            'mode'                  => self::currentMode(),
            'apache'                => self::apacheFlavour(),
            'package_manager'       => self::pkgManager(),
            'can_install'           => self::pkgManager() !== null,
            'managed_by_us'         => is_file(self::confDir() . '/serverscrub-waf.conf'),
            'include_path'          => $inc,
            'include_present'       => $inc !== null && is_file($inc),
            'validator'             => self::validatorBinary(),
        ];
    }

    /**
     * How many RULE files a CRS tree holds.
     *
     * crs-setup.conf is configuration, not rules: a tree holding only that
     * file blocks and detects exactly nothing, and it was reading as a working
     * ruleset. Two single-directory reads, no recursion -- a CRS release holds
     * around thirty files in rules/, and this runs on every panel load.
     */
    public static function crsRuleFileCount(?string $dir): int
    {
        if ($dir === null || $dir === '' || !is_dir($dir)) { return 0; }
        $n = 0;
        foreach ([$dir . '/rules/*.conf', $dir . '/*.conf'] as $glob) {
            $hits = glob($glob);
            if (!is_array($hits)) { continue; }
            foreach ($hits as $f) {
                $base = basename($f);
                // Setup and the operator's own exclusion stubs are not rules.
                if (strcasecmp($base, 'crs-setup.conf') === 0) { continue; }
                if (!is_file($f) || filesize($f) === 0) { continue; }
                $n++;
            }
        }
        return $n;
    }

    /**
     * The sentence the panel shows, composed here rather than in the browser.
     *
     * It was assembled in app.js from `modsecurity_installed && crs_installed`
     * and nothing else, so it could not take account of a tree with no rules
     * in it, and it ignored include_present entirely -- a mode of "on" with
     * our include gone is a blocking WAF filtering no requests, which is
     * exactly what install()'s failure path leaves behind. In PHP it is one
     * sentence, in one place, that a test can hold to the evidence.
     */
    public static function engineClaim(bool $modsec, ?string $crs, int $ruleFiles,
                                       string $mode, bool $managedByUs,
                                       bool $includePresent): string
    {
        if (!$modsec) {
            return 'No web application firewall engine is active on this '
                 . 'server. ServerScrub can install and configure ModSecurity '
                 . 'with the OWASP Core Rule Set.';
        }
        if ($crs === null) {
            return 'ModSecurity is installed but no OWASP Core Rule Set was '
                 . 'found, so no rule can match and nothing is being '
                 . 'inspected.';
        }
        if ($ruleFiles === 0) {
            return 'ModSecurity is installed and a rule set directory exists ('
                 . $crs . ') but it holds NO RULE FILES, so nothing is being '
                 . 'inspected, nothing is being logged and nothing is being '
                 . 'blocked. This is not protection.';
        }
        if ($managedByUs && !$includePresent) {
            return 'ModSecurity is installed with ' . $ruleFiles . ' rule file(s), '
                 . 'but our configuration is NOT included by Apache, so the mode '
                 . 'shown is not in force and no request is being filtered. '
                 . 'Re-apply the mode to write the include.';
        }
        if ($mode === 'on') {
            return 'ModSecurity is enforcing the OWASP Core Rule Set ('
                 . $ruleFiles . ' rule file(s)).';
        }
        if ($mode === 'detectiononly') {
            return 'ModSecurity is logging matches against ' . $ruleFiles
                 . ' rule file(s) and is not blocking them yet.';
        }
        if ($mode === 'off') {
            return 'ModSecurity is installed with ' . $ruleFiles . ' rule '
                 . 'file(s), and the rule engine is OFF: nothing is being '
                 . 'inspected.';
        }
        // currentMode() could not read a mode. That is not "detection only".
        return 'ModSecurity is installed with ' . $ruleFiles . ' rule file(s), '
             . 'but the rule engine mode could not be read from its '
             . 'configuration, so what it is doing with them is unknown.';
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
        /* rpm's EXIT CODE, and a shape check on what it printed.
         *
         * `rpm -q` prints "package ea-apache24-mod_security2 is not installed"
         * on STDOUT and exits 1. `2>/dev/null` redirects the wrong stream, the
         * exit code was never looked at, and that sentence was returned as the
         * version -- so the panel rendered "ModSecurity  installed package
         * ea-apache24-mod_security2 is not installed" as a version field. Any
         * command whose stdout is passed through as a value needs its exit
         * code checked and its output shaped; this one needed both. */
        $out = [];
        $rc  = 0;
        @exec('rpm -q --qf "%{VERSION}" ea-apache24-mod_security2 2>/dev/null',
              $out, $rc);
        $o = trim(implode('', $out));
        if ($rc === 0 && $o !== '' && preg_match('/^[0-9][0-9A-Za-z._-]*$/', $o)) {
            return $o;
        }
        // Present, version unknown. Saying "installed" is honest; saying rpm's
        // error message is not.
        return null;
    }

    /**
     * Where the OWASP CRS rule files are, or null when none are installed.
     *
     * Public because WAF::getRuleCategories() reports category counts read
     * from these files. It used to return a hardcoded array of sixteen
     * categories with exact rule counts and Active/Disabled flags, which
     * rendered identically on a server with CRS 4.7.0, with CRS 3.x and with
     * no CRS at all.
     */
    public static function crsPath(): ?string
    {
        /* The override wins outright, and only a tree that is really there is
         * returned -- a test that silently fell through to the system CRS
         * would be asserting against whatever the host happens to have.
         *
         * setConfDir() and setIncludeDir() exist so the write paths can be
         * exercised off /etc; this one was missing, so the category feature
         * could only be tested on a machine with NO system CRS -- and every
         * machine that resembles a cPanel server has one, at the vendor path
         * tried first below. That is the same shape as the scan_types test
         * defect, and it is why 13 assertions failed on the live-WAF image. */
        if (self::$crsPathOverride !== null) {
            return is_file(self::$crsPathOverride . '/crs-setup.conf')
                ? self::$crsPathOverride : null;
        }
        foreach ([
            // The vendor tree first, deliberately: on a cPanel server that is
            // the one Apache loads, so it is the one whose rules are live.
            '/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/crs-setup.conf',
            '/etc/httpd/modsecurity.d/owasp-crs/crs-setup.conf',
            self::confDir() . '/coreruleset/crs-setup.conf',
        ] as $p) {
            if (is_file($p)) { return dirname($p); }
        }
        return null;
    }

    /**
     * The CRS version of the tree at $dir.
     *
     * Public because WAF::getRuleCategories() reports the version beside
     * counts read from that same tree, and its own getCRSVersion() looks at a
     * different path entirely -- so the panel could show counts from one
     * ruleset and a version from another, or "Not installed" beside 214 rules.
     */
    public static function crsVersion(string $dir): string
    {
        $f = $dir . '/crs-setup.conf';
        $body = is_readable($f) ? (string) @file_get_contents($f) : '';

        /* What CRS 4.7.0 actually writes, on one line, is
         *
         *     #    ver:'OWASP_CRS/4.7.0',\
         *
         * so "ver" comes BEFORE the name and the number follows a slash. The
         * pattern here expected the opposite order and matched nothing against
         * the real file: a tree we installed ourselves survived on the
         * .crs-version marker installCrs() writes, and any tree we did not
         * install -- cPanel's vendor OWASP3 tree, a distro package, a
         * hand-installed one -- reported "unknown", which the panel rendered
         * as the literal "vunknown".
         *
         * Both orders are tried, because the 3.x files write
         * "# OWASP_CRS ver.3.3.4" and some packagers rewrite the header. The
         * capture starts on a digit either way: `.*?([\d.]+)` used to take the
         * separator with it and read ".4.7.0". */
        foreach (['#OWASP_CRS/(\d[\d.]*)#',
                  '#OWASP_CRS.*?ver[^\d\n]*(\d[\d.]*)#i'] as $re) {
            if ($body !== '' && preg_match($re, $body, $m)) {
                return rtrim($m[1], '.');
            }
        }
        return is_file($dir . '/.crs-version')
            ? trim((string)@file_get_contents($dir . '/.crs-version'))
            : 'unknown';
    }

    public static function currentMode(): string
    {
        $f = self::confDir() . '/serverscrub-waf.conf';
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
            /* "Already present" was accepted without being read. The
             * production tree was already present AND already defined 913100
             * twice, so every install and every mode change after 6 Oct wrote
             * a config that Apache could not parse, and the installer said
             * the ruleset was fine. */
            $dups = self::duplicateRuleIds($crs);
            if ($dups) {
                $no('The OWASP CRS tree at ' . $crs . ' defines the same rule id more than once');
                return ['success' => false, 'steps' => $steps,
                        'error' => 'The OWASP CRS tree already at ' . $crs . ' is corrupt: it '
                                 . 'defines the same rule id more than once, which Apache refuses '
                                 . 'with "Found another rule with the same id" — so no config was '
                                 . 'written and nothing was reloaded. Duplicates: '
                                 . self::describeDuplicates($dups) . '. Move that directory aside '
                                 . 'and run the install again to fetch a clean copy.'];
            }
            $ok('OWASP CRS already present at ' . $crs . ' — no duplicate rule ids');
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
        $ok('Wrote ServerScrub WAF config (DetectionOnly)');

        // 4. Validate BEFORE reloading. A bad include would otherwise take
        //    Apache down on restart, and with it every site on the server.
        $v = self::validateApache();
        if (!$v['ok']) {
            self::disableConfig();
            // "Could not check" is not "checked and rejected". Saying the
            // second when the first happened sends the operator looking for a
            // syntax error that no program has ever reported.
            return ['success' => false, 'steps' => $steps,
                    'error' => ($v['ran']
                        ? 'Apache rejected the configuration, so it was removed and '
                          . 'nothing was reloaded: '
                        : 'No Apache syntax check could be run, so the configuration was '
                          . 'removed and nothing was reloaded rather than arming a WAF this '
                          . 'server cannot be asked about: ') . $v['output']];
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

    /**
     * Every ModSecurity rule id that is defined more than once in a CRS tree.
     *
     * ── WHY THIS EXISTS ──────────────────────────────────────────────────────
     *
     * On the production server /etc/serverscrub/waf/coreruleset held TWO
     * definitions of rule 913100. Apache refused the whole configuration:
     *
     *     AH00526: Syntax error on line 56 of REQUEST-913-SCANNER-DETECTION.conf
     *     ModSecurity: Found another rule with the same id
     *
     * so the WAF had not loaded once since 6 Oct while the panel reported it
     * armed. A clean re-extraction of the identical 4.7.0 tarball parsed
     * fine — the tree was the fault, not the ruleset, and installCrs()
     * extracted over whatever was already there and assumed it had worked.
     *
     * One duplicate id anywhere in the tree costs every site on the server at
     * the next Apache restart, so it is worth reading the files to find out.
     *
     * ── BOUNDS ───────────────────────────────────────────────────────────────
     *
     * Deliberately not a walk: rules/*.conf one level down plus the two setup
     * files, at most $maxFiles of them, and nothing over 4 MB is read. CRS
     * 4.7.0 is ~35 files of ~40 KB. confDir() is under /etc and this must not
     * become able to read an arbitrary tree on a 132-account box.
     *
     * Commented-out lines are stripped first: CRS ships example rules in
     * comments, and counting those would reject a perfectly good ruleset.
     *
     * @return array<string,array<int,string>> id => the files defining it
     */
    public static function duplicateRuleIds(string $dir, int $maxFiles = 400): array
    {
        $seen = self::collectRuleIds(self::crsRuleFiles($dir, $maxFiles));

        $dups = [];
        foreach ($seen as $id => $where) {
            // Counted BEFORE de-duplicating the file names: the production
            // fault was one id in two files, but the same id twice inside one
            // file is the identical error from Apache, and uniquing first
            // hides it.
            if (count($where) > 1) { $dups[(string) $id] = array_values(array_unique($where)); }
        }
        return $dups;
    }

    /**
     * The rule files in one CRS tree: exactly what the generated config
     * includes, and nothing else.
     *
     * rules/*.conf one level down plus the setup files. A leftover that does
     * not end in .conf is not loaded by Apache, so it is not a second
     * definition of anything -- reporting it would refuse an install over a
     * file Apache never reads.
     *
     * @return string[]
     */
    private static function crsRuleFiles(string $dir, int $maxFiles = 400): array
    {
        $files = glob($dir . '/rules/*.conf') ?: [];
        foreach (['crs-setup.conf', 'REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf'] as $extra) {
            if (is_file($dir . '/' . $extra)) { $files[] = $dir . '/' . $extra; }
        }
        sort($files);
        return array_slice($files, 0, $maxFiles);
    }

    /**
     * id => the files that define it, across the given files.
     *
     * Comment lines are stripped first: CRS ships example rules commented out,
     * and counting those would condemn a perfectly good ruleset. Nothing over
     * 4 MB is read, because this runs on a production box.
     *
     * @param string[] $files
     * @return array<string,array<int,string>>
     */
    private static function collectRuleIds(array $files, bool $fullPaths = false): array
    {
        $seen = [];
        foreach ($files as $f) {
            $size = @filesize($f);
            if ($size === false || $size > 4194304) { continue; }
            $body = preg_replace('/^[ \t]*#.*$/m', '', (string) @file_get_contents($f));
            if (!preg_match_all('/(?:^|[,"\s])id:[\'"]?(\d+)/m', (string) $body, $m)) { continue; }
            foreach ($m[1] as $id) {
                $seen[$id][] = $fullPaths ? $f : basename($f);
            }
        }
        return $seen;
    }

    /**
     * Where else on this host a ModSecurity ruleset might be loaded from.
     *
     * Not a search: a fixed list of the places the platforms we support put
     * one, so this cannot turn into a walk of /etc on a 132-account box. One
     * level of subdirectory under the cPanel vendor directory, because that is
     * how cPanel stores a vendor ruleset (modsec_vendor_configs/<vendor>/).
     *
     * @return string[] globs
     */
    const FOREIGN_RULE_GLOBS = [
        '/etc/apache2/conf.d/modsec_vendor_configs/*/*.conf',
        '/etc/apache2/conf.d/modsec_vendor_configs/*/rules/*.conf',
        '/etc/httpd/modsecurity.d/*.conf',
        '/etc/httpd/modsecurity.d/*/*.conf',
        '/etc/httpd/modsecurity.d/*/rules/*.conf',
        '/etc/modsecurity/*.conf',
        '/etc/apache2/modsecurity.d/*.conf',
    ];

    /**
     * Where to look for a second ModSecurity ruleset, overridable.
     *
     * The same seam as setCrsPath() and Scanner::setCpanelUsersDir(), and for
     * the same reason: four tests in a row have been written on a bare
     * developer machine and then failed on the container that is deliberately
     * shaped like a cPanel server, because the thing they assumed was absent
     * is exactly what a real server has. A test that needs "no other ruleset
     * on this host" can now say so -- setForeignRuleGlobs([]) -- instead of
     * depending on the machine it runs on.
     *
     * An empty array means look nowhere, and duplicateIdExplanation() reports
     * what it searched, so an operator still sees that nothing was searched
     * rather than that nothing was found.
     */
    private static ?array $foreignGlobs = null;

    public static function setForeignRuleGlobs(?array $globs): void
    {
        self::$foreignGlobs = $globs;
    }

    /** @return string[] */
    public static function foreignRuleGlobs(): array
    {
        return self::$foreignGlobs ?? self::FOREIGN_RULE_GLOBS;
    }

    /**
     * Rule ids that OUR tree defines and some OTHER ruleset on this host
     * defines too.
     *
     * ── WHY ──────────────────────────────────────────────────────────────────
     *
     * duplicateRuleIds() checks a tree against itself. It cannot see a second
     * CRS that Apache already loads from somewhere else, and cPanel ships a
     * vendor ruleset, so that configuration is one to expect on a customer's
     * server. Both trees are individually valid; loaded together Apache says
     *
     *     AH00526: Syntax error on line 818 of .../crs-setup.conf:
     *     ModSecurity: Found another rule with the same id
     *
     * and refuses the whole configuration -- which sends the operator looking
     * for the fault inside our tree, where there is none. This is what the
     * message needs in order to be actionable.
     *
     * The rollback is what keeps the server safe; this is only about saying
     * something true about why. It is best-effort by nature: it reads a fixed
     * list of locations, not Apache's resolved configuration, so a ruleset
     * included from somewhere unusual will not be found. Callers must say so
     * rather than implying our tree is clean when they did not look everywhere
     * -- see duplicateIdExplanation().
     *
     * @return array<string,array<int,string>> id => the foreign files defining it
     */
    public static function foreignRuleIdCollisions(string $ourDir, int $maxFiles = 600): array
    {
        $ours = self::collectRuleIds(self::crsRuleFiles($ourDir));
        if (!$ours) { return []; }

        $ourReal = realpath($ourDir);
        $confReal = realpath(self::confDir());

        $foreign = [];
        foreach (self::foreignRuleGlobs() as $glob) {
            foreach (glob($glob) ?: [] as $f) {
                $real = realpath($f);
                if ($real === false) { continue; }
                // Never count our own tree, or anything else under our own
                // config directory, as a foreign definition.
                if ($ourReal !== false && strpos($real, $ourReal) === 0) { continue; }
                if ($confReal !== false && strpos($real, $confReal) === 0) { continue; }
                $foreign[$real] = true;
                if (count($foreign) >= $maxFiles) { break 2; }
            }
        }
        if (!$foreign) { return []; }

        $theirs = self::collectRuleIds(array_keys($foreign), true);

        $clash = [];
        foreach ($theirs as $id => $where) {
            if (isset($ours[(string) $id])) {
                $clash[(string) $id] = array_values(array_unique($where));
            }
        }
        ksort($clash);
        return $clash;
    }

    /**
     * The sentence to add when Apache has refused a config for a duplicate
     * rule id. Says which other ruleset defines it, or says plainly that it
     * could not be identified and where it looked -- "could not find it" must
     * not read as "our tree is at fault".
     */
    public static function duplicateIdExplanation(?string $crsDir = null): string
    {
        $dir = $crsDir ?? self::crsPath();
        if ($dir === null) { return ''; }

        $clash = self::foreignRuleIdCollisions($dir);
        if ($clash) {
            $parts = [];
            foreach (array_slice($clash, 0, 5, true) as $id => $where) {
                $parts[] = $id . ' (also defined in ' . implode(', ', $where) . ')';
            }
            return ' ANOTHER MODSECURITY RULESET ON THIS SERVER DEFINES THE SAME RULE ID: '
                 . implode('; ', $parts)
                 . (count($clash) > 5 ? ' and ' . (count($clash) - 5) . ' more' : '')
                 . '. Each ruleset is valid on its own; Apache cannot load both, because a '
                 . 'rule id has to be unique across the whole configuration. Disable one of '
                 . 'them -- on cPanel, the vendor ruleset is switched off in WHM > '
                 . 'ModSecurity Vendors -- and set the mode again. Nothing in '
                 . $dir . ' defines an id twice.';
        }

        $dups = self::duplicateRuleIds($dir);
        if ($dups) {
            return ' The tree at ' . $dir . ' itself defines the same id more than once: '
                 . self::describeDuplicates($dups) . '.';
        }

        return ' Apache reports a duplicate rule id, and the tree at ' . $dir
             . ' defines each of its own ids exactly once, so the second definition is in a '
             . 'ruleset this check could not identify. It looked in: '
             . implode(', ', self::foreignRuleGlobs()) . '. A second OWASP CRS loaded by '
             . 'Apache is the usual cause (cPanel ships a vendor ruleset); `apachectl -t` '
             . 'names the file it was reading when it stopped.';
    }

    /** "913100 (REQUEST-913-...conf, REQUEST-913-...conf)" for each duplicate. */
    private static function describeDuplicates(array $dups): string
    {
        $parts = [];
        foreach ($dups as $id => $where) {
            $parts[] = $id . ' (' . implode(', ', $where) . ')';
        }
        return implode('; ', $parts);
    }

    /**
     * Download, stage, check, then swap the CRS tree into place.
     *
     * It used to extract straight into confDir() over whatever was there and
     * report success without looking at the result. Two things follow from
     * that, and both happened: tar MERGES over an existing tree, so a renamed
     * or removed rule file from a previous version stays behind next to the new
     * one — which is how one tree came to define 913100 twice — and a failed
     * or partial download replaced a working ruleset with a broken one.
     *
     * So: a fresh staging directory per attempt, a duplicate-id check on the
     * staged tree BEFORE it goes anywhere near Apache, an atomic rename into
     * place (replacing, never merging), the previous tree kept aside until the
     * new one is known good, and — when our config already points at the tree,
     * so a syntax check is actually a check of it — `apachectl -t` with the
     * swap undone if Apache says no.
     */
    private static function installCrs(): array
    {
        $dir = self::confDir();
        @mkdir($dir, 0750, true);
        $target = $dir . '/coreruleset';

        $stage = $dir . '/.crs-stage-' . getmypid() . '-' . substr(sha1(uniqid('', true)), 0, 8);
        if (!@mkdir($stage, 0750, true)) {
            return ['success' => false, 'error' => 'Could not create a CRS staging directory at ' . $stage];
        }
        $rmStage = static function () use ($stage) { @exec('rm -rf ' . escapeshellarg($stage)); };

        $tgz = $stage . '/crs.tar.gz';
        $url = sprintf(self::CRS_URL, self::CRS_VERSION);

        @exec(sprintf('curl -fsSL --max-time 120 -o %s %s 2>&1',
              escapeshellarg($tgz), escapeshellarg($url)), $o, $c);
        if ($c !== 0 || !is_file($tgz) || filesize($tgz) < 10000) {
            $rmStage();
            return ['success' => false, 'error' => 'Could not download OWASP CRS: ' . implode(' ', $o)];
        }

        @exec(sprintf('tar -xzf %s -C %s 2>&1', escapeshellarg($tgz), escapeshellarg($stage)), $o2, $c2);
        if ($c2 !== 0) {
            $rmStage();
            return ['success' => false, 'error' => 'Could not extract CRS: ' . implode(' ', $o2)];
        }
        @unlink($tgz);

        $extracted = glob($stage . '/coreruleset-*');
        if (!$extracted || !is_dir($extracted[0])) {
            $rmStage();
            return ['success' => false, 'error' => 'CRS archive had unexpected contents'];
        }
        $tree = $extracted[0];

        // crs-setup.conf.example must be copied to crs-setup.conf — CRS ships
        // the example so a package upgrade cannot overwrite local edits.
        if (is_file($tree . '/crs-setup.conf.example') && !is_file($tree . '/crs-setup.conf')) {
            @copy($tree . '/crs-setup.conf.example', $tree . '/crs-setup.conf');
        }
        @file_put_contents($tree . '/.crs-version', self::CRS_VERSION);

        // Does the staged tree even look like CRS? 4.7.0 ships ~35 rule files.
        $ruleFiles = glob($tree . '/rules/*.conf') ?: [];
        if (count($ruleFiles) < 10) {
            $rmStage();
            return ['success' => false,
                    'error' => 'The extracted CRS tree has only ' . count($ruleFiles)
                             . ' rule file(s), so it was not installed. Nothing was changed.'];
        }

        // The 7 Nov check. Done on the staged tree, so a corrupt extraction
        // never reaches the directory Apache reads.
        $dups = self::duplicateRuleIds($tree);
        if ($dups) {
            $rmStage();
            return ['success' => false,
                    'error' => 'The extracted CRS tree defines the same rule id more than once, '
                             . 'which Apache refuses with "Found another rule with the same id" '
                             . 'and which takes every site on this server down at its next '
                             . 'restart. It was NOT installed and nothing was changed. Duplicates: '
                             . self::describeDuplicates($dups)];
        }

        // Swap, never merge. tar extracting over a live tree is what left two
        // copies of 913100 behind.
        $old = null;
        if (is_dir($target)) {
            $old = $target . '.replaced-' . time();
            if (!@rename($target, $old)) {
                $rmStage();
                return ['success' => false,
                        'error' => 'Could not move the existing CRS tree aside to ' . $old
                                 . ', so the new one was not installed. Nothing was changed.'];
            }
        }
        if (!@rename($tree, $target)) {
            if ($old !== null) { @rename($old, $target); }
            $rmStage();
            return ['success' => false,
                    'error' => 'Could not move the new CRS tree into ' . $target
                             . '. The previous tree was put back.'];
        }
        $rmStage();

        /* If our config already includes this tree then a syntax check is a
         * check OF this tree, and it is worth the seconds it costs. During a
         * first install the config does not exist yet, so there is nothing for
         * apachectl to read it from -- install() validates after writeConfig()
         * and rolls back there. */
        if (is_file(self::confDir() . '/serverscrub-waf.conf')) {
            $v = self::validateApache();
            if ($v['ran'] && !$v['ok']) {
                /* Explained BEFORE the swap is undone, while the tree Apache
                 * objected to is still on disk to be read. A new CRS colliding
                 * with a ruleset the host already loads is the likeliest
                 * failure here -- cPanel ships a vendor ruleset -- and it is
                 * the one whose raw message points at the wrong file. */
                $extra = stripos((string) $v['output'], 'same id') !== false
                    ? self::duplicateIdExplanation($target) : '';
                @exec('rm -rf ' . escapeshellarg($target));
                if ($old !== null) { @rename($old, $target); }
                return ['success' => false,
                        'error' => 'Apache rejected the configuration with the new CRS tree, so '
                                 . 'the previous one was put back: ' . $v['output'] . $extra];
            }
        }

        if ($old !== null) { @exec('rm -rf ' . escapeshellarg($old)); }
        return ['success' => true, 'rule_files' => count($ruleFiles)];
    }

    /** Write our include, and reference it from Apache. */
    private static function writeConfig(string $mode, ?string $crsDir): array
    {
        @mkdir(self::confDir(), 0750, true);
        $conf = self::confDir() . '/serverscrub-waf.conf';

        /* Fail rather than write a config missing an exclusion. An
         * exclusion silently dropped here means a rule the operator
         * switched off is armed against a live site -- the exact
         * outcome the exclusion was added to prevent. Refusing the
         * mode change is the safe failure. */
        try {
            $excl = WAFExclusions::render();
        } catch (Throwable $e) {
            return ['success' => false,
                    'error'   => 'Could not render the WAF rule exclusions, so the '
                                 . 'config was not written: ' . $e->getMessage()];
        }

        $rules = '';
        if ($crsDir) {
            $rules = "IncludeOptional " . $crsDir . "/crs-setup.conf\n"
                   . "IncludeOptional " . $crsDir . "/rules/*.conf\n";
        }

        $body = <<<CONF
# ServerScrub — WAF configuration
# Generated automatically. Change the mode from the dashboard, not here:
# edits are overwritten whenever the mode is changed.

<IfModule security2_module>
    SecRuleEngine {$mode}
    SecRequestBodyAccess On
    SecResponseBodyAccess Off

    # Body limits. Memory is bounded by SecRequestBodyInMemoryLimit -- bodies
    # past 128 KB spool to SecTmpDir -- not by these two, so they are sized
    # for real sites, not as a memory guard.
    #  - 128 MB total: ea-nginx's own default, so the WAF is never the
    #    tighter of the two layers in front of an upload.
    #  - 10 MB without files: page builders (Elementor, Gutenberg) save a
    #    whole page as one JSON/form body. At the old 128 KB every save of a
    #    mid-sized page was rejected with a 413 (usefulblogs.com, 4.37.0).
    SecRequestBodyLimit 134217728
    SecRequestBodyNoFilesLimit 10485760
    SecRequestBodyInMemoryLimit 131072
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
    <LocationMatch "^/serverscrub">
        SecRuleEngine Off
    </LocationMatch>

{$rules}{$excl}
</IfModule>
CONF;
        if (@file_put_contents($conf, $body) === false) {
            return ['success' => false, 'error' => 'Could not write ' . $conf];
        }
        @chmod($conf, 0644);

        $inc = self::includePath();
        if ($inc === null) {
            return ['success' => false, 'error' => 'Could not locate the Apache config directory'];
        }
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

    /**
     * Where the Apache include is dropped.
     *
     * Resolved in one place because writeConfig() writes it and
     * restoreConfig() has to put it back. Returns null when there is no
     * Apache config directory to write into.
     */
    public static function includePath(): ?string
    {
        // apacheFlavour() returns null on a machine with no Apache, and using
        // null as an array offset is deprecated in PHP 8.1+ — it emitted a
        // notice on every call. Look the key up only when there is one.
        $flavour = self::apacheFlavour();
        $incDir  = self::$includeDir;
        if ($incDir === null && $flavour !== null) {
            $incDir = [
                'ea4'    => '/etc/apache2/conf.d',
                'httpd'  => '/etc/httpd/conf.d',
                'debian' => '/etc/apache2/conf-enabled',
            ][$flavour] ?? null;
        }
        if ($incDir === null || !is_dir($incDir)) { return null; }
        // zz- prefix so our settings load last and win over earlier includes.
        return $incDir . '/zz-serverscrub-waf.conf';
    }

    /**
     * The contents of both files we own, before we touch them.
     *
     * null for a file that does not exist yet, which restoreConfig() turns
     * back into "not there" rather than into an empty file — an empty
     * SecRuleEngine config and no config are not the same thing.
     *
     * @return array<string,?string> path => contents, or path => null
     */
    private static function snapshotConfig(): array
    {
        $snap = [];
        foreach ([self::confDir() . '/serverscrub-waf.conf', self::includePath()] as $p) {
            if ($p === null) { continue; }
            $snap[$p] = is_file($p) ? (string) @file_get_contents($p) : null;
        }
        return $snap;
    }

    /**
     * Put both files back exactly as snapshotConfig() found them, and report
     * whether every one of them is genuinely back.
     *
     * ── WHY THIS RETURNS A RESULT ────────────────────────────────────────────
     *
     * It used to be three unchecked statements — @file_put_contents, @chmod,
     * @unlink — and setMode() reported 'rolled_back' => true whatever they
     * did. That reaches the 7 Nov outage state through the fix for the 7 Nov
     * outage: the config Apache refuses is still on disk, the Apache include
     * still points at it, and the operator has a sentence in writing telling
     * them it was put back, so they stop looking.
     *
     * Everything that can defeat the restore happens inside the window
     * `apachectl -t` occupies, which on a 132-account box with the full CRS is
     * seconds, not milliseconds: /etc fills up, a config-management agent
     * re-asserts the file, `chattr +i` (several hardening guides apply it to
     * the Apache conf.d), or the filesystem remounts read-only after an I/O
     * error.
     *
     * So each path is checked, in this order, and none of it is assumed:
     *
     *   1. The byte count, from writeAll() rather than file_put_contents():
     *      a truncated config written and reported as a successful restore is
     *      exactly how this fails silently, and file_put_contents() answers a
     *      partial write with false and a suppressed warning, so the size of
     *      the truncation is lost. See writeAll().
     *   2. A read-back comparison, which is the check that does not depend on
     *      being right about any API's return value. Measured on a 64 KB
     *      tmpfs: a write that runs out of space LEAVES THE BYTES IT MANAGED
     *      on disk, so a caller that sees a failure and stops has still
     *      replaced a working config with half of one. The count says what the
     *      call believes it wrote; this says what the filesystem holds.
     *   3. For a file that did not exist before: unlink()'s return AND a
     *      file_exists() afterwards, because "restored" means absent, and an
     *      empty SecRuleEngine config is not the same thing as no config.
     *
     * Public because WAF::addCustomRule() writes a second file Apache loads
     * and must roll it back by the same verified mechanism. One restore
     * implementation, checked once.
     *
     * @param array<string,?string> $snap path => contents, or path => null
     * @return array{ok:bool,failed:array<int,array{path:string,reason:string}>}
     */
    public static function restoreConfig(array $snap): array
    {
        $failed = [];
        foreach ($snap as $p => $contents) {
            if ($contents === null) {
                // There was no file here before this change, so putting it
                // back means removing it.
                if (file_exists($p)) { @unlink($p); }
                clearstatcache(true, $p);
                if (file_exists($p)) {
                    $failed[] = ['path' => $p,
                                 'reason' => 'it did not exist before this change and could not be removed'];
                }
                continue;
            }

            $want = (string) $contents;
            $n = self::writeAll($p, $want);
            @chmod($p, 0644);
            clearstatcache(true, $p);

            if ($n === null) {
                $failed[] = ['path' => $p, 'reason' => 'it could not be opened for writing'];
                continue;
            }
            if ($n !== strlen($want)) {
                $failed[] = ['path' => $p, 'reason' => sprintf(
                    'only %d of its %d bytes were written, which is what a full filesystem does',
                    $n, strlen($want))];
                continue;
            }
            $back = is_file($p) ? (string) @file_get_contents($p) : null;
            if ($back !== $want) {
                $failed[] = ['path' => $p,
                             'reason' => 'what reads back from it is not what was there before this change'];
            }
        }
        return ['ok' => $failed === [], 'failed' => $failed];
    }

    /**
     * Write a file and report how many bytes of it landed.
     *
     * ── WHY NOT file_put_contents() ──────────────────────────────────────────
     *
     * Because it cannot tell a partial write from a failure. On a short write
     * it emits "Only 500 of 1080 bytes written, possibly out of free disk
     * space" and then returns FALSE -- and the warning is suppressed by the @
     * this code has to carry, so all that reaches the caller is "something
     * went wrong". That was measured, not assumed: a stream wrapper that
     * accepts half its input makes file_put_contents() return false, not a
     * count. (The widely repeated "it returns a short count" is true of
     * fwrite(), not of file_put_contents().)
     *
     * ENOSPC on /etc while rolling a WAF config back is one of the real
     * scenarios this exists for, and "only 500 of 1080 bytes were written" is
     * a different instruction to an operator than "it could not be written":
     * the first says the file on disk is now truncated and the filesystem is
     * full. fwrite() reports the count, so the count is what is reported.
     *
     * Bounded: the loop stops the moment a write makes no progress, so a
     * stream that keeps accepting zero bytes cannot spin.
     *
     * @return int|null bytes written, or null if the path could not be opened
     */
    private static function writeAll(string $path, string $data): ?int
    {
        $h = @fopen($path, 'wb');
        if ($h === false) { return null; }

        $len     = strlen($data);
        $written = 0;
        while ($written < $len) {
            $n = @fwrite($h, substr($data, $written));
            if ($n === false || $n <= 0) { break; }   // a full filesystem writes 0
            $written += $n;
        }
        @fflush($h);
        @fclose($h);
        return $written;
    }

    /**
     * Last resort when the rollback itself failed: leave Apache nothing of
     * ours that it cannot parse.
     *
     * A rejected config we cannot replace with the previous one is still a
     * config Apache will refuse at its next restart, and that is the outage.
     * No ServerScrub WAF config at all is a server with no WAF — worse than
     * the operator asked for, and infinitely better than a server that will
     * not start. So the include goes first, because removing it means Apache
     * never reads the config even if the config itself cannot be removed, and
     * it lives in a different directory from the config, so a full or
     * read-only filesystem under /etc/serverscrub does not necessarily stop
     * it.
     *
     * The mode bit is cleared first: a file that was made read-only (or whose
     * mode a hardening agent re-asserted) is ours to remove.
     *
     * @return array{ok:bool,removed:array<int,string>,left:array<int,string>}
     */
    private static function neutraliseConfig(): array
    {
        $removed = [];
        $left    = [];
        foreach ([self::includePath(), self::confDir() . '/serverscrub-waf.conf'] as $p) {
            if ($p === null) { continue; }
            if (!file_exists($p)) { $removed[] = $p; continue; }
            @chmod($p, 0644);
            if (is_dir($p)) { @rmdir($p); } else { @unlink($p); }
            clearstatcache(true, $p);
            if (file_exists($p)) { $left[] = $p; } else { $removed[] = $p; }
        }
        return ['ok' => $left === [], 'removed' => $removed, 'left' => $left];
    }

    /**
     * What to tell an operator when the rollback itself failed.
     *
     * This is the most dangerous state the server can be in, and it is worse
     * than a failed mode change: a configuration Apache will not parse is on
     * disk, Apache is still serving the config it parsed at its last start, so
     * nothing looks wrong — and the next restart, whenever that is, fails.
     * On 7 Nov that was ten hours later, cPanel gave up after three retries,
     * and nginx returned 502 for all 132 accounts.
     *
     * So it names the file and says what to do with it, now.
     *
     * @param array{ok:bool,failed:array<int,array{path:string,reason:string}>} $rb
     */
    private static function restoreFailureText(array $rb, array $neu): string
    {
        $parts = [];
        foreach ($rb['failed'] as $f) {
            $parts[] = $f['path'] . ' (' . $f['reason'] . ')';
        }
        $why = 'The previous config could NOT be put back: ' . implode('; ', $parts) . '.';

        if ($neu['ok']) {
            return $why . ' Our WAF config and its Apache include were REMOVED instead, so Apache '
                 . 'will still start — but no ServerScrub WAF is loaded and no request is being '
                 . 'filtered. Removed: ' . implode(', ', $neu['removed']) . '. Fix the cause and '
                 . 'set the mode again.';
        }

        return 'EMERGENCY: ' . $why . ' It could not be removed either, so a config Apache has '
             . 'already refused is STILL ON DISK at ' . implode(', ', $neu['left']) . '. Apache is '
             . 'running on the configuration it parsed at its last start, so nothing will look '
             . 'wrong until it is next restarted — and then it will refuse to start and take every '
             . 'site on this server with it (132 accounts, 7 Nov, ten hours after the write). Move '
             . 'that file aside BY HAND, now, before anything restarts Apache.';
    }

    /**
     * Re-write the WAF config so a change to the exclusions takes effect.
     *
     * Adding or removing a row changes nothing on its own: Apache is serving the
     * config generated at the last mode change, so the config has to be written
     * again from the exclusions as they now stand.
     *
     * ── WHY THIS IS NOT JUST setMode(currentMode()) ──────────────────────────────
     *
     * Because that is what it was, and on a server where the WAF has never been
     * armed -- which is every server, the first time an operator uses this
     * feature -- currentMode() returns the literal 'unknown', setMode('unknown')
     * misses its map lookup, and the operator got:
     *
     *     applied:               no
     *     mode:                  unknown
     *     WARNING: the exclusion is recorded but Apache was not updated: Invalid mode
     *     Run `serverscrub waf exclude apply` once that is resolved.
     *
     * "Invalid mode" about a mode they never supplied -- the CLI generated the
     * value itself -- with advice to resolve something that is not broken, and a
     * non-zero exit for a command that had done exactly what was asked. The row
     * IS saved, and it takes effect the first time the mode is set, which is the
     * opposite of what the operator was just told.
     *
     * @return array{applied:bool,configured:bool,mode:string,message:?string}
     */
    public static function reapplyConfig(): array
    {
        $mode = self::currentMode();

        if ($mode === 'unknown') {
            return ['applied' => false, 'configured' => false, 'mode' => $mode,
                    'message' => 'the WAF is not configured on this server yet, so there is '
                               . 'nothing to apply. The exclusion is saved and will be included '
                               . 'the first time the mode is set — run `serverscrub waf install`, '
                               . 'or `serverscrub waf mode detectiononly` if ModSecurity is '
                               . 'already installed.'];
        }

        $r = self::setMode($mode);
        return ['applied'    => !empty($r['success']),
                'configured' => true,
                'mode'       => $mode,
                'message'    => empty($r['success']) ? (string) ($r['error'] ?? 'unknown error') : null];
    }

    /**
     * Change enforcement mode: on | detectiononly | off.
     *
     * ── WHY THIS ROLLS BACK ───────────────────────────────────────
     *
     * This used to write the config, validate it, and on failure return an
     * error — leaving the rejected config on disk. Apache goes on serving the
     * configuration it has already parsed, so nothing looks wrong: the CLI
     * reports the failure, the operator reads it as "the mode did not change",
     * and the server keeps running.
     *
     * The next restart is what finds out. On the production server that was
     * ten hours later, and httpd refused to start:
     *
     *     AH00526: Syntax error on line 56 of .../REQUEST-913-SCANNER-DETECTION.conf
     *     ModSecurity: Found another rule with the same id
     *
     * cPanel retried three times, rebuilt httpd.conf, gave up. Every site on
     * the server returned 502 from nginx until the include was moved aside by
     * hand. 132 accounts, down, because a failed mode change left a file
     * behind.
     *
     * So a config Apache will not accept never survives this call.
     *
     * ── WHY NO SYNTAX CHECKER MEANS NO MODE CHANGE ───────────────────────────
     *
     * validateApache() has three outcomes, not two, and the one that was
     * missing is "could not check". With no apachectl on the box the old code
     * returned ok=false and this method rendered it as "Apache rejected the
     * change" — a verdict attributed to a program that was never executed,
     * sending the operator to look for a syntax error that does not exist.
     *
     * The deliberate decision: with no checker, the mode is NOT changed and
     * nothing is written. The alternative is to write an unvalidated
     * ModSecurity config to a server we cannot ask about it, and that is the
     * precise shape of the 7 Nov outage — it stays invisible until the next
     * restart, which is the worst possible time to find out. A host with no
     * apachectl also has no Apache, and therefore no ModSecurity for this
     * config to configure, so refusing costs nothing real. The check is made
     * BEFORE the write, so the config file is never touched at all in that
     * case and there is no window to roll back.
     */
    public static function setMode(string $mode): array
    {
        $map = ['on' => 'On', 'detectiononly' => 'DetectionOnly', 'off' => 'Off'];
        $m = $map[strtolower($mode)] ?? null;
        if ($m === null) { return ['success' => false, 'error' => 'Invalid mode']; }

        /* Cheap capability question: is there a binary to check WITH? It does
         * not run `-t`, which is seconds against the full CRS. Asked before
         * the write so that on a host with no Apache tools the config file is
         * never touched and there is no window at all.
         *
         * Skipped when a runner is injected, because then the caller is
         * supplying Apache's answers and the filesystem has nothing to say
         * about what that host has. The post-write branch below is the real
         * safety net and is what the suite exercises. */
        if (self::$runner === null && self::validatorBinary() === null) {
            return ['success' => false, 'applied' => false, 'rolled_back' => false,
                    'error' => self::NO_CHECKER_ERR];
        }

        $snap = self::snapshotConfig();

        $r = self::writeConfig($m, self::crsPath());
        if (!$r['success']) {
            // writeConfig() writes the config first and the include second, so
            // a part-way failure can leave the config replaced and the include
            // missing. Roll back — and report it when the rollback fails too.
            $rb = self::restoreConfig($snap);
            $r['rolled_back'] = $rb['ok'];
            if (!$rb['ok']) {
                $neu = self::neutraliseConfig();
                $r['neutralised'] = $neu['ok'];
                $r['error'] = $r['error'] . ' | ' . self::restoreFailureText($rb, $neu);
                Logger::error('WAF config write failed and the rollback failed: ' . $r['error']);
            }
            return $r;
        }

        $v = self::validateApache();
        if (!$v['ok']) {
            // Nothing is reloaded, and the config comes back off the disk.
            $rb = self::restoreConfig($snap);
            return self::rejected($v, $rb);
        }

        self::reloadApache();
        Database::setSetting('waf_mode', strtolower($mode));
        Logger::info('WAF mode set to ' . $m);
        return ['success' => true, 'mode' => strtolower($mode)];
    }

    /**
     * The answer when the config we wrote did not survive validation.
     *
     * Split out of setMode() so the shape of the answer -- and the words in
     * it -- is in one place: which of the three things happened (Apache said
     * no / nothing could ask Apache / the rollback itself failed) is the only
     * thing an operator has to go on at 3am.
     */
    private static function rejected(array $v, array $rb): array
    {
        /* The verdict is reported as what it is. A checker that ran and said
         * no gives Apache's words, which is the only thing that tells the
         * operator what to fix. A checker that could not be run gives no
         * verdict at all, and attributing one to Apache sends them looking for
         * a syntax error that no program has ever reported. */
        $why = $v['ran']
            ? 'Apache rejected the change'
            : 'no Apache syntax check could be run, so the change was not applied';

        /* "Found another rule with the same id" is the one Apache message an
         * operator cannot act on as it stands: it names the file it was
         * reading, which is usually ours, when the second definition is in a
         * different ruleset entirely. So this says which one, or says plainly
         * that it could not tell. */
        $explain = ($v['ran'] && stripos((string) $v['output'], 'same id') !== false)
            ? self::duplicateIdExplanation()
            : '';

        if (!$rb['ok']) {
            /* Deliberately does NOT contain the words "rolled back": nothing
             * was. It does not speculate about a pre-existing fault either,
             * which is what the old message did -- this call is what left the
             * file there, and sending the operator after an older problem
             * costs the one thing they do not have. */
            $neu  = self::neutraliseConfig();
            $text = self::restoreFailureText($rb, $neu);
            Logger::error('WAF mode change failed AND the rollback failed: ' . $text);
            return ['success' => false, 'rolled_back' => false, 'restored_ok' => false,
                    'neutralised' => $neu['ok'], 'left_on_disk' => $neu['left'],
                    'error' => $why . ': ' . $v['output'] . $explain . ' | ' . $text];
        }

        /* The explanation goes AFTER Apache's output, not inside $why. Spliced
         * into the clause it produced "…defines an id twice., so it was rolled
         * back:" -- a stray ".," in the middle of the one sentence an operator
         * reads at 3am. */
        $err = $why . ', so it was rolled back: ' . $v['output'] . $explain;

        // Validate AGAIN. If what we put back is also broken, the operator has
        // to learn that now rather than at the next reboot -- the whole point
        // of this rollback is that nobody discovers a bad config hours later.
        // Only meaningful because the restore above is confirmed: otherwise
        // this would blame a pre-existing fault for a file this call left behind.
        $after = self::validateApache();
        if ($after['ran'] && !$after['ok']) {
            $err .= ' | WARNING: the restored config does not validate either,'
                  . ' so Apache may already have been unable to restart before'
                  . ' this change: ' . $after['output'];
        }
        /* Read off the restore result, not written as a literal true, even
         * here where the branch above has already established it. A literal
         * is how 'rolled_back' => true came to be returned whatever the
         * restore did, and the next person to add a branch would copy it. */
        return ['success' => false, 'error' => $err, 'rolled_back' => $rb['ok'],
                'restored_ok' => $rb['ok'],
                'restored_validates' => $after['ran'] ? (bool) $after['ok'] : null];
    }

    /** @var string[] Candidates, in the order they are tried. */
    const VALIDATOR_BINS = [
        '/usr/sbin/apachectl', '/usr/sbin/httpd', '/usr/sbin/apache2ctl',
        'apachectl', 'apache2ctl', 'httpd',
    ];

    /** What an operator is told when nothing on the host can check a config. */
    const NO_CHECKER_ERR =
        'No Apache syntax checker was found on this server (looked for apachectl, apache2ctl '
        . 'and httpd), so the WAF mode was NOT changed and no config was written. Apache has '
        . 'said nothing about this configuration either way - this is not a rejection. '
        . 'Install the Apache tools so the config can be checked before it goes live.';

    /**
     * The first Apache binary on this host that can run a syntax check, or
     * null when there is none.
     *
     * Existence is asked of the filesystem, never inferred from output. The
     * old loop returned on the first candidate that printed ANYTHING, and
     * sh() folds stderr into out, so an absent binary's "No such file or
     * directory" counted as a verdict from Apache and every candidate after
     * the first was unreachable. On a Debian or Ubuntu host - which
     * includePath() claims to support - /usr/sbin/apachectl does not exist,
     * so apache2ctl was never reached and a WAF mode could never be set at
     * all, while the operator was told Apache had rejected their config.
     */
    private static function validatorBinary(): ?string
    {
        /* Memoised: status() reports it on every panel load and the bare-name
         * candidates cost a fork each. */
        static $cached = false;
        if ($cached !== false) { return $cached; }

        $found = null;
        foreach (self::VALIDATOR_BINS as $bin) {
            if (strpos($bin, '/') === 0) {
                if (is_file($bin) && is_executable($bin)) { $found = $bin; break; }
                continue;
            }
            $r = self::sh('command -v ' . escapeshellarg($bin));
            if ($r['code'] === 0 && trim($r['out']) !== '') { $found = $bin; break; }
        }
        return $cached = $found;
    }

    /**
     * Syntax check only - never reloads.
     *
     * Three outcomes, because "could not check" and "checked and rejected"
     * are different facts, and conflating them put words in Apache's mouth:
     *
     *   ran=true,  ok=true    Apache parsed the configuration and accepted it.
     *   ran=true,  ok=false   Apache parsed it and REJECTED it. $output is
     *                         Apache's own words, which is the only thing
     *                         that tells an operator what to fix.
     *   ran=false, ok=false   No syntax checker could be run. NOTHING may be
     *                         claimed on Apache's behalf, including failure.
     *
     * Every candidate is tried. A candidate that cannot be executed -
     * exit 127, or a shell "not found" on its output - is skipped rather than
     * believed, which is what made apache2ctl unreachable before.
     *
     * @return array{ok:bool,ran:bool,binary:?string,output:string}
     */
    public static function validateApache(): array
    {
        $absent = [];
        foreach (self::VALIDATOR_BINS as $bin) {
            $r   = self::sh(escapeshellarg($bin) . ' -t');
            $out = trim($r['out']);

            // 127 is the shell's own "command not found", and the message is
            // checked too because sh() folds stderr into out and some shells
            // exit 1 on it.
            if ($r['code'] === 127
                || preg_match('/(No such file or directory|command not found|not found$)/i', $out)) {
                $absent[] = $bin;
                continue;
            }

            return ['ok' => $r['code'] === 0, 'ran' => true, 'binary' => $bin,
                    'output' => $out === ''
                        ? ($r['code'] === 0
                            ? 'Syntax OK'
                            : $bin . ' -t exited ' . $r['code'] . ' without saying why')
                        : implode("
", array_slice(explode("
", $out), -5))];
        }

        return ['ok' => false, 'ran' => false, 'binary' => null,
                'output' => 'Could not run an Apache syntax check: none of '
                          . implode(', ', $absent) . ' could be run on this server'];
    }

    /**
     * Ask Apache to re-read its configuration, and say whether anything
     * actually did.
     *
     * It used to return void, so every caller assumed it had worked. A rule
     * that is on disk but not loaded is not protecting anything, and reporting
     * that as an applied change is the same false claim in a quieter place.
     * Public so WAF::addCustomRule() reloads the same way, having validated
     * the same way, rather than firing its own unchecked `service httpd
     * graceful`.
     */
    public static function reloadApache(): bool
    {
        foreach (['/scripts/restartsrv_httpd', '/usr/sbin/apachectl graceful',
                  '/usr/sbin/apache2ctl graceful', 'systemctl reload httpd',
                  'systemctl reload apache2'] as $cmd) {
            $r = self::sh($cmd);
            if ($r['code'] === 0) { return true; }
        }
        Logger::warn('Could not reload Apache: no reload command on this host succeeded');
        return false;
    }

    /** Remove everything we installed. Used by the uninstaller. */
    public static function remove(): void
    {
        self::disableConfig();
        @unlink(self::confDir() . '/serverscrub-waf.conf');
        self::reloadApache();
    }
}
