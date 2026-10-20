<?php
/**
 * ServerScrub — third-party security stack
 *
 * WHAT THIS IS FOR
 * ----------------
 * ServerScrub leans on four external tools where a mature one already exists:
 * ClamAV, ModSecurity, rkhunter/chkrootkit and CSF. The product works without
 * any of them — it ships its own pattern/heuristic scanner, its own rootkit
 * engine and its own nftables/iptables firewall — but each one is better than
 * the fallback where it is present.
 *
 * This class answers one question honestly: what is actually installed, where
 * did it come from, and what is degraded without it.
 *
 * WHERE THESE COME FROM, AND WHY NEVER BY DOWNLOAD
 * ------------------------------------------------
 * Every one of these is installed through the OS package manager. That is a
 * deliberate decision, not convenience:
 *
 *   1. A tarball fetched at install time is PINNED FOREVER. The server's own
 *      `dnf update` does not know it exists, so it never gets patched again.
 *      The package manager IS the patch channel. Downloading to "always have
 *      the latest" achieves the exact opposite.
 *
 *   2. ModSecurity must match Apache's ABI. On EasyApache 4 the module has to
 *      be the one cPanel compiled against its own Apache
 *      (`ea-apache24-mod_security2`). A generic binary, or a source build
 *      against the wrong headers, means httpd will not start — which on a
 *      shared host is every site down at once.
 *
 *   3. CSF's upstream is GONE. Way to the Web Ltd ceased operations on
 *      2025-08-31 and download.configserver.com no longer resolves. CSF's
 *      updater runs AS ROOT, so hardcoding a fetch from an expired domain
 *      would mean that whoever re-registers it owns every server we installed
 *      on. cPanel now maintains a fork, published as the `cpanel-csf` package
 *      and sourced at github.com/cpanel/cpanel-csf. Their README is explicit
 *      that the RPM is for cPanel & WHM only and fails elsewhere.
 *
 *   4. Licensing. CSF and ClamAV are GPL. Installing them as separate OS
 *      packages is aggregation and carries no obligation onto this product.
 *      Vendoring either into our own archive would. FirewallEngine.php is a
 *      clean-room implementation for the same reason.
 *
 * READ-ONLY. Nothing here installs anything. install.sh does the installing,
 * because package management belongs in the installer where the operator can
 * see it and decline it.
 */

class Dependencies
{
    /** The dead vendor. Checked for, never contacted. */
    public const DEAD_CSF_HOSTS = ['download.configserver.com', 'configserver.com'];

    /** cPanel's maintained fork: an accountable vendor, signed packages. */
    public const CSF_FORK_PKG  = 'cpanel-csf';
    public const CSF_FORK_REPO = 'https://github.com/cpanel/cpanel-csf';

    /**
     * The community fork, for servers that are not cPanel.
     *
     * Black-HOST picked CSF up days after the GPLv3 release, maintains it
     * actively, runs CI, and crucially has NO cPanel dependency -- it supports
     * DirectAdmin and Webmin too, which cpanel-csf refuses to install
     * alongside. For a non-cPanel server it is the only maintained CSF there
     * is.
     *
     * ServerScrub does NOT install it automatically, and the reason is not
     * doubt about the project. CSF runs as root and its installer is
     * `bash <(curl -sL https://csf.black.host)` -- a pipe-to-bash from a
     * third-party domain. That is the same shape as the configserver.com
     * failure: if the domain ever lapses or is compromised, every server
     * pointed at it fetches and executes code as root. The difference is only
     * that it has not happened.
     *
     * So the choice is the operator's to make, not ours to make for them on
     * every server we touch. ServerScrub detects it, uses it as the firewall
     * backend, and does not nag about it. What it will not do is decide on an
     * operator's behalf to hand root to a third party -- that decision is
     * exactly the one a security product should leave to a human.
     *
     * The safer route, if an operator does want it, is the pinned release
     * asset rather than the one-liner: the tag is immutable and GitHub serves
     * it over TLS.
     */
    public const CSF_COMMUNITY_REPO     = 'https://github.com/Black-HOST/csf';
    public const CSF_COMMUNITY_RELEASES = 'https://github.com/Black-HOST/csf/releases';

    /**
     * The last version the original vendor ever shipped.
     *
     * Way to the Web released 15.00 and closed. So anything NEWER than this is
     * necessarily a maintained fork, which is the only local signal available
     * for telling "abandoned" apart from "community-maintained" without
     * contacting anything.
     */
    public const CSF_LAST_UPSTREAM = '15.00';

    // ── Presence ────────────────────────────────────────────────────────────

    public static function isCpanel(): bool
    {
        return is_dir('/usr/local/cpanel');
    }

    /** First of these binaries that exists, or null. */
    private static function which(array $bins): ?string
    {
        foreach ($bins as $b) {
            if ($b[0] === '/') {
                if (is_executable($b)) return $b;
                continue;
            }
            $p = trim((string)@shell_exec('command -v ' . escapeshellarg($b) . ' 2>/dev/null'));
            if ($p !== '' && is_executable($p)) return $p;
        }
        return null;
    }

    private static function rpmInstalled(string $pkg): bool
    {
        if (!self::which(['rpm'])) return false;
        @exec('rpm -q ' . escapeshellarg($pkg) . ' 2>/dev/null', $o, $rc);
        return $rc === 0;
    }

    /**
     * Everything, with a verdict on each.
     *
     * @return array<string,array<string,mixed>>
     */
    public static function status(): array
    {
        $cpanel = self::isCpanel();

        return [
            'clamav' => self::entry(
                'ClamAV',
                self::which(['clamscan', '/usr/local/cpanel/3rdparty/bin/clamscan',
                             '/opt/clamav/bin/clamscan']),
                $cpanel ? 'clamav clamav-update' : 'clamav',
                'Signature-based malware scanning.',
                'The built-in pattern and heuristic engine runs instead. It needs no '
              . 'signature database and finds things signatures cannot, but ClamAV '
              . 'adds a large curated set of known samples.',
                true
            ),

            'rkhunter' => self::entry(
                'rkhunter',
                self::which(['rkhunter']),
                'rkhunter',
                'Curated rootkit signature database.',
                'The built-in rootkit engine covers the same ground and needs no '
              . 'third-party tool.',
                true,
                'EPEL on RHEL-family hosts. The installer adds EPEL *disabled* and '
              . 'enables it for that one transaction, so it cannot take part in '
              . 'anything cPanel does later.'
            ),

            'chkrootkit' => self::entry(
                'chkrootkit',
                self::which(['chkrootkit']),
                'chkrootkit',
                'Second opinion alongside rkhunter.',
                'Optional. The built-in engine does not depend on it.',
                false,
                'EPEL, same handling as rkhunter.'
            ),

            'modsecurity' => self::entry(
                'ModSecurity',
                self::modsecPath(),
                self::modsecPackage(),
                'Web application firewall, driven by the OWASP Core Rule Set.',
                'No request filtering at the web server. Nothing else in ServerScrub '
              . 'replaces this — the scanner finds a backdoor after it is on disk; '
              . 'the WAF is what stops the request that put it there.',
                true,
                $cpanel
                    ? 'cPanel\'s own EasyApache 4 repository, which is already '
                    . 'configured on every cPanel server. It MUST be the EA4 build: '
                    . 'the module has to match the Apache that cPanel compiled, or '
                    . 'httpd will not start.'
                    : 'The distribution repository.'
            ),

            'csf' => self::csfEntry($cpanel),
        ];
    }

    private static function entry(string $name, ?string $path, string $pkg,
                                  string $what, string $without, bool $recommended,
                                  ?string $source = null): array
    {
        return [
            'name'        => $name,
            'installed'   => $path !== null,
            'path'        => $path,
            'package'     => $pkg,
            'what_for'    => $what,
            'without_it'  => $without,
            'recommended' => $recommended,
            'source'      => $source ?? 'The distribution repository.',
        ];
    }

    private static function modsecPath(): ?string
    {
        foreach (['/etc/apache2/modules/mod_security2.so',
                  '/usr/lib64/httpd/modules/mod_security2.so',
                  '/usr/lib/apache2/modules/mod_security2.so'] as $f) {
            if (is_file($f)) return $f;
        }
        return null;
    }

    public static function modsecPackage(): string
    {
        if (is_dir('/etc/apache2/conf.d') && self::isCpanel()) {
            return 'ea-apache24-mod_security2';
        }
        if (self::which(['apt-get'])) return 'libapache2-mod-security2';
        return 'mod_security';
    }

    // ── CSF, which needs its own explanation ────────────────────────────────

    private static function csfEntry(bool $cpanel): array
    {
        $path = self::which(['/usr/sbin/csf', 'csf']);
        $fork = self::rpmInstalled(self::CSF_FORK_PKG);

        $e = self::entry(
            'CSF',
            $path,
            self::CSF_FORK_PKG,
            'Firewall and the lfd login-failure daemon. ServerScrub uses CSF as its '
          . 'firewall backend when it is present, rather than managing rules itself.',
            'ServerScrub manages nftables or iptables directly through its own '
          . 'engine. Fully supported — CSF is an integration, not a prerequisite.',
            // Only worth recommending where it can actually be installed.
            $cpanel,
            $cpanel
                ? 'cPanel\'s maintained fork, package `' . self::CSF_FORK_PKG . '`, '
                . 'sourced at ' . self::CSF_FORK_REPO . '. The original vendor closed '
                . 'on 2025-08-31 and its download servers no longer exist.'
                : 'Not installed automatically here. cPanel\'s `'
                . self::CSF_FORK_PKG . '` package refuses to install when cPanel is '
                . 'not detected, and the original vendor is gone. ServerScrub uses '
                . 'its own firewall engine instead, which is fully supported. If you '
                . 'want CSF on this server, the maintained community fork is '
                . self::CSF_COMMUNITY_REPO . ' -- install it yourself from a pinned '
                . 'release at ' . self::CSF_COMMUNITY_RELEASES . ' rather than by '
                . 'piping its one-liner to a root shell. ServerScrub will detect it '
                . 'and use it as the firewall backend.'
        );

        $e['is_cpanel_fork'] = $fork;
        $e['installable']    = $cpanel;
        $e['upstream_risk']  = self::csfUpstreamRisk($path !== null, $fork);
        return $e;
    }

    /**
     * Is this CSF install still pointed at a vendor that no longer exists?
     *
     * This is a genuine finding, not pedantry. CSF's updater runs as root. The
     * company behind it closed on 2025-08-31 and download.configserver.com
     * stopped resolving. An expired domain that still receives traffic from
     * thousands of servers is worth money to somebody, and the day it is
     * re-registered, every server with AUTO_UPDATES on fetches code from it
     * and runs it as root.
     *
     * Nothing here contacts those hosts. The check is entirely local: is CSF
     * installed, is it cPanel's fork, and are automatic updates on?
     *
     * @return array{risk:bool,severity:string,what:string,action:string}|null
     */
    public static function csfUpstreamRisk(?bool $installed = null,
                                           ?bool $isFork = null): ?array
    {
        $installed = $installed ?? (self::which(['/usr/sbin/csf', 'csf']) !== null);
        if (!$installed) return null;

        $isFork = $isFork ?? self::rpmInstalled(self::CSF_FORK_PKG);
        if ($isFork) {
            return ['risk' => false, 'severity' => 'ok',
                    'what'   => 'CSF is cPanel\'s maintained fork ('
                              . self::CSF_FORK_PKG . ') and still receives updates.',
                    'action' => 'Nothing to do.'];
        }

        $conf = '/etc/csf/csf.conf';
        $auto = null;
        $ver  = null;
        if (is_readable($conf)) {
            // Bounded read: csf.conf is a few hundred lines.
            $src = (string)@file_get_contents($conf, false, null, 0, 262144);
            if (preg_match('/^\s*AUTO_UPDATES\s*=\s*"?([01])"?/m', $src, $m)) {
                $auto = $m[1] === '1';
            }
            if (preg_match('/^\s*VERSION\s*=\s*"?([0-9.]+)"?/m', $src, $m2)) {
                $ver = $m2[1];
            }
        }
        if ($ver === null && is_readable('/etc/csf/version.txt')) {
            $ver = trim((string)@file_get_contents('/etc/csf/version.txt'));
        }

        $vs = $ver !== null ? "v$ver" : 'an unknown version';

        // Newer than anything the original vendor ever shipped, so this is a
        // maintained community fork. Not flagged: an operator who deliberately
        // migrated to a maintained fork has already solved this problem, and
        // nagging them would train them to ignore the warning that matters.
        if ($ver !== null && version_compare($ver, self::CSF_LAST_UPSTREAM, '>')) {
            return [
                'risk'     => false,
                'severity' => 'ok',
                'what'     => "CSF $vs is newer than the original vendor's final "
                            . 'release (' . self::CSF_LAST_UPSTREAM . '), so this is '
                            . 'a maintained community fork.',
                'action'   => 'Nothing to do. Keep it updated from wherever you '
                            . 'installed it.',
            ];
        }

        if ($auto === true) {
            return [
                'risk'     => true,
                'severity' => 'high',
                'what'     => "CSF $vs is installed, is not cPanel's maintained fork, "
                            . 'and AUTO_UPDATES is on. Its updater runs as root and '
                            . 'its vendor closed on 2025-08-31, leaving '
                            . 'download.configserver.com unregistered. If that domain '
                            . 'is ever bought, this server would fetch and run code '
                            . 'from it as root.',
                'action'   => 'Either migrate to cPanel\'s fork — `dnf install '
                            . self::CSF_FORK_PKG . '`, or `/scripts/autorepair '
                            . 'cpanel_csf_install` — or set AUTO_UPDATES = "0" in '
                            . '/etc/csf/csf.conf and update CSF yourself.',
            ];
        }

        return [
            'risk'     => true,
            'severity' => 'medium',
            'what'     => "CSF $vs is installed and is not cPanel's maintained fork, "
                        . 'and its original vendor closed on 2025-08-31. '
                        . ($auto === false
                            ? 'AUTO_UPDATES is off, so it cannot fetch code from the '
                            . 'retired vendor — but it also receives no security fixes.'
                            : 'AUTO_UPDATES could not be read from /etc/csf/csf.conf.'),
            'action'   => 'Migrate to cPanel\'s maintained fork: `dnf install '
                        . self::CSF_FORK_PKG . '`. It keeps your existing rules and '
                        . 'configuration.',
        ];
    }

    // ── Summaries ───────────────────────────────────────────────────────────

    /**
     * What is missing that we would recommend, and can install.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function missing(): array
    {
        $out = [];
        foreach (self::status() as $key => $d) {
            if ($d['installed']) continue;
            if (!$d['recommended']) continue;
            if (isset($d['installable']) && !$d['installable']) continue;
            $d['key'] = $key;
            $out[] = $d;
        }
        return $out;
    }

    /** One line per tool, for the installer's closing summary and the CLI. */
    public static function summary(): array
    {
        $s = self::status();
        $have = $need = [];
        foreach ($s as $k => $d) {
            if ($d['installed']) { $have[] = $d['name']; } else { $need[] = $d['name']; }
        }
        $risk = $s['csf']['upstream_risk'] ?? null;

        return [
            'installed'    => $have,
            'missing'      => $need,
            'recommended_missing' => array_column(self::missing(), 'name'),
            'csf_warning'  => ($risk && !empty($risk['risk'])) ? $risk : null,
            'detail'       => $s,
        ];
    }
}
