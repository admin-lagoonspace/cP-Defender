<?php
/**
 * Sentinel Gate — built-in rootkit detection engine
 *
 * A native scanner, so rootkit detection works on a bare server with no
 * third-party tools installed. RootkitScanner previously wrapped rkhunter and
 * chkrootkit and returned "not installed" when neither was present, which meant
 * the feature was inert on exactly the machines most likely to need it.
 *
 * rkhunter is still used ON TOP of this when available — it carries a large
 * curated signature database that is worth having. This engine is the floor,
 * not a replacement.
 *
 * ── DETECTION APPROACH ───────────────────────────────────────────────────────
 * Signature lists alone age badly, so most checks here are behavioural: they
 * look for the *techniques* rootkits depend on rather than specific filenames.
 * A rootkit can rename its files; it cannot avoid hiding processes, or
 * preloading a library, without ceasing to be a rootkit.
 *
 * Every finding carries a severity and an explanation. False positives are
 * expected on some checks (a legitimate admin may add ld.so.preload), so the
 * output states what was found and why it is suspicious rather than asserting
 * compromise.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class RootkitEngine
{
    /** Paths rootkits are known to use for persistence or storage. */
    private const SUSPECT_PATHS = [
        '/dev/.lib', '/dev/.hdlc', '/dev/.udev.tdb', '/dev/.initramfs-tools',
        '/usr/share/.aPa', '/usr/lib/.fx', '/lib/.so', '/lib/.fx',
        '/etc/rc.d/init.d/.lib', '/usr/bin/.sshd', '/usr/sbin/.sshd',
        '/tmp/.ICE-unix/.X11', '/var/tmp/.X11-unix/.X0-lock',
        '/usr/local/bin/.hst', '/etc/.pwd.lock2', '/dev/shm/.x',
    ];

    /** Directories where a hidden entry is inherently suspicious. */
    private const HIDDEN_SCAN_DIRS = [
        '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/lib64',
        '/usr/lib', '/etc/init.d', '/dev',
    ];

    /** SUID binaries expected on a normal system — anything else is reported. */
    private const KNOWN_SUID = [
        'ping', 'ping6', 'su', 'sudo', 'passwd', 'chsh', 'chfn', 'newgrp',
        'gpasswd', 'mount', 'umount', 'pkexec', 'fusermount', 'fusermount3',
        'crontab', 'at', 'ssh-agent', 'expiry', 'unix_chkpwd', 'suexec',
        'sg', 'staprun', 'write', 'wall', 'screen', 'dotlockfile', 'mtr',
        'newuidmap', 'newgidmap', 'polkit-agent-helper-1', 'utempter',
    ];

    // ── Entry point ──────────────────────────────────────────────────────────

    /** @return array{findings:array,checks:int,duration:float,summary:array} */
    public static function scan(): array
    {
        $t0 = microtime(true);
        $findings = [];
        $checks = 0;

        foreach ([
            'checkPreload', 'checkSuspectPaths', 'checkHiddenFiles',
            'checkSuidBinaries', 'checkHiddenProcesses', 'checkPromiscuous',
            'checkKernelModules', 'checkPasswdIntegrity', 'checkCronPersistence',
            'checkSshdConfig', 'checkPackageIntegrity',
        ] as $check) {
            $checks++;
            try {
                foreach (self::$check() as $f) { $findings[] = $f; }
            } catch (\Throwable $e) {
                // One failing check must not abort the whole scan — a rootkit
                // that breaks a probe would otherwise suppress every later one.
                $findings[] = self::finding('scan_error', 'low',
                    "Check {$check} failed: " . $e->getMessage(),
                    'This check could not complete; its area was not inspected.');
            }
        }

        $sev = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($findings as $f) { $sev[$f['severity']] = ($sev[$f['severity']] ?? 0) + 1; }

        return [
            'findings' => $findings,
            'checks'   => $checks,
            'duration' => round(microtime(true) - $t0, 2),
            'summary'  => $sev,
            'clean'    => ($sev['critical'] + $sev['high']) === 0,
            'engine'   => 'builtin',
        ];
    }

    // ── Checks ───────────────────────────────────────────────────────────────

    /**
     * /etc/ld.so.preload forces a library into every dynamically linked
     * process. It is the single most common userland-rootkit mechanism, and is
     * empty or absent on almost every clean system.
     */
    private static function checkPreload(): array
    {
        $out = [];
        $f = '/etc/ld.so.preload';
        if (is_file($f)) {
            $c = trim((string)@file_get_contents($f));
            if ($c !== '') {
                $out[] = self::finding('ld_preload', 'critical',
                    "/etc/ld.so.preload is populated: {$c}",
                    'This forces a library into every dynamically linked process — the '
                  . 'standard userland rootkit hook. Legitimate uses exist but are rare.');
            }
        }
        // LD_PRELOAD set globally has the same effect
        foreach (['/etc/environment', '/etc/profile'] as $p) {
            if (is_readable($p) && preg_match('/^\s*(export\s+)?LD_PRELOAD=/m', (string)@file_get_contents($p))) {
                $out[] = self::finding('ld_preload_env', 'high',
                    "LD_PRELOAD is set globally in {$p}",
                    'A global LD_PRELOAD injects code into every process started from a shell.');
            }
        }
        return $out;
    }

    private static function checkSuspectPaths(): array
    {
        $out = [];
        foreach (self::SUSPECT_PATHS as $p) {
            if (file_exists($p)) {
                $out[] = self::finding('known_path', 'critical',
                    "Known rootkit path present: {$p}",
                    'This path is used by documented rootkit families and has no legitimate purpose.');
            }
        }
        return $out;
    }

    /**
     * Hidden files inside system binary directories. Normal packages never
     * install dotfiles there, so anything found is worth a look.
     */
    private static function checkHiddenFiles(): array
    {
        $out = [];
        foreach (self::HIDDEN_SCAN_DIRS as $dir) {
            if (!is_dir($dir) || !is_readable($dir)) { continue; }
            foreach ((array)@scandir($dir) as $e) {
                if ($e === '.' || $e === '..' || $e[0] !== '.') { continue; }
                // A few dotfiles are legitimate in /dev
                if ($dir === '/dev' && in_array($e, ['.udev', '.mount', '.initramfs'], true)) { continue; }
                $out[] = self::finding('hidden_file', 'high',
                    "Hidden entry in a system directory: {$dir}/{$e}",
                    'Packages do not install dotfiles into binary directories; rootkits do.');
            }
        }
        return $out;
    }

    /**
     * Unexpected SUID root binaries — the usual way a rootkit leaves itself a
     * privilege-escalation door.
     */
    private static function checkSuidBinaries(): array
    {
        $out = [];
        $dirs = '/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /tmp /var/tmp /dev/shm';
        @exec("find {$dirs} -xdev -type f -perm -4000 2>/dev/null", $lines);
        foreach ((array)$lines as $path) {
            $name = basename($path);
            if (in_array($name, self::KNOWN_SUID, true)) { continue; }
            // World-writable temp dirs should never hold a SUID binary at all
            $sev = preg_match('#^/(tmp|var/tmp|dev/shm)#', $path) ? 'critical' : 'high';
            $out[] = self::finding('suid_binary', $sev,
                "Unexpected SUID root binary: {$path}",
                'A SUID root binary outside the known set grants privilege escalation to any user.');
        }
        return $out;
    }

    /**
     * Compare /proc against ps. A process visible in /proc but hidden from ps
     * means the userland tool is lying — i.e. it has been replaced or hooked.
     * This catches a rootkit even when its files are unknown.
     */
    private static function checkHiddenProcesses(): array
    {
        $out = [];
        if (!is_dir('/proc')) { return $out; }

        $procPids = [];
        foreach ((array)@scandir('/proc') as $e) {
            if (ctype_digit($e)) { $procPids[] = (int)$e; }
        }
        @exec('ps -eo pid --no-headers 2>/dev/null', $psLines);
        $psPids = array_map('intval', array_map('trim', (array)$psLines));

        if (!$psPids) { return $out; }   // ps unavailable — inconclusive, not a finding

        $hidden = array_diff($procPids, $psPids);
        foreach ($hidden as $pid) {
            // Re-verify: the process may simply have exited between the reads.
            if (!is_dir("/proc/{$pid}")) { continue; }
            $cmd = trim((string)@file_get_contents("/proc/{$pid}/comm"));
            $out[] = self::finding('hidden_process', 'critical',
                "PID {$pid} ({$cmd}) exists in /proc but is hidden from ps",
                'ps is not reporting a running process. That indicates a replaced binary '
              . 'or a kernel module hiding it — a defining rootkit behaviour.');
        }
        return $out;
    }

    /** A promiscuous interface usually means a packet sniffer is running. */
    private static function checkPromiscuous(): array
    {
        $out = [];
        @exec('ip link show 2>/dev/null', $lines);
        foreach ((array)$lines as $l) {
            if (stripos($l, 'PROMISC') !== false && preg_match('/^\d+:\s+([^:@]+)/', $l, $m)) {
                $out[] = self::finding('promiscuous_iface', 'high',
                    'Interface in promiscuous mode: ' . trim($m[1]),
                    'Promiscuous mode captures traffic not addressed to this host — typical of a sniffer. '
                  . 'Legitimate on a monitoring bridge or with some virtualisation.');
            }
        }
        return $out;
    }

    /** Kernel modules that are loaded but absent from the on-disk module tree. */
    private static function checkKernelModules(): array
    {
        $out = [];
        if (!is_readable('/proc/modules')) { return $out; }
        $rel = trim((string)@shell_exec('uname -r'));
        foreach (explode("\n", (string)@file_get_contents('/proc/modules')) as $line) {
            $name = strtok(trim($line), ' ');
            if (!$name) { continue; }
            @exec('modinfo ' . escapeshellarg($name) . ' 2>&1', $mi, $code);
            if ($code !== 0) {
                $out[] = self::finding('orphan_module', 'critical',
                    "Loaded kernel module has no on-disk file: {$name}",
                    "modinfo cannot find {$name} under kernel {$rel}. A loaded module with no "
                  . 'backing file is characteristic of a kernel rootkit.');
            }
            $mi = [];
        }
        return $out;
    }

    /** Unexpected UID 0 accounts — a persistence method that survives file cleanup. */
    private static function checkPasswdIntegrity(): array
    {
        $out = [];
        if (!is_readable('/etc/passwd')) { return $out; }
        foreach (explode("\n", (string)@file_get_contents('/etc/passwd')) as $line) {
            $p = explode(':', $line);
            if (count($p) < 4) { continue; }
            if ((int)$p[2] === 0 && $p[0] !== 'root') {
                $out[] = self::finding('uid0_account', 'critical',
                    "Non-root account with UID 0: {$p[0]}",
                    'Any UID 0 account has full root privileges. Only "root" should have it.');
            }
            // Empty password field
            if (isset($p[1]) && $p[1] === '') {
                $out[] = self::finding('empty_password', 'high',
                    "Account with an empty password field: {$p[0]}",
                    'This account may be usable without a password.');
            }
        }
        return $out;
    }

    /** Cron entries pulling and executing remote code. */
    private static function checkCronPersistence(): array
    {
        $out = [];
        $paths = array_merge(
            glob('/etc/cron.d/*') ?: [],
            glob('/var/spool/cron/*') ?: [],
            glob('/var/spool/cron/crontabs/*') ?: [],
            ['/etc/crontab']
        );
        foreach ($paths as $f) {
            if (!is_file($f) || !is_readable($f)) { continue; }
            $c = (string)@file_get_contents($f);
            // curl|wget piped into a shell is the standard dropper pattern
            if (preg_match('#(curl|wget)[^\n|]*\|\s*(ba)?sh#i', $c, $m)) {
                $out[] = self::finding('cron_dropper', 'critical',
                    "Cron entry pipes a download into a shell: {$f}",
                    'Downloading and executing remote code on a schedule is the standard '
                  . 'persistence mechanism for cryptominers and backdoors.');
            }
            if (preg_match('#base64\s+-d|base64_decode|eval\s*\(#i', $c)) {
                $out[] = self::finding('cron_obfuscated', 'high',
                    "Cron entry contains obfuscated code: {$f}",
                    'Base64 or eval in a cron job is used to hide the payload from casual review.');
            }
        }
        return $out;
    }

    /** sshd settings that would let an intruder back in. */
    private static function checkSshdConfig(): array
    {
        $out = [];
        $f = '/etc/ssh/sshd_config';
        if (!is_readable($f)) { return $out; }
        $c = (string)@file_get_contents($f);
        if (preg_match('/^\s*PermitRootLogin\s+yes/mi', $c)) {
            $out[] = self::finding('ssh_root_login', 'medium',
                'sshd permits direct root login',
                'PermitRootLogin yes lets an attacker brute-force root directly.');
        }
        if (preg_match('/^\s*PermitEmptyPasswords\s+yes/mi', $c)) {
            $out[] = self::finding('ssh_empty_pass', 'critical',
                'sshd permits empty passwords',
                'PermitEmptyPasswords yes allows login to any account with a blank password.');
        }
        // Authorized keys in unusual locations
        if (preg_match('/^\s*AuthorizedKeysFile\s+(.+)$/mi', $c, $m)
            && strpos($m[1], '.ssh/authorized_keys') === false) {
            $out[] = self::finding('ssh_keys_path', 'high',
                'sshd reads authorized keys from a non-standard path: ' . trim($m[1]),
                'Relocating the key file is a way to hide an implanted key from review.');
        }
        return $out;
    }

    /**
     * Ask the package manager whether core binaries still match what it
     * installed. This is the strongest available check — it compares against the
     * distribution's own hashes rather than any list we ship.
     */
    private static function checkPackageIntegrity(): array
    {
        $out = [];
        $bins = ['/bin/ls', '/bin/ps', '/usr/bin/ps', '/bin/netstat', '/usr/bin/netstat',
                 '/usr/bin/top', '/bin/login', '/usr/sbin/sshd', '/bin/bash'];
        $bins = array_values(array_filter($bins, 'is_file'));
        if (!$bins) { return $out; }

        if (trim((string)@shell_exec('command -v rpm')) !== '') {
            foreach ($bins as $b) {
                @exec('rpm -Vf ' . escapeshellarg($b) . ' 2>/dev/null', $lines, $code);
                foreach ((array)$lines as $l) {
                    // Column 1 = '5' means the MD5 digest differs
                    if (preg_match('/^..5/', $l)) {
                        $out[] = self::finding('modified_binary', 'critical',
                            "System binary modified since installation: {$b}",
                            'The package manager reports a checksum mismatch. Replaced core '
                          . 'utilities (ps, ls, netstat) are how a rootkit hides itself.');
                        break;
                    }
                }
                $lines = [];
            }
        } elseif (trim((string)@shell_exec('command -v dpkg')) !== '') {
            @exec('dpkg --verify 2>/dev/null', $lines);
            foreach ((array)$lines as $l) {
                if (preg_match('/^..5.*?\s(\S+)$/', $l, $m)) {
                    $out[] = self::finding('modified_binary', 'critical',
                        "System file modified since installation: {$m[1]}",
                        'dpkg reports a checksum mismatch against the installed package.');
                }
            }
        }
        return $out;
    }

    // ── Helper ───────────────────────────────────────────────────────────────

    private static function finding(string $type, string $sev, string $what, string $why): array
    {
        return [
            'type'        => $type,
            'severity'    => $sev,
            'finding'     => $what,
            'explanation' => $why,
            'detected_at' => time(),
        ];
    }
}
