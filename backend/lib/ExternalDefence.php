<?php
/**
 * What the OTHER defences on this server are already doing.
 *
 * WHY
 * ---
 * A cPanel box normally runs two brute-force defences before this product is
 * installed: CSF's lfd, and cPanel's own cPHulk. When ServerScrub reported
 * "Not blocked" against an address, that was true of ServerScrub and often
 * false of the server — lfd had usually dropped the address minutes earlier.
 *
 * Reporting our own inaction while another tool is doing the work makes this
 * module look useless and, worse, invites an operator to go and "fix" a
 * problem that does not exist.
 *
 * It also explains the refusals. `csf -d` fails for specific, knowable
 * reasons, and every one of them is readable from CSF's own files:
 *
 *   - the address is already in csf.deny   (nothing to do)
 *   - the address is in csf.allow          (CSF will never deny it)
 *   - CSF is in TESTING mode               (rules are written and then flushed
 *                                           by the cron that reverts TESTING)
 *
 * EVERYTHING HERE IS READ-ONLY AND BOUNDED. It runs on a shared host that is
 * usually already under load when somebody opens this page: files are read
 * with a byte cap, logs are tailed rather than parsed whole, and nothing here
 * shells out per offender.
 */

declare(strict_types=1);

class ExternalDefence
{
    /** Most of csf.deny / csf.allow we will read. Big enough for a real deny
     *  list, small enough that a runaway file cannot be loaded into memory. */
    private const MAX_LIST_BYTES = 2097152;   // 2 MB

    /** How much of lfd.log to look at. The reason we want is always recent. */
    private const MAX_LOG_BYTES  = 262144;    // 256 KB

    /** @var array<string,mixed>|null */
    private static $csfCache = null;

    // ── CSF ─────────────────────────────────────────────────────────────────

    /**
     * CSF's own state: installed, running, and critically whether it is in
     * TESTING mode.
     *
     * TESTING="1" is the single most common reason a block "works" and then
     * stops working: csf writes the rule, and a cron job flushes the whole
     * ruleset every few minutes until TESTING is turned off. A panel that
     * cannot see that will report success and protect nothing.
     *
     * @return array{installed:bool,path:?string,testing:bool,
     *               deny_count:int,allow_count:int,conf_readable:bool}
     */
    public static function csf(): array
    {
        if (self::$csfCache !== null) { return self::$csfCache; }

        require_once __DIR__ . '/FirewallEngine.php';
        $path = FirewallEngine::csfPath();
        $out  = [
            'installed'     => $path !== null && is_dir('/etc/csf'),
            'path'          => $path,
            'testing'       => false,
            'deny_count'    => 0,
            'allow_count'   => 0,
            'conf_readable' => false,
        ];

        if ($out['installed']) {
            $conf = self::head('/etc/csf/csf.conf', self::MAX_LIST_BYTES);
            if ($conf !== null) {
                $out['conf_readable'] = true;
                // TESTING = "1" with any spacing or quoting.
                $out['testing'] = (bool) preg_match('/^\s*TESTING\s*=\s*"?1"?/mi', $conf);
            }
            $out['deny_count']  = count(self::listEntries('/etc/csf/csf.deny'));
            $out['allow_count'] = count(self::listEntries('/etc/csf/csf.allow'));
        }

        self::$csfCache = $out;
        return $out;
    }

    /** For tests, and for a long-running process that must not cache forever. */
    public static function resetCache(): void
    {
        self::$csfCache = null;
    }

    /**
     * ip => comment, from csf.deny or csf.allow.
     *
     * Parsed once and matched in PHP rather than running `csf -g` per address:
     * twenty offenders would be twenty forks of a Perl script on a box that is
     * already busy, and the file is the same answer.
     *
     * @return array<string,string>
     */
    public static function listEntries(string $file): array
    {
        $raw = self::head($file, self::MAX_LIST_BYTES);
        if ($raw === null) { return []; }

        $out = [];
        foreach (explode("\n", $raw) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') { continue; }
            // "1.2.3.4 # lfd: (sshd) Failed SSH login ..."  or a bare address,
            // or a CIDR, or "tcp|in|d=22|s=1.2.3.4" advanced syntax.
            $comment = '';
            $hash = strpos($line, '#');
            if ($hash !== false) {
                $comment = trim(substr($line, $hash + 1));
                $line    = trim(substr($line, 0, $hash));
            }
            if ($line === '') { continue; }
            // Take the first thing that looks like an address, so the advanced
            // syntax above still yields 1.2.3.4 rather than being skipped.
            if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3})(?:\/\d{1,2})?|([0-9a-f:]{3,}:[0-9a-f:]*)/i',
                           $line, $m)) {
                $ip = $m[1] !== '' ? $m[1] : ($m[2] ?? '');
                if ($ip !== '') { $out[$ip] = $comment; }
            }
        }
        return $out;
    }

    /**
     * Why lfd acted on an address, in its own words.
     *
     * Tailed, never read whole: lfd.log on a server under attack is large, and
     * the line we want is by definition recent.
     */
    public static function lfdReason(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) { return ''; }
        foreach (['/var/log/lfd.log', '/var/log/lfd_log'] as $f) {
            $tail = self::tail($f, self::MAX_LOG_BYTES);
            if ($tail === null) { continue; }
            $found = '';
            foreach (explode("\n", $tail) as $line) {
                if (strpos($line, $ip) !== false) { $found = trim($line); }
            }
            if ($found !== '') { return mb_substr($found, 0, 240); }
        }
        return '';
    }

    // ── cPHulk ──────────────────────────────────────────────────────────────

    /**
     * cPanel's own brute-force daemon.
     *
     * Read from its config file rather than through whmapi1: shelling out to
     * the WHM API on every page load is slow, and this only needs to know
     * whether the thing is switched on so the panel can stop claiming to be
     * the only defence.
     *
     * @return array{installed:bool,enabled:?bool}
     */
    public static function cphulk(): array
    {
        $conf = '/var/cpanel/hulkd/conf';
        if (!@is_file($conf)) {
            return ['installed' => is_dir('/var/cpanel/hulkd'), 'enabled' => null];
        }
        $raw = self::head($conf, 262144);
        if ($raw === null) {
            // Present but unreadable. NULL, not false: "we could not tell" and
            // "it is off" are different, and only one of them is reassuring.
            return ['installed' => true, 'enabled' => null];
        }
        $j = json_decode($raw, true);
        if (is_array($j) && array_key_exists('is_enabled', $j)) {
            return ['installed' => true, 'enabled' => (bool) $j['is_enabled']];
        }
        if (preg_match('/"?is_enabled"?\s*[:=]\s*"?([01])"?/', $raw, $m)) {
            return ['installed' => true, 'enabled' => $m[1] === '1'];
        }
        return ['installed' => true, 'enabled' => null];
    }

    // ── Reconciliation ──────────────────────────────────────────────────────

    /**
     * Who, if anyone, is already acting on these addresses.
     *
     * Takes the whole list so the deny and allow files are read ONCE per
     * request rather than once per address.
     *
     * @param string[] $ips
     * @return array<string,array{denied_by:?string,allowed_by:?string,note:string}>
     */
    public static function reconcile(array $ips): array
    {
        $csf = self::csf();
        $out = [];
        foreach ($ips as $ip) {
            $out[(string) $ip] = ['denied_by' => null, 'allowed_by' => null, 'note' => ''];
        }
        if (!$csf['installed'] || !$ips) { return $out; }

        $deny  = self::listEntries('/etc/csf/csf.deny');
        $allow = self::listEntries('/etc/csf/csf.allow');

        foreach ($out as $ip => &$row) {
            if (isset($allow[$ip])) {
                // This is why our block is refused, every time, for ever.
                $row['allowed_by'] = 'csf';
                $row['note'] = trim($allow[$ip]) !== ''
                    ? 'in csf.allow: ' . $allow[$ip]
                    : 'in csf.allow';
                continue;
            }
            if (isset($deny[$ip])) {
                $row['denied_by'] = (stripos($deny[$ip], 'lfd') !== false) ? 'lfd' : 'csf';
                $row['note'] = trim($deny[$ip]) !== '' ? $deny[$ip] : 'in csf.deny';
            }
        }
        unset($row);
        return $out;
    }

    /**
     * A sentence explaining a refused block, using CSF's own state.
     *
     * Returns '' when we have nothing better to say than the caller already
     * does — an empty string is honest, a guess is not.
     */
    public static function explainRefusal(string $ip): string
    {
        $csf = self::csf();
        if (!$csf['installed']) { return ''; }

        $r = self::reconcile([$ip])[$ip] ?? null;
        if ($r && $r['allowed_by'] === 'csf') {
            return 'CSF will never deny this address because it is in '
                 . 'csf.allow — remove it there first.';
        }
        if ($r && $r['denied_by'] !== null) {
            return 'CSF is already blocking this address, so there was nothing '
                 . 'for us to add.';
        }
        if ($csf['testing']) {
            return 'CSF is in TESTING mode (TESTING="1" in csf.conf). Rules are '
                 . 'written and then flushed automatically, so no block will '
                 . 'hold until testing is turned off.';
        }
        return '';
    }

    // ── Bounded file reads ──────────────────────────────────────────────────

    /** First $max bytes, or null. */
    private static function head(string $file, int $max): ?string
    {
        if (!@is_file($file) || !@is_readable($file)) { return null; }
        $fh = @fopen($file, 'rb');
        if ($fh === false) { return null; }
        $data = @fread($fh, $max);
        @fclose($fh);
        return $data === false ? null : $data;
    }

    /** Last $max bytes, or null. Never loads a large log whole. */
    private static function tail(string $file, int $max): ?string
    {
        if (!@is_file($file) || !@is_readable($file)) { return null; }
        $size = @filesize($file);
        if ($size === false) { return null; }
        $fh = @fopen($file, 'rb');
        if ($fh === false) { return null; }
        if ($size > $max) { @fseek($fh, $size - $max); }
        $data = @stream_get_contents($fh);
        @fclose($fh);
        return $data === false ? null : $data;
    }
}
