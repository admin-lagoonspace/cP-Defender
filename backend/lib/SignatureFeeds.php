<?php
/* Pulls in what it calls, rather than trusting the caller to have done it. */
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';
require_once __DIR__ . '/Signatures.php';

/**
 * Third-party detection databases, fetched onto this server.
 *
 * WHY, AND WHY NOT A FORK
 *
 * The only thing that updated was ClamAV's own database, weekly. ClamAV is
 * weak on exactly what matters on shared hosting -- PHP webshells dropped
 * into a customer's docroot -- so the product was running on twenty
 * hand-written regexes and whatever freshclam happened to carry.
 *
 * ClamAV already loads third-party databases natively: .ndb, .hdb, .hsb,
 * .ldb and YARA, from its own database directory. Nothing needs patching.
 * Forking it would mean owning a C codebase and losing upstream security
 * fixes to gain a feature it already has.
 *
 * REPORT-ONLY, AND WHY THAT IS NOT TIMIDITY
 *
 * These rules are written by other people for other environments. A rule
 * that is merely noisy on a workstation quarantines a working website here,
 * on 132 accounts at once, and the first anyone hears of it is a customer
 * whose site is down.
 *
 * So a feed arrives in 'report' mode: detections are recorded and shown, and
 * nothing is touched. An operator promotes a feed to 'disable' or
 * 'quarantine' once they have seen what it actually finds on THEIR server.
 * The promotion is per feed, because the feeds differ wildly in precision.
 */
class SignatureFeeds
{
    /** How much of any one feed we will take. A runaway download helps nobody. */
    private const MAX_BYTES = 33554432;   // 32 MB

    /** Setting prefix for each feed's action policy. */
    private const ACTION_KEY = 'feed_action_';

    /**
     * The feeds, in the order they are fetched.
     *
     * Both chosen for this workload specifically: Linux Malware Detect is
     * built by a hosting operator for shared hosting, and PHP-malware-finder
     * is YARA aimed squarely at webshells. Neither is a general antivirus
     * set, which is the point -- ClamAV already covers that ground badly.
     */
    public static function catalogue(): array
    {
        return [
            'lmd' => [
                'label' => 'Linux Malware Detect (rfxn)',
                'why'   => 'built by a hosting operator for shared-hosting PHP malware',
                'files' => [
                    // ClamAV-format HEX signatures and MD5 hashes.
                    'rfxn.ndb' => 'https://cdn.rfxn.com/downloads/rfxn.ndb',
                    'rfxn.hdb' => 'https://cdn.rfxn.com/downloads/rfxn.hdb',
                ],
            ],
            'pmf' => [
                'label' => 'PHP-malware-finder',
                'why'   => 'YARA rules aimed at webshells and obfuscated PHP',
                'files' => [
                    'php-malware-finder.yar' =>
                        'https://raw.githubusercontent.com/jvoisin/php-malware-finder/master/data/php.yar',
                ],
            ],
        ];
    }

    /** Where ClamAV reads its databases from on this machine. */
    public static function clamDbDir(): ?string
    {
        foreach (['/var/lib/clamav', '/usr/local/cpanel/3rdparty/share/clamav',
                  '/usr/local/share/clamav', '/usr/share/clamav'] as $d) {
            if (is_dir($d) && is_writable($d)) { return $d; }
        }
        return null;
    }

    /**
     * What a feed is allowed to do when it matches.
     *
     * Defaults to 'report' and stays there until somebody changes it. A feed
     * that silently escalated itself to deleting files would be the worst
     * possible reading of "keep the signatures up to date".
     */
    public static function action(string $feed): string
    {
        $v = (string) Database::setting(self::ACTION_KEY . $feed, 'report');
        return in_array($v, ['report', 'disable', 'quarantine'], true) ? $v : 'report';
    }

    public static function setAction(string $feed, string $action): bool
    {
        if (!in_array($action, ['report', 'disable', 'quarantine'], true)) { return false; }
        if (!isset(self::catalogue()[$feed])) { return false; }
        Database::setSetting(self::ACTION_KEY . $feed, $action);
        Logger::info('Signature feed ' . $feed . ' set to ' . $action);
        return true;
    }

    /**
     * Which feed a detection came from, by the name ClamAV reports.
     *
     * LMD names its rules rfxn.*; php-malware-finder's YARA rules are
     * compiled by ClamAV under YARA.<rule>. Anything else is ours or
     * ClamAV's own, and keeps whatever behaviour it already had.
     */
    public static function feedFor(string $threatName): ?string
    {
        $n = strtolower($threatName);
        if (strpos($n, 'rfxn') === 0 || strpos($n, 'lmd.') === 0) { return 'lmd'; }
        if (strpos($n, 'yara.') === 0 || strpos($n, 'php_malware') !== false) { return 'pmf'; }
        return null;
    }

    /**
     * True when this detection must not be acted on automatically.
     *
     * Called before anything touches a customer's file. A detection from a
     * feed still in report mode is recorded and displayed and nothing else.
     */
    public static function isReportOnly(string $threatName): bool
    {
        $feed = self::feedFor($threatName);
        return $feed !== null && self::action($feed) === 'report';
    }

    /**
     * Fetch every enabled feed into ClamAV's database directory.
     *
     * Each file is downloaded to a temp path, sanity-checked, and only then
     * renamed into place. A half-written database in that directory makes
     * every clamscan on the server fail to start, which would take the
     * scanner down rather than merely leaving it out of date.
     */
    public static function update(bool $force = false): array
    {
        $dir = self::clamDbDir();
        if ($dir === null) {
            return ['success' => false,
                    'error'   => 'no writable ClamAV database directory found'];
        }

        $results = [];
        foreach (self::catalogue() as $key => $feed) {
            if (!$force && (string) Database::setting('feed_enabled_' . $key, '1') !== '1') {
                $results[$key] = ['skipped' => 'disabled'];
                continue;
            }
            $ok = 0; $failed = 0; $bytes = 0;
            foreach ($feed['files'] as $name => $url) {
                $r = self::fetchOne($url, $dir . '/' . $name);
                if ($r['ok']) { $ok++; $bytes += $r['bytes']; }
                else { $failed++; Logger::warn('Feed ' . $key . ': ' . $r['error']); }
            }
            Database::setSetting('feed_at_' . $key, (string) time());
            $results[$key] = ['files' => $ok, 'failed' => $failed, 'bytes' => $bytes,
                              'action' => self::action($key)];
            Logger::info('Signature feed ' . $key . ': ' . $ok . ' file(s), '
                       . $bytes . ' bytes, acting in ' . self::action($key) . ' mode');
        }
        return ['success' => true, 'dir' => $dir, 'feeds' => $results];
    }

    /** One file, bounded, verified as far as its format allows, then renamed in. */
    private static function fetchOne(string $url, string $dest): array
    {
        $tmp = $dest . '.part';
        @unlink($tmp);

        $ch = curl_init($url);
        if ($ch === false) { return ['ok' => false, 'error' => 'curl unavailable', 'bytes' => 0]; }
        $fh = @fopen($tmp, 'wb');
        if ($fh === false) { return ['ok' => false, 'error' => 'cannot write ' . $tmp, 'bytes' => 0]; }

        curl_setopt_array($ch, [
            CURLOPT_FILE           => $fh,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_TIMEOUT        => 120,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_FAILONERROR    => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            // A feed that grows without bound must not fill the disk that
            // every account on this server shares.
            CURLOPT_NOPROGRESS     => false,
            CURLOPT_PROGRESSFUNCTION => static function ($r, $dl) {
                return $dl > self::MAX_BYTES ? 1 : 0;
            },
            CURLOPT_USERAGENT      => 'ServerScrub signature updater',
        ]);
        $okCurl = curl_exec($ch);
        $err    = curl_error($ch);
        curl_close($ch);
        fclose($fh);

        $size = (int) @filesize($tmp);
        if (!$okCurl || $size <= 0) {
            @unlink($tmp);
            return ['ok' => false, 'error' => ($err ?: 'empty response') . ' for ' . $url, 'bytes' => 0];
        }

        // Does it look like what we asked for? A proxy or a captive portal
        // returning an HTML error page, written into ClamAV's database
        // directory, stops clamscan starting at all.
        $head = (string) @file_get_contents($tmp, false, null, 0, 512);
        if (stripos($head, '<html') !== false || stripos($head, '<!doctype') !== false) {
            @unlink($tmp);
            return ['ok' => false, 'error' => 'got HTML, not a signature database, from ' . $url,
                    'bytes' => 0];
        }

        @chmod($tmp, 0644);
        if (!@rename($tmp, $dest)) {
            @unlink($tmp);
            return ['ok' => false, 'error' => 'cannot place ' . $dest, 'bytes' => 0];
        }
        return ['ok' => true, 'error' => '', 'bytes' => $size];
    }

    /** For the CLI and the UI. */
    public static function status(): array
    {
        $out = [];
        foreach (self::catalogue() as $key => $feed) {
            $at = (int) Database::setting('feed_at_' . $key, '0');
            $files = [];
            $dir = self::clamDbDir();
            foreach (array_keys($feed['files']) as $name) {
                $p = ($dir ?? '') . '/' . $name;
                $files[$name] = is_file($p) ? (int) @filesize($p) : 0;
            }
            $out[$key] = [
                'label'   => $feed['label'],
                'why'     => $feed['why'],
                'action'  => self::action($key),
                'enabled' => (string) Database::setting('feed_enabled_' . $key, '1') === '1',
                'updated' => $at,
                'files'   => $files,
            ];
        }
        return $out;
    }
}
