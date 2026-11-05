<?php
/* Pulls in what it calls, rather than trusting the caller to have done it. */
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Logger.php';

/**
 * Where detection patterns live, and how they survive.
 *
 * WHAT THIS REPLACES
 *
 * The PHP detection patterns were twenty regexes in Scanner's constructor.
 * They could only change by shipping a release, could not be disabled when
 * one caused a false positive on a customer's live site, and nothing could
 * add to them from a feed. The only thing that updated at all was ClamAV's
 * own database, weekly, through freshclam.
 *
 * THREE PLACES, DELIBERATELY
 *
 *   1. The DATABASE is the working set. It is queryable, a bad rule can be
 *      disabled in one statement, and a feed can add to it without a release.
 *
 *   2. A FILE beside it -- signatures.json -- is written after every
 *      successful change. If the database is lost or corrupted, the patterns
 *      are not: the file reseeds it. Asked for directly, and right: a
 *      scanner that forgets every rule it has ever learned because one SQLite
 *      file went bad is a scanner that silently stops finding things.
 *
 *   3. The BUILTIN array in this file is the floor. If the database is
 *      unreadable AND the file is missing or corrupt, scanning continues on
 *      these. There is no state in which the scanner runs with no patterns
 *      at all, because that failure looks exactly like a clean server.
 *
 * The order matters: database, then file, then builtin. Each fallback is
 * narrower than the last, and every one of them is better than zero.
 */
class Signatures
{
    /** The file the database is mirrored to, inside SIG_DIR. */
    public const EXPORT = 'signatures.json';

    /** Rules shipped in the code. The last resort, and the seed for a new install. */
    public const BUILTIN = [
        // Obfuscation
        'base64_decode_exec' => '/base64_decode\s*\(.*\)\s*;?\s*\)?\s*;?\s*eval\s*\(/i',
        'eval_base64'        => '/eval\s*\(\s*base64_decode\s*\(/i',
        'eval_gzinflate'     => '/eval\s*\(\s*gzinflate\s*\(/i',
        'eval_str_rot13'     => '/eval\s*\(\s*str_rot13\s*\(/i',
        'preg_replace_eval'  => '/preg_replace\s*\(\s*[\'"].*\/e[\'"],/i',
        'assert_base64'      => '/assert\s*\(\s*base64_decode\s*\(/i',
        'hex_decode_exec'    => '/\\\\x[0-9a-f]{2}.*eval/i',
        'gzuncompress_eval'  => '/eval\s*\(\s*gzuncompress\s*\(/i',
        // Shells
        'c99_shell'          => '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[.{0,30}\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'system_shell'       => '/\$_(?:GET|POST|REQUEST)\s*\[.{0,30}\]\s*;\s*(?:system|exec|passthru|shell_exec)/i',
        'backdoor_connect'   => '/fsockopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'stdin_exec'         => '/proc_open.*STDIN.*STDOUT.*STDERR/is',
        'reverse_shell'      => '/(?:bash|sh)\s*-i\s*>&?\s*\/dev\/tcp/i',
        // Crypto miners
        'xmrig_pattern'      => '/stratum\+tcp:\/\/|xmrig|moneropool|minergate\.com/i',
        'coin_hive'          => '/CoinHive\.Anonymous|coinhive\.min\.js/i',
        // Injections
        'spam_mailer'        => '/\$(?:to|from|subject|body|message)\s*=.*(?:@gmail|@yahoo|@hotmail).*;.*mail\s*\(/is',
        'seo_spam_hidden'    => '/<div\s+style=["\']display\s*:\s*none["\'][^>]*>.*(?:viagra|cialis|pharmacy|casino|poker)/is',
        // Encoded payloads
        'long_base64'        => '/[\'"][A-Za-z0-9+\/]{500,}={0,2}[\'"]/',
        'hex_string_long'    => '/[\'"][0-9a-f]{200,}[\'"]/i',
        'char_code_obf'      => '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)/i',
    ];

    /** Cached for the life of the process; a scan asks for these per batch. */
    private static ?array $cache = null;

    /** The mirror file's path, or null when SIG_DIR is not defined. */
    public static function exportPath(): ?string
    {
        if (!defined('SIG_DIR')) { return null; }
        return rtrim((string) SIG_DIR, '/') . '/' . self::EXPORT;
    }

    /**
     * The active regex patterns, as name => pattern.
     *
     * Database first, then the mirror file, then the builtins. Every step
     * down is logged once: a scanner quietly running on twenty hard-coded
     * rules when it should have four thousand is the failure this whole
     * class exists to make visible.
     */
    public static function activePatterns(): array
    {
        if (self::$cache !== null) { return self::$cache; }

        try {
            self::seedIfEmpty();
            $rows = Database::fetchAll(
                "SELECT name, pattern FROM signatures
                  WHERE enabled = 1 AND sig_type = 'regex'
                  ORDER BY name"
            );
            if ($rows) {
                $out = [];
                foreach ($rows as $r) { $out[(string) $r['name']] = (string) $r['pattern']; }
                return self::$cache = $out;
            }
            Logger::warn('Signatures: the database holds no enabled patterns; falling back');
        } catch (Throwable $e) {
            Logger::error('Signatures: database unusable (' . $e->getMessage()
                        . '); falling back to the mirror file');
        }

        $fromFile = self::readExport();
        if ($fromFile) {
            Logger::warn('Signatures: running from ' . self::EXPORT . ' ('
                       . count($fromFile) . ' pattern(s)), not the database');
            return self::$cache = $fromFile;
        }

        Logger::error('Signatures: no database and no usable ' . self::EXPORT
                    . ' - running on the ' . count(self::BUILTIN) . ' built-in patterns only');
        return self::$cache = self::BUILTIN;
    }

    /** Forget the cache. Used after an update, and by the tests. */
    public static function flush(): void { self::$cache = null; }

    /**
     * Put the builtins in an empty table.
     *
     * Prefers the mirror file when one exists: a server whose database was
     * rebuilt should come back with everything it had learned from feeds,
     * not just what shipped in the code.
     */
    public static function seedIfEmpty(): int
    {
        $have = (int) (Database::fetchOne('SELECT COUNT(*) AS c FROM signatures')['c'] ?? 0);
        if ($have > 0) { return 0; }

        $seed = self::readExport();
        $src  = $seed ? 'file' : 'builtin';
        if (!$seed) { $seed = self::BUILTIN; }

        $n = self::upsert($seed, $src === 'file' ? 'restored' : 'builtin');
        Logger::info('Signatures: seeded ' . $n . ' pattern(s) from the ' . $src);
        if ($src === 'builtin') { self::export(); }
        return $n;
    }

    /**
     * Add or update patterns. Returns how many rows were written.
     *
     * @param array<string,string> $patterns name => regex
     */
    public static function upsert(array $patterns, string $source = 'custom'): int
    {
        $now = time();
        $n   = 0;
        foreach ($patterns as $name => $pattern) {
            $name    = (string) $name;
            $pattern = (string) $pattern;
            if ($name === '' || $pattern === '') { continue; }

            // A pattern that does not compile would make every scan emit a
            // warning per file and match nothing. Refuse it here, once,
            // rather than in the scan loop a million times.
            if (@preg_match($pattern, '') === false) {
                Logger::warn('Signatures: refusing ' . $name . ' - it is not a valid regex');
                continue;
            }

            $exists = Database::fetchOne('SELECT id FROM signatures WHERE name = ?', [$name]);
            if ($exists) {
                Database::query(
                    'UPDATE signatures SET pattern=?, source=?, updated_at=? WHERE name=?',
                    [$pattern, $source, $now, $name]
                );
            } else {
                Database::query(
                    'INSERT INTO signatures (name, sig_type, pattern, severity, source,
                                             enabled, added_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, 1, ?, ?)',
                    [$name, 'regex', $pattern, 'high', $source, $now, $now]
                );
            }
            $n++;
        }
        if ($n) { self::flush(); }
        return $n;
    }

    /** Turn one rule off without removing it, for a false positive. */
    public static function disable(string $name): bool
    {
        Database::query('UPDATE signatures SET enabled=0, updated_at=? WHERE name=?',
                        [time(), $name]);
        self::flush();
        return true;
    }

    /**
     * Mirror the table to disk.
     *
     * Written to a temp file and renamed, so a crash mid-write cannot leave a
     * truncated mirror -- which would be worse than none, since a truncated
     * one still parses and would silently reseed a partial rule set.
     */
    public static function export(): ?string
    {
        $path = self::exportPath();
        if ($path === null) { return null; }

        try {
            $rows = Database::fetchAll(
                'SELECT name, sig_type, pattern, severity, source, enabled FROM signatures ORDER BY name'
            );
        } catch (Throwable $e) {
            Logger::warn('Signatures: cannot export - ' . $e->getMessage());
            return null;
        }
        if (!$rows) { return null; }

        $body = json_encode(
            ['version' => 1, 'exported_at' => time(), 'count' => count($rows), 'signatures' => $rows],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );
        if ($body === false) { return null; }

        @mkdir(dirname($path), 0750, true);
        $tmp = $path . '.tmp';
        if (@file_put_contents($tmp, $body) === false) {
            Logger::warn('Signatures: cannot write ' . $tmp);
            return null;
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $path)) { @unlink($tmp); return null; }
        return $path;
    }

    /**
     * Read the mirror back, as name => pattern.
     *
     * Only enabled regex rules, and only ones that still compile: a mirror
     * is restored precisely when something has already gone wrong, so it is
     * the last place to take anything on trust.
     */
    public static function readExport(): array
    {
        $path = self::exportPath();
        if ($path === null || !is_file($path) || is_link($path)) { return []; }

        $raw = @file_get_contents($path);
        if ($raw === false) { return []; }
        $data = json_decode($raw, true);
        if (!is_array($data) || empty($data['signatures']) || !is_array($data['signatures'])) {
            return [];
        }

        $out = [];
        foreach ($data['signatures'] as $r) {
            if (!is_array($r)) { continue; }
            if ((int) ($r['enabled'] ?? 1) !== 1) { continue; }
            if ((string) ($r['sig_type'] ?? 'regex') !== 'regex') { continue; }
            $name    = (string) ($r['name'] ?? '');
            $pattern = (string) ($r['pattern'] ?? '');
            if ($name === '' || $pattern === '') { continue; }
            if (@preg_match($pattern, '') === false) { continue; }
            $out[$name] = $pattern;
        }
        return $out;
    }

    /** Counts for the UI and the CLI. */
    public static function stats(): array
    {
        try {
            $total   = (int) (Database::fetchOne('SELECT COUNT(*) AS c FROM signatures')['c'] ?? 0);
            $enabled = (int) (Database::fetchOne('SELECT COUNT(*) AS c FROM signatures WHERE enabled=1')['c'] ?? 0);
            $bySrc   = Database::fetchAll(
                'SELECT source, COUNT(*) AS c FROM signatures GROUP BY source ORDER BY c DESC');
        } catch (Throwable $e) {
            return ['total' => 0, 'enabled' => 0, 'by_source' => [], 'error' => $e->getMessage()];
        }
        $path = self::exportPath();
        return [
            'total'      => $total,
            'enabled'    => $enabled,
            'by_source'  => $bySrc,
            'mirror'     => $path,
            'mirror_at'  => ($path && is_file($path)) ? (int) @filemtime($path) : 0,
            'builtin'    => count(self::BUILTIN),
        ];
    }
}
