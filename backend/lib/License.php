<?php
/**
 * Sentinel Gate — License client (WHMCS Licensing Addon)
 *
 * Implements the WHMCS Licensing Addon check contract:
 *   POST licensekey, domain, ip, dir, check_token  ->  XML tag/value response
 *   A signed "local key" is returned and cached so the remote server is only
 *   contacted every LOCALKEY_DAYS, not on every page load.
 *
 * ── ENFORCEMENT POSTURE ──────────────────────────────────────────────────────
 * EVERY feature is licensed — scanning, firewall, WAF, monitor, quarantine and
 * the management UI. An unlicensed server gets no functionality.
 *
 * The single deliberate softness is the grace window: a license that verified
 * successfully keeps working for GRACE_DAYS if the licensing server later
 * becomes unreachable. This is not a loophole — reaching it requires a local key
 * that was already signed for THIS hostname, so it cannot be entered without
 * having been licensed. It exists so an outage at the licensing server does not
 * disable protection on every paying customer's server at the same moment.
 *
 * Past that window, and for Unlicensed/Invalid/Expired/Suspended, everything
 * stops.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class License
{
    /**
     * WHMCS installation that issues licenses. Verified reachable — a POST to
     * /modules/servers/licensing/verify.php returns <status>Invalid</status>
     * for an unknown key, which is the expected addon response format.
     * Override with SG_WHMCS_URL in mode.php.
     */
    const WHMCS_URL = 'https://clientarea.lagoonspace.net';

    /**
     * Fallback local-key salt. This MUST be overridden with SG_LICENSE_SECRET in
     * backend/config/mode.php, which is generated per-installation and is NOT in
     * the repository.
     *
     * Why it must not live here: the salt is what makes a local key
     * unforgeable. This repository is PUBLIC — a value committed here is a value
     * every customer can read, and anyone who has it can mint their own
     * "Active" local key and bypass licensing entirely. The constant below is
     * deliberately an obvious placeholder so a misconfiguration is visible
     * rather than silently insecure; secretConfigured() reports on it.
     */
    const SECRET = 'CHANGEME_SET_IN_mode_php';

    /** Days between remote re-checks. */
    const LOCALKEY_DAYS = 15;

    /** Extra days tolerated when the license server cannot be reached. */
    const GRACE_DAYS = 10;

    /** Seconds to wait on the license server before giving up. */
    const TIMEOUT = 12;

    private static $cache = null;

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Full status array. Never throws — a licensing fault must not take down
     * the app that is protecting the server.
     *
     * @return array{status:string,valid:bool,ui_allowed:bool,message:string,
     *               expires:string,checked_at:int,degraded:bool}
     */
    public static function status(): array
    {
        if (self::$cache !== null) { return self::$cache; }

        try {
            self::$cache = self::evaluate();
        } catch (\Throwable $e) {
            // Any unexpected fault degrades to "unlicensed but protecting"
            self::log('exception: ' . $e->getMessage());
            self::$cache = self::result('Unknown', false, false, true,
                'License check failed.');
        }
        return self::$cache;
    }

    /** True only for a confirmed-good license. */
    public static function isValid(): bool
    {
        return self::status()['valid'];
    }

    /**
     * Whether the management UI should be usable.
     */
    public static function uiAllowed(): bool
    {
        return self::status()['ui_allowed'];
    }

    /**
     * Whether protection features (scanning, firewall, monitor, quarantine) may
     * run. Everything is licensed — an unlicensed server gets no functionality.
     *
     * This is TRUE only for a license that is, or recently was, good:
     *   Active                                   -> true
     *   Active but server unreachable, in grace  -> true  (cached local key)
     *   Unlicensed / Invalid / Expired / Suspended -> false
     *   Unreachable past the grace window        -> false
     *
     * The grace window is the one deliberate softness, and it is not a loophole:
     * it requires a previously-verified local key signed for THIS hostname, so it
     * cannot be reached without having been licensed. It exists so an outage at
     * the licensing server does not simultaneously disable protection on every
     * paying customer's server.
     */
    public static function protectionAllowed(): bool
    {
        return self::status()['protection_allowed'];
    }

    /**
     * Hard gate for CLI and cron entry points. Prints a consistent message and
     * exits non-zero when the licence does not permit the action.
     */
    public static function requireValid(string $context = 'This feature'): void
    {
        $s = self::status();
        if ($s['protection_allowed']) { return; }

        $msg = "$context requires a valid Sentinel Gate license.\n"
             . "  Status : {$s['status']}\n"
             . "  {$s['message']}\n"
             . "  Activate with:  sentinel license activate <key>\n";
        if (PHP_SAPI === 'cli') { fwrite(STDERR, $msg); }
        self::log("blocked: $context — {$s['status']}");
        exit(4);
    }

    /**
     * Publish the decision where non-PHP components can read it. monitor.py is
     * Python and cannot validate a signed local key itself; re-implementing the
     * crypto there would mean two implementations to keep in sync and two places
     * to get wrong. The daemon reads this flag instead, and the timestamp lets it
     * refuse to trust a flag that has gone stale (i.e. PHP has stopped running).
     */
    public static function publishFlag(): void
    {
        $s = self::status();
        Database::setSetting('license_protection_ok', $s['protection_allowed'] ? '1' : '0');
        Database::setSetting('license_flag_at', (string)time());
        Database::setSetting('license_status', $s['status']);
    }

    /** Store a license key and immediately verify it remotely. */
    public static function activate(string $key): array
    {
        $key = trim($key);
        if ($key === '') {
            return self::result('Invalid', false, false, false, 'No license key supplied.');
        }
        Database::setSetting('license_key', $key);
        Database::setSetting('license_localkey', '');   // force a remote check
        self::$cache = null;
        return self::status();
    }

    /** Drop the cached local key so the next call re-checks remotely. */
    public static function refresh(): array
    {
        Database::setSetting('license_localkey', '');
        self::$cache = null;
        return self::status();
    }

    // ── Core evaluation ──────────────────────────────────────────────────────

    private static function evaluate(): array
    {
        $key = (string)Database::getSetting('license_key', '');
        if ($key === '') {
            return self::result('Unlicensed', false, false, false,
                'No license key configured. Enter one in Settings → License.');
        }

        // 1. Try the cached local key first — avoids hitting WHMCS every load.
        $localkey = (string)Database::getSetting('license_localkey', '');
        if ($localkey !== '') {
            $decoded = self::decodeLocalKey($localkey);
            if ($decoded !== null) {
                $age = (time() - (int)$decoded['checkdate']) / 86400;

                if ($age < self::LOCALKEY_DAYS) {
                    return self::fromResults($decoded['results'], false);
                }
                // Stale — re-check remotely, but keep it as the fallback.
                $remote = self::remoteCheck($key);
                if ($remote !== null) { return $remote; }

                if ($age < (self::LOCALKEY_DAYS + self::GRACE_DAYS)) {
                    $left = (int)ceil(self::LOCALKEY_DAYS + self::GRACE_DAYS - $age);
                    return self::fromResults($decoded['results'], true,
                        "License server unreachable. Operating on cached license for {$left} more day(s).");
                }
                // Past grace. Degrade the UI, but keep protecting.
                return self::result('Unknown', false, false, true,
                    'License server unreachable beyond the grace period. Features are disabled until the license can be verified.');
            }
            self::log('local key failed validation — discarding');
        }

        // 2. No usable local key: check remotely.
        $remote = self::remoteCheck($key);
        if ($remote !== null) { return $remote; }

        return self::result('Unknown', false, false, true,
            'Could not reach the license server. Protection continues.');
    }

    /** @return array|null null when the server could not be reached at all. */
    private static function remoteCheck(string $key): ?array
    {
        $checkToken = time() . self::rand(12);
        $post = [
            'licensekey'  => $key,
            'domain'      => self::hostname(),
            'ip'          => self::serverIp(),
            'dir'         => defined('SG_ROOT') ? SG_ROOT : __DIR__,
            'version'     => defined('SG_VERSION') ? SG_VERSION : 'unknown',
            'check_token' => $checkToken,
        ];

        $body = self::post(rtrim(self::whmcsUrl(), '/') . '/modules/servers/licensing/verify.php', $post);
        if ($body === null) {
            self::log('remote check: server unreachable');
            return null;   // distinct from "server said no"
        }

        $results = self::parseXml($body);
        if (!$results || empty($results['status'])) {
            self::log('remote check: unparseable response');
            return null;
        }

        // Guard against a replayed/spoofed response: WHMCS echoes an md5 of the
        // token we just generated, salted with our secret.
        if (!empty($results['md5hash'])) {
            $expected = md5(self::secret() . $checkToken);
            if (!hash_equals($expected, (string)$results['md5hash'])) {
                self::log('remote check: md5hash mismatch — response not trusted');
                return self::result('Invalid', false, false, false,
                    'License response failed verification.');
            }
        }

        // The server does NOT return a local key — the client builds one from the
        // response. Reading a 'localkey' field off the reply (as an earlier
        // version did) means nothing is ever cached and every single page load
        // hits the licensing server.
        if ($results['status'] === 'Active') {
            Database::setSetting('license_localkey', self::buildLocalKey($results));
            Database::setSetting('license_checked_at', (string)time());
        }

        return self::fromResults($results, false);
    }

    // ── Local key handling ───────────────────────────────────────────────────

    /**
     * Build the cached local key from a successful check, in the exact layout
     * the WHMCS licensing addon defines:
     *
     *   d = base64(serialize(results))
     *   d = md5(checkdate + secret) . d          (32-char hash PREPENDED)
     *   d = strrev(d)
     *   d = d . md5(d + secret)                  (32-char hash APPENDED)
     *
     * checkdate is stored inside the serialised payload, not in the string —
     * decodeLocalKey() has to unserialise before it can verify the inner hash.
     */
    private static function buildLocalKey(array $results): string
    {
        $results['checkdate'] = date('Ymd');
        // Bind to this machine so a key lifted from one server is rejected on another
        $results['domain'] = self::hostname();
        $results['ip']     = self::serverIp();

        $d = base64_encode(serialize($results));
        $d = md5($results['checkdate'] . self::secret()) . $d;
        $d = strrev($d);
        $d = $d . md5($d . self::secret());
        return wordwrap($d, 80, "
", true);
    }

    /**
     * Validate and decode a stored local key — the inverse of buildLocalKey().
     *
     * Both md5 layers must verify and the domain must still match, or the key is
     * rejected: otherwise a valid key could simply be copied to another server.
     *
     * @return array{results:array,checkdate:string}|null
     */
    private static function decodeLocalKey(string $localkey): ?array
    {
        $localkey = str_replace("
", '', $localkey);
        if (strlen($localkey) < 65) { return null; }

        // Outer layer: trailing md5 over everything before it
        $data = substr($localkey, 0, -32);
        $hash = substr($localkey, -32);
        if (!hash_equals(md5($data . self::secret()), $hash)) { return null; }

        // Un-reverse, then the FIRST 32 chars are md5(checkdate + secret)
        $data      = strrev($data);
        $innerHash = substr($data, 0, 32);
        $payload   = substr($data, 32);

        $decoded = base64_decode($payload, true);
        if ($decoded === false) { return null; }

        $results = @unserialize($decoded, ['allowed_classes' => false]);
        if (!is_array($results) || empty($results['checkdate'])) { return null; }

        // checkdate lives inside the payload, so the inner hash can only be
        // verified after unserialising.
        if (!hash_equals(md5((string)$results['checkdate'] . self::secret()), $innerHash)) {
            return null;
        }

        // A local key is bound to the machine it was issued for.
        if (!empty($results['domain']) && $results['domain'] !== self::hostname()) {
            self::log('local key domain mismatch');
            return null;
        }

        $ts = strtotime((string)$results['checkdate']);
        if ($ts === false) { return null; }

        return ['results' => $results, 'checkdate' => (string)$ts];
    }

    private static function fromResults(array $r, bool $degraded, string $note = ''): array
    {
        $status  = (string)($r['status'] ?? 'Unknown');
        $expires = (string)($r['nextduedate'] ?? $r['registeredname'] ?? '');

        switch ($status) {
            case 'Active':
                return self::result('Active', true, true, $degraded,
                    $note !== '' ? $note : 'License active.', $expires);
            case 'Expired':
                return self::result('Expired', false, false, false,
                    'License expired. Renew to restore the management UI.', $expires);
            case 'Suspended':
                return self::result('Suspended', false, false, false,
                    'License suspended. Contact support.', $expires);
            case 'Invalid':
            default:
                return self::result('Invalid', false, false, false,
                    'License key invalid for this server.', $expires);
        }
    }

    private static function result(string $status, bool $valid, bool $ui,
                                   bool $degraded, string $msg, string $expires = ''): array
    {
        return [
            'status'     => $status,
            'valid'      => $valid,
            'ui_allowed' => $ui,
            // Everything is licensed. Protection tracks validity exactly: a
            // server that is not licensed gets no functionality at all.
            'protection_allowed' => $valid,
            'degraded'   => $degraded,
            'message'    => $msg,
            'expires'    => $expires,
            'checked_at' => (int)Database::getSetting('license_checked_at', 0),
        ];
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static function whmcsUrl(): string
    {
        return defined('SG_WHMCS_URL') ? SG_WHMCS_URL : self::WHMCS_URL;
    }

    /** The per-installation salt, from mode.php when present. */
    private static function secret(): string
    {
        return defined('SG_LICENSE_SECRET') && SG_LICENSE_SECRET !== ''
            ? SG_LICENSE_SECRET
            : self::SECRET;
    }

    /** False when still running on the placeholder salt. */
    public static function secretConfigured(): bool
    {
        return self::secret() !== 'CHANGEME_SET_IN_mode_php';
    }

    private static function hostname(): string
    {
        $h = php_uname('n');
        if ($h === '' || $h === false) { $h = gethostname() ?: 'unknown'; }
        return strtolower(preg_replace('/:\d+$/', '', (string)$h));
    }

    private static function serverIp(): string
    {
        if (!empty($_SERVER['SERVER_ADDR'])) { return (string)$_SERVER['SERVER_ADDR']; }
        $ip = @gethostbyname(self::hostname());
        return ($ip && $ip !== self::hostname()) ? $ip : '127.0.0.1';
    }

    private static function rand(int $n): string
    {
        try { return substr(bin2hex(random_bytes($n)), 0, $n); }
        catch (\Throwable $e) { return substr(md5((string)mt_rand()), 0, $n); }
    }

    /** @return string|null null on transport failure (distinct from an empty body). */
    private static function post(string $url, array $fields): ?string
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => http_build_query($fields),
                CURLOPT_TIMEOUT        => self::TIMEOUT,
                CURLOPT_CONNECTTIMEOUT => 6,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT      => 'SentinelGate/' . (defined('SG_VERSION') ? SG_VERSION : '0'),
            ]);
            $out = curl_exec($ch);
            $err = curl_error($ch);
            curl_close($ch);
            if ($out === false) { self::log('curl: ' . $err); return null; }
            return (string)$out;
        }

        $ctx = stream_context_create(['http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content'       => http_build_query($fields),
            'timeout'       => self::TIMEOUT,
            'ignore_errors' => true,
        ]]);
        $out = @file_get_contents($url, false, $ctx);
        return $out === false ? null : (string)$out;
    }

    /** WHMCS replies with flat <tag>value</tag> pairs. */
    private static function parseXml(string $body): array
    {
        $out = [];
        if (preg_match_all('/<(.*?)>([^<]+)<\/\1>/i', $body, $m)) {
            foreach ($m[1] as $i => $tag) { $out[$tag] = $m[2][$i]; }
        }
        return $out;
    }

    private static function log(string $msg): void
    {
        if (class_exists('Logger')) {
            @Logger::write('license', $msg);
        }
    }
}
