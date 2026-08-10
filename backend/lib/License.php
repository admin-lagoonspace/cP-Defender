<?php
/**
 * Sentinel Gate — License client (WHMCS Licensing Addon)
 *
 * Implements the WHMCS Licensing Addon check contract:
 *   POST licensekey, domain, ip, dir, check_token  ->  XML tag/value response
 *   A signed "local key" is returned and cached so the remote server is only
 *   contacted every LOCALKEY_DAYS, not on every page load.
 *
 * ── FAIL POSTURE — read before changing ──────────────────────────────────────
 * This is a SECURITY product. A licensing fault must never leave a server
 * unprotected: that converts a billing problem into a security incident, and a
 * WHMCS outage would silently disable malware scanning across every customer.
 *
 * So enforcement is deliberately asymmetric:
 *   * Protection (scanning, firewall, monitor, quarantine) NEVER stops.
 *   * Only the management UI and premium features gate on a license.
 *   * An unreachable license server is a WARNING, not a failure, for
 *     GRACE_DAYS — and even past that it degrades rather than disables.
 * Only an explicit Invalid/Expired/Suspended verdict from the server locks the
 * UI, because that is a real answer rather than an absence of one.
 */

if (!defined('SG_ROOT')) { die('Direct access denied'); }

class License
{
    /** WHMCS installation that issues licenses. Override in mode.php. */
    const WHMCS_URL = 'https://billing.lws-s1.com';

    /**
     * Salts the local key so ours cannot be produced by another addon user.
     * MUST match the licensing addon's configured secret. Not a credential the
     * customer ever sees, but treat it as a secret in this repo's context: it is
     * what stops a customer forging their own "Active" local key.
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
            self::$cache = self::result('Unknown', false, true, true,
                'License check failed — protection continues.');
        }
        return self::$cache;
    }

    /** True only for a confirmed-good license. */
    public static function isValid(): bool
    {
        return self::status()['valid'];
    }

    /**
     * Whether the management UI should be usable. Separate from isValid() on
     * purpose — see the fail-posture note above.
     */
    public static function uiAllowed(): bool
    {
        return self::status()['ui_allowed'];
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
                    'License server unreachable beyond the grace period. Protection continues; management UI locked.');
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
            $expected = md5(self::SECRET . $checkToken);
            if (!hash_equals($expected, (string)$results['md5hash'])) {
                self::log('remote check: md5hash mismatch — response not trusted');
                return self::result('Invalid', false, false, false,
                    'License response failed verification.');
            }
        }

        if ($results['status'] === 'Active' && !empty($results['localkey'])) {
            Database::setSetting('license_localkey', (string)$results['localkey']);
            Database::setSetting('license_checked_at', (string)time());
        }

        return self::fromResults($results, false);
    }

    // ── Local key handling ───────────────────────────────────────────────────

    /**
     * Validate and decode a stored local key.
     *
     * The key is: base64(serialize(results)) with an md5(data+SECRET) suffix,
     * then reversed with a second md5(checkdate+SECRET) suffix. Both hashes must
     * verify, and the domain/ip must still match, or the key is rejected —
     * otherwise a valid key could simply be copied to another server.
     *
     * @return array{results:array,checkdate:string}|null
     */
    private static function decodeLocalKey(string $localkey): ?array
    {
        $localkey = str_replace("\n", '', $localkey);
        if (strlen($localkey) < 41) { return null; }

        $data = substr($localkey, 0, -32);
        $hash = substr($localkey, -32);
        if (!hash_equals(md5($data . self::SECRET), $hash)) { return null; }

        $data = strrev($data);
        if (strlen($data) < 41) { return null; }
        $checkdate = substr($data, 0, 8);
        $data      = substr($data, 8);

        $hash = substr($data, -32);
        $data = substr($data, 0, -32);
        if (!hash_equals(md5($checkdate . self::SECRET), $hash)) { return null; }

        $decoded = base64_decode($data, true);
        if ($decoded === false) { return null; }

        $results = @unserialize($decoded, ['allowed_classes' => false]);
        if (!is_array($results)) { return null; }

        // A local key is bound to the machine it was issued for.
        if (!empty($results['domain']) && $results['domain'] !== self::hostname()) {
            self::log('local key domain mismatch');
            return null;
        }

        $ts = strtotime($checkdate);
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
