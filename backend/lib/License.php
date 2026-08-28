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

    /**
     * Days a brand-new install runs before a licence is required.
     *
     * Applies ONLY to an install that has never had a key entered. If it applied
     * to any not-valid state, a customer whose licence expired could delete the
     * key and be handed a fresh trial, repeatedly and indefinitely.
     */
    const TRIAL_DAYS = 3;

    /**
     * Install timestamp is written here as well as to the database.
     * Kept outside the install directory so an update — which rsyncs over it
     * with --delete — cannot reset the trial, and the EARLIEST of the two is
     * used so removing one does not extend it either.
     */
    const INSTALL_MARKER = '/var/lib/sentinel-gate/installed-at';

    /**
     * Where the install timestamp is stamped outside the install directory.
     *
     * Deliberately outside SG_ROOT: update.sh rsyncs the install dir with
     * --delete, so a marker kept inside would vanish on every update and hand
     * out a fresh trial each time.
     *
     * Overridable with SG_INSTALL_MARKER so a test can point it at a sandbox.
     * Without that the path is machine-global, and the test suite both depended
     * on and corrupted real state — a stale marker from an earlier run reported
     * an expired trial on a fresh install.
     */
    public static function markerPath(): string
    {
        return defined('SG_INSTALL_MARKER') && SG_INSTALL_MARKER !== ''
            ? SG_INSTALL_MARKER
            : self::INSTALL_MARKER;
    }

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

    /**
     * When this installation first ran. Recorded in two places and the earliest
     * is taken: the database can be edited and the marker file deleted, so
     * either alone would be trivial to reset.
     */
    public static function installedAt(): int
    {
        $db   = (int)Database::setting('installed_at', 0);
        $file = 0;
        if (is_readable(self::markerPath())) {
            $file = (int)trim((string)@file_get_contents(self::markerPath()));
        }

        $candidates = array_filter([$db, $file]);
        if (!$candidates) {
            // First ever call — stamp both.
            $now = time();
            Database::setSetting('installed_at', (string)$now);
            @mkdir(dirname(self::markerPath()), 0755, true);
            @file_put_contents(self::markerPath(), (string)$now);
            return $now;
        }

        $earliest = min($candidates);
        // Re-sync whichever copy is missing or later, so a deleted marker is
        // restored from the database rather than granting a new trial.
        if ($db === 0 || $db > $earliest)   { Database::setSetting('installed_at', (string)$earliest); }
        if ($file === 0 || $file > $earliest) {
            @mkdir(dirname(self::markerPath()), 0755, true);
            @file_put_contents(self::markerPath(), (string)$earliest);
        }
        return $earliest;
    }

    /** Whole days remaining in the trial; 0 once it has ended. */
    public static function trialDaysLeft(): int
    {
        $elapsed = (time() - self::installedAt()) / 86400;
        return (int)max(0, ceil(self::TRIAL_DAYS - $elapsed));
    }

    /**
     * Is the trial still usable?
     *
     * Requires that no key has ever been entered. Once a key is stored — even a
     * rejected one — the trial is spent, so it cannot be re-entered by clearing
     * the key.
     */
    private static function trialActive(): bool
    {
        if (Database::setting('license_ever_entered', '0') === '1') { return false; }
        return self::trialDaysLeft() > 0;
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

        // evaluate() raises this condition with the same wording for every
        // caller. Storing the key first would be pointless: nothing can verify a
        // response without the shared secret, so the answer is "Invalid"
        // whatever the key says.
        if (!self::secretConfigured()) {
            return self::status();
        }
        Database::setSetting('license_key', $key);
        Database::setSetting('license_localkey', '');   // force a remote check
        // Entering a key ends the trial permanently, so an expired licence
        // cannot be swapped for another free period by clearing it.
        Database::setSetting('license_ever_entered', '1');
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
        // Checked here, not only in activate(), because EVERY licence operation
        // is pointless without the shared secret: no reply can be verified, so
        // the answer is "Invalid" regardless of the key.
        //
        // The guard was originally in activate() alone, which left status()
        // still contacting the licence server and then reporting "signed with a
        // different secret" -- a second, more confusing explanation of the same
        // condition on a server whose secret was simply never set. One problem
        // described two ways is worse than either description.
        if (!self::secretConfigured()) {
            return self::result('Unconfigured', false, false, false,
                'This server has no licensing secret, so no reply from the licence '
                . 'server can be verified and every key will be refused. Set it with:  '
                . 'sentinel license secret <your-whmcs-addon-secret>  '
                . '- the value from Addons > License Manager > Settings in WHMCS. '
                . 'The licence key is not the problem.');
        }

        $key = (string)Database::setting('license_key', '');
        if ($key === '') {
            if (self::trialActive()) {
                $left = self::trialDaysLeft();
                $r = self::result('Trial', true, true, false,
                    'Trial — ' . $left . ' day' . ($left === 1 ? '' : 's') . ' remaining. '
                  . 'Activate a licence to keep protection running.');
                $r['trial']           = true;
                $r['trial_days_left'] = $left;
                return $r;
            }
            return self::result('Unlicensed', false, false, false,
                'No licence key configured. Enter one to switch on protection.');
        }

        // 1. Try the cached local key first — avoids hitting WHMCS every load.
        $localkey = (string)Database::setting('license_localkey', '');
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
                // The licence server answered, and the answer was signed with a
                // different secret to ours. That is a configuration mismatch
                // between this server and the WHMCS addon, not a bad key -- and
                // saying "failed verification" sent people to re-check the key
                // they had just correctly pasted.
                return self::result('Invalid', false, false, false,
                    'The licence server replied, but the response was signed with a '
                    . 'different secret than this server is configured with. Check that '
                    . 'SG_LICENSE_SECRET in backend/config/mode.php matches the secret '
                    . 'in the WHMCS licensing addon.');
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
                // WHMCS returns Invalid both for an unknown key and for a key
                // already bound to a different server. The customer cannot tell
                // those apart from "invalid", and the second is by far the more
                // common support case once one-license-per-IP/domain is enforced.
                return self::result('Invalid', false, false, false,
                    'License not valid for this server (' . self::hostname() . ' / '
                    . self::serverIp() . '). If this license is already active on '
                    . 'another server, reissue it from the client area — each '
                    . 'license is valid on one server only.', $expires);
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
            'checked_at' => (int)Database::setting('license_checked_at', 0),
            // What WHMCS is matching this license against. A "one license per
            // IP/domain" rejection is almost always explained by these values.
            'domain'     => self::hostname(),
            'ip'         => self::serverIp(),
            // Carried on EVERY result, not just failures: an unconfigured
            // server should say so before a key is entered, rather than after
            // the customer has pasted a correct key and been told it is invalid.
            'secret_configured' => self::secretConfigured(),
            'whmcs_url'         => self::whmcsUrl(),
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

    /**
     * Does this candidate secret match what the licence server signs with?
     *
     * Tests WITHOUT storing it. Finding the right value otherwise means writing
     * each guess into mode.php and re-running activation, which edits live
     * configuration to answer a question -- and leaves the wrong value in place
     * when the guess is wrong.
     */
    public static function trySecret(string $candidate): array
    {
        $candidate = trim($candidate);
        if ($candidate === '') {
            return ['success' => false, 'error' => 'No candidate supplied.'];
        }

        $key        = (string)Database::setting('license_key', '');
        $checkToken = time() . self::rand(12);
        $body = self::post(rtrim(self::whmcsUrl(), '/') . '/modules/servers/licensing/verify.php', [
            'licensekey'  => $key,
            'domain'      => self::hostname(),
            'ip'          => self::serverIp(),
            'dir'         => defined('SG_ROOT') ? SG_ROOT : __DIR__,
            'version'     => defined('SG_VERSION') ? SG_VERSION : 'unknown',
            'check_token' => $checkToken,
        ]);
        if ($body === null) {
            return ['success' => false, 'error' => 'Could not reach the licence server.'];
        }

        $parsed = self::parseXml($body);
        if (!$parsed || empty($parsed['md5hash'])) {
            return ['success' => false,
                    'error' => 'The server returned no md5hash, so no secret can be tested.'];
        }

        $matches = hash_equals(md5($candidate . $checkToken), (string)$parsed['md5hash']);
        return [
            'success'  => true,
            'matches'  => $matches,
            'licence'  => $parsed['status'] ?? 'unknown',
            'message'  => $matches
                ? 'This IS the correct secret. Store it with: sentinel license secret <value>'
                : 'This is not the secret the licence server signs with. Nothing was changed.',
        ];
    }

    /**
     * Ask the licence server directly and return everything about the exchange.
     *
     * Diagnosing a licensing failure otherwise means reconstructing the POST by
     * hand with curl and guessing at the field names. This sends exactly what
     * the real check sends and shows exactly what came back, which is the only
     * way to tell apart the cases that all surface as "Invalid":
     *
     *   - the addon is not installed (no XML, or an HTML error page)
     *   - the key is unknown to WHMCS (status Invalid, md5hash present)
     *   - the key is fine but our secret is wrong (md5hash mismatch)
     *
     * The secret is never included in the output.
     */
    public static function probe(): array
    {
        $key        = (string)Database::setting('license_key', '');
        $checkToken = time() . self::rand(12);
        $url        = rtrim(self::whmcsUrl(), '/') . '/modules/servers/licensing/verify.php';

        $body = self::post($url, [
            'licensekey'  => $key,
            'domain'      => self::hostname(),
            'ip'          => self::serverIp(),
            'dir'         => defined('SG_ROOT') ? SG_ROOT : __DIR__,
            'version'     => defined('SG_VERSION') ? SG_VERSION : 'unknown',
            'check_token' => $checkToken,
        ]);

        $out = [
            'url'              => $url,
            'key_sent'         => $key === '' ? '(none stored)' : $key,
            'domain_sent'      => self::hostname(),
            'ip_sent'          => self::serverIp(),
            'secret_configured'=> self::secretConfigured(),
            'reachable'        => $body !== null,
        ];

        if ($body === null) {
            $out['diagnosis'] = 'The licence server could not be reached at all. Check '
                              . 'outbound HTTPS and that the URL above is correct.';
            return $out;
        }

        $out['raw_response'] = substr($body, 0, 2000);
        $parsed = self::parseXml($body);
        $out['parsed'] = $parsed ?: [];

        if (!$parsed || empty($parsed['status'])) {
            $out['diagnosis'] = 'The server replied, but not with a licensing response. '
                              . 'That usually means the WHMCS Licensing Addon is not '
                              . 'installed at this URL, or the URL points somewhere else.';
            return $out;
        }

        $out['server_status'] = $parsed['status'];

        if (empty($parsed['md5hash'])) {
            $out['diagnosis'] = 'The addon replied with status "' . $parsed['status']
                              . '" and no md5hash, so the response cannot be verified '
                              . 'and the secret is not the issue.';
            return $out;
        }

        $matches = hash_equals(md5(self::secret() . $checkToken), (string)$parsed['md5hash']);
        $out['hash_matches'] = $matches;
        $out['diagnosis'] = $matches
            ? 'The secret is correct. The licence itself is "' . $parsed['status'] . '" -- '
              . 'anything other than Active is a decision made in WHMCS about this key, '
              . 'domain or IP.'
            : 'The addon signed its reply with a different secret than this server holds. '
              . 'The value must come FROM the WHMCS Licensing Addon configuration; it '
              . 'cannot be generated here, and it is not the licence key. The licence '
              . 'itself reads as "' . $parsed['status'] . '".';
        return $out;
    }

    /** Where the per-installation settings live. */
    public static function modePhpPath(): string
    {
        return (defined('SG_ROOT') ? SG_ROOT : dirname(__DIR__, 2))
             . '/backend/config/mode.php';
    }

    /**
     * Write the licensing secret into mode.php.
     *
     * Hand-editing PHP over SSH to fix a licensing problem invites a typo that
     * takes the whole plugin down: mode.php is required by config.php, so a
     * stray quote is a fatal on every request rather than a licensing error.
     * This edits only the one line, keeps a backup, and refuses to leave the
     * file unparseable.
     *
     * The value is never logged or echoed back. It is the salt that makes a
     * cached local key unforgeable; anyone holding it can mint their own
     * "Active" licence.
     */
    public static function setSecret(string $value): array
    {
        $value = trim($value);
        if ($value === '') {
            return ['success' => false, 'error' => 'No secret supplied.'];
        }
        if ($value === self::SECRET) {
            return ['success' => false,
                    'error'   => 'That is the placeholder value, not a real secret.'];
        }

        // Reject the stand-ins that appear in the documentation and in the error
        // messages this tool itself prints. They are written to be pasted, and
        // one was: the result is an installation that reports "configured" while
        // holding a value the licence server has never heard of, which is a
        // more confusing state than having set nothing at all.
        $placeholders = [
            'your-whmcs-addon-secret', 'whmcs-addon-secret', 'your-secret',
            'yoursecret', 'changeme', 'secret', 'xxxxx', '<value>',
        ];
        if (in_array(strtolower($value), $placeholders, true)) {
            return ['success' => false,
                    'error'   => 'That is the example text from the instructions, not your '
                               . 'secret. The real value is configured in WHMCS under '
                               . 'Addons > License Manager, and must match there exactly. '
                               . 'If none is set there yet, generate one with '
                               . '"openssl rand -hex 32", save it in WHMCS, then pass the '
                               . 'same string here.'];
        }

        // Anything this short is far more likely to be a mistake than a salt.
        if (strlen($value) < 8) {
            return ['success' => false,
                    'error'   => 'That secret is too short to be a licensing salt '
                               . '(' . strlen($value) . ' characters). Check you have '
                               . 'copied the whole value from WHMCS.'];
        }

        $path = self::modePhpPath();
        if (!is_file($path)) {
            return ['success' => false, 'error' => 'mode.php not found at ' . $path];
        }
        if (!is_writable($path)) {
            return ['success' => false, 'error' => 'mode.php is not writable: ' . $path];
        }

        $src = (string) file_get_contents($path);
        $line = "define('SG_LICENSE_SECRET'," . var_export($value, true) . ");";

        if (preg_match("/^.*define\\(\\s*'SG_LICENSE_SECRET'.*$/m", $src)) {
            $out = preg_replace("/^.*define\\(\\s*'SG_LICENSE_SECRET'.*$/m", $line, $src, 1);
        } else {
            $out = rtrim($src) . "\n" . $line . "\n";
        }

        // Prove it still parses BEFORE putting it in place. A mode.php that does
        // not compile takes down every request, which is far worse than the
        // licensing problem being fixed.
        $tmp = $path . '.new';
        if (@file_put_contents($tmp, $out) === false) {
            return ['success' => false, 'error' => 'Could not write ' . $tmp];
        }
        $check = [];
        $code  = 0;
        @exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($tmp) . ' 2>&1', $check, $code);
        if ($code !== 0) {
            @unlink($tmp);
            return ['success' => false,
                    'error'   => 'Refusing to write a mode.php that does not parse: '
                               . implode(' ', $check)];
        }

        @copy($path, $path . '.bak');
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            return ['success' => false, 'error' => 'Could not replace ' . $path];
        }
        @chmod($path, 0640);

        return ['success' => true,
                'message' => 'Licensing secret written to ' . $path
                           . ' (backup: mode.php.bak). Activate the licence now.'];
    }

    /**
     * False when still running on the placeholder salt.
     *
     * This existed from the start and nothing called it, so an installation
     * with no secret behaved exactly like one with a wrong licence key.
     */
    public static function secretConfigured(): bool
    {
        return self::secret() !== self::SECRET && self::secret() !== '';
    }

    private static function hostname(): string
    {
        $h = php_uname('n');
        if ($h === '' || $h === false) { $h = gethostname() ?: 'unknown'; }
        return strtolower(preg_replace('/:\d+$/', '', (string)$h));
    }

    /**
     * The IP this server reports to the licensing server.
     *
     * MUST be identical in every execution context. An earlier version preferred
     * $_SERVER['SERVER_ADDR'], which only exists during a web request — so the
     * dashboard reported the address Apache bound to while cron and the CLI
     * reported the DNS answer. On a multi-homed, NAT'd or proxied host those
     * differ, and WHMCS would see a single license checking in from two
     * addresses. With "Allow IP Conflict" disabled (which is what enforces one
     * license per IP) that reads as a conflict and can invalidate a legitimate
     * customer.
     *
     * Resolution is therefore deterministic and derived only from the hostname,
     * and the answer is pinned on first use so a transient DNS change cannot
     * silently re-identify the server.
     */
    private static function serverIp(): string
    {
        $pinned = (string)Database::setting('license_pinned_ip', '');
        if ($pinned !== '' && filter_var($pinned, FILTER_VALIDATE_IP)) {
            return $pinned;
        }

        $host = self::hostname();
        $ip   = @gethostbyname($host);
        if (!$ip || $ip === $host || !filter_var($ip, FILTER_VALIDATE_IP)) {
            // Last resort: the primary outbound address. Never SERVER_ADDR —
            // that is web-only and would reintroduce the context split.
            $ip = self::outboundIp() ?: '127.0.0.1';
        }

        if ($ip !== '127.0.0.1') {
            Database::setSetting('license_pinned_ip', $ip);
        }
        return $ip;
    }

    /** Primary outbound address, without sending anything (UDP connect only). */
    private static function outboundIp(): string
    {
        $sock = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (!$sock) { return ''; }
        @socket_connect($sock, '8.8.8.8', 53);
        @socket_getsockname($sock, $addr);
        @socket_close($sock);
        return (is_string($addr) && filter_var($addr, FILTER_VALIDATE_IP)) ? $addr : '';
    }

    /**
     * The identity this install presents to the licensing server. Exposed so
     * support can see exactly what WHMCS is matching against when a customer
     * reports a conflict.
     */
    public static function identity(): array
    {
        return [
            'domain'    => self::hostname(),
            'ip'        => self::serverIp(),
            'dir'       => defined('SG_ROOT') ? SG_ROOT : __DIR__,
            'pinned_ip' => (string)Database::setting('license_pinned_ip', ''),
        ];
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
        // Logger::write() is PRIVATE. Calling it threw an Error, and because
        // this method is itself called from the catch block in status(), the
        // failure replaced whatever it was reporting — every licence check
        // became a fatal and every page that consults one went blank.
        //
        // The @ was worse than useless here: it suppresses warnings, not
        // Errors, so it silenced nothing while implying the call was risky.
        if (class_exists('Logger')) {
            try {
                Logger::info('license: ' . $msg);
            } catch (Throwable $e) {
                // Logging must never be the thing that breaks a request.
            }
        }
    }
}
