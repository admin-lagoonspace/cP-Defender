<?php
/**
 * ServerScrub — Heuristic rule engine
 *
 * WHY THIS EXISTS
 * ---------------
 * The flat pattern list in Scanner.php asks one question per rule: "does this
 * regex appear?" Every genuinely dangerous file found during the October 2026
 * incident response on a live 118-account server answered "no" to all of them.
 *
 * Three findings drove this module:
 *
 *   1. An arbitrary-file-upload backdoor authenticated with
 *      hash_equals('<32 hex>', $_POST['api_key']) and called move_uploaded_file.
 *      Each of those three things alone is ordinary. Together they are a shell.
 *      Eight live copies, two of them on accounts a previous sweep had declared
 *      clean.
 *
 *   2. A 456-byte mu-plugin called health-monitor.php that read ?_wplogin=,
 *      matched a token in usermeta and called wp_set_auth_cookie(). No
 *      obfuscation, no eval, no base64 — textbook WordPress API use. No
 *      signature will ever match it. What condemns it is WHERE it sits and
 *      WHAT it does together: nothing in mu-plugins has any business logging a
 *      user in from a query string.
 *
 *   3. A self-healing persistence framework spread over 22 files, including
 *      wp-content/db.php and object-cache.php — WordPress drop-ins, which load
 *      before every plugin and which the old scanner skipped, because
 *      wp-content was on the "user data, leave alone" list. That is exactly
 *      where the worst of it lived.
 *
 * So a rule here is a CONJUNCTION, optionally scoped to a path, and it can
 * match files that are not .php at all (the framework stashed an encrypted
 * payload in wp-content/uploads/.<hash>.cache, invisible to every scan we ran).
 *
 * RULE SHAPE
 * ----------
 *   name      stable identifier; becomes SG.WP.<name> or SG.HEUR.<name>
 *   severity  low | medium | high | critical
 *   why       one line shown to the operator — what the combination means
 *   all       every regex must match                        (required)
 *   any       at least one must match, if present
 *   none      none may match — the false-positive brake
 *   path      regex the file path must match, if present
 *   not_path  regex the file path must NOT match, if present
 *   min_hits  for 'any': how many must match (default 1)
 *
 * FALSE POSITIVES
 * ---------------
 * `none` is not decoration. The hash-key rule was validated against 19,666
 * legitimate WordPress core and plugin files and matched none of them, and it
 * only stayed that way because the brakes are there. A rule that fires on a
 * customer's live site costs more than the malware it was looking for: high
 * and critical severities delete without a copy by default.
 *
 * Keep rules narrow. If a rule needs a wide `none` list to behave, it is the
 * wrong rule.
 */

class Heuristics
{
    /** Paths we never judge: our own quarantine and backup trees. */
    private const SKIP_PATHS = '#/(?:malscan_quarantine|malscan_backup|'
                             . 'serverscrub[_-]?quarantine|quarantine/\d{4})/#';

    /**
     * WordPress drop-ins. These three filenames are loaded by WordPress itself
     * before any plugin, from wp-content/ directly. Legitimate ones exist
     * (Redis and Memcached object caches, Query Monitor's db.php), so presence
     * alone is not a finding — but their contents are held to a much harder
     * standard than a normal plugin file, because whatever is in them runs on
     * every single request including wp-login.php.
     */
    public const DROPINS = ['db.php', 'object-cache.php', 'advanced-cache.php'];

    /** Path fragment matching the three drop-ins at their only valid location. */
    private const DROPIN_PATH = '#/wp-content/(?:db|object-cache|advanced-cache)\.php$#';

    /** mu-plugins: auto-loaded, cannot be deactivated from the admin UI. */
    private const MU_PATH = '#/wp-content/mu-plugins/#';

    /** Anywhere the attacker's code was found to hide, for path-scoped rules. */
    private const WP_EXEC_PATH = '#/wp-content/(?:mu-plugins|plugins|themes)/|'
                               . '/wp-content/(?:db|object-cache|advanced-cache)\.php$#';

    /** A request-controlled value arriving from the client. */
    private const REQ = '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/';

    /** Any way of reaching the network to post stolen data out. */
    private const EXFIL = '/curl_exec\s*\(|curl_init\s*\(|fsockopen\s*\(|'
                        . 'stream_socket_client\s*\(|wp_remote_(?:post|get)\s*\(|'
                        . 'file_get_contents\s*\(\s*[\'"]https?:/i';

    private static ?array $rules = null;

    // ── Rule set ────────────────────────────────────────────────────────────

    /**
     * @return array<int,array<string,mixed>>
     */
    public static function rules(): array
    {
        if (self::$rules !== null) return self::$rules;

        self::$rules = [

            // ── Upload backdoors ────────────────────────────────────────────
            //
            // The family that was live on eight accounts. A hex constant
            // compared with hash_equals() is a password; combined with a file
            // write whose destination or contents come from the request, it is
            // an upload shell. Real code comparing a hash against a hex
            // constant does not then write the uploaded file somewhere.
            [
                'name'     => 'upload_backdoor_hashkey',
                'severity' => 'critical',
                'why'      => 'A 32-hex password checked with hash_equals() guarding a file write — '
                            . 'this is an authenticated arbitrary-file-upload shell',
                'all'      => [
                    '/hash_equals\s*\(/i',
                    '/[\'"][0-9a-fA-F]{32}[\'"]/',
                ],
                'any'      => [
                    '/move_uploaded_file\s*\(/i',
                    '/file_put_contents\s*\(.{0,120}base64_decode/is',
                    '/fwrite\s*\(.{0,80}base64_decode/is',
                ],
                // WordPress core and well-behaved plugins do use hash_equals
                // on nonces and tokens. What they do not do is pair it with a
                // raw upload. The brake is for signed-download and licence
                // code that legitimately verifies a hex digest near a write.
                'none'     => [
                    '/wp_verify_nonce\s*\(|check_admin_referer\s*\(/i',
                    '/current_user_can\s*\(/i',
                ],
            ],

            // GIF89a emitted from PHP as an escape sequence. A real image is
            // never produced this way; this is camouflage so a request for the
            // backdoor returns something that looks like a picture.
            [
                'name'     => 'upload_backdoor_gifmask',
                'severity' => 'critical',
                'why'      => 'PHP emitting a hand-built GIF89a header — camouflage so the '
                            . 'backdoor returns a fake image to anything that probes it',
                'all'      => [
                    '/\\\\x47\\\\x49\\\\x46\\\\x38\\\\x39\\\\x61/',
                ],
            ],

            // ── Authentication bypass ───────────────────────────────────────
            //
            // The health-monitor.php family: clean code, no obfuscation, and
            // undetectable by signature. Caught on behaviour and location.
            [
                'name'     => 'auth_cookie_from_request',
                'severity' => 'critical',
                'why'      => 'Logs a user in from a request parameter via a usermeta token — '
                            . 'a password-free admin backdoor',
                'all'      => [
                    '/wp_set_auth_cookie\s*\(/i',
                    self::REQ,
                    '/usermeta|get_user_meta\s*\(|update_user_meta\s*\(/i',
                ],
                // Legitimate SSO and social-login plugins do set auth cookies
                // from a request. They also check a nonce or verify against
                // the provider first.
                'none'     => [
                    '/wp_verify_nonce\s*\(|check_admin_referer\s*\(/i',
                ],
            ],

            // Narrower but unconditional: a drop-in or mu-plugin has no reason
            // to authenticate anyone, nonce or not.
            [
                'name'     => 'auth_cookie_in_dropin',
                'severity' => 'critical',
                'why'      => 'A WordPress drop-in or mu-plugin that sets an auth cookie — '
                            . 'these load before every plugin and must never log anyone in',
                'path'     => '#/wp-content/mu-plugins/|'
                            . '/wp-content/(?:db|object-cache|advanced-cache)\.php$#',
                'all'      => [
                    '/wp_set_auth_cookie\s*\(|wp_set_current_user\s*\(/i',
                ],
            ],

            // ── Rogue administrators ────────────────────────────────────────
            [
                'name'     => 'admin_creator',
                'severity' => 'critical',
                'why'      => 'Creates an administrator account in code',
                'all'      => [
                    '/wp_insert_user\s*\(|wp_create_user\s*\(/i',
                    '/[\'"]administrator[\'"]/i',
                ],
                'none'     => [
                    // The installer and user-management screens legitimately do
                    // this behind a capability check.
                    '/current_user_can\s*\(\s*[\'"](?:create_users|promote_users|manage_options)/i',
                ],
            ],

            // A fabricated role is a better detector than any password-hash
            // check. The framework registered 'internal_cache_sync' with
            // administrator capabilities; the accounts themselves had proper
            // bcrypt hashes and backdated registration dates, so every
            // hash-format and date-window test missed them.
            //
            // NARROWED ON PURPOSE. "add_role() with edit_users" is not enough:
            // WooCommerce's shop_manager holds edit_users legitimately, and so
            // do several LMS and membership plugins. A file-content rule
            // cannot know which roles a server's plugins are entitled to
            // register, so this one only fires when the role NAME reads like
            // infrastructure rather than a job — cache, sync, backup, system.
            // That is exactly the shape the attacker chose, and it is the
            // shape no real plugin uses for a user-facing role.
            //
            // WPDatabaseScanner::checkRoles() is the authoritative detector:
            // it reads the roles actually registered on the site, diffs them
            // against a maintained allowlist, and can say how many accounts
            // hold each one. This rule catches the file before the role is
            // ever created; that one catches it afterwards.
            [
                'name'     => 'role_injection',
                'severity' => 'high',
                'why'      => 'Registers a role named like infrastructure that carries '
                            . 'administrator capabilities — how backdoor accounts hide '
                            . 'from a scan that only looks for administrators',
                'all'      => [
                    '/add_role\s*\(\s*[\'"][a-z0-9_\-]*'
                    . '(?:cache|sync|backup|system|internal|helper|monitor|cron|daemon)'
                    . '[a-z0-9_\-]*[\'"]/i',
                ],
                'any'      => [
                    '/[\'"]edit_users[\'"]/i',
                    '/[\'"]manage_options[\'"]\s*=>\s*(?:true|1)/i',
                    '/[\'"]promote_users[\'"]/i',
                    '/[\'"]unfiltered_upload[\'"]/i',
                ],
                'path'     => self::WP_EXEC_PATH,
            ],

            // ── Credential theft ────────────────────────────────────────────
            //
            // The 143 KB stealer on 39 copies of one reseller's sites, dated
            // June-July 2025 — a separate and much older compromise than the
            // one we were called in for. It harvested payment-processor keys.
            [
                'name'     => 'payment_key_harvest',
                'severity' => 'critical',
                'why'      => 'Reads payment-processor secrets and has a way to send them out',
                'all'      => [ self::EXFIL ],
                'any'      => [
                    '/STRIPE_(?:SECRET|KEY|API)/i',
                    '/AWS_SECRET_ACCESS_KEY/i',
                    '/BRAINTREE_PRIVATE_KEY/i',
                    '/AUTHORIZE_NET_TRANSACTION_KEY/i',
                    '/PAYPAL_CLIENT_SECRET/i',
                ],
                'min_hits' => 2,
            ],

            [
                'name'     => 'session_cookie_harvest',
                'severity' => 'critical',
                'why'      => 'Reads WordPress authentication cookies or session tokens and '
                            . 'has a way to send them out — account takeover without a password',
                'all'      => [ self::EXFIL ],
                'any'      => [
                    '/SECURE_AUTH_COOKIE|LOGGED_IN_COOKIE|AUTH_COOKIE/',
                    '/[\'"]session_tokens[\'"]/',
                ],
                'none'     => [
                    // Core's own cookie handling, and security plugins that
                    // legitimately report sessions, run from wp-includes.
                    '#/wp-includes/pluggable\.php#',
                ],
            ],

            // Hooking the login form to capture the plaintext password. The
            // hash in the database is useless to an attacker who already has
            // database access; the plaintext is what gets reused elsewhere.
            [
                'name'     => 'login_password_capture',
                'severity' => 'critical',
                'why'      => 'Hooks the login flow and ships the submitted password somewhere',
                'all'      => [
                    '/add_action\s*\(\s*[\'"](?:wp_login|wp_authenticate|login_form)/i',
                    '/\$_POST\s*\[\s*[\'"](?:pwd|password|user_pass)[\'"]\s*\]/i',
                    self::EXFIL,
                ],
            ],

            // ── Persistence and self-healing ────────────────────────────────
            //
            // The locale-cache framework. 22 executor files, any one of which
            // rebuilt the other 21, plus eight storage layers including a
            // draft post and two dotfiles with no .php extension. We deleted
            // the mu-plugin and declared it stopped; it came back twice,
            // because wp-config.php, db.php and object-cache.php all load
            // earlier than mu-plugins and each one was an executor.
            [
                'name'     => 'self_healing_dropper',
                'severity' => 'critical',
                'why'      => 'Reads a stored payload and writes PHP files to disk — '
                            . 'a self-healing loader that rebuilds itself after deletion',
                'all'      => [
                    '/get_option\s*\(|get_post_meta\s*\(|get_transient\s*\(/i',
                    '/file_put_contents\s*\(|fwrite\s*\(/i',
                ],
                'any'      => [
                    '/[\'"]<\?php/',
                    '/base64_decode\s*\(/i',
                    '/gzinflate\s*\(|gzuncompress\s*\(/i',
                    '/openssl_decrypt\s*\(/i',
                ],
                'path'     => self::WP_EXEC_PATH,
                'none'     => [
                    // Caching and minification plugins write generated PHP.
                    // They do it from a known plugin directory, under a
                    // plugin header, and they do not decrypt it first.
                    '#/wp-content/plugins/(?:w3-total-cache|wp-super-cache|'
                    . 'litespeed-cache|wp-rocket|autoptimize|wp-optimize)/#',
                ],
            ],

            // A script that removes itself after running. The droppers that
            // planted login tokens did this — 118 of them across 56 accounts,
            // every one gone by the time any scheduled scan would have run.
            // Near-zero legitimate use outside of installers.
            [
                'name'     => 'self_deleting_script',
                'severity' => 'critical',
                'why'      => 'Deletes itself after executing — a dropper covering its tracks',
                'all'      => [
                    '/@?unlink\s*\(\s*__FILE__\s*\)/i',
                ],
                'not_path' => '#/(?:wp-admin/includes/upgrade|wp-admin/install)\.php$#',
            ],

            // Planting the login token the auth-bypass loader looks for.
            [
                'name'     => 'login_token_plant',
                'severity' => 'critical',
                'why'      => 'Writes a long secret into usermeta against an administrator — '
                            . 'planting the key for a password-free login backdoor',
                'all'      => [
                    '/update_user_meta\s*\(|add_user_meta\s*\(/i',
                    '/[\'"][A-Za-z0-9_\-]{20,}[\'"]/',
                ],
                'any'      => [
                    '/[\'"]administrator[\'"]/i',
                    '/WHERE\s+meta_key|usermeta/i',
                ],
                'path'     => self::WP_EXEC_PATH,
                'none'     => [
                    '/current_user_can\s*\(/i',
                    '/wp_verify_nonce\s*\(/i',
                ],
            ],

            // wp-config.php is not a place for code. It defines constants and
            // includes wp-settings.php. Anything that pulls in a file from
            // wp-content, or defines a function, was put there by someone.
            [
                'name'     => 'wpconfig_injection',
                'severity' => 'critical',
                'why'      => 'wp-config.php pulling in code or defining functions — '
                            . 'the earliest-loading injection point there is',
                'path'     => '#/wp-config\.php$#',
                'any'      => [
                    '/(?:include|require)(?:_once)?\s*[\(\s][^;]{0,200}wp-content/i',
                    '/function\s+[a-z_][a-z0-9_]*\s*\(/i',
                    '/eval\s*\(|base64_decode\s*\(|gzinflate\s*\(/i',
                    '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
                ],
            ],

            // ── Obfuscation the flat patterns miss ──────────────────────────
            //
            // The stealer used neither base64 nor gzinflate. It carried a long
            // literal and a character-substitution table, then called the
            // decoded name as a variable function — which defeats every
            // eval(...) regex in the old list.
            [
                'name'     => 'charmap_obfuscation',
                'severity' => 'high',
                'why'      => 'A long literal decoded through a substitution table and called '
                            . 'as a variable function — obfuscation built to miss eval() rules',
                'all'      => [
                    '/[\'"][^\'"]{2000,}[\'"]/s',
                    '/strtr\s*\(|str_replace\s*\(\s*(?:array|\[)/i',
                    '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$/',
                ],
            ],

            // ── Location-only rules ─────────────────────────────────────────
            //
            // Executable PHP in the uploads directory. WordPress never puts it
            // there. A handful of plugins drop an index.php stub, which is why
            // the rule wants actual code.
            [
                'name'     => 'php_in_uploads',
                'severity' => 'high',
                'why'      => 'Executable PHP inside wp-content/uploads — WordPress never '
                            . 'puts code there, and the directory is web-reachable',
                'path'     => '#/wp-content/uploads/#',
                'any'      => [
                    '/\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[/',
                    '/\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i',
                    '/base64_decode\s*\(/i',
                    '/move_uploaded_file\s*\(/i',
                ],
            ],

            // The encrypted payload stash: a dotfile with a hex name and no
            // .php extension, under uploads or upgrade. Nothing we ran looked
            // at files like this, which is precisely why it was chosen.
            [
                'name'     => 'hidden_payload_stash',
                'severity' => 'high',
                'why'      => 'A hidden, hex-named blob stashed under wp-content — '
                            . 'offline storage for a loader that rebuilds itself',
                'path'     => '#/wp-content/(?:uploads|upgrade|cache)/.*/?\.[0-9a-f]{16,}'
                            . '(?:\.(?:cache|tmp|dat|bin))?$#',
                'any'      => [
                    '/^<\?php/',
                    '/^[A-Za-z0-9+\/]{512,}={0,2}$/m',
                    '/[\x00-\x08\x0e-\x1f]{32,}/s',   // high-entropy binary body
                ],
            ],

            // Core directories duplicated under a different name stay
            // web-reachable and keep serving whatever version they were copied
            // from, long after the site itself is updated.
            [
                'name'     => 'duplicated_core_dir',
                'severity' => 'medium',
                'why'      => 'A renamed copy of a WordPress core directory, still reachable '
                            . 'over HTTP and frozen at whatever version it was copied from',
                'path'     => '#/wp-(?:admin|includes)[0-9_][^/]*/#',
                'all'      => [ '/<\?php/' ],
            ],
        ];

        return self::$rules;
    }

    // ── Matching ────────────────────────────────────────────────────────────

    /**
     * Should this file be read at all?
     *
     * Called before the file is opened, so the decision is made on the path
     * alone. This is where the cost control lives: the scanner walks a lot of
     * files and most of them must be rejected without a read.
     *
     * Returns true for PHP by extension, for the three drop-in names wherever
     * they appear, and for the hidden hex-named stash files — which have no
     * PHP extension and would otherwise never be examined.
     */
    public static function shouldInspect(string $path, int $size): bool
    {
        if ($size <= 0 || $size > SCAN_MAX_SIZE) return false;
        if (preg_match(self::SKIP_PATHS, $path))  return false;

        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (in_array($ext, ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phps'], true)) {
            return true;
        }

        // Hidden hex-named payloads under wp-content. Bounded by extension so
        // this does not turn into "read every file in uploads".
        if (preg_match('#/wp-content/(?:uploads|upgrade|cache)/#', $path)
            && preg_match('#/\.[0-9a-f]{16,}(?:\.(?:cache|tmp|dat|bin))?$#', $path)) {
            return true;
        }

        return false;
    }

    /**
     * Evaluate every rule against one file.
     *
     * Returns the highest-severity match, or null. One finding per file is
     * enough — the operator acts on the file, not on each rule it tripped —
     * but the rest are returned in 'also' so a report can show why.
     *
     * @return array{name:string,severity:string,why:string,also:array<int,string>}|null
     */
    public static function evaluate(string $path, string $content): ?array
    {
        $order = ['low' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3];
        $hits  = [];

        foreach (self::rules() as $rule) {
            if (self::matches($rule, $path, $content)) $hits[] = $rule;
        }
        if (!$hits) return null;

        usort($hits, fn($a, $b) => $order[$b['severity']] <=> $order[$a['severity']]);
        $best = $hits[0];

        return [
            'name'     => $best['name'],
            'severity' => $best['severity'],
            'why'      => $best['why'],
            'also'     => array_column(array_slice($hits, 1), 'name'),
        ];
    }

    /** Does one rule fire on this file? */
    public static function matches(array $rule, string $path, string $content): bool
    {
        // Path gates first: they are cheap and they reject the most.
        $norm = str_replace('\\', '/', $path);
        if (isset($rule['path'])     && !preg_match($rule['path'], $norm))    return false;
        if (isset($rule['not_path']) &&  preg_match($rule['not_path'], $norm)) return false;

        foreach ($rule['all'] ?? [] as $re) {
            if (!preg_match($re, $content)) return false;
        }

        if (!empty($rule['any'])) {
            $need = (int)($rule['min_hits'] ?? 1);
            $got  = 0;
            foreach ($rule['any'] as $re) {
                if (preg_match($re, $content)) $got++;
                if ($got >= $need) break;
            }
            if ($got < $need) return false;
        }

        foreach ($rule['none'] ?? [] as $re) {
            // A `none` entry may be a path regex (it starts with #) or a
            // content regex. Both brake the same rule for different reasons:
            // "this file is allowed to do that" vs "this code checks a
            // capability first".
            $subject = str_starts_with($re, '#') ? $norm : $content;
            if (preg_match($re, $subject)) return false;
        }

        // A rule with no conditions at all would fire on everything. That is
        // a rule-authoring bug, not a detection; refuse it rather than delete
        // a customer's entire site.
        if (empty($rule['all']) && empty($rule['any'])
            && !isset($rule['path']) && !isset($rule['not_path'])) {
            return false;
        }

        return true;
    }

    /**
     * Drop-ins present in an install, with a verdict on each.
     *
     * Presence is not a finding — Redis and Memcached object caches are real,
     * and Query Monitor ships a db.php. But these files load before every
     * plugin on every request, so the operator should be told they exist and
     * which ones look like somebody else's work.
     *
     * @return array<int,array{file:string,path:string,suspicious:bool,why:string}>
     */
    public static function auditDropins(string $wpRoot): array
    {
        $out = [];
        foreach (self::DROPINS as $name) {
            $p = rtrim($wpRoot, '/') . '/wp-content/' . $name;
            if (!is_file($p)) continue;

            $size    = (int)@filesize($p);
            $content = $size > 0 && $size <= SCAN_MAX_SIZE ? (string)@file_get_contents($p) : '';
            $verdict = $content !== '' ? self::evaluate($p, $content) : null;

            $out[] = [
                'file'       => $name,
                'path'       => $p,
                'size'       => $size,
                'mtime'      => (int)@filemtime($p),
                'suspicious' => $verdict !== null,
                'why'        => $verdict['why']
                    ?? 'Loads before every plugin on every request — confirm you installed it',
            ];
        }
        return $out;
    }
}
