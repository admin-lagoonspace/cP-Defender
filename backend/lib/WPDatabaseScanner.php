<?php
/**
 * ServerScrub — WordPress database scanner
 *
 * WHY THIS EXISTS
 * ---------------
 * Until now every module in this product looked at files. During the October
 * 2026 incident response on a live 118-account server, most of what mattered
 * was not in a file:
 *
 *   - 148 administrator accounts on one site, inserted straight into the
 *     users table.
 *   - A persistence framework whose payload lived in wp_options, wp_postmeta
 *     and a draft post titled "Cache compatibility notes". Deleting every
 *     malicious FILE on that site changed nothing; it rebuilt itself from the
 *     database on the next request.
 *   - A login backdoor keyed on a usermeta row (_wpl_token). The loader was a
 *     456-byte file with no detectable signature; the token was the only
 *     durable evidence.
 *   - 92,954 spam messages relayed through one Contact Form 7 form's
 *     autoresponder. Nothing on disk was modified. The attack was a database
 *     row, form 91's mail_2 configuration.
 *
 * A file scanner cannot see any of that.
 *
 * TWO HARD RULES
 * --------------
 * 1. NEVER EXECUTE wp-config.php. It is parsed as text here, with regex. On a
 *    compromised site that file contains attacker code, and running wp-cli
 *    against one such site during the incident re-created as root the malware
 *    that had just been deleted. Reading credentials is not worth executing
 *    the thing you are investigating.
 *
 * 2. READ ONLY. This module reports. It does not DELETE, UPDATE or INSERT
 *    anything in a customer's database, ever. Everything it finds needs a
 *    human to look at it — the account that looks fabricated is sometimes the
 *    client's accountant, and on this server one of the "obvious" fake admins
 *    turned out to be a real user logging in through a VPN.
 */

class WPDatabaseScanner
{
    /** Roles WordPress itself ships. Anything else is worth a look. */
    private const CORE_ROLES = [
        'administrator', 'editor', 'author', 'contributor', 'subscriber',
    ];

    /**
     * Role-name prefixes belonging to plugins seen on real customer sites.
     * Without this the scan reports a finding on every WooCommerce and LMS
     * install on the server, and an alert that is wrong most of the time
     * gets ignored — which is how the fabricated role hid in the first place.
     */
    private const KNOWN_ROLE_PREFIXES = [
        'wc_', 'woocommerce_', 'shop_', 'customer', 'kivicare', 'kivi_',
        'jobsearch_', 'wholesalex_', 'tutor_', 'llms_', 'learndash_',
        'bbp_', 'seller', 'vendor', 'translator', 'um_', 'wpseo_',
        'subscriber_', 'student', 'teacher', 'instructor', 'affiliate',
    ];

    /**
     * Option names the persistence framework used. The first three are fixed
     * fallbacks it always wrote, which makes them the single best indicator
     * that a site carries it — the rest of its storage was keyed on hashes
     * derived from the install's own salts and cannot be matched by name.
     */
    private const BAD_OPTION_PATTERNS = [
        'wp_user_scopes_crc32%',
        '%locale_cache%',
        '%_bootstrap_payload%',
        '%reseed%',
    ];

    /** Usermeta keys that are login tokens by any other name. */
    private const TOKEN_META_KEYS = [
        '_wpl_token', '_wp_login_token', '_auth_token', '_login_key',
        '_session_key', '_remote_login',
    ];

    private array $findings = [];
    private array $errors   = [];
    /** @var callable(string,array):array */
    private $runner;

    /**
     * @param callable|null $runner Injectable query runner, for tests.
     *                              fn(string $sql, array $cfg): array<int,array>
     */
    public function __construct(?callable $runner = null)
    {
        $this->runner = $runner ?? [$this, 'runQuery'];
    }

    // ── wp-config parsing ───────────────────────────────────────────────────

    /**
     * Pull database credentials out of a wp-config.php as TEXT.
     *
     * Deliberately not include()d — see the header. The cost of parsing is
     * that an unusual wp-config (credentials assembled from variables, or
     * pulled from an environment file) will not yield a connection. That is
     * the right failure: it reports "could not read credentials" instead of
     * running attacker code to find out.
     *
     * @return array{db:string,user:string,pass:string,host:string,prefix:string}|null
     */
    public static function parseConfig(string $wpRoot): ?array
    {
        $file = rtrim($wpRoot, '/') . '/wp-config.php';
        if (!is_file($file) || !is_readable($file)) return null;

        // 256 KB is far more than a wp-config needs. A larger one is either
        // injected or not a wp-config; either way, read a bounded amount.
        $src = (string)@file_get_contents($file, false, null, 0, 262144);
        if ($src === '') return null;

        $grab = static function (string $const) use ($src): ?string {
            $re = '/define\s*\(\s*[\'"]' . preg_quote($const, '/')
                . '[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\s*\)/i';
            return preg_match($re, $src, $m) ? $m[1] : null;
        };

        $db = $grab('DB_NAME');
        if ($db === null || $db === '') return null;

        // $table_prefix may be reassigned later in the file; the last
        // assignment is the one WordPress ends up using.
        //
        // If the file assigns a prefix that is NOT a plain identifier, this
        // refuses the whole install rather than falling back to 'wp_'. The
        // fallback looks harmless and is not: every query below would then run
        // against wp_* tables that either do not exist or belong to a
        // different install, and the scan would come back clean on a
        // compromised site. Empty output is not proof of nothing there.
        $rawCount = preg_match_all('/\$table_prefix\s*=/', $src);
        $prefix   = 'wp_';
        $safe     = preg_match_all(
            '/\$table_prefix\s*=\s*[\'"]([A-Za-z0-9_]+)[\'"]\s*;/', $src, $m);

        if ($safe > 0) {
            $prefix = end($m[1]);
        }
        if ($rawCount > $safe) {
            // An assignment we could not read. Could be an unusual but
            // legitimate wp-config building the prefix from a variable, or an
            // injection; either way this module must not guess.
            return null;
        }

        return [
            'db'     => $db,
            'user'   => (string)$grab('DB_USER'),
            'pass'   => (string)$grab('DB_PASSWORD'),
            'host'   => $grab('DB_HOST') ?: 'localhost',
            'prefix' => $prefix,
        ];
    }

    /**
     * Does wp-config.php carry injected code?
     *
     * Checked separately from the content scanner because this is the file the
     * framework used to survive everything else: it loads before drop-ins,
     * before mu-plugins, before any plugin, and it is the one file an operator
     * is least likely to replace when cleaning a site.
     *
     * @return array{clean:bool,markers:array<int,string>,why:string}
     */
    public static function auditConfig(string $wpRoot): array
    {
        $file = rtrim($wpRoot, '/') . '/wp-config.php';
        if (!is_file($file)) {
            return ['clean' => true, 'markers' => [], 'why' => 'no wp-config.php'];
        }
        $src = (string)@file_get_contents($file, false, null, 0, 262144);

        $markers = [];
        if (preg_match('/(?:include|require)(?:_once)?\s*[\(\s][^;]{0,200}wp-content/i', $src)) {
            $markers[] = 'includes a file from wp-content';
        }
        if (preg_match('/function\s+([a-z_][a-z0-9_]*)\s*\(/i', $src, $m)) {
            $markers[] = "defines a function ({$m[1]}())";
        }
        if (preg_match('/eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|openssl_decrypt\s*\(/i', $src)) {
            $markers[] = 'decodes or evaluates something';
        }
        if (preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/', $src)) {
            $markers[] = 'reads request input';
        }
        // Paired marker comments: how the injection found its own block again
        // in order to update it.
        if (preg_match('/\/\/\s*([a-z0-9\-_]{4,})\s*$.*^\s*\/\/\s*\1-end/ims', $src)) {
            $markers[] = 'carries paired begin/end marker comments';
        }

        return [
            'clean'   => $markers === [],
            'markers' => $markers,
            'why'     => $markers === []
                ? 'wp-config.php defines constants only, as it should'
                : 'wp-config.php contains code: ' . implode('; ', $markers),
        ];
    }

    // ── Scanning one install ────────────────────────────────────────────────

    /**
     * @return array{ok:bool,findings:array,errors:array,db?:string}
     */
    public function scanInstall(string $wpRoot): array
    {
        $this->findings = [];
        $this->errors   = [];

        $cfgAudit = self::auditConfig($wpRoot);
        if (!$cfgAudit['clean']) {
            $this->add('wpconfig_injection', 'critical', $wpRoot,
                       $cfgAudit['why'],
                       'Replace wp-config.php from a clean copy and rotate the salts. '
                     . 'This file runs before everything else, so nothing else you '
                     . 'clean on this site will stay clean while it is there.');
        }

        $cfg = self::parseConfig($wpRoot);
        if ($cfg === null) {
            $this->errors[] = "$wpRoot: could not read database credentials from wp-config.php";
            return ['ok' => false, 'findings' => $this->findings, 'errors' => $this->errors];
        }

        $p = $cfg['prefix'];
        if (!preg_match('/^[A-Za-z0-9_]+$/', $p)) {
            $this->errors[] = "$wpRoot: refusing an unsafe table prefix";
            return ['ok' => false, 'findings' => $this->findings, 'errors' => $this->errors];
        }

        $this->checkAdmins($cfg, $wpRoot);
        $this->checkRoles($cfg, $wpRoot);
        $this->checkTokenMeta($cfg, $wpRoot);
        $this->checkOptions($cfg, $wpRoot);
        $this->checkPostStash($cfg, $wpRoot);
        $this->checkMailRelay($cfg, $wpRoot);

        return [
            'ok'       => true,
            'db'       => $cfg['db'],
            'findings' => $this->findings,
            'errors'   => $this->errors,
        ];
    }

    // ── Individual checks ───────────────────────────────────────────────────

    /**
     * Administrator accounts, judged on several signals at once.
     *
     * WHAT CHANGED AND WHY: the method everybody uses — "a raw 32-character
     * MD5 in user_pass means the row was inserted by SQL, because WordPress
     * only ever writes $P$, $2y$ or $wp$" — is sound, and it found 148
     * accounts on one site here. It is also no longer sufficient. One of the
     * tools on this server created administrators with a proper bcrypt hash
     * and a user_registered date backdated to between 2020 and 2024, with
     * plausible names and gmail addresses. Hash format cannot see those, and
     * neither can a date window.
     *
     * So this reports several weaker signals rather than one strong one, and
     * says which fired. None of them is a reason to delete an account on its
     * own.
     */
    private function checkAdmins(array $cfg, string $root): void
    {
        $p   = $cfg['prefix'];
        $sql = "SELECT u.ID, u.user_login, u.user_email, u.user_pass,
                       u.user_registered,
                       (SELECT COUNT(*) FROM `{$p}posts` WHERE post_author = u.ID) AS posts,
                       (SELECT COUNT(*) FROM `{$p}usermeta`
                          WHERE user_id = u.ID AND meta_key = 'session_tokens') AS sessions
                  FROM `{$p}users` u
                  JOIN `{$p}usermeta` m ON m.user_id = u.ID
                 WHERE m.meta_key = '{$p}capabilities'
                   AND m.meta_value LIKE '%administrator%'
                 ORDER BY u.ID
                 LIMIT 500";

        $rows = $this->ask($sql, $cfg, $root);
        if ($rows === null) return;

        $total = count($rows);
        if ($total >= 20) {
            // Not a judgement on any one account — a site with this many
            // administrators has lost control of who its administrators are.
            $this->add('admin_count', 'critical', $root,
                "$total administrator accounts on one install",
                'Review the whole list. A normal site has one to five. '
              . 'Export it before deleting anything and confirm with the site owner.');
        }

        foreach ($rows as $r) {
            $signals = [];
            $hash    = (string)($r['user_pass'] ?? '');
            $login   = (string)($r['user_login'] ?? '');
            $email   = (string)($r['user_email'] ?? '');

            // Written by SQL, not by WordPress. The strongest single signal
            // there is — WordPress has never produced a bare MD5.
            if (preg_match('/^[0-9a-f]{32}$/i', $hash)) {
                $signals[] = 'password hash is a raw MD5, which WordPress never writes';
            }
            // The generated-name shape: firstname_lastname1234.
            if (preg_match('/^[a-z]{3,12}_[a-z]{3,12}[0-9]{3,4}$/', $login)) {
                $signals[] = 'login follows a generated name_name#### pattern';
            }
            if (preg_match('/@(?:wordpress\.org|wp\.com|example\.com)$/i', $email)) {
                $signals[] = 'email is at a domain nobody receives mail on';
            }
            // Administrator, never wrote anything, never logged in. On its own
            // this is also what a dormant real account looks like, so it is
            // only reported alongside something else.
            if ((int)($r['posts'] ?? 0) === 0 && (int)($r['sessions'] ?? 0) === 0) {
                $signals[] = 'no posts and has never logged in';
            }
            if ($email === '') {
                $signals[] = 'no email address at all';
            }

            if (!$signals) continue;

            // One weak signal is noise. Two together is worth a look. The raw
            // MD5 is conclusive by itself.
            $strong = (bool)preg_match('/^[0-9a-f]{32}$/i', $hash);
            if (!$strong && count($signals) < 2) continue;

            $this->add('rogue_admin', $strong ? 'critical' : 'high', $root,
                sprintf('Administrator "%s" (ID %s, %s): %s',
                        $login, $r['ID'], $email ?: 'no email',
                        implode('; ', $signals)),
                $strong
                    ? 'This row was inserted directly into the database. Export it, then delete it.'
                    : 'Confirm with the site owner before deleting. Dormant real accounts look like this too.');
        }
    }

    /**
     * Fabricated roles.
     *
     * This turned out to be a better detector than anything to do with
     * password hashes: the framework registered a role called
     * internal_cache_sync carrying administrator capabilities, and the
     * accounts holding it were invisible to every other test because their
     * capabilities row does not contain the word "administrator".
     */
    private function checkRoles(array $cfg, string $root): void
    {
        $p    = $cfg['prefix'];
        $rows = $this->ask(
            "SELECT option_value FROM `{$p}options`
              WHERE option_name = '{$p}user_roles' LIMIT 1", $cfg, $root);
        if (!$rows) return;

        $blob = (string)($rows[0]['option_value'] ?? '');
        // Read the role keys out of the serialized blob textually. unserialize()
        // on attacker-controlled data can instantiate objects; the role names
        // are all that is needed and a regex cannot be made to run anything.
        if (!preg_match_all('/"([a-z0-9_\-]{2,60})";a:\d+:\{s:\d+:"name"/i', $blob, $m)) {
            return;
        }

        foreach (array_unique($m[1]) as $role) {
            $lower = strtolower($role);
            if (in_array($lower, self::CORE_ROLES, true)) continue;

            $known = false;
            foreach (self::KNOWN_ROLE_PREFIXES as $pref) {
                if (str_starts_with($lower, $pref)) { $known = true; break; }
            }
            if ($known) continue;

            // How many accounts hold it, and does it carry admin power?
            $cnt = $this->ask(
                "SELECT COUNT(*) AS c FROM `{$p}usermeta`
                  WHERE meta_key = '{$p}capabilities'
                    AND meta_value LIKE " . $this->lit('%"' . $role . '"%'), $cfg, $root);
            $users = (int)($cnt[0]['c'] ?? 0);

            $elevated = (bool)preg_match(
                '/"' . preg_quote($role, '/') . '";a:\d+:\{.{0,4000}?'
                . '"(?:edit_users|promote_users|manage_options|unfiltered_upload)";b:1/is',
                $blob);

            $this->add('unknown_role', $elevated ? 'critical' : 'medium', $root,
                sprintf('Role "%s" is not a WordPress role and is held by %d account(s)%s',
                        $role, $users, $elevated ? ', and it carries administrator capabilities' : ''),
                $elevated
                    ? 'Treat every account holding this role as compromised. '
                    . 'This is how backdoor accounts avoid a scan that only looks for administrators.'
                    : 'Probably a plugin. Confirm which plugin registered it; if none did, remove it.');
        }
    }

    /** Login-token rows: the durable half of a file-based auth backdoor. */
    private function checkTokenMeta(array $cfg, string $root): void
    {
        $p    = $cfg['prefix'];
        $in   = implode(',', array_map([$this, 'lit'], self::TOKEN_META_KEYS));
        $rows = $this->ask(
            "SELECT user_id, meta_key, LEFT(meta_value, 64) AS v
               FROM `{$p}usermeta`
              WHERE meta_key IN ($in) LIMIT 100", $cfg, $root);
        if (!$rows) return;

        foreach ($rows as $r) {
            $this->add('login_token', 'critical', $root,
                sprintf('Usermeta "%s" on user ID %s holds an opaque token (%s…)',
                        $r['meta_key'], $r['user_id'], substr((string)$r['v'], 0, 12)),
                'This is a password-free login key. Delete the row, then find the file '
              . 'that reads it — look in wp-content/mu-plugins and at the three drop-ins. '
              . 'Rotate that user\'s password and force all sessions out.');
        }
    }

    /**
     * Payload storage in wp_options.
     *
     * Two ways in: by name, for the fixed fallback names the framework always
     * wrote; and by shape, for anything autoloaded, large and opaque. The
     * second catches the salt-derived names that cannot be matched literally,
     * at the cost of occasionally reporting a big legitimate cache entry —
     * which is why it is reported at 'high', not 'critical'.
     */
    private function checkOptions(array $cfg, string $root): void
    {
        $p = $cfg['prefix'];

        $like = [];
        foreach (self::BAD_OPTION_PATTERNS as $pat) {
            $like[] = "option_name LIKE " . $this->lit($pat);
        }
        $rows = $this->ask(
            "SELECT option_name, LENGTH(option_value) AS len, autoload
               FROM `{$p}options`
              WHERE " . implode(' OR ', $like) . " LIMIT 50", $cfg, $root);

        foreach ($rows ?? [] as $r) {
            $this->add('persistence_option', 'critical', $root,
                sprintf('Option "%s" (%s bytes, autoload=%s) matches a known '
                      . 'self-healing payload store',
                        $r['option_name'], $r['len'], $r['autoload']),
                'Deleting this alone will not help: the payload is mirrored across '
              . 'several options, post meta and hidden files on disk, and any one '
              . 'copy rebuilds the rest. Rebuild the site rather than clean it.');
        }

        // By shape. Autoloaded means it is read on every single request, which
        // is what a loader wants and what a genuine large cache entry almost
        // never is.
        $rows = $this->ask(
            "SELECT option_name, LENGTH(option_value) AS len
               FROM `{$p}options`
              WHERE autoload = 'yes' AND LENGTH(option_value) > 8192
              ORDER BY LENGTH(option_value) DESC LIMIT 20", $cfg, $root);

        foreach ($rows ?? [] as $r) {
            $name = (string)$r['option_name'];
            // Legitimate big autoloaded options exist in quantity. Only the
            // ones whose NAME looks machine-generated are worth a word.
            if (!preg_match('/^[a-z_]*_?[0-9a-f]{16,}$/i', $name)
                && !preg_match('/^_?[a-z]+_[0-9a-f]{8,}/i', $name)) {
                continue;
            }
            $this->add('opaque_autoload_option', 'high', $root,
                sprintf('Autoloaded option "%s" is %s bytes and has a machine-generated name',
                        $name, $r['len']),
                'Read it before deleting it. A hash-named option loaded on every '
              . 'request is how the persistence framework on this server stored its payload.');
        }
    }

    /**
     * Posts used as a payload container.
     *
     * The framework kept a copy in a draft post titled "Cache compatibility
     * notes" with a hash-shaped slug, plus post meta. Nothing looks at drafts.
     */
    private function checkPostStash(array $cfg, string $root): void
    {
        $p    = $cfg['prefix'];
        $rows = $this->ask(
            "SELECT ID, post_title, post_name, post_status,
                    LENGTH(post_content) AS len
               FROM `{$p}posts`
              WHERE post_status IN ('draft','private','auto-draft','trash')
                AND LENGTH(post_content) > 4096
                AND (post_name REGEXP '[0-9a-f]{16}' OR post_content LIKE '%<?php%')
              LIMIT 25", $cfg, $root);

        foreach ($rows ?? [] as $r) {
            $this->add('post_payload_stash', 'critical', $root,
                sprintf('%s post ID %s ("%s", slug %s) holds %s bytes of code or opaque data',
                        ucfirst((string)$r['post_status']), $r['ID'],
                        $r['post_title'], $r['post_name'], $r['len']),
                'Unpublished posts are not content. Export it as evidence, then treat '
              . 'the whole install as compromised — this is a backup copy of a loader.');
        }
    }

    /**
     * Contact-form mail relay.
     *
     * This is here because of what it cost: 92,954 queued messages from a
     * single Contact Form 7 form whose autoresponder had been reconfigured to
     * send to attacker-supplied addresses. No file on the server was modified.
     * The server's mail reputation was the damage, and the only evidence was
     * one row in wp_posts' meta.
     *
     * The test is simple: does a form's second mail template send to an
     * address that is not on this site's own domain?
     */
    private function checkMailRelay(array $cfg, string $root): void
    {
        $p    = $cfg['prefix'];
        $rows = $this->ask(
            "SELECT pm.post_id, p.post_title, LEFT(pm.meta_value, 2048) AS v
               FROM `{$p}postmeta` pm
               JOIN `{$p}posts` p ON p.ID = pm.post_id
              WHERE pm.meta_key IN ('_mail_2','_form','_mail')
                AND p.post_type = 'wpcf7_contact_form'
              LIMIT 200", $cfg, $root);
        if (!$rows) return;

        $site = $this->siteDomain($cfg, $root);

        foreach ($rows as $r) {
            $blob = (string)$r['v'];
            // Only the autoresponder matters: mail_2 fires to whatever address
            // the submitter typed, which is the whole mechanism.
            if (!preg_match('/"active";b:1/', $blob)) continue;
            if (!preg_match('/"recipient";s:\d+:"([^"]*)"/', $blob, $m)) continue;

            $to = trim($m[1]);
            if ($to === '') continue;
            // A mail tag means "send to whatever was submitted" — that is the
            // relay. A fixed address on another domain is also worth saying.
            $isTag = (bool)preg_match('/\[[^\]]+\]/', $to);
            $offsite = !$isTag && $site !== ''
                       && !str_contains(strtolower($to), strtolower($site));

            if (!$isTag && !$offsite) continue;

            $this->add('form_mail_relay', $isTag ? 'high' : 'medium', $root,
                sprintf('Contact form %s ("%s") has an active autoresponder sending to "%s"',
                        $r['post_id'], $r['post_title'], $to),
                $isTag
                    ? 'An autoresponder addressed from submitted input is an open mail relay. '
                    . 'One form configured this way sent 92,954 messages from this server in a day. '
                    . 'Disable the second mail template or add a captcha.'
                    : 'Confirm the site owner intended mail to leave for this address.');
        }
    }

    private function siteDomain(array $cfg, string $root): string
    {
        $p    = $cfg['prefix'];
        $rows = $this->ask(
            "SELECT option_value FROM `{$p}options`
              WHERE option_name = 'siteurl' LIMIT 1", $cfg, $root);
        $url = (string)($rows[0]['option_value'] ?? '');
        $h   = parse_url($url, PHP_URL_HOST);
        return is_string($h) ? preg_replace('/^www\./i', '', $h) : '';
    }


    // -- Sweeping the whole server ------------------------------------------

    /**
     * Scan every WordPress install CMSGuard knows about, and record what turns up.
     *
     * COST CONTROL. This is the expensive module in the product: one database
     * connection and six queries per install, and the server this was written
     * for has 503 of them. During the incident a loop that opened one mysql
     * process per install pushed load past 20 on a box that was already
     * struggling -- the work was trivial, the 503 forks were not. So:
     *
     *   - PDO connections are reused per database, not per query.
     *   - The sweep runs to a wall-clock budget and stops when it runs out,
     *     rather than finishing at any cost. The next run resumes where this
     *     one stopped.
     *   - Every query carries a LIMIT.
     *
     * @param int $budgetSeconds Wall-clock budget; 0 means no limit, which is
     *                           only appropriate from a nightly cron.
     * @return array{installs:int,scanned:int,findings:int,errors:array,complete:bool}
     */
    public static function sweep(?int $jobId = null, int $budgetSeconds = 900,
                                 ?array $installs = null): array
    {
        $started = time();
        $roots   = $installs;

        if ($roots === null) {
            $roots = [];
            foreach ((new CMSGuard())->getInstalls() as $i) {
                if (strtolower((string)($i['cms'] ?? '')) !== 'wordpress') continue;
                $d = (string)($i['path'] ?? $i['docroot'] ?? '');
                if ($d !== '') $roots[] = $d;
            }
            $roots = array_values(array_unique($roots));
        }

        // Resume point, so a sweep that runs out of budget rotates through the
        // server across successive runs instead of re-scanning the same
        // alphabetical prefix every night and never reaching the rest.
        $cursor = (int)(Database::setting('wpdb_sweep_cursor', '0') ?? 0);
        if ($cursor > 0 && $cursor < count($roots)) {
            $roots = array_merge(array_slice($roots, $cursor), array_slice($roots, 0, $cursor));
        }

        $scanner  = new self();
        $scanned  = 0;
        $recorded = 0;
        $errors   = [];
        $complete = true;

        foreach ($roots as $idx => $root) {
            if ($budgetSeconds > 0 && (time() - $started) >= $budgetSeconds) {
                $complete = false;
                Database::setSetting('wpdb_sweep_cursor',
                    (string)(($cursor + $idx) % max(1, count($roots))));
                break;
            }

            $r = $scanner->scanInstall($root);
            $scanned++;

            foreach ($r['findings'] as $f) {
                // Do not re-raise a finding already open against this install.
                // Without this, one unresolved issue adds a row a night until
                // the list is unreadable and genuinely new findings are buried
                // under repeats of old ones.
                $dupe = Database::fetchOne(
                    "SELECT id FROM wp_findings
                      WHERE install_path = ? AND finding_type = ? AND what = ?
                        AND status = 'open' LIMIT 1",
                    [$root, $f['type'], $f['what']]);
                if ($dupe) continue;

                Database::insert('wp_findings', [
                    'scan_job_id'  => $jobId,
                    'install_path' => $root,
                    'db_name'      => $r['db'] ?? null,
                    'cpanel_user'  => Scanner::getCpanelUser($root),
                    'finding_type' => $f['type'],
                    'severity'     => $f['severity'],
                    'what'         => $f['what'],
                    'action'       => $f['action'],
                    'status'       => 'open',
                ]);
                $recorded++;
            }

            foreach ($r['errors'] as $e) $errors[] = $e;
        }

        if ($complete) Database::setSetting('wpdb_sweep_cursor', '0');
        Database::setSetting('wpdb_sweep_last', (string)time());

        Logger::info(sprintf(
            'WordPress database sweep: %d of %d installs, %d new findings, %d errors%s',
            $scanned, count($roots), $recorded, count($errors),
            $complete ? '' : ' (budget reached, will resume)'));

        return [
            'installs' => count($roots),
            'scanned'  => $scanned,
            'findings' => $recorded,
            // Errors are returned, not swallowed. A query that failed and an
            // install that is clean produce the same empty result set, and
            // reading one as the other is the easiest way there is to report a
            // compromised server as healthy.
            'errors'   => array_slice($errors, 0, 50),
            'complete' => $complete,
        ];
    }

    /** Open findings, worst first. */
    public static function openFindings(int $limit = 200): array
    {
        return Database::fetchAll(
            "SELECT * FROM wp_findings WHERE status = 'open'
              ORDER BY CASE severity
                         WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                         WHEN 'medium'   THEN 2 ELSE 3 END,
                       detected_at DESC
              LIMIT " . max(1, min(1000, $limit)));
    }

    public static function stats(): array
    {
        $row = Database::fetchOne(
            "SELECT
               COUNT(*) AS total,
               SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
               SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END) AS high,
               SUM(CASE WHEN severity = 'medium'   THEN 1 ELSE 0 END) AS medium
             FROM wp_findings WHERE status = 'open'") ?: [];

        return [
            'open'     => (int)($row['total']    ?? 0),
            'critical' => (int)($row['critical'] ?? 0),
            'high'     => (int)($row['high']     ?? 0),
            'medium'   => (int)($row['medium']   ?? 0),
            'last_run' => (int)(Database::setting('wpdb_sweep_last', '0') ?? 0),
        ];
    }

    /**
     * Mark a finding dealt with.
     *
     * The operator decides, not the software. Nothing here is auto-remediated:
     * every finding needs a human to look at the account or the row. On this
     * server an account matching three of the rogue-admin signals turned out
     * to be the client's real administrator logging in through a VPN.
     */
    public static function resolve(int $id, string $status = 'resolved'): bool
    {
        if (!in_array($status, ['resolved', 'accepted', 'open'], true)) return false;
        Database::query(
            "UPDATE wp_findings SET status = ?, resolved_at = ? WHERE id = ?",
            [$status, $status === 'open' ? null : time(), $id]);
        return true;
    }

    // ── Plumbing ────────────────────────────────────────────────────────────

    private function add(string $type, string $severity, string $root,
                         string $what, string $action): void
    {
        $this->findings[] = [
            'type'     => $type,
            'severity' => $severity,
            'install'  => $root,
            'what'     => $what,
            'action'   => $action,
        ];
    }

    /** @return array<int,array>|null null means the query could not be run. */
    private function ask(string $sql, array $cfg, string $root): ?array
    {
        try {
            return ($this->runner)($sql, $cfg);
        } catch (Throwable $e) {
            // Record it. A query that silently returns nothing reads exactly
            // like a clean site, and that mistake was made repeatedly during
            // the incident: empty output is not proof of nothing there.
            $this->errors[] = "$root: " . $e->getMessage();
            return null;
        }
    }

    /** Quote a literal for inlining. Used only for values this class owns. */
    private function lit(string $s): string
    {
        return "'" . str_replace(['\\', "'"], ['\\\\', "\\'"], $s) . "'";
    }

    /**
     * Run one query against a site's database.
     *
     * Connects as the MySQL root user over the local socket, which on a
     * cPanel server is already configured in /root/.my.cnf. The site's own
     * credentials from wp-config are the fallback, for the case where this
     * runs without root.
     *
     * PDO is preferred; where pdo_mysql is not built into the PHP running
     * this plugin, the mysql client is used instead. Both are read-only by
     * construction here — nothing in this class builds a write.
     */
    private function runQuery(string $sql, array $cfg): array
    {
        if (extension_loaded('pdo_mysql')) {
            static $pdos = [];
            $key = $cfg['db'];
            if (!isset($pdos[$key])) {
                $dsn = "mysql:dbname={$cfg['db']};charset=utf8mb4";
                $sock = '/var/lib/mysql/mysql.sock';
                $dsn .= is_file($sock) ? ";unix_socket=$sock" : ";host={$cfg['host']}";
                try {
                    $pdos[$key] = new PDO($dsn, 'root', '', [
                        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_TIMEOUT            => 10,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    ]);
                } catch (Throwable $e) {
                    $pdos[$key] = new PDO($dsn, $cfg['user'], $cfg['pass'], [
                        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_TIMEOUT            => 10,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    ]);
                }
            }
            return $pdos[$key]->query($sql)->fetchAll();
        }

        return $this->runViaClient($sql, $cfg);
    }

    /**
     * Fallback: the mysql client, one process per query.
     *
     * Deliberately `nice`d. During the incident a loop that opened one mysql
     * process per site across 503 installs pushed load past 20 on a server
     * that was already struggling — the work was trivial but 503 forks were
     * not. Callers that need breadth should batch; this path exists for depth
     * on one install.
     */
    private function runViaClient(string $sql, array $cfg): array
    {
        $bin = '/usr/bin/mysql';
        if (!is_executable($bin)) {
            throw new RuntimeException('no PDO MySQL and no mysql client available');
        }
        $cmd = 'nice -n 19 ' . escapeshellarg($bin)
             . ' --batch --raw --skip-column-names=0 --connect-timeout=10 '
             . escapeshellarg($cfg['db']) . ' 2>&1';

        $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) throw new RuntimeException('could not start mysql client');

        fwrite($pipes[0], $sql . ";\n");
        fclose($pipes[0]);
        $out = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($proc);

        if ($code !== 0) {
            throw new RuntimeException('mysql client failed: ' . trim(substr($out, 0, 200)));
        }

        $lines = explode("\n", trim($out));
        if (count($lines) < 2) return [];
        $head = explode("\t", array_shift($lines));
        $rows = [];
        foreach ($lines as $line) {
            if ($line === '') continue;
            $vals = explode("\t", $line);
            $rows[] = array_combine($head, array_pad($vals, count($head), null));
        }
        return $rows;
    }
}
