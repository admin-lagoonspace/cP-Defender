<?php
/**
 * WordPress database scanner.
 *
 * The queries are driven through an injected runner, so this suite needs no
 * MySQL and touches no customer data. The rows it feeds back are the rows
 * actually seen on the server in October 2026.
 *
 * Two things are tested harder than the detections:
 *
 *   1. That wp-config.php is parsed as TEXT and never executed. Running
 *      wp-cli against one compromised site during the incident executed its
 *      injected wp-config as root and re-created the malware that had just
 *      been deleted.
 *
 *   2. That a failing query is reported as a failure. A query that errors and
 *      a site that is clean both produce an empty result set, and reading one
 *      as the other is the easiest way there is to call a compromised server
 *      healthy. That mistake was made repeatedly during the incident.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

$tmp = sys_get_temp_dir() . '/sg-wpdb-' . getmypid();
@mkdir($tmp, 0700, true);

/** Write a wp-config.php and return the install root. */
$install = function (string $body) use ($tmp): string {
    $d = $tmp . '/' . substr(md5($body), 0, 8);
    @mkdir($d, 0700, true);
    file_put_contents($d . '/wp-config.php', $body);
    return $d;
};

// ── wp-config parsing ───────────────────────────────────────────────────────

$clean = <<<'PHP'
<?php
define('DB_NAME', 'alice_wp123');
define('DB_USER', 'alice_wpuser');
define('DB_PASSWORD', 'sekrit');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_abc1';
require_once ABSPATH . 'wp-settings.php';
PHP;

$root = $install($clean);
$cfg  = WPDatabaseScanner::parseConfig($root);
t_ok($cfg !== null, 'credentials are read out of wp-config.php');
t_eq('alice_wp123',  $cfg['db'],     'the database name');
t_eq('alice_wpuser', $cfg['user'],   'the user');
t_eq('wp_abc1',      $cfg['prefix'], 'and the table prefix');

t_eq(true, WPDatabaseScanner::auditConfig($root)['clean'],
     'a wp-config that only defines constants is clean');

// THE CRITICAL PROPERTY. If this file were include()d, the marker would exist
// and the exit() would end the test run. It is read as text, so neither
// happens.
$hostile = <<<'PHP'
<?php
define('DB_NAME', 'bob_wp1');
define('DB_USER', 'bob_u');
define('DB_PASSWORD', 'p');
$table_prefix = 'wp_';
// locale-cache-config
file_put_contents(sys_get_temp_dir() . '/sg-wpconfig-EXECUTED', 'boom');
function wp_locale_cache_config_reseed() {
  $s = get_option(hash('sha256', AUTH_KEY . '|lpc|boot'));
  if ($s) { eval(base64_decode($s)); }
}
wp_locale_cache_config_reseed();
// locale-cache-config-end
require_once ABSPATH . 'wp-settings.php';
PHP;

$marker = sys_get_temp_dir() . '/sg-wpconfig-EXECUTED';
@unlink($marker);

$root2 = $install($hostile);
$cfg2  = WPDatabaseScanner::parseConfig($root2);

t_ok(!file_exists($marker),
     'parsing a compromised wp-config.php does NOT execute it');
t_eq('bob_wp1', $cfg2['db'],
     'and the credentials are still read out of it');

$a = WPDatabaseScanner::auditConfig($root2);
t_eq(false, $a['clean'], 'the injected wp-config is reported as not clean');
t_ok(count($a['markers']) >= 3, 'with several reasons given');
t_contains(implode('|', $a['markers']), 'function', 'it defines a function');
t_contains(implode('|', $a['markers']), 'decodes',  'and it decodes something');
t_contains($a['why'], 'wp-config.php contains code', 'and says so plainly');

// The last $table_prefix assignment wins, as it does in WordPress.
$root3 = $install("<?php define('DB_NAME','c_wp');\n\$table_prefix='wp_';\n"
                . "\$table_prefix='live_';\n");
t_eq('live_', WPDatabaseScanner::parseConfig($root3)['prefix'],
     'the last table_prefix assignment is the one used');

t_eq(null, WPDatabaseScanner::parseConfig($tmp . '/nope'),
     'a missing wp-config yields no credentials rather than a guess');

// ── Detections, through an injected runner ──────────────────────────────────

/**
 * Answer queries from a fixture keyed on a fragment of the SQL.
 * Anything unmatched returns no rows, which is what a clean site looks like.
 */
$runner = function (array $fixture): callable {
    return function (string $sql) use ($fixture): array {
        foreach ($fixture as $needle => $rows) {
            if (str_contains($sql, $needle)) return $rows;
        }
        return [];
    };
};

// bgkgvs_wp840: 148 administrators, inserted by SQL. Two of them shown.
$sc = new WPDatabaseScanner($runner([
    'capabilities' => [
        ['ID' => 1, 'user_login' => 'alice', 'user_email' => 'alice@example.com',
         'user_pass' => '$2y$10$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL',
         'user_registered' => '2019-01-01 00:00:00', 'posts' => 42, 'sessions' => 1],
        ['ID' => 981, 'user_login' => 'wpadm01', 'user_email' => 'x@mailinator.com',
         'user_pass' => '5f4dcc3b5aa765d61d8327deb882cf99',
         'user_registered' => '2026-04-02 11:00:00', 'posts' => 0, 'sessions' => 0],
        ['ID' => 982, 'user_login' => 'james_smith1234', 'user_email' => 'jsmi.ptr@gmail.com',
         'user_pass' => '$2y$10$zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
         'user_registered' => '2021-06-14 09:12:00', 'posts' => 0, 'sessions' => 0],
    ],
]));
$r = $sc->scanInstall($root);
t_eq(true, $r['ok'], 'the scan completes');

$types = array_column($r['findings'], 'type');
t_ok(in_array('rogue_admin', $types, true), 'rogue administrators are reported');

$admins = array_values(array_filter($r['findings'], fn($f) => $f['type'] === 'rogue_admin'));
t_eq(2, count($admins), 'the two suspicious accounts, not the real one');

$whats = implode(' || ', array_column($admins, 'what'));
t_contains($whats, 'wpadm01',         'the SQL-inserted account');
t_contains($whats, 'raw MD5',         'identified by its impossible password hash');
t_contains($whats, 'james_smith1234', 'and the bcrypt account with a backdated date');
t_ok(!str_contains($whats, '"alice"'), 'the real administrator is left alone');

// The bcrypt/backdated account is the one that defeats every hash-format
// check, so it must be reported — but at 'high', not 'critical', because the
// signals are circumstantial and a dormant real account looks the same.
$gen = array_values(array_filter($admins,
    fn($f) => str_contains($f['what'], 'james_smith1234')));
t_eq('high', $gen[0]['severity'],
     'a circumstantial match is high, not critical — a human decides');
t_contains($gen[0]['action'], 'Confirm with the site owner',
     'and is told to confirm before deleting');

$md5 = array_values(array_filter($admins, fn($f) => str_contains($f['what'], 'wpadm01')));
t_eq('critical', $md5[0]['severity'], 'a raw MD5 hash is conclusive on its own');

// A site with 20+ administrators is a finding in itself.
$many = [];
for ($i = 1; $i <= 30; $i++) {
    $many[] = ['ID' => $i, 'user_login' => "u$i", 'user_email' => "u$i@example.com",
               'user_pass' => '$2y$10$' . str_repeat('a', 50),
               'user_registered' => '2024-01-01 00:00:00', 'posts' => 5, 'sessions' => 1];
}
$sc = new WPDatabaseScanner($runner(['capabilities' => $many]));
$r  = $sc->scanInstall($root);
$t  = array_column($r['findings'], 'type');
t_ok(in_array('admin_count', $t, true),
     'thirty administrators on one site is itself reported');

// The fabricated role. This is the detector that works when every hash and
// date test fails.
$roles = 'a:6:{s:13:"administrator";a:2:{s:4:"name";s:13:"Administrator";s:12:"capabilities";'
       . 'a:1:{s:13:"manage_options";b:1;}}'
       . 's:19:"internal_cache_sync";a:2:{s:4:"name";s:10:"Cache Sync";s:12:"capabilities";'
       . 'a:3:{s:10:"edit_users";b:1;s:13:"manage_options";b:1;s:13:"promote_users";b:1;}}'
       . 's:13:"shop_manager";a:2:{s:4:"name";s:12:"Shop manager";s:12:"capabilities";'
       . 'a:1:{s:10:"edit_users";b:1;}}}';

$sc = new WPDatabaseScanner($runner([
    'user_roles'   => [['option_value' => $roles]],
    'COUNT(*) AS c' => [['c' => 2]],
]));
$r = $sc->scanInstall($root);

$roleF = array_values(array_filter($r['findings'], fn($f) => $f['type'] === 'unknown_role'));
t_eq(1, count($roleF), 'only the fabricated role is reported');
t_contains($roleF[0]['what'], 'internal_cache_sync', 'by name');
t_contains($roleF[0]['what'], '2 account', 'with the number of accounts holding it');
t_eq('critical', $roleF[0]['severity'], 'as critical, because it carries admin power');
t_ok(!str_contains($roleF[0]['what'], 'shop_manager'),
     "WooCommerce's shop_manager is not reported");

// The login token: the durable half of a file backdoor whose file self-deleted.
$sc = new WPDatabaseScanner($runner([
    "meta_key IN ('_wpl_token'" => [
        ['user_id' => 1, 'meta_key' => '_wpl_token',
         'v' => 'ZweH4vu_thj1BEWmOgGjau31HMXi'],
    ],
]));
$r = $sc->scanInstall($root);
$tok = array_values(array_filter($r['findings'], fn($f) => $f['type'] === 'login_token'));
t_eq(1, count($tok), 'a login token in usermeta is reported');
t_eq('critical', $tok[0]['severity'], 'as critical');
t_contains($tok[0]['action'], 'mu-plugins',
     'and the operator is told where to look for the file that reads it');

// The persistence options. Named ones are conclusive.
$sc = new WPDatabaseScanner($runner([
    'wp_user_scopes_crc32' => [
        ['option_name' => 'wp_user_scopes_crc32', 'len' => 19422, 'autoload' => 'yes'],
        ['option_name' => 'wp_locale_cache_bootstrap', 'len' => 43789, 'autoload' => 'yes'],
    ],
]));
$r = $sc->scanInstall($root);
$opt = array_values(array_filter($r['findings'],
    fn($f) => $f['type'] === 'persistence_option'));
t_eq(2, count($opt), 'both payload options are reported');
t_contains($opt[0]['action'], 'Rebuild',
     'and the advice is to rebuild, not to delete the option — '
   . 'deleting one copy of eight achieves nothing');

// The draft post used as a payload container.
$sc = new WPDatabaseScanner($runner([
    "post_status IN ('draft'" => [
        ['ID' => 4821, 'post_title' => 'Cache compatibility notes',
         'post_name' => 'sync-a3f9c1d4e5b6a7c8', 'post_status' => 'draft',
         'len' => 43789],
    ],
]));
$r = $sc->scanInstall($root);
$po = array_values(array_filter($r['findings'],
    fn($f) => $f['type'] === 'post_payload_stash'));
t_eq(1, count($po), 'a draft post holding a payload is reported');
t_contains($po[0]['what'], 'Cache compatibility notes', 'by title');

// Contact Form 7 relay — the one that sent 92,954 messages in a day.
$relay = 'a:4:{s:9:"recipient";s:13:"[your-email]";s:6:"active";b:1;'
       . 's:7:"subject";s:5:"Thank";s:4:"body";s:2:"hi";}';
$fixed = 'a:4:{s:9:"recipient";s:17:"owner@example.com";s:6:"active";b:1;'
       . 's:7:"subject";s:5:"Thank";s:4:"body";s:2:"hi";}';

$sc = new WPDatabaseScanner($runner([
    'wpcf7_contact_form' => [
        ['post_id' => 91, 'post_title' => 'Enquiry', 'v' => $relay],
        ['post_id' => 92, 'post_title' => 'Careers', 'v' => $fixed],
    ],
    "option_name = 'siteurl'" => [['option_value' => 'https://www.example.com']],
]));
$r = $sc->scanInstall($root);
$mr = array_values(array_filter($r['findings'],
    fn($f) => $f['type'] === 'form_mail_relay'));
t_eq(1, count($mr), 'only the autoresponder addressed from submitted input');
t_contains($mr[0]['what'], '91', 'the offending form is named');
t_contains($mr[0]['action'], '92,954',
     'and the advice says what this cost when it happened');

// ── A failing query must not read as a clean site ───────────────────────────

$sc = new WPDatabaseScanner(function (string $sql): array {
    throw new RuntimeException('Access denied for user');
});
$r = $sc->scanInstall($root);
t_ok(count($r['errors']) > 0,
     'a failing query is reported as an error, not as a clean result');
t_contains(implode(' ', $r['errors']), 'Access denied', 'with the reason');
t_eq(0, count(array_filter($r['findings'], fn($f) => $f['type'] !== 'wpconfig_injection')),
     'and no detections are invented from the empty result');

// An install whose credentials cannot be read is an error too — not a pass.
$noCfg = $tmp . '/empty';
@mkdir($noCfg, 0700, true);
$r = (new WPDatabaseScanner($runner([])))->scanInstall($noCfg);
t_eq(false, $r['ok'], 'an unreadable install does not report success');
t_contains(implode(' ', $r['errors']), 'could not read database credentials',
     'and says why');

// An unsafe table prefix is refused rather than interpolated.
$bad = $install("<?php define('DB_NAME','x_wp');\n\$table_prefix='wp`; DROP TABLE x; --';\n");
$r = (new WPDatabaseScanner($runner([])))->scanInstall($bad);
t_ok(!$r['ok'] || count($r['errors']) > 0,
     'a table prefix that is not a plain identifier is refused');

// ── Clean site ──────────────────────────────────────────────────────────────

$sc = new WPDatabaseScanner($runner([
    'capabilities' => [
        ['ID' => 1, 'user_login' => 'owner', 'user_email' => 'owner@example.com',
         'user_pass' => '$wp$2y$10$' . str_repeat('b', 50),
         'user_registered' => '2023-03-03 00:00:00', 'posts' => 120, 'sessions' => 1],
    ],
    'user_roles' => [['option_value' =>
        'a:1:{s:13:"administrator";a:2:{s:4:"name";s:13:"Administrator";'
      . 's:12:"capabilities";a:1:{s:13:"manage_options";b:1;}}}']],
]));
$r = $sc->scanInstall($root);
t_eq(0, count($r['findings']), 'a clean site produces no findings');
t_eq(0, count($r['errors']),   'and no errors');

// cleanup
foreach (glob($tmp . '/*/wp-config.php') ?: [] as $f) @unlink($f);
foreach (glob($tmp . '/*') ?: [] as $d) @rmdir($d);
@rmdir($tmp);
@unlink($marker);
