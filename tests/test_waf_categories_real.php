<?php
/**
 * The "OWASP CRS CATEGORIES" panel was a hardcoded array.
 *
 * WAF::getRuleCategories() returned sixteen literals -- category ids, names,
 * exact rule counts and an Active/Disabled flag on each:
 *
 *     ['id' => '913', 'name' => 'Scanner Detection', 'active' => true,  'rules' => 94],
 *     ['id' => '942', 'name' => 'SQL Injection',     'active' => true,  'rules' => 214],
 *     ['id' => '944', 'name' => 'Java Attack',       'active' => false, 'rules' => 12],
 *
 * It rendered identically on a server with CRS 4.7.0, with CRS 3.x, and with
 * no CRS installed at all -- observed in the container, where crs_version is
 * unknown and the panel still asserted "942 - SQL Injection - 214 rules -
 * Active".
 *
 * "944 - Java Attack - Disabled" is a specific, actionable statement about a
 * customer's security posture, and it was a literal `false` in PHP source. An
 * operator who reads it either believes the Java rules are off and goes
 * looking for why, or believes the other fifteen are on and stops looking.
 *
 * Same defect as action = 'block' on 148,551 WAF events and as
 * MODE.textContent = 'On'. Both of those were fixed; this one was missed.
 *
 * What has to be true instead: every number comes from a file, and when there
 * is no file the panel says so rather than filling the space.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

$cdir = $sandbox . '/cat-conf';
@mkdir($cdir, 0700, true);
WAFInstaller::setConfDir($cdir);
WAFInstaller::setIncludeDir($sandbox . '/cat-inc');
@mkdir($sandbox . '/cat-inc', 0700, true);
$waf = new WAF();

// ── With no CRS on the box, the answer is "I cannot tell you" ──────────────

$none = $waf->getRuleCategories();
t_ok(empty($none['available']),
     'with no CRS rule files, the data is reported as unavailable');
t_eq([], $none['categories'], 'and no categories are invented');
t_ok(strlen((string) $none['reason']) > 20,
     'with a reason the panel can print, because an empty panel and a panel '
   . 'that could not read anything look the same to the operator');

// ── A real tree: every figure comes out of the files ───────────────────────

$crs = $cdir . '/coreruleset';
@mkdir($crs . '/rules', 0700, true);
file_put_contents($crs . '/crs-setup.conf',
    "# OWASP_CRS ver.4.7.0-fixture\nSecAction \"id:900000,phase:1,pass,nolog\"\n");
file_put_contents($crs . '/.crs-version', '4.7.0');

// Three real rules, one COMMENTED OUT. CRS ships example rules in comments,
// and counting those inflates every number on the panel.
file_put_contents($crs . '/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
      "SecRule ARGS \"@rx select\" \"id:942100,phase:2,deny\"\n"
    . "SecRule ARGS \"@rx union\"  \"id:942110,phase:2,deny\"\n"
    . "SecRule ARGS \"@rx sleep\"  \"id:942120,phase:2,deny\"\n"
    . "# SecRule ARGS \"@rx drop\" \"id:942999,phase:2,deny\"\n");
file_put_contents($crs . '/rules/REQUEST-913-SCANNER-DETECTION.conf',
      "SecRule REQUEST_HEADERS:User-Agent \"@pm nikto\" \"id:913100,phase:1,deny\"\n"
    . "SecRule REQUEST_HEADERS:User-Agent \"@pm nmap\"  \"id:913110,phase:1,deny\"\n");

$r = $waf->getRuleCategories();
t_ok(!empty($r['available']), 'with a CRS tree present, the data is available');
t_eq($crs, $r['crs_path'], 'and the path it was read from is reported');
t_eq('4.7.0', $r['crs_version'], 'along with the version actually installed');

$byId = [];
foreach ($r['categories'] as $c) { $byId[$c['id']] = $c; }
t_eq(2, count($byId), 'one category per rule file that was read, and no more');
t_eq(3, $byId['942']['rules'] ?? null,
     'THE COUNT IS COUNTED: three rules in the 942 file, not the literal 214 '
   . 'that was displayed on every server regardless of what was installed');
t_eq(2, $byId['913']['rules'] ?? null, 'and two in the 913 file');
t_eq('SQL Injection', $byId['942']['name'] ?? null,
     'the name is derived from the file name CRS itself uses');
t_eq('Scanner Detection', $byId['913']['name'] ?? null, 'for each category');
t_contains(implode(',', $byId['942']['files'] ?? []), 'REQUEST-942',
     'and the file each figure came from is returned, so the derivation can be '
   . 'checked rather than trusted');

// ── "Loaded" means our config loads it, and nothing more ──────────────────

t_ok($byId['942']['loaded'] === false,
     'before our config exists, no category is claimed to be loaded: the panel '
   . 'used to show a green "Active" badge with no ModSecurity on the server');

WAFInstaller::setRunner(function (string $cmd) { return ['out' => 'Syntax OK', 'code' => 0]; });
$applied = WAFInstaller::setMode('detectiononly');
t_ok(!empty($applied['success']), 'the config is written and includes the tree');

$r2 = $waf->getRuleCategories();
$byId2 = [];
foreach ($r2['categories'] as $c) { $byId2[$c['id']] = $c; }
t_ok($byId2['942']['loaded'] === true,
     'with the config in place, the category is reported as included -- read '
   . 'from the config file, not assumed from the files existing');

// ── A rule the operator switched off is visible ───────────────────────────

WAFExclusions::add('942100', '', '', 'false positive on the shop');
$r3 = $waf->getRuleCategories();
$byId3 = [];
foreach ($r3['categories'] as $c) { $byId3[$c['id']] = $c; }
t_eq(1, $byId3['942']['excluded'] ?? null,
     'an exclusion the product itself wrote is counted against its category. '
   . 'The panel otherwise reports complete coverage while a rule is off');
t_eq(0, $byId3['913']['excluded'] ?? null, 'and categories with none say zero');

// ── The literals are gone, from the server and from the panel ────────────

$src = t_code($repo . '/backend/lib/WAF.php');
t_ok(strpos($src, 'Java Attack') === false,
     'THE FABRICATED LIST IS GONE: "944 Java Attack / Disabled" was a literal '
   . 'false in PHP source, presented to the operator as the state of their WAF');
t_ok(strpos($src, "'rules' => 214") === false && strpos($src, "'rules' => 94") === false,
     'and so are the invented rule counts');

$js = (string) file_get_contents($repo . '/frontend/js/app.js');
$panel = substr($js, (int) strpos($js, "getElementById('waf-categories')"), 1800);
t_ok(strpos($panel, "'Active' : 'Disabled'") === false,
     'the panel no longer labels a category Active or Disabled on data the '
   . 'product cannot derive');
t_contains($panel, 'reason',
     'and when the categories cannot be read it prints the reason instead of '
   . 'an empty list that looks like a clean bill of health');
