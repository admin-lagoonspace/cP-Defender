<?php
/**
 * The CRS tree on the production server was corrupt, and the installer said
 * it was fine.
 *
 * /etc/serverscrub/waf/coreruleset held TWO definitions of rule 913100.
 * Apache refused the entire configuration:
 *
 *     AH00526: Syntax error on line 56 of REQUEST-913-SCANNER-DETECTION.conf
 *     ModSecurity: Found another rule with the same id
 *
 * so the WAF had not loaded once since 6 Oct while the panel reported it
 * armed, and the first Apache restart after the 7 Nov mode change failed and
 * took 132 accounts to 502. A clean re-extraction of the IDENTICAL 4.7.0
 * tarball parsed fine, which is what proves the tree was the fault and not the
 * ruleset.
 *
 * How a tree gets two copies of one rule: installCrs() ran
 *
 *     tar -xzf crs.tar.gz -C /etc/serverscrub/waf
 *
 * into the live directory and then assumed it had worked. tar MERGES over what
 * is already there, so a rule file that was renamed or dropped between CRS
 * versions stays behind next to its replacement -- and a half-finished
 * download replaces a working ruleset with a broken one.
 *
 * What has to be true instead: extract somewhere else, check the result, swap
 * it in, and never merge over a live tree.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

// ── The check itself: find the id that is defined twice ───────────────────

$clean = $sandbox . '/crs-clean';
@mkdir($clean . '/rules', 0700, true);
file_put_contents($clean . '/rules/REQUEST-913-SCANNER-DETECTION.conf',
      "SecRule REQUEST_HEADERS:User-Agent \"@pm nikto\" \"id:913100,phase:1,deny\"\n"
    . "SecRule REQUEST_HEADERS:User-Agent \"@pm nmap\"  \"id:913110,phase:1,deny\"\n");
file_put_contents($clean . '/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
      "SecRule ARGS \"@rx select\" \"id:942100,phase:2,deny\"\n");

t_eq([], WAFInstaller::duplicateRuleIds($clean),
     'a clean tree reports no duplicates — a check that fires on a good '
   . 'ruleset would stop every install and be turned off within a week');

// The production shape: the same rule in a file left behind by an earlier
// version, which is exactly what tar's merge produces.
$dirty = $sandbox . '/crs-dirty';
@mkdir($dirty . '/rules', 0700, true);
copy($clean . '/rules/REQUEST-913-SCANNER-DETECTION.conf',
     $dirty . '/rules/REQUEST-913-SCANNER-DETECTION.conf');
file_put_contents($dirty . '/rules/REQUEST-913-SCANNER-DETECTION-3.x.conf',
      "SecRule REQUEST_HEADERS:User-Agent \"@pm nikto\" \"id:913100,phase:1,deny\"\n");
copy($clean . '/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
     $dirty . '/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf');

$dups = WAFInstaller::duplicateRuleIds($dirty);
t_ok(isset($dups['913100']),
     'THE 7 NOV FAULT IS FOUND: rule 913100 defined in two files in one tree. '
   . 'Apache refuses the whole configuration for this, and the WAF had been '
   . 'silently unloaded for a month because nothing ever looked');
t_eq(2, count($dups['913100'] ?? []),
     'and both files are named, because the operator has to delete one of them');
t_ok(!isset($dups['942100']), 'an id defined once is not reported');

// The scan reads rules/*.conf and nothing else, which is exactly what the
// generated config includes. A leftover that does not end in .conf is not
// loaded by Apache, so it is not a duplicate DEFINITION -- reporting it would
// block an install over a file Apache never reads.
file_put_contents($dirty . '/rules/REQUEST-913-SCANNER-DETECTION.conf.bak',
      "SecRule ARGS \"@rx a\" \"id:942100,phase:2,deny\"\n");
t_ok(!isset(WAFInstaller::duplicateRuleIds($dirty)['942100']),
     'a backup file Apache does not include is not treated as a second '
   . 'definition: the scan covers exactly what the config loads');

// The real production shape as well: the same id twice inside ONE file.
$twice = $sandbox . '/crs-twice';
@mkdir($twice . '/rules', 0700, true);
file_put_contents($twice . '/rules/REQUEST-913-SCANNER-DETECTION.conf',
      "SecRule ARGS \"@rx a\" \"id:913100,phase:1,deny\"\n"
    . "SecRule ARGS \"@rx b\" \"id:913100,phase:1,deny\"\n");
t_ok(isset(WAFInstaller::duplicateRuleIds($twice)['913100']),
     'and an id repeated inside one file is caught as well');

// CRS ships example rules commented out. Counting those would condemn a
// perfectly good ruleset and the check would be the thing that broke installs.
$commented = $sandbox . '/crs-commented';
@mkdir($commented . '/rules', 0700, true);
file_put_contents($commented . '/rules/REQUEST-913-SCANNER-DETECTION.conf',
      "SecRule ARGS \"@rx a\" \"id:913100,phase:1,deny\"\n"
    . "# SecRule ARGS \"@rx a\" \"id:913100,phase:1,deny\"\n");
t_eq([], WAFInstaller::duplicateRuleIds($commented),
     'a commented-out copy of a rule is not a duplicate definition');

// Bounded on purpose: this runs on a box with 132 accounts.
t_eq([], WAFInstaller::duplicateRuleIds($dirty, 0),
     'the file cap is honoured, so this cannot become an unbounded walk of '
   . 'whatever else is under /etc/serverscrub/waf');
t_eq([], WAFInstaller::duplicateRuleIds($sandbox . '/does-not-exist'),
     'and a missing directory is empty, not an error');

// ── The installer stages, checks, swaps -- and never merges ───────────────

$src = t_code($repo . '/backend/lib/WAFInstaller.php');
$fn  = t_fn_body($src, 'installCrs', 'php');

t_contains($fn, 'crs-stage-',
     'the archive is extracted into a fresh staging directory, not over the '
   . 'tree Apache is reading');
t_ok(strpos($fn, 'duplicateRuleIds') !== false,
     'the staged tree is checked for duplicate ids BEFORE it goes anywhere '
   . 'near Apache');
$dupPos  = strpos($fn, 'duplicateRuleIds');
$movePos = strpos($fn, '@rename($tree, $target)');
t_ok($movePos !== false && $dupPos < $movePos,
     'and the check happens before the swap, so a corrupt extraction never '
   . 'reaches the directory the config includes');
t_contains($fn, '@rename($target, $old)',
     'the existing tree is MOVED ASIDE rather than extracted over: tar merges, '
   . 'and a merge is how one tree came to define 913100 twice');
t_contains($fn, '@rename($old, $target)',
     'and it is put back if the swap fails, so a failed install leaves the '
   . 'ruleset that was working');
t_contains($fn, 'validateApache',
     'what was installed is validated rather than assumed, when there is a '
   . 'config for apachectl to read it from');
t_ok(strpos($fn, "tar -xzf %s -C %s") !== false
     && strpos($fn, 'escapeshellarg($stage)') !== false,
     'the extraction target is the staging directory and nothing else');

// An existing tree was accepted on sight. The production tree was "already
// present" AND already broken, so every install after 6 Oct wrote a config
// Apache could not parse and reported the ruleset as fine.
$inst = t_fn_body($src, 'install', 'php');
t_contains($inst, 'duplicateRuleIds',
     'A CRS TREE THAT IS ALREADY PRESENT IS READ, NOT TRUSTED: "already '
   . 'present at /etc/serverscrub/waf/coreruleset" was printed in green for a '
   . 'month about a tree Apache was refusing');

// ── A SECOND ruleset that Apache already loads (N4) ────────────────────────
//
// duplicateRuleIds() checks a tree against itself, so it cannot see a CRS
// included from somewhere else -- and cPanel ships a vendor ruleset, so that
// is a configuration to expect on a customer's server. Both trees are valid
// alone; together Apache says
//
//     AH00526: Syntax error on line 818 of .../crs-setup.conf:
//     ModSecurity: Found another rule with the same id
//
// and names the file it was READING, which is ours and is clean. Shakaal
// reproduced exactly that against real ModSecurity 2.9.6 with the distro
// mod_security_crs 3.3.4 installed alongside. The rollback held and nothing
// went live; what was missing was a message an operator could act on.

$ours = $sandbox . '/crs-ours';
@mkdir($ours . '/rules', 0700, true);
file_put_contents($ours . '/crs-setup.conf',
    "SecAction \"id:900990,phase:1,pass,nolog\"\n");
file_put_contents($ours . '/rules/REQUEST-913-SCANNER-DETECTION.conf',
    "SecRule ARGS \"@rx a\" \"id:913100,phase:1,deny\"\n");

$foreignDir = $sandbox . '/crs-foreign';
@mkdir($foreignDir, 0700, true);
file_put_contents($foreignDir . '/crs-setup.conf',
    "SecAction \"id:900990,phase:1,pass,nolog\"\n");

// The scan looks in a fixed list of platform locations; the sandbox is not one
// of them, which is itself worth asserting, because a check that claims to
// have looked everywhere while looking nowhere is the failure mode here.
t_eq([], WAFInstaller::foreignRuleIdCollisions($ours),
     'with no OTHER ruleset in any of the locations it knows about, there is '
   . 'no collision to report -- and it does not invent one from our own tree, '
   . 'which defines 900990 itself');

$globs = WAFInstaller::FOREIGN_RULE_GLOBS;
t_ok(count($globs) >= 5,
     'the places a second ModSecurity ruleset lives are a FIXED LIST, not a '
   . 'search: this runs on a 132-account box and must not become a walk of /etc');
$joined = implode(' ', $globs);
t_contains($joined, 'modsec_vendor_configs',
     "cPanel's vendor directory is one of them — that is the ruleset a cPanel "
   . 'server actually ships');
t_contains($joined, '/etc/httpd/modsecurity.d',
     'and so is the RHEL/AlmaLinux package path, which is where the collision '
   . 'was reproduced');

// The message. With nothing found it must say so, and must NOT imply our tree
// is at fault -- that is the sentence that sent the operator to the wrong file.
WAFInstaller::setCrsPath($ours);
$msg = WAFInstaller::duplicateIdExplanation();
t_ok($msg !== '', 'a duplicate-id rejection is explained rather than passed through raw');
t_contains($msg, 'could not identify',
     'WHEN IT CANNOT TELL, IT SAYS IT CANNOT TELL. "we looked and found '
   . 'nothing" must not be reported as "your tree is broken"');
t_contains($msg, 'defines each of its own ids exactly once',
     'and it states what it DID establish — that our tree is internally '
   . 'consistent — rather than leaving the operator to assume either way');
t_contains($msg, 'modsec_vendor_configs',
     'and names where it looked, so the operator can look somewhere else');

// And when our own tree is the one at fault, it says that instead. The tree is
// passed explicitly here: crsPath() takes crs-setup.conf as the marker that a
// directory IS a CRS tree, and this fixture is only a rules/ directory.
t_contains(WAFInstaller::duplicateIdExplanation($twice), 'itself defines the same id more than once',
     'a tree that really does define an id twice is named as the cause');
WAFInstaller::setCrsPath(null);

$src2 = t_code($repo . '/backend/lib/WAFInstaller.php');
$rej  = t_fn_body($src2, 'rejected', 'php');
t_contains($rej, 'duplicateIdExplanation',
     'and a mode change that Apache refused for a duplicate id carries the '
   . 'explanation, which is the path the operator actually hits');
