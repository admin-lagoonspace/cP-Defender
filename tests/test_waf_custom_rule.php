<?php
/**
 * The custom-rule route was the 7 Nov outage, in a path the rollback fix
 * never touched.
 *
 * WAF::addCustomRule() appended a rule to a file Apache loads, ran
 * `service httpd graceful`, and returned ['success' => true] unconditionally:
 *
 *     $rule = sprintf('SecRule ... "id:%s,phase:2,deny,..."', ...);
 *     file_put_contents($confPath, $rule, FILE_APPEND);
 *     exec('service httpd graceful 2>/dev/null || service apache2 graceful 2>/dev/null');
 *     return ['success' => true];
 *
 * No syntax check anywhere, the return of neither the write nor the restart
 * examined, and any string accepted as the id -- while the API defaulted the
 * id to uniqid('SG'), so the ordinary call wrote
 *
 *     id:SG6910abc12def3
 *
 * ModSecurity rule ids are numeric. That is a syntax error, written into a
 * config registered with cPanel's modsec2.user.conf (install.sh:1121), and
 * then Apache was restarted. One API call, 132 accounts, 502.
 *
 * ── AND THE TWO FEATURES COULD COLLIDE ───────────────────────────────────────
 *
 * WAFExclusions generates host/path exclusion rules of its own. Its docblock
 * reserved 15,000+ for itself and said everything below was "for anything
 * hand-written and for WAF::addCustomRule(), where the operator picks the
 * id" -- but addCustomRule() validated nothing, so a custom rule at id:15001
 * was accepted. Shakaal planted exactly that and reproduced the production
 * error:
 *
 *     ModSecurity: Found another rule with the same id (id:15001)
 *
 * which is Apache refusing the WHOLE configuration. So the bands are disjoint
 * now and enforced at both ends, and the id is also checked against what has
 * actually been written.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

$cdir = $sandbox . '/cr-conf';
$idir = $sandbox . '/cr-inc';
@mkdir($cdir, 0700, true);
@mkdir($idir, 0700, true);
WAFInstaller::setConfDir($cdir);
WAFInstaller::setIncludeDir($idir);

$rulesPath = $sandbox . '/cr-modsec/serverscrub/custom_rules.conf';
WAF::setCustomRulesPath($rulesPath);
$waf = new WAF();

// Every command the product ran, so "did it reload Apache?" is a question with
// an answer rather than an assumption.
$cmds = [];
$accept = function (string $cmd) use (&$cmds) {
    $cmds[] = $cmd;
    return ['out' => 'Syntax OK', 'code' => 0];
};
WAFInstaller::setRunner($accept);

// ── The bands are disjoint, by construction ────────────────────────────────

t_ok(WAFExclusions::ID_CEIL < WAFExclusions::CUSTOM_ID_MIN,
     'the generated-exclusion band ends before the custom-rule band begins. '
   . 'Two rule writers sharing one band is a duplicate id, and a duplicate id '
   . 'is Apache refusing every site on the server at its next restart');

// ── The id ─────────────────────────────────────────────────────────────────

$sg = $waf->addCustomRule(uniqid('SG'), 'evil');
t_ok(empty($sg['success']),
     'THE API DEFAULT IS REFUSED: uniqid("SG") is not a ModSecurity id, and it '
   . 'was what the route used when the caller sent none');
t_contains((string) $sg['error'], 'digits only',
     'and the reason says what an id has to be');
t_ok(!is_file($rulesPath),
     'and nothing was written at all — the rejected id never reached the file '
   . 'Apache loads');

t_ok(empty($waf->addCustomRule('15001', 'evil')['success']),
     'THE COLLISION: id 15001 is refused. It is inside the band the exclusion '
   . 'generator emits into, and planting a rule there reproduced '
   . '"Found another rule with the same id" on a real config');
t_contains((string) $waf->addCustomRule('15001', 'evil')['error'], 'reserved',
     'and the operator is told the range is reserved rather than just "no"');

t_ok(empty($waf->addCustomRule('913100', 'evil')['success']),
     'a CRS id is refused too: 913100 is the rule that was defined twice on the '
   . 'production server on 7 Nov');
t_ok(empty($waf->addCustomRule('99', 'evil')['success']),
     'and so is an id below the band, which may belong to a rule the operator '
   . 'wrote by hand years ago');

// The band check alone would do it. This is the check that still holds when
// somebody widens a band later.
$ex = WAFExclusions::add('420047', 'shop.test', '/shop/checkout', 'fixture');
t_ok($ex['success'], 'an exclusion exists, so a generated id exists');
$genId = WAFExclusions::ID_BASE + (int) $ex['id'];
t_eq($genId, WAFExclusions::generatedIds()[0] ?? null,
     'and the product can say which rule ids it generates');
t_ok($waf->ruleIdInUse($genId) !== null,
     'that id is reported as in use, independently of which band it is in');

// ── The pattern and the action ─────────────────────────────────────────────

t_ok(empty($waf->addCustomRule('20001', '')['success']),
     'a rule with no pattern is refused');
t_ok(empty($waf->addCustomRule('20001', 'x" "id:1,phase:1,allow')['success']),
     'a pattern containing a quote is REFUSED rather than escaped: addslashes() '
   . 'was all that stood between it and the quoted directive it is pasted '
   . 'into, and a quote there ends the directive and starts one that allows '
   . 'everything');
t_ok(empty($waf->addCustomRule('20001', 'un(ion')['success']),
     'and a pattern that is not a valid regex is refused, because ModSecurity '
   . 'would refuse it at load time -- which means at the next restart');
t_ok(empty($waf->addCustomRule('20001', 'union.*select', 'maim')['success']),
     'an action that is not block or log is refused instead of silently '
   . 'becoming deny');

// ── The happy path, and what it claims ─────────────────────────────────────

$cmds = [];
$ok = $waf->addCustomRule('20010', 'union.*select', 'block');
t_ok(!empty($ok['success']), 'a numeric in-band id with a usable pattern is added');
$body = (string) @file_get_contents($rulesPath);
t_contains($body, 'id:20010', 'the rule is in the file');
t_contains($body, '@rx union.*select', 'with the pattern as an explicit @rx');
t_contains($body, 'deny,status:403', 'and block means deny');
t_eq(true, $ok['live'] ?? null,
     'and the result says whether Apache actually re-read it: a rule on disk '
   . 'that Apache has not loaded is filtering nothing');

$validatedBefore = false;
foreach ($cmds as $c) {
    if (strpos($c, '-t') !== false) { $validatedBefore = true; }
    if (strpos($c, 'graceful') !== false || strpos($c, 'restartsrv') !== false
        || strpos($c, 'reload') !== false) {
        t_ok($validatedBefore,
             'APACHE IS RELOADED ONLY AFTER A SYNTAX CHECK HAS RUN. The old '
           . 'code restarted Apache with no check at all, which is how a '
           . 'config nobody had parsed became 132 accounts at 502');
        break;
    }
}
t_ok($validatedBefore, 'a syntax check ran at all');

// The same id twice is the production error, so the second one is refused.
$dupe = $waf->addCustomRule('20010', 'something.else');
t_ok(empty($dupe['success']),
     'the same id a second time is refused: it is already in the file, and '
   . 'Apache answers a duplicate with "Found another rule with the same id" '
   . 'and refuses the entire configuration');
t_contains((string) $dupe['error'], 'already used', 'and says where it is used');

// 'log' was accepted and then ignored -- every rule was deny. An operator who
// asked to log and got blocking finds out from their customers.
$log = $waf->addCustomRule('20011', 'curl/7', 'log');
t_ok(!empty($log['success']), 'a log-only rule is added');
$body = (string) @file_get_contents($rulesPath);
t_contains($body, 'id:20011,phase:2,pass,log', 'and is pass,log, not deny');

// ── A rejected rule leaves the file exactly as it was ──────────────────────

$before = (string) @file_get_contents($rulesPath);
$cmds   = [];
WAFInstaller::setRunner(function (string $cmd) use (&$cmds) {
    $cmds[] = $cmd;
    if (strpos($cmd, '-t') !== false) {
        return ['out' => "AH00526: Syntax error on line 3 of custom_rules.conf"
                       . "\nModSecurity: Found another rule with the same id", 'code' => 1];
    }
    return ['out' => '', 'code' => 0];
});
$bad = $waf->addCustomRule('20012', 'wp-login', 'block');
t_ok(empty($bad['success']),
     'A FAILURE IS REPORTED AS A FAILURE: the old version returned success '
   . 'unconditionally');
t_contains((string) $bad['error'], 'same id',
     "and passes through Apache's own words");
t_eq($before, (string) @file_get_contents($rulesPath),
     'THE WHOLE POINT: the file is byte-for-byte what it was before the '
   . 'rejected rule. Left behind, it is a config Apache refuses, waiting for '
   . 'the next restart to find it');
t_ok(!empty($bad['rolled_back']), 'and the rollback is reported, having been verified');
foreach ($cmds as $c) {
    t_ok(strpos($c, 'graceful') === false && strpos($c, 'restartsrv') === false,
         'NOTHING RELOADED APACHE after the rule was rejected');
}

// ── No syntax checker is not a rejection by Apache ────────────────────────

WAFInstaller::setRunner(function (string $cmd) { return ['out' => '', 'code' => 127]; });
$none = $waf->addCustomRule('20013', 'xmlrpc', 'block');
t_ok(empty($none['success']), 'with nothing to check with, the rule is not applied');
t_ok(strpos((string) $none['error'], 'Apache rejected') === false,
     'and Apache is not quoted as having rejected something it was never '
   . 'shown. "Could not check" and "checked and refused" are different facts');
t_eq($before, (string) @file_get_contents($rulesPath),
     'the file is unchanged either way');

// ── Structure: the unchecked restart is gone ──────────────────────────────

$src = t_code($repo . '/backend/lib/WAF.php');
t_ok(strpos($src, "service httpd graceful") === false,
     'the unchecked `service httpd graceful` is gone from this file: reloading '
   . 'Apache is WAFInstaller::reloadApache(), which reports whether anything '
   . 'actually reloaded');
$fn = t_fn_body($src, 'addCustomRule', 'php');
$vPos = strpos($fn, 'validateApache');
$rPos = strpos($fn, 'reloadApache');
t_ok($vPos !== false && $rPos !== false && $vPos < $rPos,
     'the syntax check precedes the reload in the source, not just in this '
   . 'run: a reload of a config nobody parsed is the outage');
t_contains($fn, 'restoreConfig',
     'and the rollback goes through the one verified restore, rather than a '
   . 'second copy of it');
