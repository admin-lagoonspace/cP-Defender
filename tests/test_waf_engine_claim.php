<?php
/**
 * "ModSecurity is installed and logging matches" — WITH NO RULE FILES.
 *
 * The WAF card rendered all of this at once, on a server where the OWASP CRS
 * directory existed and was empty:
 *
 *     WAF ENGINE   Installed
 *     ModSecurity is installed and logging matches, but not blocking them yet.
 *     ModSecurity   installed package ea-apache24-mod_security2 is not installed
 *     OWASP CRS     vunknown
 *     … The OWASP CRS directory … holds no rule files that could be read.
 *
 * Two defects, both in the logic rather than the fixture:
 *
 *  1. `crs_installed` was `crsPath() !== null`, which tests only that a
 *     DIRECTORY exists. A rule engine with no rules inspects nothing, logs
 *     nothing and blocks nothing, and the card asserted it was logging
 *     matches. `ready` was derived from that, so the badge went green-ish and
 *     the install button disappeared.
 *  2. `modsecVersion()` ran `rpm -q --qf "%{VERSION}" … 2>/dev/null`. rpm
 *     prints `package <name> is not installed` on STDOUT and exits 1, so the
 *     wrong stream was redirected and the exit code was never read — and that
 *     sentence was returned as a version number.
 *
 * WHY THIS HELD A RELEASE. It is a protection claim the product has not
 * verified, which is the same failure shape as `setMode()` reporting success
 * for a config Apache had rejected — that took host.lws-s1.com down for two
 * minutes across 132 accounts on 2026-11-07 and cost the operator a customer.
 * That server has one line of defence and no CPGuard, and the April ransomware
 * went unnoticed for six months partly because nothing contradicted the
 * impression that things were fine. A green state nobody has earned is how
 * that happens.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

// ── Counting what is actually there ────────────────────────────────────────

$empty = $sandbox . '/crs-empty';
@mkdir($empty . '/rules', 0700, true);
file_put_contents($empty . '/crs-setup.conf', "SecDefaultAction \"phase:1,log\"\n");

t_eq(0, WAFInstaller::crsRuleFileCount($empty),
     'A TREE HOLDING ONLY crs-setup.conf HAS NO RULES. Setup is configuration; '
   . 'it matches nothing. This is the state the panel called "installed and '
   . 'logging matches"');

$full = $sandbox . '/crs-full';
@mkdir($full . '/rules', 0700, true);
file_put_contents($full . '/crs-setup.conf', "SecDefaultAction \"phase:1,log\"\n");
file_put_contents($full . '/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
    "SecRule ARGS \"@rx select\" \"id:942100,phase:2,deny\"\n");
file_put_contents($full . '/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf',
    "SecRule ARGS \"@rx <script\" \"id:941100,phase:2,deny\"\n");
t_eq(2, WAFInstaller::crsRuleFileCount($full),
     'and a tree with two rule files has two, counted from the files rather '
   . 'than inferred from the directory existing');

file_put_contents($full . '/rules/EMPTY.conf', '');
t_eq(2, WAFInstaller::crsRuleFileCount($full),
     'a zero-byte .conf is not a rule file either: it would have inflated the '
   . 'count that the claim now rests on');

t_eq(0, WAFInstaller::crsRuleFileCount(null),
     'and no tree at all is zero, not an error, so the caller has one number '
   . 'to reason about');
t_eq(0, WAFInstaller::crsRuleFileCount($sandbox . '/does-not-exist'),
     'as is a path that is not there');

// ── The sentence the operator reads ────────────────────────────────────────

$claim = function (bool $modsec, ?string $crs, int $files, string $mode,
                   bool $ours = false, bool $inc = true) {
    return WAFInstaller::engineClaim($modsec, $crs, $files, $mode, $ours, $inc);
};

t_contains($claim(true, '/etc/crs', 0, 'detectiononly'), 'NO RULE FILES',
     'THE CLAIM FOLLOWS FROM THE RULES. With a rule set directory and no rule '
   . 'files in it, the card says so in those words');
t_contains($claim(true, '/etc/crs', 0, 'detectiononly'), 'nothing is being logged',
     'and states the consequence — nothing inspected, nothing logged, nothing '
   . 'blocked — instead of "installed and logging matches"');
t_contains($claim(true, '/etc/crs', 0, 'detectiononly'), 'not protection',
     'and refuses the word protection for it. An operator skimming a card '
   . 'needs the one-line verdict to be the true one');

t_contains($claim(true, '/etc/crs', 31, 'detectiononly'), '31 rule file(s)',
     'with rules present and the engine in DetectionOnly it says what it is '
   . 'logging against, and how many files that is');
t_contains($claim(true, '/etc/crs', 31, 'detectiononly'), 'not blocking',
     'and that it is not blocking, which is the honest version of the old '
   . 'sentence');
t_contains($claim(true, '/etc/crs', 31, 'on'), 'enforcing',
     'and in On it says enforcing');

t_contains($claim(true, null, 0, 'on'), 'no OWASP Core Rule Set was found',
     'ModSecurity present with no rule set at all is its own case, named');
t_contains($claim(false, null, 0, 'unknown'), 'No web application firewall',
     'and nothing installed is still offered the install');

t_contains($claim(true, '/etc/crs', 31, 'unknown'), 'could not be read',
     'A MODE IT COULD NOT READ IS NOT DetectionOnly. The old card fell through '
   . 'to "installed and logging matches" for an unknown mode, which is a claim '
   . 'about behaviour made from a failure to read the configuration');
t_contains($claim(true, '/etc/crs', 31, 'off'), 'rule engine is OFF',
     'and an engine switched off says so rather than reading as installed');

t_contains($claim(true, '/etc/crs', 31, 'on', true, false), 'NOT included by Apache',
     'AND A MODE THAT IS NOT IN FORCE IS NOT A MODE. Our config with the '
   . 'include gone -- which install()\'s failure path leaves behind -- is a '
   . 'blocking WAF filtering no requests. status() has reported '
   . 'include_present all along and the card ignored it');

// ── rpm's exit code ────────────────────────────────────────────────────────

$src = t_code($repo . '/backend/lib/WAFInstaller.php');
$ver = t_fn_body($src, 'modsecVersion', 'php');

t_ok(strpos($ver, 'shell_exec') === false,
     'THE VERSION IS NO LONGER WHATEVER rpm PRINTED. shell_exec() hands back '
   . 'stdout with no exit code at all, and rpm writes "package … is not '
   . 'installed" to stdout and exits 1');
t_contains($ver, '$rc === 0',
     'the exit code is checked');
t_contains($ver, 'preg_match(\'/^[0-9]',
     'and the output has to look like a version before it is believed, '
   . 'because a command can exit 0 and still print prose');
t_ok(strpos($ver, "return null;") !== false,
     'and when it cannot tell, it returns null rather than a sentence. '
   . '"installed, version unknown" is true; "installed package … is not '
   . 'installed" was not');

// ── Where the claim is composed ────────────────────────────────────────────

$st = t_fn_body($src, 'status', 'php');
t_contains($st, "'ready'",
     'readiness is decided in PHP, in one place, from the rule count');
t_contains($st, 'crsRuleFileCount',
     'and it is the rule count that decides it');
t_contains($st, "'claim'",
     'and the operator-facing sentence travels with the data rather than being '
   . 'assembled in the browser from two booleans that could not express the '
   . 'empty-tree case');

$app = t_js($repo . '/frontend/js/app.js');
$card = t_fn_body($app, 'loadWafEngine', 'js');
t_contains($card, 'd.claim',
     'THE CARD RENDERS THE ENGINE\'S OWN SENTENCE. It composed its own from '
   . '`modsecurity_installed && crs_installed`, and no arrangement of those '
   . 'two booleans can say "the directory is there and has nothing in it"');
t_contains($card, '!!d.ready',
     'and takes readiness from the same source, so the badge, the sentence and '
   . 'the install button cannot disagree with each other');
t_contains($card, 'No rules loaded',
     'with a badge for the state that was being rendered as "Installed"');
t_ok(strpos($card, 'installed and logging matches') === false,
     'and the sentence that was false is gone from the browser entirely');
t_contains($card, 'version unknown',
     'and an unknown version is shown as unknown rather than as rpm\'s error');
