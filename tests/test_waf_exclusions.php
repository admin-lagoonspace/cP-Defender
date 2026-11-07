<?php
/**
 * An operator must be able to arm the WAF without breaking one customer's site.
 *
 * On the live server, rule 420047 is "Bad user-agent (Mozilla/5.0)": 617
 * hits across 150 sites, firing on /livewire/update, / and /wp-login.php.
 * A Laravel Livewire endpoint and two ordinary pages — real visitors, matched
 * on a User-Agent string half the web sends.
 *
 * With no exclusion mechanism the only two options were to leave the engine
 * in DetectionOnly across all 132 accounts, or arm it and break application
 * traffic on 150 of them.
 *
 * The shopfront.test / 420047 / checkout case below is a FIXTURE, not a
 * production observation. It is the shape triage classifies as a
 * false-positive risk, written small enough to assert on. What the mechanism
 * has to get right either way:
 *
 *  - a narrowed exclusion must NOT disable the rule for the other 131
 *    accounts, which is what SecRuleRemoveById would do;
 *  - the exclusion must survive `waf mode on`, because writeConfig()
 *    regenerates the config from scratch and anything held only in that file
 *    is erased at the moment it matters;
 *  - the fields reach an Apache config file, so a quote in a URI must be
 *    refused rather than written.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];
require_once $repo . '/backend/lib/WAFTriage.php';

// ── Input that would end up inside an Apache directive ─────────────────────

t_ok(!WAFExclusions::add('not-a-number')['success'],
     'a non-numeric rule id is refused — it becomes a SecRuleRemoveById argument');
t_ok(!WAFExclusions::add('420047', 'exa mple.com')['success'],
     'and a hostname with a space is refused');
t_ok(!WAFExclusions::add('420047', '', 'shop/checkout')['success'],
     'a URI prefix without a leading slash is refused: @beginsWith would never match');
t_ok(!WAFExclusions::add('420047', '', '/shop" "id:1,phase:1,allow')['success'],
     'a URI prefix containing a quote is refused rather than escaped — it would '
   . 'otherwise close the directive and start one that allows everything');
t_ok(!WAFExclusions::add('420047', '', "/shop\nSecRuleEngine Off")['success'],
     'and a newline is refused for the same reason');

// ── Nothing excluded means a config identical to the one before this existed ─

t_eq('', WAFExclusions::render(),
     'with no exclusions the config gains nothing at all');

// ── The narrowed case: one rule, one site ──────────────────────────────────

$r = WAFExclusions::add('420047', 'shopfront.test', '/shop/checkout',
                        'real checkout traffic, triage 2026-11-06');
t_ok($r['success'], 'the checkout exclusion is accepted');
t_ok($r['scoped'], 'and is reported as narrowed, not server-wide');

$conf = WAFExclusions::render();
t_contains($conf, 'ctl:ruleRemoveById=420047',
           'it disables the rule per request, which is the only form that can be '
         . 'conditional on the host');
t_contains($conf, '@streq shopfront.test', 'for that host');
t_contains($conf, '@beginsWith /shop/checkout', 'and only on that path');
t_contains($conf, 'chain', 'host and path together are expressed as a chain');
t_ok(strpos($conf, 'SecRuleRemoveById 420047') === false,
     'and NOT as SecRuleRemoveById, which would have switched rule 420047 off '
   . 'for all 132 accounts to protect one shop');
t_contains($conf, 'phase:1',
     'the ctl runs in phase 1, ahead of the phase-2 rules false positives come from');

// ── Generated rule ids cannot collide with the CRS ──────────────────────────

preg_match('/id:(\d+)/', $conf, $m);
$genId = (int) ($m[1] ?? 0);
t_ok($genId >= WAFExclusions::ID_BASE && $genId <= WAFExclusions::ID_CEIL,
     'the generated rule id sits in the 1-99999 band reserved for local use, so '
   . 'it cannot collide with a CRS rule (900000+) and silently replace it');
t_ok($genId < 900000, 'and is nowhere near the CRS range');

// ── The server-wide case, and the duplicate case ───────────────────────────

$g = WAFExclusions::add('913100', '', '', 'scanner rule, noisy everywhere');
t_ok($g['success'], 'a server-wide exclusion is accepted');
t_ok(!$g['scoped'], 'and is reported as server-wide so the caller can warn');
t_contains(WAFExclusions::render(), 'SecRuleRemoveById 913100',
           'a server-wide exclusion drops the rule at startup rather than per request');

$dupe = WAFExclusions::add('913100', '', '', 'again');
t_ok(!$dupe['success'],
     'the same rule and scope twice is refused — two identical directives is a '
   . 'config Apache may reject, and the operator would not know which won');
t_eq($g['id'], $dupe['existing'], 'and the refusal names the exclusion already there');

// ── describe() must not make a server-wide exclusion look narrow ───────────

t_contains(WAFExclusions::describe(WAFExclusions::get($g['id'])), 'EVERY site',
           'a server-wide exclusion says so in plain words: the difference between '
         . 'this and a scoped one is 131 accounts');

// ── Surviving a mode change, which is the reason this is in the database ────

$cdir = $sandbox . '/wafconf';
$idir = $sandbox . '/wafinc';
@mkdir($cdir, 0700, true);
@mkdir($idir, 0700, true);
WAFInstaller::setConfDir($cdir);
WAFInstaller::setIncludeDir($idir);
// apachectl does not exist here. Report a successful syntax check so the write
// path runs to completion; the write itself is what is under test.
WAFInstaller::setRunner(fn(string $cmd) => ['out' => 'Syntax OK', 'code' => 0]);

$set = WAFInstaller::setMode('detectiononly');
t_ok(!empty($set['success']), 'the mode change completes against the sandbox config dir');

$written = (string) @file_get_contents($cdir . '/serverscrub-waf.conf');
t_contains($written, 'SecRuleEngine DetectionOnly', 'the config holds the requested mode');
t_contains($written, 'ctl:ruleRemoveById=420047',
           'and the checkout exclusion is in the generated file — this is the whole '
         . 'point: writeConfig() rebuilds this file from scratch, so an exclusion '
         . 'kept only in the file would be erased by the next `waf mode on`');
t_contains($written, 'SecRuleRemoveById 913100',
           'as is the server-wide one');

$armed = WAFInstaller::setMode('on');
t_ok(!empty($armed['success']), 'arming the engine succeeds');
$written2 = (string) @file_get_contents($cdir . '/serverscrub-waf.conf');
t_contains($written2, 'SecRuleEngine On', 'the engine is now armed');
t_contains($written2, 'ctl:ruleRemoveById=420047',
           'and the exclusion is still there after arming — the one moment it must '
         . 'not be lost');

// ── Exclusions must load after the rules they exclude ──────────────────────

$src = t_code($repo . '/backend/lib/WAFInstaller.php');
t_contains($src, '{$rules}{$excl}',
           'the exclusion block is emitted after the CRS include: SecRuleRemoveById '
         . 'can only remove a rule that has already been defined');
t_contains($src, 'WAFExclusions::render()',
           'and writeConfig() renders them rather than trusting the file on disk');
t_contains($src, 'catch (Throwable $e)',
     'a render failure aborts the write. Writing a config without an exclusion '
   . 'would arm a rule the operator switched off against a live site, so refusing '
   . 'the mode change is the safe failure');
t_contains($src, "require_once __DIR__ . '/WAFExclusions.php'",
     'required at the top of the file — an inline require fatals silently in cron, '
   . 'which is what preflight checks for');

// ── Removal reaches the config too ─────────────────────────────────────────

$rm = WAFExclusions::remove((int) $g['id']);
t_ok($rm['success'], 'an exclusion can be removed');
t_ok(strpos(WAFExclusions::render(), 'SecRuleRemoveById 913100') === false,
     'and is gone from what would be written');
t_ok(!WAFExclusions::remove(999999)['success'],
     'removing an id that does not exist is an error, not a silent success');

// ── The suggested command triage prints ────────────────────────────────────

t_eq('/shop/checkout', WAFTriage::uriPrefix('/shop/checkout?step=2&token=abc'),
     'the query string is dropped from a suggested --uri=: @beginsWith matches '
   . 'REQUEST_URI including the query, so an exclusion carrying ?step=2 would '
   . 'stop working as soon as the parameters differed');
t_eq('', WAFTriage::uriPrefix('/'), 'a bare / suggests nothing — it would exclude everything');
t_eq('', WAFTriage::uriPrefix('/shop/"x'), 'and a quoted path suggests nothing');

$rep = [
    'generated_at' => time(), 'window_days' => 7, 'engine_mode' => 'DetectionOnly',
    'totals' => ['events' => 6, 'rules' => 1, 'ips' => 1, 'hosts' => 1],
    'notes'  => [], 'hosts' => [], 'attackers' => [],
    'rules'  => [[
        'rule_id' => '420047', 'rule_msg' => 'Possible SQLi', 'severity' => 'CRITICAL',
        'hits' => 6, 'ips' => 1, 'hosts' => 1, 'verdict' => 'false-positive-risk',
        'why' => 'Confined to one site and 1 address(es).',
        'uri_sample' => [['uri' => '/shop/checkout', 'hits' => 6]],
        'top_hosts'  => [['h' => 'shopfront.test', 'c' => 6]],
    ]],
];
$txt = WAFTriage::text($rep);
t_contains($txt, 'waf exclude add 420047 --domain=shopfront.test',
           'triage prints the exact command for the rule it says would break a site — '
         . 'retyping the rule id by hand is how the wrong rule gets disabled');
t_contains($txt, '--uri=/shop/checkout',
           'and offers the narrower form scoped to the path it actually fired on');

// A rule triage calls safe must not come with a command to switch it off.
$rep['rules'][0]['verdict'] = 'arm';
t_ok(strpos(WAFTriage::text($rep), 'waf exclude add') === false,
     'a rule triage judges safe to arm carries no exclusion suggestion');
