<?php
/*
 * The WAF's request-body limits, and getting a change to them onto servers.
 *
 * 4.37.0 wrote SecRequestBodyNoFilesLimit 131072 with LimitAction Reject.
 * Elementor and Gutenberg save a page as one form/JSON body, so on
 * usefulblogs.com every save of a page past 128 KB came back as
 * "Server Error 413" -- and raising ModSecurity's limits in cPanel's own
 * modsec2.user.conf changed nothing, because our include is loaded later
 * and wins.
 */
require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

$cdir = $sandbox . '/wafconf-limits';
$idir = $sandbox . '/wafinc-limits';
@mkdir($cdir, 0700, true);
@mkdir($idir, 0700, true);
WAFInstaller::setConfDir($cdir);
WAFInstaller::setIncludeDir($idir);
WAFInstaller::setRunner(fn(string $cmd) => ['out' => 'Syntax OK', 'code' => 0]);

$set = WAFInstaller::setMode('on');
t_ok(!empty($set['success']), 'the config is written against the sandbox');
$conf = (string) @file_get_contents($cdir . '/serverscrub-waf.conf');

$limit = function (string $directive) use ($conf): ?int {
    return preg_match('/^\s*' . $directive . '\s+(\d+)\s*$/m', $conf, $m) ? (int) $m[1] : null;
};

$nofiles = $limit('SecRequestBodyNoFilesLimit');
t_ok($nofiles !== null && $nofiles >= 10 * 1024 * 1024,
     'a page-builder save of up to 10 MB is not rejected -- 128 KB was the 413 on '
   . 'usefulblogs.com (got ' . var_export($nofiles, true) . ')');

$total = $limit('SecRequestBodyLimit');
t_ok($total !== null && $total >= 128 * 1024 * 1024,
     'uploads are allowed up to ea-nginx\'s own 128 MB default, so the WAF is never '
   . 'the tighter layer (got ' . var_export($total, true) . ')');
t_ok($total !== null && $nofiles !== null && $nofiles <= $total,
     'and the no-files limit does not exceed the total -- ModSecurity refuses to start '
   . 'when it does');

$mem = $limit('SecRequestBodyInMemoryLimit');
t_ok($mem !== null && $mem <= 1024 * 1024,
     'memory stays bounded: bodies past the in-memory limit spool to disk');

/* The config is generated, not shipped, so a limit change in a release
 * reaches no server unless the update re-renders it. And it must be the NEW
 * code that does so: an update runs the installed (old) update.sh, which only
 * re-execs a copy of itself, but calls the freshly installed
 * install.sh --register-only. 4.37.1 put the step in update.sh, where it
 * would only have run one release later. */
$inst = t_shell($repo . '/install.sh');
$upd  = t_shell($repo . '/update.sh');
t_contains($inst, 'WAFInstaller::reapplyConfig()',
           'install.sh re-renders the WAF config, so new limits reach servers that '
         . 'already have the WAF set up on the update that ships them');
t_ok((bool) preg_match('/if \$REGISTER_ONLY && \[\[ -f \/etc\/serverscrub\/waf\/serverscrub-waf\.conf \]\]/', $inst),
     'only on --register-only (the update path) and only where a WAF config exists -- '
   . 'a fresh install has no database or WAF yet');
t_ok(strpos($inst, "<<'WAFEOF'") !== false,
     'the PHP is in a QUOTED heredoc, so bash cannot expand its $variables to nothing');
t_ok(strpos($upd, 'reapplyConfig') === false,
     'and update.sh does not do it as well -- that would reload Apache twice per update');
t_ok(strpos($inst . $upd, 'setMode(WAFInstaller::currentMode())') === false,
     'through reapplyConfig(), not currentMode() fed back into setMode()');
t_ok(strpos($upd, 'install.sh" --register-only') !== false,
     'update.sh still calls install.sh --register-only, which is what makes this run');

/* Large WordPress editor saves skip body inspection -- the CRS rules that
 * scan them are quadratic in field length. The exact four-link chain below
 * was run against ModSecurity 2 + CRS 4.7.0: large+logged-in on an editor
 * endpoint uninspected; small, cookieless and non-editor requests inspected. */
$expected = <<<'RULE'
    SecRule REQUEST_FILENAME "@rx /(?:wp-admin/(?:admin-ajax|post)\.php|wp-json/wp/v2/)" \
        "id:30100,phase:1,pass,nolog,chain"
        SecRule REQUEST_HEADERS:Content-Length "@gt 65536" "chain"
        SecRule REQUEST_HEADERS:Content-Type "!@rx ^multipart/" "chain"
        SecRule REQUEST_COOKIES_NAMES "@rx ^wordpress_logged_in_" "ctl:requestBodyAccess=Off"
RULE;
t_contains(str_replace("\r\n", "\n", $conf), $expected,
           'the editor-save rule is rendered exactly as it was validated against ModSecurity');
$starter = preg_match('/"id:30100,[^"]*"/', $conf, $m) ? $m[0] : '';
t_ok($starter !== '' && strpos($starter, 'ctl:') === false,
     'ctl is not on the chain starter -- there it fires on the first link alone and '
   . 'switched body inspection off for every admin-ajax.php request');
t_ok(30100 > WAFExclusions::CUSTOM_ID_MAX && 30100 > WAFExclusions::ID_CEIL,
     'id 30100 is outside both the generated-exclusion and the custom-rule bands, so '
   . 'neither can collide with it');
