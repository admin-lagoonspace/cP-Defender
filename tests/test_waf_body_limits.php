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
 * reaches no server unless the update re-renders it. */
$upd = t_shell($repo . '/update.sh');
t_contains($upd, 'WAFInstaller::reapplyConfig()',
           'update.sh re-renders the WAF config, so new limits reach servers that '
         . 'already have the WAF set up');
t_ok(strpos($upd, 'setMode(WAFInstaller::currentMode())') === false,
     'through reapplyConfig(), not currentMode() fed back into setMode()');
t_ok(strpos($upd, "\\\$_r = WAFInstaller::reapplyConfig()") !== false,
     'with the PHP variables escaped -- the heredoc is unquoted, and an unescaped '
   . '$_r would be expanded by bash to nothing');
