<?php
/**
 * A rejected WAF config must never survive on disk. 132 sites went down
 * because one did.
 *
 * setMode() wrote the config, ran `apachectl -t`, and on failure returned an
 * error — leaving the rejected file exactly where Apache would read it next.
 *
 * Nothing appears to be wrong when that happens. Apache goes on serving the
 * configuration it parsed at its last start, the CLI prints the failure, and
 * the operator reads it as "the mode did not change". The server keeps
 * running. On the production server the file was written at 00:02 and the
 * failure was reported at 05:02.
 *
 * The next restart is what finds out. Ten hours later:
 *
 *     AH00526: Syntax error on line 56 of
 *     /etc/serverscrub/waf/coreruleset/rules/REQUEST-913-SCANNER-DETECTION.conf:
 *     ModSecurity: Found another rule with the same id
 *
 *     httpd.service: Control process exited, code=exited status=1
 *     [RESTART FAILURE] httpd.conf rebuild exited 25 during forced restart
 *
 * cPanel retried three times, rebuilt httpd.conf, and gave up. nginx returned
 * 502 for every one of 132 accounts until the include was moved aside by hand.
 *
 * The duplicate rule id was a separate bug. THIS is the one that took the
 * server down: a failed call that leaves the failure behind, armed, for
 * whenever something next restarts Apache — a kernel update, a cPanel
 * upgrade, a reboot at 3am.
 */

require_once __DIR__ . '/assert.php';
$ctx     = require __DIR__ . '/bootstrap.php';
$repo    = $ctx['repo'];
$sandbox = $ctx['sandbox'];

$cdir = $sandbox . '/wafconf';
$idir = $sandbox . '/wafinc';
@mkdir($cdir, 0700, true);
@mkdir($idir, 0700, true);
WAFInstaller::setConfDir($cdir);
WAFInstaller::setIncludeDir($idir);

$conf = $cdir . '/serverscrub-waf.conf';
$inc  = WAFInstaller::includePath();
t_eq($idir . '/zz-serverscrub-waf.conf', $inc,
     'includePath() resolves to the zz- prefixed include, so it loads after '
   . 'anything else and wins');

// ── A good change still applies ────────────────────────────────────────────

WAFInstaller::setRunner(fn(string $cmd) => ['out' => 'Syntax OK', 'code' => 0]);
$ok = WAFInstaller::setMode('detectiononly');
t_ok(!empty($ok['success']), 'a config Apache accepts is applied');
t_contains((string) @file_get_contents($conf), 'SecRuleEngine DetectionOnly',
           'and is on disk');
t_ok(is_file($inc), 'with the Apache include in place');

$good = (string) @file_get_contents($conf);

// ── A rejected change leaves NOTHING behind ────────────────────────────────

WAFInstaller::setRunner(fn(string $cmd) => [
    'out'  => 'AH00526: Syntax error on line 56 of REQUEST-913-SCANNER-DETECTION.conf'
            . "\nModSecurity: Found another rule with the same id",
    'code' => 1,
]);

$bad = WAFInstaller::setMode('on');
t_ok(empty($bad['success']), 'a config Apache rejects is reported as a failure');
t_ok(!empty($bad['rolled_back']), 'and says it was rolled back');
t_contains($bad['error'], 'rolled back',
           'the operator is told the file was put back, not left to assume either way');
t_contains($bad['error'], 'same id',
           'and Apache\'s own words are passed through — the reason matters');

$after = (string) @file_get_contents($conf);
t_eq($good, $after,
     'THE WHOLE POINT: the file on disk is byte-for-byte what it was before the '
   . 'failed call. The old behaviour left SecRuleEngine On here, and the next '
   . 'restart of Apache — hours or weeks later — failed and took every site on '
   . 'the server down');
t_ok(strpos($after, 'SecRuleEngine On') === false,
     'specifically, the rejected mode is NOT the one left on disk');
t_contains($after, 'SecRuleEngine DetectionOnly',
           'the previously working mode is what Apache will read next');

// ── And a FIRST-EVER failed install leaves no files at all ─────────────────
//
// Restoring "what was there before" has to mean absent, not empty. An empty
// config file and no config file are different things to Apache, and a
// zero-byte include would be a no-op that looks like an install.

@unlink($conf);
@unlink($inc);
$first = WAFInstaller::setMode('on');
t_ok(empty($first['success']), 'the first install also fails when Apache rejects it');
t_ok(!is_file($conf),
     'and leaves NO config file, rather than an empty one — there was none before');
t_ok(!is_file($inc),
     'and no Apache include, so Apache is in exactly the state it was in');

// ── If the restored config is ALSO broken, say so now ──────────────────────
//
// The restore puts back whatever was there. If that was already unparseable,
// the operator is one restart away from the same outage and has to hear it
// while they are looking at a terminal.

t_contains($bad['error'] . ' ', 'rolled back', 'sanity: the earlier failure is the one with the message');
$src = t_code($repo . '/backend/lib/WAFInstaller.php');
t_contains($src, '$after = self::validateApache();',
           'the restored config is validated too');
t_contains($src, 'the restored config does not validate either',
           'and a restore that is itself broken is reported, not assumed good');

// ── Structure: the rollback cannot be skipped ──────────────────────────────

$snapPos  = strpos($src, '$snap = self::snapshotConfig();');
$writePos = strpos($src, '$r = self::writeConfig($m, self::crsPath());');
t_ok($snapPos !== false && $writePos !== false, 'both calls are present');
t_ok($snapPos < $writePos,
     'the snapshot is taken BEFORE the write. Taken after, it would capture the '
   . 'broken config and "restoring" it would be a no-op');

t_contains($src, 'if (!$r[\'success\']) { self::restoreConfig($snap); return $r; }',
           'a write that fails part way through also rolls back: writeConfig() '
         . 'writes the config first and the include second, so it can leave the '
         . 'config replaced and the include missing');

t_contains($src, 'is_file($p) ? (string) @file_get_contents($p) : null',
           'a file that does not exist is snapshotted as null, not as an empty string');
t_contains($src, 'if ($contents === null) { @unlink($p); continue; }',
           'and null restores to absent');

// ── The reload still never runs on a config that failed ────────────────────

$valPos    = strpos($src, '$v = self::validateApache();');
$reloadPos = strpos($src, 'self::reloadApache();');
t_ok($valPos !== false && $reloadPos !== false, 'validate and reload are both present');
t_ok($valPos < $reloadPos,
     'validation still precedes the reload. This part was always right — it is '
   . 'why Apache kept running and the breakage stayed invisible until a restart');
