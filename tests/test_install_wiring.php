<?php
/**
 * The installer's wiring, asserted from the script itself.
 *
 * Every failure below was seen in a single production install run, and none of
 * them was caught by anything in the pipeline, because the shell scripts run on
 * the customer's server and nothing here had an opinion about their contents.
 *
 *   [INFO]  Detected firewall backend: Usage: php-cgi [-q] [-h] ...
 *           Error in argument 1, char 2: option not found r
 *   install.sh: line 622: : No such file or directory
 *   [WARN]  No ClamAV signature database found   (right after downloading them)
 *   warn [install_plugin] ... lacks the required parameter "icon"
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

/**
 * Shell source with whole-line `#` comments removed.
 *
 * Needed because this file explains the bugs it guards against by quoting them,
 * and those quotes live in install.sh's comments too -- so a search for
 * `>> "${MANIFEST}"` or `pgrep -x cpsrvd` found the prose describing the bug
 * and concluded the bug was still there. Assertions must read code.
 */
function sh_code(string $path): string
{
    $out = [];
    foreach (file($path) as $line) {
        if (preg_match('/^\s*#/', $line)) {
            continue;
        }
        $out[] = $line;
    }
    return implode('', $out);
}

$installRaw = file_get_contents($repo . '/install.sh');
$install    = sh_code($repo . '/install.sh');
$test       = sh_code($repo . '/test.sh');

// ── A real CLI PHP is resolved, and nothing bypasses it ──────────────────────
// /usr/bin/php on a cPanel box is routinely a symlink to php-cgi, which rejects
// -r outright and prints its usage instead. FirewallEngine::backendInfo() was
// invoked that way, so the "detected backend" was a php-cgi help screen.
t_contains($install, 'SG_PHP=""', 'a PHP binary is resolved into SG_PHP');
t_contains($install, "echo PHP_SAPI;",
    'candidates are asked what SAPI they are rather than trusted by name');
t_contains($install, '== "cli"', 'and only a cli SAPI is accepted');

$sapiPos = strpos($install, 'echo PHP_SAPI;');
t_ok($sapiPos !== false, 'the SAPI probe exists');

// After the resolver, no invocation may reach for php by a bare or fixed name.
$after = substr($install, $sapiPos);
$stray = [];
foreach (explode("\n", $after) as $i => $line) {
    if (strpos($line, '#') === 0 || trim($line) === '') {
        continue;
    }
    // Comments explaining the problem are allowed to mention the paths.
    $code = preg_replace('/#.*$/', '', $line);
    if (preg_match('#(^|[^-\w/])(/usr/bin/php|/usr/local/bin/php)(\s|$)#', $code)
        || preg_match('/(^|[^_\w"$])php\s+-r/', $code)) {
        $stray[] = trim($line);
    }
}
t_eq(0, count($stray), 'every PHP call after the resolver goes through SG_PHP'
    . ($stray ? ' — stray: ' . implode(' | ', array_slice($stray, 0, 3)) : ''));

// The cron jobs bake the resolved path in: cron has no useful PATH, and a
// php-cgi here would write CGI headers into the scheduler log.
t_contains($install, '${SG_PHP} ${INSTALL_DIR}/backend/cron/scheduler.php',
    'the scheduler cron uses the resolved interpreter');

// ── MANIFEST exists before anything appends to it ────────────────────────────
// It was defined after the firewall section that appends to it, so two
// redirects ran with an empty filename -- and the definition block opened the
// file with `>`, so those keys would have been truncated away regardless.
$defPos   = strpos($install, "\nMANIFEST=\"\${INSTALL_DIR}/install-manifest.env\"");
// The guard banner is itself a comment, so it has to be located in the raw
// file; the two positions are compared as offsets into the same raw text.
$defPos   = strpos($installRaw, "
MANIFEST=\"\${INSTALL_DIR}/install-manifest.env\"");
$guardPos = strpos($installRaw, 'INSTALL-ONLY SECTIONS (skipped');
t_ok($defPos !== false, 'MANIFEST is defined');
t_ok($defPos < $guardPos,
    'MANIFEST is defined outside the INSTALL-ONLY guard, which --register-only skips');

$firstAppend = strpos($install, '>> "${MANIFEST}"');
$codeDef     = strpos($install, "
MANIFEST=\"\${INSTALL_DIR}/install-manifest.env\"");
t_ok($firstAppend !== false && $codeDef !== false && $codeDef < $firstAppend,
    'MANIFEST is defined before the first line that appends to it');

$truncate = strpos($install, '} > "${MANIFEST}"');
t_ok($truncate !== false && $truncate < $firstAppend,
    'the file is created before it is appended to, not after');

// ── ClamAV: look where THIS clamscan looks ───────────────────────────────────
// The installer downloaded signatures and then reported none, because cPanel
// keeps them under 3rdparty/share/clamav and the search list had distro paths.
t_contains($install, '/usr/local/cpanel/3rdparty/share/clamav',
    'the cPanel ClamAV database location is searched');
t_contains($install, 'CLAMSCAN_BIN', 'the search is derived from the binary in use');

// ── The cPanel plugin ships an icon ──────────────────────────────────────────
// install_plugin refuses an entry without one, so it failed for both themes.
t_contains($install, '"icon":     "sentinel_gate.png"',
    'install.json declares an icon');
t_contains($install, '${CPANEL_PLUGIN_DIR}/sentinel_gate.png',
    'and the icon is copied in beside it');
$iconCopy = strpos($install, '${CPANEL_PLUGIN_DIR}/sentinel_gate.png');
$jsonPos  = strpos($install, '"icon":     "sentinel_gate.png"');
t_ok($iconCopy < $jsonPos, 'the icon is in place before install_plugin runs');
t_ok(is_file($repo . '/whm/sentinel_gate.png'), 'the icon exists in the repo to copy');

// ── test.sh must not fail a working install ──────────────────────────────────
// The CGI is a /bin/sh dispatcher. Two checks demanded a cPanel Perl shebang
// and ran `perl -cw` on it, so every correct install reported two failures --
// in the same run where the installer's own API check returned JSON.
t_ok(strpos($test, 'perl -cw "$WHM_CGI"') === false,
    'the CGI is no longer syntax-checked as Perl');
t_contains($test, '_INTERP', 'the interpreter is taken from the shebang');
t_contains($test, '-x "$_INTERP"', 'and checked to exist');

// acls=any is deliberate; the check looked for acls=all and called it missing.
t_ok(strpos($test, 'grep -q "acls=all" "$APPCONF" && pass') === false,
    'the acls check no longer demands acls=all specifically');
t_contains($install, 'acls=any', 'the installer still writes acls=any');

// cpsrvd rewrites its process title, so an exact-name match never finds it.
t_ok(strpos($test, 'pgrep -x cpsrvd') === false,
    'cpsrvd is not looked up by exact process name');
t_contains($test, "pgrep -f '[c]psrvd'", 'it is matched on the full command line');
