<?php
/**
 * A migrated server could never arm the WAF, and nothing noticed for months.
 *
 * The product was renamed from Sentinel Gate. install.sh migrates the old
 * install, and step 9 of that block renames one Apache include called
 * `sentinel-waf.conf`. It did not touch /etc/sentinel-gate/waf/, which holds a
 * COMPLETE SECOND COPY of the OWASP CRS, nor the include that loads it — that
 * file has had other names.
 *
 * On the live server both copies were loaded:
 *
 *     /etc/sentinel-gate/waf/coreruleset/rules/REQUEST-913-SCANNER-DETECTION.conf
 *     /etc/serverscrub/waf/coreruleset/rules/REQUEST-913-SCANNER-DETECTION.conf
 *
 * Both define id:913100, so every `serverscrub waf mode on` ended in
 *
 *     AH00526: Found another rule with the same id
 *
 * WAFInstaller::setMode() validates before reloading and correctly refused —
 * so Apache was never damaged, and the failure was reported. But the panel
 * still showed the WAF as installed with a mode, and nobody connected the
 * refusal to a directory named after a product that no longer existed. The
 * WAF has been unarmable on that server since the rename.
 *
 * TWO things make this test exist rather than just the fix:
 *
 *  1. The cleanup must run OUTSIDE the `if [[ -d /usr/local/sentinel-gate ]]`
 *     migration gate. Inside it, the cleanup never runs again on a server that
 *     has already migrated — which is every server that has this problem.
 *
 *  2. It must NOT delete /etc/apache2/conf.d/modsec_vendor_configs/sentinel-gate/.
 *     cPanel's own modsec2.user.conf loads that with `Include`, not
 *     `IncludeOptional`. Deleting the directory makes Apache fail to start.
 *     Cleaning up a leftover must not cause the outage it was meant to prevent.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$sh = t_shell($repo . '/install.sh');

t_contains($sh, 'LEGACY_WAF_DIR="/etc/sentinel-gate"',
           'install.sh knows about the old WAF config directory at all');

// ── It has to run on an already-migrated server ────────────────────────────

$gate   = strpos($sh, 'if [[ -d "${OLD_DIR}" && "${OLD_DIR}" != "${INSTALL_DIR}" ]]');
$legacy = strpos($sh, 'LEGACY_WAF_DIR="/etc/sentinel-gate"');
$prefl  = strpos($sh, 'section "Pre-flight checks"');

t_ok($gate !== false, 'the migration block is still gated on the old install dir');
t_ok($legacy !== false && $prefl !== false, 'both markers are present');
t_ok($legacy > $gate,
     'the legacy WAF cleanup comes after the migration block opens');
t_ok($legacy < $prefl,
     'and before pre-flight, so it runs on every install');

// The migration block ends with this line. The cleanup must be past it.
$endOfMigration = strpos($sh, 'ok "  Migration complete — continuing as ServerScrub"');
t_ok($endOfMigration !== false, 'the end of the migration block is findable');
t_ok($legacy > $endOfMigration,
     'the cleanup sits AFTER the migration block closes. Inside it, it would be '
   . 'gated on /usr/local/sentinel-gate still existing — which is false on every '
   . 'server that already migrated, meaning every server that has this fault');

// ── It must not cause the outage it is preventing ──────────────────────────

t_ok(strpos($sh, 'rm -rf /etc/apache2/conf.d/modsec_vendor_configs/sentinel-gate') === false,
     'the old vendor config directory is NOT deleted: cPanel loads it with '
   . 'Include, not IncludeOptional, so removing it stops Apache starting');
// t_shell() strips comments, so the reasoning is checked against the raw file.
t_contains((string) file_get_contents($repo . '/install.sh'),
           'loads it with `Include`, not `IncludeOptional`',
           'and the reason is written down where the next person will read it, '
         . 'because the next person will otherwise delete that directory');

// ── It must not delete a file that is not ours ─────────────────────────────

t_contains($sh, '_total}" -eq "${_legacy}',
           'an Apache file is removed only when every non-comment line refers to '
         . 'the old path — i.e. it is our own one-line include. cPanel\'s '
         . 'modsec2.user.conf mentions the old name too, and deleting that takes '
         . 'ModSecurity\'s whole config with it');
t_contains($sh, 'is not ours - left alone',
           'and a file that is not ours is reported, not silently skipped: the '
         . 'duplicate rules survive and the operator has to know why');

// ── Find the include by what it points at, not by name ─────────────────────

t_contains($sh, 'grep -rlsF "${LEGACY_WAF_DIR}"',
           'the stale include is located by the path it references. Matching on a '
         . 'filename is what left this behind: step 9 looks for '
         . '"sentinel-waf.conf" and the file was called something else');

// ── Never reload Apache on a config that does not parse ────────────────────

$valid  = strpos($sh, 'if apachectl -t >/dev/null 2>&1; then');
$reload = strpos($sh, 'apachectl graceful >/dev/null 2>&1 || true');
t_ok($valid !== false && $reload !== false, 'both the check and the reload are present');
t_ok($valid < $reload,
     'the syntax check runs BEFORE the graceful reload. Reloading a config that '
   . 'does not parse takes Apache down, and this runs on a server with 132 live '
   . 'accounts');
t_contains($sh, 'still does not validate - NOT reloading',
           'and a config that fails the check is left alone, loudly');

// ── The new block cannot abort the installer it is bolted into ─────────────
//
// install.sh runs under `set -o pipefail` WITHOUT `set -e`: it handles errors
// per command, because an installer that dies halfway leaves a server with
// neither the old product nor the new one working. So every command in the new
// block that is allowed to fail has to say so, or a server without apachectl
// aborts its own upgrade.

t_contains($sh, 'set -o pipefail', 'install.sh still sets pipefail');
t_contains($sh, 'apachectl graceful >/dev/null 2>&1 || true',
           'the reload tolerates its own failure: on a cPanel box Apache is often '
         . 'restarted through /scripts/restartsrv_httpd instead');
t_contains($sh, '2>/dev/null || true)',
           'and the search for stale includes cannot abort the install when one of '
         . 'those config directories is unreadable');
