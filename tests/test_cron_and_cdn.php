<?php
/**
 * The two things that were silently not happening on a live server.
 *
 * A server running a current build was found with NO user-scans line in
 * /etc/cron.d/serverscrub. Every customer who pressed "Scan my account" saw
 * "Queued" and nothing else for eight hours, because nothing was scheduled to
 * pick the request up. Every install and every update had reported success on
 * the way past.
 *
 * And every serverscrub.com download URL was returning 404, because the CDN
 * had never been populated under the account the domain moved to. Installs
 * kept working -- they fall back to the GitHub mirror -- so nothing ever said
 * a word about it, release after release.
 *
 * Both have the same shape: the step is performed, success is announced, and
 * nothing checks. These tests are about the checking.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$ins = t_shell($repo . '/install.sh');
$upd = t_shell($repo . '/update.sh');
$pub = t_shell($repo . '/scripts/publish.sh');

// ── The installer checks what it wrote ──────────────────────────────────────
t_contains($ins, 'grep -q "cron/${_need}" "${CRON_FILE}"',
     'THE UNCHECKED WRITE: install.sh verifies the cron entries are in the '
   . 'file afterwards, instead of printing "Cron jobs installed" and moving '
   . 'on. The write is the easy part');
t_contains($ins, 'for _need in scheduler.php user-scans.php',
     'and checks BOTH — the scheduled sweep and the customer scan pickup');
t_contains($ins, 'entries are MISSING',
     'and says so plainly when they are not there');
t_contains($ins, 'if [[ ! -x "$SG_PHP" ]]',
     'the PHP those lines will run is checked now rather than at 03:00, when '
   . 'a bad path means every task fails silently');

// ── The updater repairs, not just reports ───────────────────────────────────
t_contains($upd, "grep -q 'cron/user-scans\\.php' \"\$CRON_FILE\"",
     'update.sh looks for the pickup line');
t_contains($upd, 'backend/cron/user-scans.php >> ${_cron_log}',
     'THE REPAIR: and appends it when it is absent. An update that can see '
   . 'the line is missing and leaves it missing has told the operator about a '
   . 'problem it could have fixed');
t_contains($upd, "grep -q 'cron/scheduler\\.php' \"\$CRON_FILE\"",
     'the scheduler line is repaired the same way');
t_contains($upd, 'cp -a "$CRON_FILE" "${CRON_FILE}.pre-cronfix"',
     'with a copy of the file first, because this is editing something an '
   . 'administrator may also have touched');

// The log path is the trap here: LOG_DIR is set further down the script, for
// the systemd unit. Reading it empty writes cron output to /cron.log, at the
// filesystem root.
t_contains($upd, '_cron_log="${INSTALL_DIR}/logs/cron.log"',
     'the log path is derived locally rather than read before it is set');
$block = substr($upd, (int) strpos($upd, 'Did the cron entries'));
$block = substr($block, 0, 2000);
t_ok(strpos($block, '${LOG_DIR}') === false,
     'and LOG_DIR, which is not in scope yet, is not used — "${LOG_DIR}/cron.log" '
   . 'unset redirects every cron run to /cron.log');

// ── The release asks the CDN instead of assuming ────────────────────────────
t_contains($pub, 'curl -sS -o /dev/null -w',
     'THE SILENT 404: publish.sh asks the CDN whether it is actually serving '
   . 'anything, rather than printing "CDN mirrors automatically" and stopping');
t_ok(strpos($pub, "-fsS -o /dev/null -w '%{http_code}'") === false,
     'and asks WITHOUT -f: with it curl exits non-zero on a 404, a fallback '
   . 'fires as well, and the two concatenate into "404000"');
t_contains($pub, '[[ "$_cdn_code" =~ ^[0-9]{3}$ ]] || _cdn_code=000',
     'anything that is not a three-digit status reads as unreachable');
t_contains($pub, 'Installs will use the GitHub mirror (CDN is not serving)',
     'THE CONTRADICTION: the closing line does not promise "CDN will pick it '
   . 'up" directly underneath "CDN IS NOT SERVING ANYTHING" — printing both '
   . 'is how the 404 stayed invisible for so long');
t_contains($pub, 'CDN IS NOT SERVING ANYTHING',
     'and says so in plain words when it is not');
t_contains($pub, 'they fall back to the GitHub mirror',
     'explaining why nothing appeared broken — which is exactly why this went '
   . 'unnoticed for release after release');
t_contains($pub, 'scripts/cdn-setup.sh)',
     'and gives the one-time setup to fix it, rather than a pointer to a '
   . 'script header. It names the setup SCRIPT, not the five commands that '
   . 'script replaces: those hard-code /home/<acct>/public_html, which is the '
   . 'right docroot only when the domain is the MAIN domain of that account — '
   . 'otherwise the sync publishes where no vhost serves and still succeeds');

// ── Nothing still names the account the domain moved away from ──────────────
foreach ([
    'scripts/publish.sh',
    'scripts/cdn-sync.sh',
    'scripts/cdn-trigger-watch.sh',
    'get.sh',
    'update.sh',
    'install.sh',
] as $f) {
    $body = (string) file_get_contents($repo . '/' . $f);
    t_ok(!preg_match('#/home/lwss1|lwss1/(bin|logs)#', $body),
         'THE HALF-DONE MOVE: ' . $f . ' does not still point at the old '
       . 'hosting account — being told to run a path that does not exist '
       . 'costs a round trip and leaves the operator unsure what happened');
}

// The CDN account and base belong together: a probe against serverscrub.com
// that then names some other account's home is worse than no advice.
t_contains($pub, 'CDN_ACCT="${SG_CDN_ACCOUNT:-serversc}"',
     'the account the CDN is served from is named once');
t_contains($pub, 'CDN_BASE="${SG_CDN_BASE:-https://serverscrub.com/releases}"',
     'and matches the URL the updater reads');

$uc = (string) file_get_contents($repo . '/backend/lib/UpdateChecker.php');
t_contains($uc, "'https://serverscrub.com/releases'",
     'which is the same base the product itself checks for updates — a probe '
   . 'against a different URL than the one that matters proves nothing');

// ── The product was shadowing its own download URL ──────────────────────────
//
// serverscrub.com/serverscrub/code/latest.json returned 404 for six releases
// while the file sat on disk with the right owner and mode, under a vhost
// with the right DocumentRoot, reachable by a fingerprinted probe. Nothing
// about the file, the directory or the vhost was wrong.
//
// install.sh writes /etc/apache2/conf.d/serverscrub.conf containing
//
//     Alias /serverscrub  ${SG_WEB_DIR}
//
// and conf.d applies to EVERY vhost on the machine. So any URL starting
// /serverscrub/ is served from the plugin's directory and never reaches
// public_html -- on any server that both runs ServerScrub and hosts the CDN,
// which is exactly one machine: ours.
//
// The download path therefore must not begin with /serverscrub.
$ins = t_shell($repo . '/install.sh');
t_contains($ins, 'Alias /serverscrub             ${SG_WEB_DIR}',
     'install.sh still installs the server-wide alias this is about');

foreach ([
    'scripts/publish.sh', 'scripts/cdn-sync.sh', 'scripts/cdn-setup.sh',
    'update.sh', 'upgrade.sh', 'get.sh', 'backend/lib/UpdateChecker.php',
    'latest.json',
] as $f) {
    // Comments stripped first. The explanation of this very bug names the old
    // URL, and reading the raw file made the test fail on its own prose --
    // the fourth time that trap has been sprung in this suite.
    $ext  = pathinfo($f, PATHINFO_EXTENSION);
    $body = $ext === 'sh'  ? t_shell($repo . '/' . $f)
          : ($ext === 'php' ? t_code($repo . '/' . $f)
          : (string) file_get_contents($repo . '/' . $f));
    t_ok(strpos($body, 'serverscrub.com/serverscrub/') === false,
         'THE SELF-COLLISION: ' . $f . ' does not serve downloads from a URL '
       . 'beginning /serverscrub — our own Apache alias owns that path on '
       . 'every vhost, so the file is never reached however correct it is');
}

// And the reason is recorded where someone tidying paths would see it.
// Raw, not comment-stripped: the note IS a comment, and that is the point --
// it has to be readable by whoever opens the file to tidy the path.
$syncRaw = (string) file_get_contents($repo . '/scripts/cdn-sync.sh');
t_contains($syncRaw, "THE PATH IS 'releases', NOT 'serverscrub/code'. Do not move it back.",
     'and the reason is written beside the setting, because the mistake is '
   . 'invisible on any machine that does not host both');

// ── The commit has to contain what the zip contains ────────────────────────
//
// make-release.sh packages from the WORKING TREE, so whatever is on disk is
// what customers get. The commit is supposed to cover the same thing, and
// twice it has not:
//
//   v4.6.0   two new library modules shipped and were never committed.
//            Fixed by enumerating SRC_TREES.
//   v4.28.0+ that enumeration omitted cpanel/ and test.sh, so the customer
//            plugin's index.live.php sat uncommitted since v4.27.0 while six
//            releases shipped changes to it -- the scan log, the Started-by
//            column, the threat dialog. The zips were right; the repository
//            was not, so a fresh clone would build a product missing all of
//            it.
//
// Enumerating is the bug, not the particular list. Ask the artifact instead.
t_contains($pub, 'SRC_TREES=(backend frontend whm scripts tests cpanel)',
     'cpanel/ — the entire customer-facing plugin — is staged with the rest '
   . 'of the source');
t_contains($pub, 'upgrade.sh get.sh test.sh',
     'and test.sh, which update.sh copies onto every server');

t_contains($pub, 'while IFS= read -r _zp; do',
     'THE LIST THAT KEEPS BEING WRONG: every path inside the built zip is '
   . 'checked against the repository, so a forgotten directory cannot let a '
   . 'release claim source it does not contain');
t_contains($pub, 'done < <(unzip -Z1 "$ZIP" 2>/dev/null || true)',
     'read from the artifact that is actually about to ship');
t_contains($pub, 'err "These files are IN THE ZIP but not in the commit:"',
     'and the release is refused rather than warned about');

// The test that matters: staged is fine, worktree-dirty is not.
t_contains($pub, 'if [[ -n "$_st" && "${_st:1:1}" != " " ]]; then',
     'THE FALSE POSITIVE: it looks at the WORKING TREE column, not at '
   . 'whether porcelain printed anything. A staged file reads as "M " and is '
   . 'about to be committed; failing on that would refuse every release, '
   . 'which is how a guard gets switched off');

// A guard that silently does nothing is the theme of this whole file.
t_contains($pub, 'warn "unzip not available — cannot verify the commit covers what shipped."',
     'and when the check cannot run it says so, instead of passing quietly');
