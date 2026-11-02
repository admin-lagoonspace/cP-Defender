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
t_contains($pub, 'latest.json" 2>/dev/null || echo 000',
     'THE SILENT 404: publish.sh asks the CDN whether it is actually serving '
   . 'anything, rather than printing "CDN mirrors automatically" and stopping');
t_contains($pub, 'CDN IS NOT SERVING ANYTHING',
     'and says so in plain words when it is not');
t_contains($pub, 'they fall back to the GitHub mirror',
     'explaining why nothing appeared broken — which is exactly why this went '
   . 'unnoticed for release after release');
t_contains($pub, 'cdn-sync.sh \\',
     'and gives the one-time setup to fix it, rather than a pointer to a '
   . 'script header');

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
t_contains($pub, 'CDN_BASE="${SG_CDN_BASE:-https://serverscrub.com/serverscrub/code}"',
     'and matches the URL the updater reads');

$uc = (string) file_get_contents($repo . '/backend/lib/UpdateChecker.php');
t_contains($uc, "'https://serverscrub.com/serverscrub/code'",
     'which is the same base the product itself checks for updates — a probe '
   . 'against a different URL than the one that matters proves nothing');
