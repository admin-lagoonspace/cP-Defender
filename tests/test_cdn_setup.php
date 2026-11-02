<?php
/**
 * The CDN setup script asks instead of assuming, and checks instead of claiming.
 *
 * serverscrub.com has returned 404 on every download URL since the domain moved
 * to a different hosting account. Installs kept working -- they fall back to the
 * GitHub mirror -- so nothing broke loudly and nothing said a word about it, for
 * release after release.
 *
 * The obvious fix was five commands in a release note. They hard-code
 *
 *     /home/serversc/public_html/serverscrub/code
 *
 * which is the right docroot only if serverscrub.com is that account's MAIN
 * domain. On an addon domain or a subdomain cPanel puts the docroot elsewhere,
 * and cdn-sync.sh would publish into a directory no vhost serves, log
 * "published v4.28.0", and exit 0. The CDN would still 404 and the operator
 * would be holding a success message saying otherwise -- the same shape as
 * every other bug in this area.
 *
 * So the setup reads the docroot out of cPanel's own records, and checks the
 * public URL before it is allowed to claim anything.
 */

require_once __DIR__ . '/assert.php';
$ctx  = require __DIR__ . '/bootstrap.php';
$repo = $ctx['repo'];

$sh  = t_shell($repo . '/scripts/cdn-setup.sh');
$pub = t_shell($repo . '/scripts/publish.sh');

// ── The docroot is asked for, not assumed ───────────────────────────────────
t_contains($sh, '/var/cpanel/userdata/${ACCT}/${DOMAIN}',
     'THE ASSUMED DOCROOT: cPanel is asked where it serves the domain from. '
   . 'The Apache vhost is generated from that file, so it cannot disagree '
   . 'with what is actually served');
t_contains($sh, '"/var/cpanel/userdata/${ACCT}/${DOMAIN}_SSL"',
     'including the SSL vhost, which is the one the https URL is served by');
t_contains($sh, 'refusing to guess a docroot',
     'AND IT REFUSES rather than falling back to /home/<acct>/public_html — a '
   . 'wrong guess publishes into a directory nothing serves and still '
   . 'succeeds, which is precisely how the 404 survived so long');
t_ok(strpos($sh, 'DOCROOT_BASE="/home/') === false,
     'there is no hard-coded home path to fall back to');

// ── It must run as root, and says so before doing anything ──────────────────
t_contains($sh, '[[ "$(id -u)" == "0" ]]',
     'root is required — the userdata is root-readable and the crontab is '
   . 'written for another user');

// ── The cron is written once, and read back ─────────────────────────────────
t_contains($sh, "grep -v 'cdn-sync\\.sh'",
     'IDEMPOTENT: an existing sync line is removed before the new one is '
   . 'added. A second copy would run two syncs forever, and flock would make '
   . 'one of them a silent no-op — which looks healthy');
t_contains($sh, "crontab -u \"\$ACCT\" -l 2>/dev/null | grep -q 'cdn-sync\\.sh'",
     'THE UNCHECKED WRITE: the crontab is read back afterwards. Writing a '
   . 'cron and reporting success without looking is the exact habit that left '
   . 'a live server with no user-scans line at all');
t_contains($sh, 'the cron line is NOT in ${ACCT}\'s crontab after writing it',
     'and it fails loudly when the line is not there');

// The cron must carry the docroot that was DERIVED, or the next run reverts to
// cdn-sync.sh's own default and publishes somewhere else than the first run.
t_contains($sh, 'SG_DOCROOT=${DOCROOT} ${SYNC} >> ${LOGS}/cdn-sync.log',
     'the derived docroot is carried into the cron, so every later run '
   . 'publishes where the first one did');

// ── Success is claimed only after the URL answers ───────────────────────────
t_contains($sh, 'if verify; then',
     'THE UNCHECKED CLAIM: the public URL is fetched before anything is '
   . 'called live');
t_contains($sh, '[[ "$code" =~ ^[0-9]{3}$ ]] || code=000',
     'anything that is not a three-digit status reads as unreachable');
t_ok(strpos($sh, "curl -fsS -o \"/tmp/sg-cdn-check") === false,
     'and the probe does not use -f: with it curl exits non-zero on a 404, '
   . 'the fallback fires too, and the two concatenate into "404000"');

// A manifest alone proves nothing. It names a zip, and the updater will go
// and fetch that zip.
t_contains($sh, 'zurl="https://${DOMAIN}/${SUBPATH}/dist/serverscrub-${ver}.zip"',
     'THE HALF-PUBLISHED CDN: the build the manifest names is fetched too. A '
   . 'manifest pointing at a file that 404s is worse than a 404 manifest — '
   . 'the updater announces an update, then fails to download it');
t_contains($sh, 'but the build it points at 404s',
     'and says so plainly when only half of it is there');

// ── A failure explains what to look at ──────────────────────────────────────
t_contains($sh, 'The files ARE on disk at ${DOCROOT}, and the URL still does not serve',
     'a sync that worked and a URL that does not are distinguished — they '
   . 'have completely different causes');
t_contains($sh, 'dig +short ${DOMAIN}',
     'with the next thing to check');

// ── --check changes nothing ─────────────────────────────────────────────────
t_contains($sh, 'if $CHECK_ONLY; then',
     'there is a check-only mode');
// Anchored on code, not on a comment: t_shell() strips comments, so a comment
// anchor silently makes this substr() the whole file and the check vacuous.
$beforeInstall = substr($sh, 0, (int) strpos($sh, 'curl -fsSL --max-time 60'));
t_ok($beforeInstall !== '' && strlen($beforeInstall) < strlen($sh),
     'the install really is further down the file');
t_ok(strpos($beforeInstall, 'if $CHECK_ONLY; then') !== false,
     'and it exits BEFORE the install, so re-checking cannot rewrite a '
   . 'crontab or re-download anything');

// ── The release points at this, not at the commands it replaces ─────────────
t_contains($pub, 'scripts/cdn-setup.sh)',
     'publish.sh offers the setup script when the CDN is not serving');
t_ok(strpos($pub, 'mkdir -p /home/${CDN_ACCT}/bin') === false,
     'and no longer prints the hard-coded five commands, which assume the '
   . 'domain is the account\'s main domain and fail silently when it is not');

// ── The sync does not keep its files in /tmp ────────────────────────────────
//
// The first live run died here, before doing anything at all:
//
//   /home/serversc/bin/cdn-sync.sh: line 53: /tmp/sg-cdn-sync.lock: Permission denied
//   ERROR: cannot open lock /tmp/sg-cdn-sync.lock
//
// A fixed name in /tmp belongs to whoever created it first. This runs as an
// unprivileged cPanel user on a machine full of other accounts; if root, or
// any of them, got there first, this user cannot open it for writing -- and
// the sync dies every ten minutes for ever, having published nothing.
$sync = t_shell($repo . '/scripts/cdn-sync.sh');

t_contains($sync, 'LOCKFILE="${SG_LOCK:-${SG_WORK}/sync.lock}"',
     'THE UNWRITABLE LOCK: the lock lives in a directory this user owns, not '
   . 'in a world-writable one where the name is first come, first served');
t_ok(!preg_match('#(["\'= ])/tmp/#', $sync),
     'and NOTHING of this script\'s is in /tmp — a predictable name in a '
   . 'shared directory can also be pre-created as a symlink by another '
   . 'account, and curl -o follows one that is already there');
t_contains($sync, 'TMP="$(mktemp -d "${SG_WORK}/sync.XXXXXX")"',
     'the download staging directory moved too, not just the lock');
t_contains($sync, '_gcheck="${SG_WORK}/get.sh.check"',
     'and so did the get.sh comparison file, which had "$$" in its name — '
   . 'predictable enough to be squatted');

t_contains($sync, 'if [ -n "${HOME:-}" ] && [ -d "${HOME}" ] && [ -w "${HOME}" ]; then',
     'SG_WORK defaults under the home directory');
t_contains($sync, 'SG_WORK="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo .)/.serverscrub-cdn"',
     'with the script\'s own directory as the fallback, because cron can run '
   . 'with no HOME at all');
t_contains($sync, 'chmod 700 "$SG_WORK"',
     'and it is not readable by the rest of the machine');

// Both runs must lock the SAME file or the lock protects nothing.
t_contains($sh, 'CRON_LINE="*/10 * * * * SG_WORK=${WORK} SG_DOCROOT=${DOCROOT}',
     'THE TWO LOCKS: the cron line pins SG_WORK. Left to the fallback, a cron '
   . 'run with no HOME would lock a different file from the one-off run, and '
   . 'a lock two processes cannot both see is not a lock');
t_contains($sh, 'su -s /bin/bash -c "SG_WORK=\'${WORK}\' SG_DOCROOT=\'${DOCROOT}\' \'${SYNC}\'" "$ACCT"',
     'and the first run is given the same one');

// set -u is on. A variable that is referenced but never assigned aborts the
// script -- and this one is referenced only inside the failure path, so it
// would abort exactly when it was trying to explain what went wrong.
t_ok(strpos($sh, '${SG_WORK}') === false,
     'NO UNBOUND VARIABLE: the setup script does not reference SG_WORK, which '
   . 'it never sets. Under set -u that aborts, and it sits in the branch that '
   . 'exists to report a failure');

// ── A failure says WHICH failure ────────────────────────────────────────────
//
// The first version printed "The sync did its job; something between that
// directory and the web has not" and then, four lines later, "latest.json is
// NOT in <docroot> -- the sync did not publish". Both, in that order.
t_contains($sh, 'if [[ ! -s "${DOCROOT}/latest.json" ]]; then',
     'THE CONTRADICTION: nothing-was-published is distinguished from '
   . 'published-but-not-served before any cause is suggested');
t_contains($sh, 'NOTHING WAS PUBLISHED.',
     'and said in plain words');
t_contains($sh, 'the web side is not',
     'with the right half of the system named — the two have completely '
   . 'different causes, and sending someone to dig and openssl when the sync '
   . 'never ran wastes the evening');

$webAdvice = (int) strpos($sh, 'resolves somewhere other than this server');
$notPub    = (int) strpos($sh, 'NOTHING WAS PUBLISHED.');
t_ok($notPub > 0 && $notPub < $webAdvice,
     'and it exits first, so the DNS and certificate advice cannot print '
   . 'underneath it');
