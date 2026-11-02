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
t_contains($sh, 'CRON_LINE="*/10 * * * * SG_DOCROOT=${DOCROOT} ${SYNC}',
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
t_contains($sh, 'The files are on disk at ${DOCROOT}, but the URL is not serving them.',
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
