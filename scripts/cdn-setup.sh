#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — one-time CDN setup. Run as ROOT on the cPanel server that
# serves serverscrub.com.
#
# WHY THIS EXISTS RATHER THAN FIVE COMMANDS IN A RELEASE NOTE
#
# Every serverscrub.com download URL has been returning 404 since the domain
# moved to a different hosting account. Installs kept working, because they
# fall back to the GitHub mirror, so nothing broke loudly and nothing said a
# word about it -- release after release.
#
# The five-command version of this setup hard-codes a docroot:
#
#     /home/serversc/public_html/serverscrub/code
#
# which is right only if serverscrub.com is that account's MAIN domain. If it
# is an addon or a subdomain, cPanel put its docroot somewhere else, and
# cdn-sync.sh will happily publish into a directory no vhost serves, log
# "published v4.28.0", and exit 0. The CDN would still 404 and the operator
# would have a success message saying otherwise. That is the exact failure
# shape this project keeps being bitten by, so this script asks cPanel where
# the docroot actually is, and then checks the public URL afterwards.
#
#   bash cdn-setup.sh            # set it up, then verify
#   bash cdn-setup.sh --check    # verify only, change nothing
#
# Override with SG_CDN_ACCOUNT / SG_CDN_DOMAIN if either ever changes.
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

ACCT="${SG_CDN_ACCOUNT:-serversc}"
DOMAIN="${SG_CDN_DOMAIN:-serverscrub.com}"
SUBPATH="${SG_CDN_SUBPATH:-serverscrub/code}"
REPO="${SG_REPO:-admin-lagoonspace/cP-Defender}"
RAW="https://raw.githubusercontent.com/${REPO}/main"

CHECK_ONLY=false
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=true

R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[1;33m'
C=$'\033[0;36m'; B=$'\033[1m';    N=$'\033[0m'
say()  { echo "${C}[*]${N} $*"; }
ok()   { echo "${G}[+]${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
die()  { echo "${R}[x]${N} $*" >&2; exit 1; }

[[ "$(id -u)" == "0" ]] \
  || die "run this as root — it reads /var/cpanel/userdata and writes a user crontab"

# ── Where does cPanel actually serve this domain from? ────────────────────────
#
# Asked, not assumed. The userdata file is cPanel's own record and is what the
# Apache vhost is generated from, so it cannot disagree with what is served.
DOCROOT_BASE=""
for _f in "/var/cpanel/userdata/${ACCT}/${DOMAIN}" \
          "/var/cpanel/userdata/${ACCT}/${DOMAIN}_SSL"; do
    [[ -r "$_f" ]] || continue
    _dr="$(grep -E '^documentroot:' "$_f" | head -1 \
           | sed -E 's/^documentroot:[[:space:]]*//' | tr -d '"' || true)"
    if [[ -n "$_dr" ]]; then DOCROOT_BASE="$_dr"; break; fi
done

if [[ -z "$DOCROOT_BASE" ]]; then
    warn "cPanel has no userdata for ${DOMAIN} under the account '${ACCT}'."
    warn "Either that account name is wrong, or the domain is not on this server."
    warn "  list the accounts:  ls /var/cpanel/userdata/"
    warn "  then re-run:        SG_CDN_ACCOUNT=<account> bash \$0"
    die "refusing to guess a docroot — publishing into a directory nothing serves is how this went unnoticed before"
fi

ok "cPanel serves ${DOMAIN} from ${DOCROOT_BASE}"

DOCROOT="${DOCROOT_BASE%/}/${SUBPATH}"
HOMEDIR="$(getent passwd "$ACCT" | cut -d: -f6 || true)"
[[ -n "$HOMEDIR" ]] || die "no such system user: ${ACCT}"

BIN="${HOMEDIR}/bin"
LOGS="${HOMEDIR}/logs"
SYNC="${BIN}/cdn-sync.sh"
SELF="${BIN}/cdn-setup.sh"
WORK="${HOMEDIR}/.serverscrub-cdn"

# SG_WORK is pinned in the cron line, not left to the sync's own fallback.
# cron frequently runs with no HOME, in which case the sync falls back to its
# own directory -- so the cron run and the one-off run below would lock
# different files and could not see each other at all. A lock two processes
# cannot both see is not a lock.
CRON_LINE="*/10 * * * * SG_WORK=${WORK} SG_DOCROOT=${DOCROOT} ${SYNC} >> ${LOGS}/cdn-sync.log 2>&1"

# ── Verification, used after setup and by --check ─────────────────────────────
#
# This asks the question the way a customer's server asks it: the product reads
# the same URL to decide whether an update exists.
verify() {
    local url="https://${DOMAIN}/${SUBPATH}/latest.json"
    local code body ver zurl zcode

    code="$(curl -sS -o "/tmp/sg-cdn-check.$$" -w '%{http_code}' --max-time 20 "$url" 2>/dev/null || true)"
    [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
    body="$(cat "/tmp/sg-cdn-check.$$" 2>/dev/null || true)"
    rm -f "/tmp/sg-cdn-check.$$"

    if [[ "$code" != "200" ]]; then
        warn "${url} → HTTP ${code}"
        return 1
    fi

    ver="$(printf '%s' "$body" \
           | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 \
           | sed -E 's/.*"([^"]+)"$/\1/' || true)"
    if [[ -z "$ver" ]]; then
        warn "${url} → HTTP 200, but the body is not a manifest"
        return 1
    fi
    ok "${url} → HTTP 200, serving v${ver}"

    # The zip it names must be fetchable too. A manifest pointing at a file
    # that 404s is worse than a 404 manifest: the updater believes an update
    # exists, announces it, and then fails downloading it.
    zurl="https://${DOMAIN}/${SUBPATH}/dist/serverscrub-${ver}.zip"
    zcode="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 "$zurl" 2>/dev/null || true)"
    [[ "$zcode" =~ ^[0-9]{3}$ ]] || zcode=000
    if [[ "$zcode" != "200" ]]; then
        warn "but the build it points at 404s: ${zurl} → HTTP ${zcode}"
        return 1
    fi
    ok "and the build downloads: dist/serverscrub-${ver}.zip"
    return 0
}

if $CHECK_ONLY; then
    say "Checking ${DOMAIN}…"
    if verify; then
        echo
        ok "${B}CDN is serving.${N}"
        exit 0
    fi
    echo
    warn "CDN is NOT serving. Run this script without --check to set it up."
    exit 1
fi

# ── Install the sync ──────────────────────────────────────────────────────────
say "Installing into ${BIN}…"
mkdir -p "$BIN" "$LOGS" "$DOCROOT" || die "cannot create directories under ${HOMEDIR}"

curl -fsSL --max-time 60 "${RAW}/scripts/cdn-sync.sh" -o "${SYNC}.tmp" \
  || die "could not download cdn-sync.sh from ${RAW}"
[[ -s "${SYNC}.tmp" ]] || die "the cdn-sync.sh that downloaded is empty"
head -1 "${SYNC}.tmp" | grep -q '^#!' || die "what downloaded is not a script"
mv -f "${SYNC}.tmp" "$SYNC"
chmod +x "$SYNC"

# Keep a copy of this script beside it, so --check is available later without
# hunting for the URL again.
curl -fsSL --max-time 60 "${RAW}/scripts/cdn-setup.sh" -o "${SELF}.tmp" 2>/dev/null \
  && [[ -s "${SELF}.tmp" ]] && mv -f "${SELF}.tmp" "$SELF" && chmod +x "$SELF"
rm -f "${SELF}.tmp"

chown -R "${ACCT}:${ACCT}" "$BIN" "$LOGS"
chown -R "${ACCT}:${ACCT}" "$DOCROOT" 2>/dev/null || true
ok "installed ${SYNC}"

# ── The cron, under the cPanel user, idempotently ─────────────────────────────
#
# Rewritten rather than appended: a second copy would run two syncs forever,
# and flock would make one of them a silent no-op, which looks healthy.
say "Installing the 10-minute sync cron for ${ACCT}…"
EXISTING="$(crontab -u "$ACCT" -l 2>/dev/null || true)"
CLEANED="$(printf '%s\n' "$EXISTING" | grep -v 'cdn-sync\.sh' || true)"
printf '%s\n%s\n' "$CLEANED" "$CRON_LINE" | sed '/^$/d' | crontab -u "$ACCT" - \
  || die "could not write the crontab for ${ACCT}"

# Read back, not assumed. Writing a cron and reporting success without checking
# is the exact habit that left a live server with no user-scans line at all.
if crontab -u "$ACCT" -l 2>/dev/null | grep -q 'cdn-sync\.sh'; then
    ok "cron installed, every 10 minutes"
else
    die "the cron line is NOT in ${ACCT}'s crontab after writing it"
fi

# ── First run, now, as the user ───────────────────────────────────────────────
#
# The same SG_WORK the cron line pins, for the same reason: `su -c` without
# `-` does not reset HOME reliably, so leaving the sync to work it out means
# this run and the cron run can lock different files.
mkdir -p "$WORK"
chown "${ACCT}:${ACCT}" "$WORK"
chmod 700 "$WORK"

say "Running the first sync — this downloads the current release…"
SYNC_OK=true
if su -s /bin/bash -c "SG_WORK='${WORK}' SG_DOCROOT='${DOCROOT}' '${SYNC}'" "$ACCT"; then
    ok "sync completed"
else
    SYNC_OK=false
    warn "the sync exited non-zero; its output is above, and ${LOGS}/cdn-sync.log has the rest"
fi

# ── Does the public URL actually serve it? ────────────────────────────────────
echo
say "Checking what ${DOMAIN} is serving…"
if verify; then
    echo
    ok "${B}CDN is live.${N} Installs and updates will use serverscrub.com,"
    ok "with the GitHub mirror still behind it as a fallback."
    echo
    echo "  Re-check at any time:"
    echo "  ${B}bash ${SELF} --check${N}"
    exit 0
fi

echo

# Which failure this is, before guessing at causes.
#
# The first version of this printed "The sync did its job; something between
# that directory and the web has not" and then, four lines later, "latest.json
# is NOT in ${DOCROOT} -- the sync did not publish". Both, in that order, in
# the same output. Printing a diagnosis and its own contradiction underneath it
# is exactly how the CDN 404 survived six releases; it does not get to happen
# in the script written to end that.
if [[ ! -s "${DOCROOT}/latest.json" ]]; then
    warn "NOTHING WAS PUBLISHED. latest.json is not in ${DOCROOT}."
    warn "The URL 404s because there is no file to serve — the web side is not"
    warn "the problem, the sync is. Its error is in the output above, and in"
    warn "  ${LOGS}/cdn-sync.log"
    echo
    warn "Run it again on its own to see the failure in isolation:"
    warn "  su -s /bin/bash -c \"SG_WORK='${WORK}' SG_DOCROOT='${DOCROOT}' '${SYNC}'\" ${ACCT}"
    exit 1
fi

if ! $SYNC_OK; then
    warn "The sync exited non-zero, but ${DOCROOT}/latest.json exists — so a"
    warn "previous run published and this one failed partway. Check the log"
    warn "before trusting what is being served:  ${LOGS}/cdn-sync.log"
    echo
fi

warn "The files ARE on disk at ${DOCROOT}, and the URL still does not serve"
warn "them. The sync did its job; something between that directory and the web"
warn "has not. In order of likelihood:"
warn "  - ${DOMAIN} resolves somewhere other than this server"
warn "      dig +short ${DOMAIN}        and compare with this box's IPs"
warn "  - the vhost has no valid certificate, so https fails before a file is read"
warn "      curl -sSI https://${DOMAIN}/ | head -1"
warn "  - an .htaccess above the path rewrites or denies it"
warn "      ls -la ${DOCROOT_BASE}/.htaccess"
echo
warn "What is on disk, for comparison:"
ls -la "${DOCROOT}/latest.json"
exit 1
