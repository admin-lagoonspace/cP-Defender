#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# ServerScrub — production upgrade bootstrap
#
# WHY THIS EXISTS, WHEN update.sh ALREADY WORKS
# ---------------------------------------------
# update.sh is the updater, and it is good: it verifies the SHA-256, backs the
# install up, rsyncs, restarts the services, and rolls back if the new version
# fails to answer. The catch is that the copy of update.sh on a server is the
# one that shipped with the version ALREADY INSTALLED there. If a fix lands in
# the updater itself, the server cannot benefit from it, because the old updater
# is the thing doing the updating.
#
# So this does one job: fetch the CURRENT update.sh from the release channel,
# show you what it is about to do, and hand over to it.
#
# WHAT IT DOES NOT DO
# -------------------
# It does not download the release, verify it, replace any files, or restart
# anything. All of that stays in update.sh, which already handles it and has
# the rollback. Reimplementing any of it here would mean two code paths for
# applying an update and only one of them tested.
#
# USAGE (as root, on the server)
#
#   bash upgrade.sh              # show what would happen, then ask
#   bash upgrade.sh --yes        # no questions, for a maintenance window
#   bash upgrade.sh --check      # report versions and exit, change nothing
#   bash upgrade.sh --local      # use the installed update.sh, fetch nothing
#
# ════════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()      { echo -e "  ${GREEN}✔${NC}  $*"; }
info()    { echo -e "  ${CYAN}→${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; }
err()     { echo -e "  ${RED}✖${NC}  $*" >&2; }
section() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }
die()     { err "$*"; exit 1; }

INSTALL_DIR="${SG_ROOT:-/usr/local/serverscrub}"
RELEASES_REPO="${SG_RELEASES_REPO:-admin-lagoonspace/cP-Defender}"
RELEASES_BRANCH="${SG_RELEASES_BRANCH:-main}"

# Same channel order as update.sh and UpdateChecker: our CDN first, because it
# has no API rate limit and keeps working on servers whose firewall blocks
# github.com; the GitHub raw mirror second.
CDN_BASE="${SG_CDN_BASE:-https://serverscrub.com/serverscrub/code}"
GITHUB_BASE="https://raw.githubusercontent.com/${RELEASES_REPO}/${RELEASES_BRANCH}"
CHANNELS=("$CDN_BASE" "$GITHUB_BASE")

AUTO_YES=false
CHECK_ONLY=false
USE_LOCAL=false
PASSTHRU=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)  AUTO_YES=true;   shift ;;
        --check)   CHECK_ONLY=true; shift ;;
        --local)   USE_LOCAL=true;  shift ;;
        --help|-h) sed -n '3,30p' "$0"; exit 0 ;;
        # Anything else is for update.sh (--version, --url, ...).
        *)         PASSTHRU+=("$1"); shift ;;
    esac
done

echo -e "${BOLD}ServerScrub upgrade${NC}"

# ── Checks ────────────────────────────────────────────────────────────────────
section "Checks"

[[ $EUID -eq 0 ]] || die "Run this as root — it replaces files under ${INSTALL_DIR}."
[[ -d "$INSTALL_DIR" ]] || die "No install found at ${INSTALL_DIR}. Use install.sh for a first install."
command -v curl >/dev/null 2>&1 || die "curl is required."

CURRENT="$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null | tr -d '[:space:]' || echo unknown)"
ok "Installed: v${CURRENT} at ${INSTALL_DIR}"

# A scan holding the install directory open is the one thing that makes an
# upgrade genuinely risky: update.sh rsyncs over it with --delete, which pulls
# the scanner's own code out from under a running worker.
if pgrep -f 'backend/cron/scan\.php' >/dev/null 2>&1 \
   || pgrep -x clamscan >/dev/null 2>&1; then
    warn "A scan is running. update.sh stops it, but finishing it first is tidier."
    warn "  Stop it now with:  php ${INSTALL_DIR}/backend/cli/serverscrub.php scan:stop"
fi

# ── Which version is available ────────────────────────────────────────────────
section "Release channel"

MANIFEST=""
CHANNEL_USED=""
for BASE in "${CHANNELS[@]}"; do
    info "Trying ${BASE}/latest.json"
    if MANIFEST="$(curl -fsSL --max-time 20 "${BASE}/latest.json" 2>/dev/null)"; then
        CHANNEL_USED="$BASE"
        ok "Answered: ${BASE}"
        break
    fi
    MANIFEST=""
done

[[ -n "$MANIFEST" ]] || {
    err "No release channel answered. Tried:"
    for BASE in "${CHANNELS[@]}"; do echo "      - ${BASE}/latest.json"; done
    die "Check outbound HTTPS and DNS from this server."
}

LATEST="$(printf '%s' "$MANIFEST" | grep -oP '"version"\s*:\s*"\K[^"]+' | head -1 || true)"
SHA="$(printf '%s' "$MANIFEST"    | grep -oP '"sha256"\s*:\s*"\K[0-9a-fA-F]+' | head -1 || true)"
[[ -n "$LATEST" ]] || die "The manifest carried no version. Refusing to guess."

ok "Available: v${LATEST}"
[[ -n "$SHA" ]] && info "Expected SHA-256: ${SHA:0:16}…"

# Compare properly. `sort -V` so 4.10.0 is newer than 4.9.0, which a string
# comparison gets wrong.
if [[ "$CURRENT" == "$LATEST" ]]; then
    ok "Already on v${LATEST} — nothing to do."
    exit 0
fi
NEWER="$(printf '%s\n%s\n' "$CURRENT" "$LATEST" | sort -V | tail -1 || true)"
if [[ "$NEWER" == "$CURRENT" && "$CURRENT" != "unknown" ]]; then
    warn "The channel offers v${LATEST}, which is OLDER than the installed v${CURRENT}."
    warn "Refusing to downgrade. Use --version ${LATEST} if you really mean it."
    exit 1
fi

# A change of major version can change behaviour. Say so out loud.
if [[ "${CURRENT%%.*}" =~ ^[0-9]+$ && "${LATEST%%.*}" =~ ^[0-9]+$ ]] \
   && (( ${LATEST%%.*} > ${CURRENT%%.*} )); then
    warn "v${LATEST} is a MAJOR version change from v${CURRENT}."
    warn "Read the changelog before this one: ${CHANNEL_USED}/v${LATEST}/CHANGELOG.md"
fi

echo
echo -e "  ${BOLD}v${CURRENT}  →  v${LATEST}${NC}"
echo

$CHECK_ONLY && { info "--check given; nothing changed."; exit 0; }

# ── Get the updater that ships WITH the new version ──────────────────────────
section "Updater"

UPDATER="${INSTALL_DIR}/update.sh"
TMP=""

if $USE_LOCAL; then
    [[ -f "$UPDATER" ]] || die "No ${UPDATER} and --local was given."
    info "Using the installed updater (--local)"
else
    TMP="$(mktemp -d /tmp/sg-upgrade.XXXXXX)"
    trap 'rm -rf "$TMP"' EXIT

    FETCHED=false
    for BASE in "$CHANNEL_USED" "${CHANNELS[@]}"; do
        if curl -fsSL --max-time 30 "${BASE}/update.sh" -o "${TMP}/update.sh" 2>/dev/null \
           && [[ -s "${TMP}/update.sh" ]] && head -1 "${TMP}/update.sh" | grep -q '^#!'; then
            ok "Fetched the current updater from ${BASE}"
            FETCHED=true
            break
        fi
    done

    if $FETCHED; then
        # Refuse a file that is not a shell script, whatever the server sent.
        # A captive portal or an error page returning 200 is a real failure mode
        # and piping one into bash as root is not a risk worth taking.
        bash -n "${TMP}/update.sh" 2>/dev/null \
            || die "The downloaded update.sh is not valid shell. Refusing to run it."
        UPDATER="${TMP}/update.sh"
    else
        warn "Could not fetch the current updater; falling back to the installed one."
        [[ -f "$UPDATER" ]] || die "...and there is no ${UPDATER} either."
    fi
fi

# ── Confirm ───────────────────────────────────────────────────────────────────
if ! $AUTO_YES; then
    section "Confirm"
    echo "  The updater will:"
    echo "    • download v${LATEST} and verify its SHA-256"
    echo "    • back up the current install under /var/backups/serverscrub"
    echo "    • replace the files, keeping the database, settings, quarantine,"
    echo "      logs, TLS certificates and custom signatures"
    echo "    • restart the web service and the real-time monitor"
    echo "    • roll back by itself if v${LATEST} does not answer afterwards"
    echo
    read -r -p "  Upgrade to v${LATEST} now? [y/N] " REPLY </dev/tty || REPLY=n
    [[ "$REPLY" =~ ^[Yy]$ ]] || { info "Nothing changed."; exit 0; }
fi

# ── Hand over ─────────────────────────────────────────────────────────────────
section "Upgrading"
info "Handing over to update.sh — its output follows."
echo

# exec so update.sh owns the terminal and its exit status is ours. Nothing is
# added after this point: the updater's own rollback is the last word on
# whether this worked.
exec bash "$UPDATER" --yes "${PASSTHRU[@]+${PASSTHRU[@]}}"
