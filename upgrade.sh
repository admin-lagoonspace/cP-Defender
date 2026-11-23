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
CDN_BASE="${SG_CDN_BASE:-https://serverscrub.com/releases}"
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

# ── Which version is available ──────────────────────────────────────────
section "Release channel"

# EVERY channel, EVERY time, and the highest version wins.
#
# This block used to take the FIRST channel that answered, with no cache
# buster and no cross-check -- the exact pattern that was removed from
# update.sh at v4.28.10 and left here. On 2026-11-23 that cost the user the
# upgrade entirely: the CDN mirror has been frozen at 4.37.0 since September,
# the CDN is first in CHANNELS, the install was 4.37.7, so this script read
# 4.37.0, decided it was being asked to downgrade and exited 1 -- never
# reaching update.sh, which would have found 4.37.9 on GitHub. A lagging
# mirror must never be able to block an upgrade.
#
# Two further things measured the same day, which is why a cache buster alone
# is not enough here either (see update.sh for the full note):
#
#   * ?cb= is NOT part of raw.githubusercontent.com's cache key -- same ETag,
#     X-Cache: HIT -- and the branch path is served with max-age=300.
#   * .../main/latest/VERSION is a 404, so the cross-check written to catch a
#     cached manifest cannot fire on the GitHub channel at all. A 404 is not a
#     passed cross-check.
#
# What cannot be served stale is a path that NAMES the version, because it is
# written once: raw.githubusercontent.com/<repo>/v4.37.9/latest.json (the git
# tag) and <cdn>/v4.37.9/latest.json (the per-build copy). The answer this
# script acts on is corroborated against one of those, or it is labelled.

CACHE_BUST="$(date +%s 2>/dev/null || echo 0)$$"
NOCACHE_HDRS=(-H 'Cache-Control: no-cache, no-store, max-age=0' -H 'Pragma: no-cache')
_nocache() { # _nocache <url> -> same url with a single-use cache-buster
    local u="$1" sep='?'
    case "$u" in *\?*) sep='&' ;; esac
    printf '%s%scb=%s' "$u" "$sep" "$CACHE_BUST"
}
# Version compare, not a string compare: 4.10.0 is newer than 4.9.0, and
# 4.28.10 is newer than 4.28.9, which is the pair that caused the v4.28.9
# rollback.
_ver_gt() { # _ver_gt <a> <b> -> true when a > b
    local a="${1%%-*}" b="${2%%-*}"
    [[ "$a" == "$b" ]] && return 1
    [[ "$(printf '%s\n%s\n' "$b" "$a" | sort -V | tail -1)" == "$a" ]]
}
_json() { # _json <body> <key>
    printf '%s' "$1" | grep -oP "\"$2\"\\s*:\\s*\"\\K[^\"]+" | head -1 || true
}
# On raw.githubusercontent.com the version is a git ref and REPLACES the
# branch component; on a file channel it is a directory under the root.
_pinned_prefix() { # _pinned_prefix <channel-base> <version>
    local base="${1%/}" ver="$2"
    case "$base" in
        https://raw.githubusercontent.com/*)
            printf 'https://raw.githubusercontent.com/%s/v%s' "$RELEASES_REPO" "$ver" ;;
        *)  printf '%s/v%s' "$base" "$ver" ;;
    esac
}
# The newest version a channel can name without reading a mutable path. One
# request to the tags API (60/hour unauthenticated, s-maxage=60 -- so the LIST
# can be a minute old; it is the manifest under the tag that cannot be stale).
# A plain file channel has no ref listing and corroborates through
# latest/VERSION and its per-build manifest instead.
_immutable_channel_version() { # _immutable_channel_version <channel-base>
    local base="$1" tags=""
    case "$base" in
        https://raw.githubusercontent.com/*)
            tags="$(curl -fsSL --max-time 10 "${NOCACHE_HDRS[@]}" \
                     -H 'Accept: application/vnd.github+json' \
                     "$(_nocache "https://api.github.com/repos/${RELEASES_REPO}/tags?per_page=10")" \
                     2>/dev/null || true)"
            printf '%s' "$tags" \
                | grep -oE '"name"[[:space:]]*:[[:space:]]*"v?[0-9]+\.[0-9]+\.[0-9]+[^"]*"' \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^"]*' \
                | sort -V | tail -1
            ;;
    esac
}

LATEST=""
SHA=""
CHANNEL_USED=""
PINNED_PREFIX=""
CORROBORATED=false
CORROB_SRC=""
REPORT=()

for BASE in "${CHANNELS[@]}"; do
    info "Asking ${BASE}"
    BODY="$(curl -fsSL --max-time 20 "${NOCACHE_HDRS[@]}" \
            "$(_nocache "${BASE}/latest.json")" 2>/dev/null || true)"
    THIS_VER="$(_json "${BODY:-}" version)"; THIS_VER="${THIS_VER#v}"
    # latest/VERSION is read out of the extracted build, so it cannot claim a
    # version the tree beside it does not hold. A 404 here is NORMAL -- a
    # channel serving only dist/ has no latest/ tree -- and must never stop
    # the run, which is what the `|| true` is for.
    THIS_TREE="$(curl -fsSL --max-time 10 "${NOCACHE_HDRS[@]}" \
            "$(_nocache "${BASE}/latest/VERSION")" 2>/dev/null | tr -d '[:space:]' || true)"
    THIS_TREE="${THIS_TREE#v}"
    if [[ -n "$THIS_TREE" ]] && _ver_gt "$THIS_TREE" "${THIS_VER:-0.0.0}"; then
        warn "  manifest says v${THIS_VER:-none} but latest/ holds v${THIS_TREE} - trusting the tree"
        THIS_VER="$THIS_TREE"
        BODY=""   # the stale manifest's url and checksum describe another build
    fi
    REPORT+=("${BASE} -> ${THIS_VER:+v}${THIS_VER:-no answer}")
    [[ -n "$THIS_VER" ]] || { warn "  no usable answer"; continue; }
    if [[ -z "$LATEST" ]] || _ver_gt "$THIS_VER" "$LATEST"; then
        LATEST="$THIS_VER"
        SHA="$(_json "${BODY:-}" sha256)"
        CHANNEL_USED="$BASE"
        [[ -n "$THIS_TREE" && "$THIS_TREE" == "$THIS_VER" ]] \
            && { CORROBORATED=true; CORROB_SRC="${BASE}/latest/VERSION"; }
    fi
done

# ── Corroborate against a path that names the version ───────────────────
for BASE in "${CHANNELS[@]}"; do
    [[ -n "$LATEST" ]] || break
    IMM_VER="$(_immutable_channel_version "$BASE" 2>/dev/null || true)"
    [[ -n "$IMM_VER" ]] || IMM_VER="$LATEST"
    IMM_VER="${IMM_VER#v}"
    # Only ever forwards. A ref older than the answer in hand is a lagging
    # mirror, reported below, and nothing to install from.
    _ver_gt "$LATEST" "$IMM_VER" && continue
    PIN_URL="$(_pinned_prefix "$BASE" "$IMM_VER")/latest.json"
    PIN_JSON="$(curl -fsSL --max-time 10 "${NOCACHE_HDRS[@]}" \
                "$(_nocache "$PIN_URL")" 2>/dev/null || true)"
    PIN_VER="$(_json "${PIN_JSON:-}" version)"; PIN_VER="${PIN_VER#v}"
    [[ -n "$PIN_JSON" && "$PIN_VER" == "$IMM_VER" ]] || continue
    if _ver_gt "$IMM_VER" "$LATEST"; then
        warn "The channel manifests say v${LATEST}; the newest release ref holds v${IMM_VER}."
        warn "  Taking the version-pinned manifest - a branch path can be answered from a"
        warn "  cache for up to 5 minutes, and a path naming the version cannot."
        LATEST="$IMM_VER"
        SHA="$(_json "$PIN_JSON" sha256)"
        CHANNEL_USED="$BASE"
    fi
    PINNED_PREFIX="$(_pinned_prefix "$BASE" "$LATEST")"
    CORROBORATED=true
    CORROB_SRC="$PIN_URL"
done

# ── What every channel said ─────────────────────────────────────────────
[[ -n "$LATEST" ]] || {
    err "No release channel answered. Tried:"
    for BASE in "${CHANNELS[@]}"; do echo "      - ${BASE}/latest.json"; done
    die "Check outbound HTTPS and DNS from this server."
}

# Named individually, every time there is more than one. A mirror that has
# stopped syncing is invisible otherwise: nine releases went unmirrored.
if [[ ${#REPORT[@]} -gt 1 ]]; then
    info "Channels:"
    for _r in "${REPORT[@]}"; do info "    ${_r}"; done
fi
for _r in "${REPORT[@]}"; do
    _rv="${_r##*-> }"; _rv="${_rv#v}"
    [[ "$_rv" == "no answer" ]] && continue
    if _ver_gt "$LATEST" "$_rv"; then
        warn "${_r%% ->*} is behind at v${_rv} (newest is v${LATEST}) - that mirror's sync has stalled."
    fi
done

ok "Available: v${LATEST}  (from ${CHANNEL_USED})"
[[ -n "$SHA" ]] && info "Expected SHA-256: ${SHA:0:16}..."
if $CORROBORATED; then
    info "Confirmed against ${CORROB_SRC} - a url that names the version, so no"
    info "  cache can have answered it with a different build."
else
    warn "UNCONFIRMED: v${LATEST} comes only from ${CHANNEL_USED}/latest.json, which is"
    warn "  a cacheable url and may be up to 5 minutes behind a release. Nothing"
    warn "  addressed by version could be reached to corroborate it."
fi

# ── Decide ──────────────────────────────────────────────────────────────
if _ver_gt "$LATEST" "$CURRENT"; then
    :   # there is something newer; fall through to the updater
elif [[ "$LATEST" == "$CURRENT" ]]; then
    if $CORROBORATED; then
        ok "Already on v${LATEST} - nothing to do."
        exit 0
    fi
    # NOT "nothing to do". That claim was printed on 2026-11-23 from a
    # five-minute-old cached manifest, minutes after v4.37.8 was published.
    warn "That is the installed version, but it could not be corroborated, so this"
    warn "  is NOT a confirmation that this server is current. Handing over to the"
    warn "  updater, which resolves the version again and installs nothing if there"
    warn "  is nothing newer."
else
    # Every channel that answered is BEHIND this install.
    warn "No channel offers anything newer than the installed v${CURRENT}."
    warn "  A mirror behind the installed version is a stalled sync, not a release"
    warn "  being withdrawn."
    if $CORROBORATED && [[ "$CURRENT" != "unknown" ]]; then
        err "Refusing to replace v${CURRENT} with the older v${LATEST}."
        echo "      To roll back deliberately:  bash ${INSTALL_DIR}/update.sh --version ${LATEST} --allow-downgrade" >&2
        echo "      To pin a channel:           SG_MANIFEST_URL=${GITHUB_BASE}/latest.json bash \"$0\"" >&2
        exit 1
    fi
    warn "  That reading is not corroborated either, so the decision is not made"
    warn "  here. The updater refuses a downgrade by itself unless"
    warn "  --allow-downgrade is given; handing over to it."
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

    # THE VERSION-PINNED COPY FIRST.
    #
    # The whole reason this script exists is that the update.sh on disk shipped
    # with the version already installed. Fetching from a channel ROOT has the
    # same shape of problem one level up: ${CDN}/update.sh is whatever that
    # mirror last synced -- 4.37.0 on the live CDN today -- and a branch path
    # can be served from a cache for five minutes. The updater that ships WITH
    # the version being installed is the one under the version-named path, and
    # it cannot be stale. The channel roots stay as fallbacks, because on a
    # firewalled box they may be all there is.
    FETCH_FROM=()
    [[ -n "$PINNED_PREFIX" ]] && FETCH_FROM+=("$PINNED_PREFIX")
    FETCH_FROM+=("$CHANNEL_USED" "${CHANNELS[@]}")
    # latest/ is where a CDN-shaped channel keeps the extracted shell scripts;
    # the root of that docroot holds get.sh only.
    for BASE in "$CHANNEL_USED" "${CHANNELS[@]}"; do FETCH_FROM+=("${BASE}/latest"); done

    FETCHED=false
    for BASE in "${FETCH_FROM[@]}"; do
        if curl -fsSL --max-time 30 "${NOCACHE_HDRS[@]}" \
                "$(_nocache "${BASE}/update.sh")" -o "${TMP}/update.sh" 2>/dev/null \
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
