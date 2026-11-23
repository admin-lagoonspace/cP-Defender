#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# ServerScrub — Safe Update Script
# Downloads the latest release from GitHub, applies it over the current
# installation, and preserves ALL user data (database, settings, quarantine,
# logs, TLS certs, custom signatures).
#
# Usage:
#   bash /usr/local/serverscrub/update.sh
#   bash /usr/local/serverscrub/update.sh --yes               # non-interactive
#   bash /usr/local/serverscrub/update.sh --version 3.3.7     # skip API, force version
#   bash /usr/local/serverscrub/update.sh --url https://...   # use a direct zip URL
#
# Run as: root
# ════════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── WHY EVERY PIPELINE ASSIGNMENT BELOW ENDS IN `|| true` ─────────────────────
#
# Under `set -e` a plain assignment takes the exit status of its command
# substitution, and under `pipefail` a pipeline fails if ANY stage fails. So
#
#     VAR="$(curl -fsSL "$URL" 2>/dev/null | tr -d '[:space:]')"
#
# does not leave VAR empty when the URL 404s. It terminates the script, and
# because stderr went to /dev/null it does so with NO MESSAGE AT ALL.
#
# This is not hypothetical. On 2026-10-20 a production server on v4.4.2 ran the
# updater twice and both times it printed "Checking releases channel for latest
# version…" and returned to the prompt. Exit 22, curl's code for HTTP 404,
# from an INFORMATIONAL cross-check of <channel>/latest/VERSION — a line whose
# only job is to print a nicer message. The CDN had never been populated, so
# that file was missing, and the updater died on the first channel before ever
# trying the GitHub mirror that was working perfectly.
#
# Every one of these assignments is followed by an `[[ -z ... ]]` check or a
# fallback: the code was written expecting an empty value on failure. `|| true`
# is what restores that intent. Where a value is genuinely required, the
# existing emptiness check reports it properly instead of dying mute.
#
# scripts/check-shell-pipefail.py fails preflight on any new one of these.

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()      { echo -e "  ${GREEN}✔${NC}  $*"; }
info()    { echo -e "  ${CYAN}→${NC}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; }
err()     { echo -e "  ${RED}✖${NC}  $*" >&2; }
section() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }
die()     { err "$*"; exit 1; }

# ── Progress state, for the dashboard ─────────────────────────────────────────
# Written OUTSIDE the install directory on purpose: the update rsyncs over
# ${INSTALL_DIR} with --delete, so anything kept inside would be destroyed
# mid-run — exactly when the UI most needs to read it.
STATE_DIR="${SG_STATE_DIR:-/var/lib/serverscrub}"
STATE_FILE="${STATE_DIR}/update-state.json"
mkdir -p "$STATE_DIR" 2>/dev/null || true

STATE_PHASE="idle"; STATE_PCT=0; STATE_STATUS="running"
state() {   # state <phase> <pct> [message]
    STATE_PHASE="$1"; STATE_PCT="$2"
    local msg="${3:-$1}"
    cat > "${STATE_FILE}.tmp" 2>/dev/null <<JSON || return 0
{
  "status":       "${STATE_STATUS}",
  "phase":        "${STATE_PHASE}",
  "percent":      ${STATE_PCT},
  "message":      "${msg//\"/}",
  "from_version": "${CURRENT_VERSION:-}",
  "to_version":   "${LATEST_VERSION:-}",
  "pid":          $$,
  "updated_at":   $(date +%s)
}
JSON
    mv -f "${STATE_FILE}.tmp" "$STATE_FILE" 2>/dev/null || true
}
state_done()   { STATE_STATUS="success";     state "done" 100 "${1:-Update complete}"; }
state_failed() { STATE_STATUS="failed";      state "failed" "${STATE_PCT}" "${1:-Update failed}"; }
state_rolled() { STATE_STATUS="rolled_back"; state "rolled_back" 100 "${1:-Rolled back to the previous version}"; }

# ── Rollback ──────────────────────────────────────────────────────────────────
# Armed only once the overlay starts. Before that nothing has been modified, so
# a failure needs no repair — arming earlier would restore a snapshot over an
# installation that was never touched.
ROLLBACK_ARMED=false
CODE_SNAPSHOT=""

rollback() {
    $ROLLBACK_ARMED || return 0
    [[ -n "$CODE_SNAPSHOT" && -d "$CODE_SNAPSHOT" ]] || {
        err "No code snapshot — cannot roll back automatically."
        return 1
    }
    echo ""
    warn "Update failed — rolling back to v${CURRENT_VERSION}…"
    STATE_STATUS="running"; state "rollback" 90 "Restoring previous version"

    # Code first, then user data on top: the data restore must win, so settings,
    # database and quarantine survive regardless of what the snapshot contains.
    for dir in "${UPDATE_DIRS[@]}"; do
        [[ -d "${CODE_SNAPSHOT}/${dir}" ]] || continue
        # --checksum here too. A rollback that silently keeps a same-size file
        # from the failed version leaves a half-reverted install, which is
        # worse than either version on its own.
        rsync -a --checksum --delete "${CODE_SNAPSHOT}/${dir}/" "${INSTALL_DIR}/${dir}/" 2>/dev/null             && ok "Restored code: ${dir}/"
    done
    for file in "${UPDATE_FILES[@]}"; do
        [[ -f "${CODE_SNAPSHOT}/${file}" ]] || continue
        cp -f "${CODE_SNAPSHOT}/${file}" "${INSTALL_DIR}/${file}" 2>/dev/null             && ok "Restored: ${file}"
    done
    for item in "${PRESERVE[@]}"; do
        src="${BACKUP_DIR}/$(basename "$item")"
        [[ -e "$src" ]] || continue
        mkdir -p "$(dirname "$item")"
        cp -a "$src" "$(dirname "$item")/" 2>/dev/null && ok "Restored data: $item"
    done

    chmod +x "${INSTALL_DIR}"/*.sh 2>/dev/null || true
    systemctl start serverscrub-monitor 2>/dev/null || true

    state_rolled "Rolled back to v${CURRENT_VERSION}. Your settings and data are intact."
    err "Rolled back to v${CURRENT_VERSION}. No changes were kept."
}

on_error() {
    local rc=$?
    [[ $rc -eq 0 ]] && return 0
    state_failed "Update failed at: ${STATE_PHASE}"
    rollback
    exit $rc
}
trap on_error ERR

# ── Config ────────────────────────────────────────────────────────────────────
# Updates are pulled from a PUBLIC releases channel, NOT the private source repo.
# This means no GitHub credentials ever ship to customer servers. The channel
# holds two things: a manifest (latest.json) and the built zips under dist/.
#
#   latest.json:
#     { "version": "3.5.0",
#       "url":     "https://raw.githubusercontent.com/<repo>/main/dist/serverscrub-3.5.0.zip",
#       "sha256":  "<hex>",
#       "notes":   "https://..." }
#
# The manifest carries the full download URL, so the updater never has to guess
# the asset filename (kills the old v-prefix / no-prefix naming mismatch).
INSTALL_DIR="${SG_ROOT:-/usr/local/serverscrub}"

# ── Never be the file you are overwriting ─────────────────────────────────────
#
# FROM A LIVE SERVER, 31 Oct 2026. An update applied cleanly and then died:
#
#     ✔  Updated: update.sh
#     /usr/local/serverscrub/update.sh: line 642: ater: command not found
#     ⚠  Update failed — rolling back
#
# "ater" is not in this file, or any file. update.sh is in UPDATE_FILES, so the
# updater copies the new version over itself WHILE BASH IS STILL READING IT.
# Bash does not slurp a script; it reads incrementally and remembers a byte
# OFFSET. Replace the file underneath it and execution resumes at that offset
# in different content -- landing mid-word, and running the tail of one as a
# command.
#
# This has always been here. It only fired when a release changed the length of
# this file enough to move the offset somewhere harmful, so every earlier
# update survived on luck rather than on design. The failure is also maximally
# confusing: the update itself worked, every file was copied, and the error
# names a command nobody wrote.
#
# So: re-exec from a private copy before touching anything. The script bash is
# reading then lives in /tmp, nothing overwrites it, and the offset stays
# valid however much this file changes.
#
# The copy is unlinked immediately. On Linux an open file keeps its inode until
# the descriptor closes, so bash reads on quite happily and nothing is left in
# /tmp if the run is killed.
if [[ "${SG_UPDATE_REEXEC:-0}" != "1" ]]; then
    _self="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
    _inst="$(readlink -f "${INSTALL_DIR}/update.sh" 2>/dev/null || echo "${INSTALL_DIR}/update.sh")"
    # Only when running the INSTALLED copy. Anything else -- upgrade.sh's
    # fetched copy in /tmp, a checkout, a hand-placed file -- is not the file
    # this run will replace, so leave it alone.
    if [[ -n "$_self" && "$_self" == "$_inst" && -r "$_self" ]]; then
        _tmp="$(mktemp /tmp/sg-updater.XXXXXX.sh 2>/dev/null || true)"
        if [[ -n "$_tmp" ]] && cp -f "$_self" "$_tmp" 2>/dev/null; then
            export SG_UPDATE_REEXEC=1
            exec bash "$_tmp" "$@"
        fi
        # Could not make a copy: carry on rather than refuse to update at all.
        # The old behaviour is a risk, not a certainty, and being unable to
        # update is worse than running the way every previous release did.
        echo "  [!] could not stage a private copy of the updater; continuing" >&2
    fi
fi
# Re-executed: drop the temp copy now. The descriptor stays open, so bash keeps
# reading it, and an interrupted run leaves nothing behind.
if [[ "${SG_UPDATE_REEXEC:-0}" == "1" ]]; then
    case "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)" in
        /tmp/sg-updater.*) rm -f "$(readlink -f "${BASH_SOURCE[0]}")" 2>/dev/null || true ;;
    esac
fi
# Repo is public, so updates are served straight from it — no separate channel,
# no credentials on customer servers. Override via env if you ever split it out.
RELEASES_REPO="${SG_RELEASES_REPO:-admin-lagoonspace/cP-Defender}"
RELEASES_BRANCH="${SG_RELEASES_BRANCH:-main}"
# Primary channel is our own CDN — no API rate limits, and it keeps working on
# servers whose firewall blocks github.com (the exact failure that broke v3.3.6
# updates in the field). GitHub raw stays as an automatic fallback.
CDN_BASE="${SG_CDN_BASE:-https://serverscrub.com/releases}"
GITHUB_BASE="https://raw.githubusercontent.com/${RELEASES_REPO}/${RELEASES_BRANCH}"
# The old download host, kept as a channel through the move to
# serverscrub.com.
#
# Every server already installed has the OLD url baked into the update.sh
# sitting on its disk, and only learns the new one by taking an update. That
# direction is covered by the old host continuing to serve. This covers the
# other direction: a server that HAS taken this update, on a day the new host
# is not yet reachable, still has somewhere to go. Remove it once no
# installation predates the move.
LEGACY_BASE="https://defender.lws-s1.com/releases"
CHANNELS=("$CDN_BASE" "$LEGACY_BASE" "$GITHUB_BASE")
# Explicit override wins and disables channel rotation
[[ -n "${SG_MANIFEST_URL:-}" ]] && CHANNELS=("${SG_MANIFEST_URL%/latest.json}")
MANIFEST_URL="${CHANNELS[0]}/latest.json"
DIST_BASE="${CHANNELS[0]}/dist"
BACKUP_ROOT="/var/backups/serverscrub"
TMP_DIR="$(mktemp -d /tmp/sg-update.XXXXXX)"
AUTO_YES=false
ALLOW_DOWNGRADE=false
FORCE_VERSION=""
FORCE_URL=""
EXPECTED_SHA256=""

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)              AUTO_YES=true ;;
        # Separate from --yes on purpose: see the downgrade guard below.
        --allow-downgrade)  ALLOW_DOWNGRADE=true ;;
        --version)          shift; FORCE_VERSION="${1:-}"; FORCE_VERSION="${FORCE_VERSION#v}" ;;
        --version=*)        FORCE_VERSION="${1#--version=}"; FORCE_VERSION="${FORCE_VERSION#v}" ;;
        --url)              shift; FORCE_URL="${1:-}" ;;
        --url=*)            FORCE_URL="${1#--url=}" ;;
        *) warn "Unknown option: $1" ;;
    esac
    shift
done

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Run as root:  sudo bash $0"
[[ -d "$INSTALL_DIR" ]] || die "ServerScrub not found at $INSTALL_DIR"

# Cleanup on exit
trap 'rm -rf "$TMP_DIR"' EXIT

echo ""
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════╗"
echo -e "║    ServerScrub — Safe Updater       ║"
echo -e "╚═══════════════════════════════════════╝${NC}"
echo ""

# ── Helper: a URL an intermediate cache cannot answer from ──────────────────
#
# The CDN sits behind cPanel's nginx reverse-proxy cache, and that cache does
# NOT honour client revalidation. Measured against the live host on 2026-11-13,
# the day v4.36.0 was published:
#
#   GET /releases/latest.json                                 -> 4.35.1
#   GET /releases/latest.json  -H 'Cache-Control: no-cache'
#                              -H 'Pragma: no-cache'          -> 4.35.1
#   GET /releases/latest.json?cb=<timestamp>                   -> 4.36.0
#
# Last-Modified on the stale answers was the 4.35.1 publish time, six days
# earlier, while the file on the origin disk read 4.36.0. Asking politely does
# nothing; only a cache key the proxy has never seen misses it. Every fetch of
# a VERSION-BEARING url therefore carries a unique query string. (The zip
# downloads do not need it -- their names already contain the version, so a
# cached copy of serverscrub-4.36.0.zip is by definition the right bytes.)
#
# The headers are kept as well. They cost nothing, and they do work on the
# other caches between a customer's server and us.
#
# The same nginx layer is what served stale WAF-event JSON at 4.35.1. It is a
# known hazard of this deployment, not a surprise.
CACHE_BUST="$(date +%s 2>/dev/null || echo 0)$$"
NOCACHE_HDRS=(-H 'Cache-Control: no-cache, no-store, max-age=0' -H 'Pragma: no-cache')
_nocache() { # _nocache <url> -> same url with a single-use cache-buster
    local u="$1" sep='?'
    case "$u" in *\?*) sep='&' ;; esac
    printf '%s%scb=%s' "$u" "$sep" "$CACHE_BUST"
}

# -- Helper: a url that is addressed BY VERSION, and so cannot be stale -------
#
# `?cb=` is not enough on every channel. MEASURED 2026-11-23 against
# raw.githubusercontent.com, the same object, two consecutive requests:
#
#   .../main/latest.json                   -> X-Cache: MISS  ETag "f7a7cab..."
#   .../main/latest.json?cb=17954488137754 -> X-Cache: HIT   ETag "f7a7cab..."
#
# Identical ETag, cache HIT on the "cache-busted" url: the query string is NOT
# part of Fastly's cache key for raw, so the trick that defeats cPanel's nginx
# cache on our own CDN does nothing there. The branch path carries
# Cache-Control: max-age=300, which is the five-minute window the operator
# landed in when v4.37.8 was published and this updater answered
# "Already up to date -- v4.37.7".
#
# A path that names a version is written once and never rewritten, so no cache
# layer can hold a wrong answer for it. The shape differs per channel:
#
#   raw.githubusercontent.com/<repo>/v4.37.9/latest.json   <- the git TAG
#   <cdn>/v4.37.9/latest.json                              <- per-build copy
#
# On raw the version replaces the BRANCH component, it is not appended to it:
# .../<repo>/main/v4.37.9/latest.json is a 404 and always was.
_pinned_manifest_url() { # _pinned_manifest_url <channel-base> <version>
    local base="${1%/}" ver="$2"
    case "$base" in
        https://raw.githubusercontent.com/*)
            printf 'https://raw.githubusercontent.com/%s/v%s/latest.json' \
                   "$RELEASES_REPO" "$ver" ;;
        *)  printf '%s/v%s/latest.json' "$base" "$ver" ;;
    esac
}

# -- Helper: the newest version a channel can name without a mutable path -----
#
# For the GitHub channel that is the tag list. The releases API is NOT used:
# github.com/<repo>/releases/latest 302s to /releases, which is what a repo
# with no published Release objects does, so there is no "latest release" to
# read. Tags do exist, and publish.sh fails the release without one.
#
# One request, `Cache-Control: s-maxage=60` on the answer and 60 requests an
# hour unauthenticated -- and this runs once a day on a schedule. The 60s is
# worth stating plainly: the tag list can be a minute old, so this is not a
# perfectly live reading. It is the manifest UNDER the tag that cannot be
# stale, and that is what gets fetched and compared next.
#
# A channel that is just files over HTTP has no ref listing at all; it
# corroborates through latest/VERSION and its per-build manifest instead.
_immutable_channel_version() { # _immutable_channel_version <channel-base>
    local base="$1" tags=""
    case "$base" in
        https://raw.githubusercontent.com/*)
            tags="$(curl -fsSL --max-time 10 "${NOCACHE_HDRS[@]}" \
                     -H 'Accept: application/vnd.github+json' \
                     "$(_nocache "https://api.github.com/repos/${RELEASES_REPO}/tags?per_page=10")" \
                     2>/dev/null || true)"
            # Highest by version, not whatever the API listed first. Tag order
            # is not a documented guarantee, and `v4.9.0` sorts above `v4.36.0`
            # one character at a time.
            printf '%s' "$tags" \
                | grep -oE '"name"[[:space:]]*:[[:space:]]*"v?[0-9]+\.[0-9]+\.[0-9]+[^"]*"' \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^"]*' \
                | sort -V | tail -1
            ;;
    esac
}

# ── Helper: download a URL to a file (curl first, wget fallback) ──────────────
_download() {
    local url="$1" dest="$2" label="${3:-file}"
    if command -v curl >/dev/null 2>&1; then
        info "Downloading ${label} via curl…"
        if curl -fL --progress-bar --max-time 120 -o "$dest" "$url"; then
            return 0
        fi
        warn "curl failed. Trying wget…"
    fi
    if command -v wget >/dev/null 2>&1; then
        info "Downloading ${label} via wget…"
        if wget -q --show-progress --timeout=120 -O "$dest" "$url" 2>&1; then
            return 0
        fi
        warn "wget also failed."
    fi
    return 1
}

# ── Detect current version ────────────────────────────────────────────────────
section "Version check"
CURRENT_VERSION="$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null | tr -d '[:space:]' || true)"
[[ -z "$CURRENT_VERSION" ]] && CURRENT_VERSION="unknown"
info "Current version: ${BOLD}v${CURRENT_VERSION}${NC}"

# ── Resolve target version ────────────────────────────────────────────────────
LATEST_VERSION=""
DOWNLOAD_URL=""
RELEASE_URL=""

if [[ -n "$FORCE_VERSION" ]]; then
    # ── Manual version override — build URL from the public dist path ──────────
    info "Using forced version: ${BOLD}v${FORCE_VERSION}${NC} (--version flag)"
    LATEST_VERSION="$FORCE_VERSION"
    DOWNLOAD_URL="${DIST_BASE}/serverscrub-${LATEST_VERSION}.zip"
    warn "No checksum available for a forced version — integrity will NOT be verified."

elif [[ -n "$FORCE_URL" ]]; then
    # ── Direct URL supplied — derive version from current install ─────────────
    info "Using direct download URL (--url flag)"
    LATEST_VERSION="${CURRENT_VERSION}-manual"
    DOWNLOAD_URL="$FORCE_URL"
    warn "No checksum available for a direct URL — integrity will NOT be verified."

else
    # ── Fetch the manifest from every channel and take the NEWEST ─────────────
    #
    # This used to stop at the first channel that answered. That was right
    # while a broken channel 404d -- it fell through to the next one. It is
    # wrong when a channel answers with STALE data: the updater believes it,
    # reports "Already up to date", and every server stays pinned to an old
    # version with nothing to indicate why.
    #
    # Which is exactly what happened. The CDN's sync died before writing its
    # manifest, so the CDN served v4.28.9 while GitHub had v4.28.10, and the
    # updater never asked GitHub because the CDN had already replied. A
    # channel that fails loudly is safe; a channel that is confidently wrong
    # is not.
    #
    # So: ask all of them, keep the highest version, and say so when they
    # disagree -- a mirror falling behind is worth knowing about.
    info "Checking releases channel for latest version…"
    API_RETRIES=2
    API_WAIT=4
    MANIFEST_JSON=""
    ACTIVE_BASE=""
    BEST_VER=""
    # Highest latest/VERSION seen on ANY channel, and where it was seen.
    # Tracked separately from the manifest because the whole point is that the
    # two can disagree, and the tree is the one that cannot lie about itself.
    BEST_LIVE=""
    BEST_LIVE_BASE=""
    CHANNEL_REPORT=()

    # Highest-version test, needed here as well as below. `_is_newer` is
    # defined further down and cannot be used before the manifest exists.
    _ver_gt() {
        local a="${1%%-*}" b="${2%%-*}"
        [[ "$a" == "$b" ]] && return 1
        [[ "$(printf '%s\n%s\n' "$b" "$a" | sort -V | tail -1)" == "$a" ]]
    }

    for BASE in "${CHANNELS[@]}"; do
        # Once a channel has answered, the rest are cross-checks. Probing them
        # with the full retry budget would add ~8s per dead channel to every
        # update, so they get one quick attempt.
        if [[ -n "$MANIFEST_JSON" ]]; then
            API_RETRIES=1
        fi
        # latest/VERSION is the extracted build the channel is actually serving.
        # Six bytes, and it cannot disagree with what is on disk there, so it is
        # used to cross-check the manifest below.
        # NO LONGER INFORMATIONAL. This used to be a nicer message plus a
        # cross-check that printed a warning and changed nothing; on
        # 2026-11-13 it read 4.36.0 next to a cached 4.35.1 manifest and the
        # updater went ahead with the manifest, reporting "Already up to
        # date" on every server in the field. It now OVERRIDES a lower
        # manifest version (see the override block after the loop).
        #
        # A missing latest/VERSION is still normal on a channel that serves
        # only dist/, and must never stop the update. THIS LINE, without its
        # `|| true`, is what silently killed the updater on a live server.
        THIS_LIVE="$(curl -fsSL --max-time 10 "${NOCACHE_HDRS[@]}" "$(_nocache "${BASE}/latest/VERSION")" 2>/dev/null | tr -d '[:space:]' || true)"
        [[ -n "$THIS_LIVE" ]] && info "  ${BASE}/latest/ reports v${THIS_LIVE}"
        # Kept even when this channel's manifest loses the comparison below. A
        # channel can serve a stale manifest and a current tree at the same
        # time -- that is exactly the 4.36.0 failure -- and discarding the tree
        # reading because the manifest beside it was older threw away the only
        # correct answer on the wire.
        if [[ -n "$THIS_LIVE" ]] && { [[ -z "$BEST_LIVE" ]] || _ver_gt "$THIS_LIVE" "$BEST_LIVE"; }; then
            BEST_LIVE="$THIS_LIVE"
            BEST_LIVE_BASE="$BASE"
        fi

        info "  Trying: ${BASE}/latest.json"
        THIS_JSON=""
        for attempt in $(seq 1 $API_RETRIES); do
            [[ $attempt -gt 1 ]] && { warn "  Retrying in ${API_WAIT}s (${attempt}/${API_RETRIES})…"; sleep $API_WAIT; }
            CURL_ERR_FILE="${TMP_DIR}/curl_err.txt"
            if THIS_JSON="$(curl -fsSL --max-time 15 \
                    "${NOCACHE_HDRS[@]}" \
                    "$(_nocache "${BASE}/latest.json")" 2>"$CURL_ERR_FILE")"; then
                break
            else
                CURL_EXIT=$?
                CURL_ERR="$(cat "$CURL_ERR_FILE" 2>/dev/null || true)"
                warn "  curl exit ${CURL_EXIT}: ${CURL_ERR}"
                THIS_JSON=""
            fi
        done

        if [[ -z "$THIS_JSON" ]]; then
            warn "Channel unreachable, trying next…"
            continue
        fi

        THIS_VER="$(echo "$THIS_JSON" | grep -oP '"version"\s*:\s*"\K[^"]+' | head -1 || true)"
        [[ -n "$THIS_VER" ]] || THIS_VER="$THIS_LIVE"
        CHANNEL_REPORT+=("${BASE} → v${THIS_VER:-unparseable}")

        if [[ -z "$MANIFEST_JSON" ]] || { [[ -n "$THIS_VER" ]] && _ver_gt "$THIS_VER" "$BEST_VER"; }; then
            MANIFEST_JSON="$THIS_JSON"
            ACTIVE_BASE="$BASE"
            DIST_BASE="${BASE}/dist"
            BEST_VER="$THIS_VER"
            LIVE_VER="$THIS_LIVE"
        fi
    done

    # A mirror serving an older build than another is not fatal -- we just
    # took the newer one -- but it is the symptom of a sync that has stopped,
    # and nothing else on the server would ever mention it.
    if [[ ${#CHANNEL_REPORT[@]} -gt 1 ]]; then
        _distinct="$(printf '%s\n' "${CHANNEL_REPORT[@]}" | sed 's/.*→ //' | sort -u | wc -l || true)"
        if [[ "$_distinct" -gt 1 ]]; then
            warn "Channels disagree about the latest version:"
            for _r in "${CHANNEL_REPORT[@]}"; do warn "    ${_r}"; done
            warn "  Using the newest. A channel behind the others has a stalled sync."
        fi
    fi

    [[ -n "$ACTIVE_BASE" ]] && ok "Channel used: ${ACTIVE_BASE} (v${BEST_VER})"

    if [[ -z "$MANIFEST_JSON" ]]; then
        err "Cannot reach ANY releases channel."
        echo ""
        echo -e "  ${BOLD}Channels tried:${NC}"
        for BASE in "${CHANNELS[@]}"; do echo "    - ${BASE}/latest.json"; done
        echo ""
        echo -e "  ${BOLD}Diagnostics:${NC}"
        for _H in "${CDN_BASE#https://}" raw.githubusercontent.com; do
            _H="${_H%%/*}"
            info "DNS for ${_H}…"
            if command -v host >/dev/null 2>&1; then
                host "$_H" 2>&1 | head -2 | while IFS= read -r l; do info "  $l"; done
            elif command -v nslookup >/dev/null 2>&1; then
                nslookup "$_H" 2>&1 | head -4 | while IFS= read -r l; do info "  $l"; done
            else
                info "  (no host/nslookup available)"
            fi
            info "HTTPS to ${_H}…"
            curl -sk --max-time 5 -o /dev/null -w "  HTTP %{http_code} in %{time_total}s\n" \
                "https://${_H}" 2>&1 || info "  (connection failed)"
        done
        echo ""
        echo -e "  ${YELLOW}To update without channel access, run:${NC}"
        echo -e "  ${BOLD}bash $0 --version 3.5.0${NC}"
        echo -e "  or download the zip manually and use:"
        echo -e "  ${BOLD}bash $0 --url https://your-mirror/serverscrub.zip${NC}"
        echo ""
        exit 1
    fi

    # Parse manifest (tolerant of whitespace; values are simple strings)
    LATEST_VERSION="$(echo "$MANIFEST_JSON" | grep -oP '"version"\s*:\s*"\K[^"]+' | head -1 || true)"
    DOWNLOAD_URL="$(echo "$MANIFEST_JSON"   | grep -oP '"url"\s*:\s*"\K[^"]+' | head -1 || true)"
    MIRROR_URL="$(echo "$MANIFEST_JSON"     | grep -oP '"mirror"\s*:\s*"\K[^"]+' | head -1 || true)"
    EXPECTED_SHA256="$(echo "$MANIFEST_JSON" | grep -oP '"sha256"\s*:\s*"\K[0-9a-fA-F]+' | head -1 || true)"
    RELEASE_URL="$(echo "$MANIFEST_JSON"    | grep -oP '"notes"\s*:\s*"\K[^"]+' | head -1 || true)"

    # Fall back to the extracted tree if the manifest was unparseable
    if [[ -z "$LATEST_VERSION" && -n "${LIVE_VER:-}" ]]; then
        LATEST_VERSION="$LIVE_VER"
        warn "Manifest unparseable — using v${LATEST_VERSION} from latest/VERSION"
    fi
    [[ -z "$LATEST_VERSION" ]] && die "Could not parse version from manifest."

    # --- How solid is this answer? -------------------------------------------
    #
    # Tracked, not assumed. "Already up to date" is a factual claim about the
    # patch level of a security product, and it may only be printed when the
    # version behind it came from somewhere a cache cannot have staled.
    # Everything else gets hedged, in words, naming the channel.
    VER_IMMUTABLE=false
    VER_SOURCE=""

    # --- latest/VERSION OVERRIDES a lower manifest version -------------------
    #
    # This cross-check used to be informational: it printed "channel mid-sync"
    # and then went ahead with the manifest anyway. On 2026-11-13 that threw
    # away the right answer while holding it. serverscrub.com/releases served
    # a cached latest.json reading 4.35.1 while latest/VERSION on the same host
    # read 4.36.0, so `update.sh --yes` compared 4.35.1 against the installed
    # 4.35.1 and reported "Already up to date" on every server in the field.
    #
    # The two sources are not equal in authority:
    #
    #   * latest.json is a small, long-lived, constantly-requested url. It is
    #     the ideal shape for a proxy cache to pin, and cPanel's nginx cache
    #     pinned it for six days.
    #   * latest/VERSION is read out of the extracted build itself. It cannot
    #     claim a version the tree beside it does not contain.
    #
    # So when the tree is NEWER than the manifest, the tree wins. The reverse
    # is still only a warning: a manifest ahead of the tree is a sync that has
    # not finished extracting yet, and there is nothing to download there.
    if [[ -n "$BEST_LIVE" ]] && _ver_gt "$BEST_LIVE" "$LATEST_VERSION"; then
        warn "Manifest says v${LATEST_VERSION} but ${BEST_LIVE_BASE}/latest/ holds v${BEST_LIVE}."
        warn "  Trusting the deployed tree: a manifest can be a cached copy of an"
        warn "  older one, while latest/VERSION is read out of the build itself."

        # cdn-sync.sh writes a per-version copy of the manifest next to each
        # build (v<ver>/latest.json). That url is requested roughly once ever,
        # so no cache has it, and it carries the url + sha256 for THIS build --
        # which the stale top-level manifest does not. Preferred over guessing
        # the dist path precisely so the download stays checksum-verified.
        PINNED_URL="${BEST_LIVE_BASE}/v${BEST_LIVE}/latest.json"
        # The two shapes differ: on raw the version is a git ref and REPLACES
        # the branch component, so appending v<ver> to .../<repo>/main/ is a
        # 404 every time. Written out here rather than called out to
        # _pinned_manifest_url so this block reads in one piece.
        case "$BEST_LIVE_BASE" in
            https://raw.githubusercontent.com/*)
                PINNED_URL="https://raw.githubusercontent.com/${RELEASES_REPO}/v${BEST_LIVE}/latest.json" ;;
        esac
        info "  Fetching the per-version manifest: ${PINNED_URL}"
        PINNED_JSON="$(curl -fsSL --max-time 15 "${NOCACHE_HDRS[@]}" "$(_nocache "$PINNED_URL")" 2>/dev/null || true)"
        PINNED_VER="$(printf '%s' "$PINNED_JSON" | grep -oP '"version"\s*:\s*"\K[^"]+' | head -1 || true)"

        if [[ -n "$PINNED_JSON" && "$PINNED_VER" == "$BEST_LIVE" ]]; then
            MANIFEST_JSON="$PINNED_JSON"
            ACTIVE_BASE="$BEST_LIVE_BASE"
            DIST_BASE="${BEST_LIVE_BASE}/dist"
            LATEST_VERSION="$BEST_LIVE"
            DOWNLOAD_URL="$(printf '%s' "$PINNED_JSON"    | grep -oP '"url"\s*:\s*"\K[^"]+' | head -1 || true)"
            MIRROR_URL="$(printf '%s' "$PINNED_JSON"      | grep -oP '"mirror"\s*:\s*"\K[^"]+' | head -1 || true)"
            EXPECTED_SHA256="$(printf '%s' "$PINNED_JSON" | grep -oP '"sha256"\s*:\s*"\K[0-9a-fA-F]+' | head -1 || true)"
            RELEASE_URL="$(printf '%s' "$PINNED_JSON"     | grep -oP '"notes"\s*:\s*"\K[^"]+' | head -1 || true)"
            ok "  Took v${LATEST_VERSION} from the per-version manifest (checksum included)"
            # Addressed by version, so no cache can have answered with another
            # build. This is a corroborated reading, and the only kind the
            # "Already up to date" line below is allowed to rest on.
            VER_IMMUTABLE=true
            VER_SOURCE="$PINNED_URL"
        else
            # No per-version manifest. Still better to install the version the
            # tree says is current than to tell the operator they are up to
            # date when they are not -- but say plainly what was lost.
            LATEST_VERSION="$BEST_LIVE"
            ACTIVE_BASE="$BEST_LIVE_BASE"
            DIST_BASE="${BEST_LIVE_BASE}/dist"
            DOWNLOAD_URL="${DIST_BASE}/serverscrub-${LATEST_VERSION}.zip"
            EXPECTED_SHA256=""
            warn "  No per-version manifest for v${LATEST_VERSION} at ${PINNED_URL}."
            warn "  Falling back to ${DOWNLOAD_URL} — integrity will NOT be verified."
        fi
    elif [[ -n "${LIVE_VER:-}" && "$LIVE_VER" != "$LATEST_VERSION" ]]; then
        warn "Manifest says v${LATEST_VERSION} but latest/ holds v${LIVE_VER} — channel mid-sync."
    fi
    # --- CORROBORATE: the answer must come from a url no cache can stale ----
    #
    # The two mitigations above -- ask every channel, and let latest/VERSION
    # override a lower manifest -- were both already here on 2026-11-23, and
    # both missed the reported failure:
    #
    #   * ?cb= is not in raw.githubusercontent.com's cache key (measured; see
    #     _pinned_manifest_url), so the GitHub manifest can be 5 minutes old
    #     however it is requested.
    #   * .../main/latest/VERSION is a 404 -- there is no latest/ tree in the
    #     repo -- so the cross-check built to catch exactly this has never been
    #     able to fire on the channel that is now the only working one. A 404
    #     is not a passed cross-check.
    #
    # So: find the newest version each channel can name through an immutable
    # ref, confirm it against the manifest committed under that ref, and take
    # it. If nothing immutable can be reached, the branch answer still stands
    # -- the updater has to keep working on a firewalled box -- but it is
    # labelled, and the "Already up to date" line below refuses to print.
    IMM_BEST=""; IMM_BEST_BASE=""; IMM_BEST_JSON=""; IMM_BEST_URL=""
    for BASE in "${CHANNELS[@]}"; do
        IMM_VER="$(_immutable_channel_version "$BASE" 2>/dev/null || true)"
        if [[ -z "$IMM_VER" ]]; then
            # No ref listing on this channel. Its per-build manifest is still
            # addressed by version, so it can corroborate the answer in hand.
            IMM_VER="$LATEST_VERSION"
        fi
        # Only ever corroborate forwards. A ref older than the answer in hand
        # is a lagging mirror -- reported above -- and nothing to download.
        if _ver_gt "$LATEST_VERSION" "$IMM_VER"; then
            continue
        fi
        if [[ -n "$IMM_BEST" ]] && ! _ver_gt "$IMM_VER" "$IMM_BEST"; then
            continue
        fi
        PIN_URL="$(_pinned_manifest_url "$BASE" "$IMM_VER")"
        PIN_JSON="$(curl -fsSL --max-time 10 "${NOCACHE_HDRS[@]}" "$(_nocache "$PIN_URL")" 2>/dev/null || true)"
        PIN_VER="$(printf '%s' "$PIN_JSON" | grep -oP '"version"\s*:\s*"\K[^"]+' | head -1 || true)"
        PIN_VER="${PIN_VER#v}"
        if [[ -n "$PIN_JSON" && "$PIN_VER" == "$IMM_VER" ]]; then
            IMM_BEST="$IMM_VER"; IMM_BEST_BASE="$BASE"
            IMM_BEST_JSON="$PIN_JSON"; IMM_BEST_URL="$PIN_URL"
        elif [[ "$IMM_VER" != "$LATEST_VERSION" ]]; then
            # The ref exists but the manifest under it does not, or disagrees:
            # mid-push, or a tag made over a tree without the file. Nothing to
            # take, and nothing is claimed -- this channel simply has no
            # immutable source today.
            warn "${BASE} names v${IMM_VER} but ${PIN_URL} does not carry it - ignoring that ref."
        fi
    done

    if [[ -n "$IMM_BEST" ]]; then
        if _ver_gt "$IMM_BEST" "$LATEST_VERSION"; then
            warn "The channel manifests say v${LATEST_VERSION}; the newest release ref holds v${IMM_BEST}."
            warn "  Taking the version-pinned manifest: a branch path can be answered from a"
            warn "  cache for up to 5 minutes, and a path naming the version cannot."
            LATEST_VERSION="$IMM_BEST"
            ACTIVE_BASE="$IMM_BEST_BASE"
            DIST_BASE="${IMM_BEST_BASE}/dist"
            DOWNLOAD_URL="$(printf '%s' "$IMM_BEST_JSON"    | grep -oP '"url"\s*:\s*"\K[^"]+' | head -1 || true)"
            MIRROR_URL="$(printf '%s' "$IMM_BEST_JSON"      | grep -oP '"mirror"\s*:\s*"\K[^"]+' | head -1 || true)"
            EXPECTED_SHA256="$(printf '%s' "$IMM_BEST_JSON" | grep -oP '"sha256"\s*:\s*"\K[0-9a-fA-F]+' | head -1 || true)"
            RELEASE_URL="$(printf '%s' "$IMM_BEST_JSON"     | grep -oP '"notes"\s*:\s*"\K[^"]+' | head -1 || true)"
        fi
        if [[ "$IMM_BEST" == "$LATEST_VERSION" ]]; then
            VER_IMMUTABLE=true
            VER_SOURCE="$IMM_BEST_URL"
            ok "Corroborated v${LATEST_VERSION} against ${IMM_BEST_URL}"
        fi
    fi

    # The deployed tree is the other reading a cache cannot fake: latest/VERSION
    # is read out of the build itself, and on our own CDN a ?cb= request was
    # measured to miss the proxy. Accepted as corroboration only when it AGREES
    # with the version being acted on.
    if [[ "$VER_IMMUTABLE" == false && -n "$BEST_LIVE" && "$BEST_LIVE" == "$LATEST_VERSION" ]]; then
        VER_IMMUTABLE=true
        VER_SOURCE="${BEST_LIVE_BASE}/latest/VERSION"
        ok "Corroborated v${LATEST_VERSION} against ${VER_SOURCE}"
    fi

    [[ -z "$DOWNLOAD_URL"   ]] && DOWNLOAD_URL="${DIST_BASE}/serverscrub-${LATEST_VERSION}.zip"
fi

info "Latest version:  ${BOLD}v${LATEST_VERSION}${NC}"

# ── Already up to date? ───────────────────────────────────────────────────────
# Skip version comparison when forced via --version or --url flags
if [[ -z "$FORCE_VERSION" && -z "$FORCE_URL" ]]; then
    if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
        # ONLY on corroborated evidence.
        #
        # This line is a factual claim about the patch level of a security
        # product, and on 2026-11-23 it was printed -- honestly, from a
        # five-minute-old cached manifest -- minutes after v4.37.8 was
        # published, telling the operator that v4.37.7 was current. Nothing in
        # the output hinted that the evidence could be stale. That is the same
        # class of defect as the WAF reporting action='block' while blocking
        # nothing: not a lie, just a claim beyond what was verified.
        if [[ "${VER_IMMUTABLE:-false}" == true ]]; then
            ok "Already up to date — v${CURRENT_VERSION}"
            info "  Confirmed against ${VER_SOURCE} (addressed by version; no cache can stale it)."
            exit 0
        fi
        warn "No channel offered anything newer than the installed v${CURRENT_VERSION}."
        warn "  But that answer came only from ${ACTIVE_BASE:-the release channel}/latest.json,"
        warn "  which is a cacheable url. Measured on raw.githubusercontent.com: a"
        warn "  cache-busted request is answered from the SAME cached object, and the"
        warn "  branch path is served with max-age=300 - so this reading may be up to"
        warn "  5 minutes behind a release."
        warn "  Nothing addressed by version could be reached to confirm it, so this is"
        warn "  NOT a confirmation that this install is current."
        echo ""
        echo -e "  ${BOLD}To settle it by hand (immutable paths only):${NC}"
        echo -e "    curl -fsS 'https://api.github.com/repos/${RELEASES_REPO}/tags?per_page=5' | grep name | head -3"
        echo -e "    curl -fsS https://raw.githubusercontent.com/${RELEASES_REPO}/v<version>/latest.json"
        echo ""
        # Exit 0 on purpose. Cron and the one-click updater both call this, and
        # a nonzero exit would read as a failed update rather than as an
        # unconfirmed check. There is nothing to install either way.
        info "Nothing newer to install. Re-run in a few minutes for a confirmed answer."
        exit 0
    fi

    # Check if update is actually newer. Tolerant of suffixes (e.g. 3.5.0-rc1):
    # compare only the leading numeric dotted parts; fall back to sort -V.
    _is_newer() {
        local latest="${1%%-*}" current="${2%%-*}"
        if command -v python3 >/dev/null 2>&1; then
            python3 -c "
import sys
def v(s):
    return tuple(int(p) for p in s.split('.') if p.isdigit())
try:
    sys.exit(0 if v('$latest') > v('$current') else 1)
except Exception:
    sys.exit(2)
" && return 0
            local rc=$?
            [[ $rc -eq 1 ]] && return 1   # definitively not newer
            # rc==2 → parse error, fall through to sort -V
        fi
        # Fallback: highest version via sort -V; newer iff latest sorts last and differs
        [[ "$latest" != "$current" && "$(printf '%s\n%s\n' "$current" "$latest" | sort -V | tail -1)" == "$latest" ]]
    }
    # ── A downgrade is not something --yes authorises ─────────────────────
    #
    # This block used to warn, skip its prompt under --yes, and fall straight
    # through. So `update.sh --yes` on a server running v4.28.10, against a
    # channel still serving v4.28.9, REPLACED the newer install with the
    # older one and reported "Update complete". Nobody asked for that.
    #
    # --yes means "do not ask me the routine question". It does not mean "do
    # anything at all without asking". Installing an older build over a newer
    # one is a different act from updating, it is how a server silently loses
    # fixes, and it needs to be asked for by name.
    #
    # The trigger was a stale mirror, which is now handled separately -- but
    # a mirror can always fall behind, and the updater must not treat that as
    # an instruction to roll back.
    _is_newer "$LATEST_VERSION" "$CURRENT_VERSION" || {
        warn "The channel is offering v${LATEST_VERSION}, which is NOT newer than"
        warn "the installed v${CURRENT_VERSION}."
        if [[ "$ALLOW_DOWNGRADE" == false ]]; then
            echo ""
            err "Refusing to replace a newer install with an older one."
            echo ""
            echo -e "  This usually means a mirror has fallen behind rather than that"
            echo -e "  a release was withdrawn. Check what each channel is serving:"
            for _B in "${CHANNELS[@]}"; do echo "    ${_B}/latest.json"; done
            echo ""
            echo -e "  ${BOLD}To take the newest build from a specific channel:${NC}"
            echo -e "    SG_MANIFEST_URL=${GITHUB_BASE}/latest.json bash $0 --yes"
            echo ""
            echo -e "  ${BOLD}If you really do mean to roll back:${NC}"
            echo -e "    bash $0 --version ${LATEST_VERSION} --allow-downgrade"
            echo ""
            exit 1
        fi
        warn "--allow-downgrade was given, so this rollback will proceed."
        if [[ "$AUTO_YES" == false ]]; then
            read -rp "  Replace v${CURRENT_VERSION} with OLDER v${LATEST_VERSION}? [y/N] " REPLY
            [[ "${REPLY,,}" =~ ^y(es)?$ ]] || { info "Aborted."; exit 0; }
        fi
    }
fi

echo ""
echo -e "  ${BOLD}v${CURRENT_VERSION}${NC} → ${BOLD}${GREEN}v${LATEST_VERSION}${NC}"
[[ -n "$RELEASE_URL" ]] && info "Release notes: ${RELEASE_URL}"
echo ""

# ── Confirm ───────────────────────────────────────────────────────────────────
if [[ "$AUTO_YES" == false ]]; then
    read -rp "  Proceed with update? All settings will be preserved. [y/N] " REPLY
    [[ "${REPLY,,}" =~ ^y(es)?$ ]] || { info "Aborted."; exit 0; }
fi

# ── Check there is room before touching anything ──────────────────────────────
# An update that runs out of space halfway leaves the install in a state nobody
# asked for. Checking first costs nothing, and the message names the two
# directories that actually fill up.
# `|| true` because the check below is written for an empty value: a df that
# cannot stat the directory must skip the space check, not kill the updater
# one step before it starts.
_SG_FREE_KB=$(df -Pk "$INSTALL_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || true)
_SG_NEED_KB=$(( 200 * 1024 ))        # 200MB: download, unpack, backup, rsync

if [[ -n "$_SG_FREE_KB" && "$_SG_FREE_KB" -lt "$_SG_NEED_KB" ]]; then
    echo ""
    warn "Only $(( _SG_FREE_KB / 1024 ))MB free on the volume holding ${INSTALL_DIR}."
    warn "An update needs about 200MB to download, unpack and back up safely."
    echo ""
    echo "  The two directories that usually account for it:"
    echo "    quarantine : $(du -sh "${INSTALL_DIR}/quarantine" 2>/dev/null | cut -f1 || echo 'n/a')"
    echo "    backups    : $(du -sh "$BACKUP_ROOT" 2>/dev/null | cut -f1 || echo 'n/a')"
    echo ""
    echo "  To free space:"
    echo "    serverscrub quarantine prune 7"
    echo "    ls -1dt ${BACKUP_ROOT}/*/ | tail -n +4 | xargs -r rm -rf"
    echo "    find ${INSTALL_DIR}/logs -name 'scan_*.log' -mtime +2 -delete"
    echo ""
    die "Not enough free space to update safely."
fi

# ── Backup user data ──────────────────────────────────────────────────────────
state "backup" 30 "Backing up your data"
section "Backing up user data"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}_v${CURRENT_VERSION}"
mkdir -p "$BACKUP_DIR"

# Items to preserve.
#
# Only what the update can actually destroy. The update rsyncs backend/,
# frontend/ and whm/ with --delete and touches nothing else -- so quarantine and
# logs were never at risk, and copying them here meant every update duplicated
# the entire quarantine onto the root partition. On a server whose quarantine
# had grown to fill /, that made updating impossible at exactly the moment the
# fix for it was waiting to be installed.
PRESERVE=(
    "${INSTALL_DIR}/database"
    "${INSTALL_DIR}/backend/config/mode.php"
    "${INSTALL_DIR}/backend/signatures/custom.sig"
)

for item in "${PRESERVE[@]}"; do
    [[ -e "$item" ]] && cp -a "$item" "$BACKUP_DIR/" && info "Backed up: $item"
done

# Snapshot installed version for rollback reference
echo "$CURRENT_VERSION" > "${BACKUP_DIR}/from_version.txt"
ok "Backup created at: ${BACKUP_DIR}"

# Keep the last few and remove the rest. Nothing pruned these, so every update
# since installation was still sitting on the root partition -- the same
# unbounded growth that quarantine had, in a second place.
_SG_KEEP=${SG_KEEP_BACKUPS:-3}
if [[ -d "$BACKUP_ROOT" ]]; then
    # `|| true` matters here: when BACKUP_ROOT exists but holds no directories
    # the glob matches nothing, ls exits non-zero, and under pipefail that
    # killed the updater mid-prune on exactly the second update a server ever
    # ran. The `[[ -n ]]` below is what was meant to handle it.
    _SG_OLD=$(ls -1dt "${BACKUP_ROOT}"/*/ 2>/dev/null | tail -n +$((_SG_KEEP + 1)) || true)
    if [[ -n "$_SG_OLD" ]]; then
        _SG_N=$(printf '%s\n' "$_SG_OLD" | wc -l || true)
        printf '%s\n' "$_SG_OLD" | xargs -r rm -rf
        info "Pruned ${_SG_N} old backup(s), keeping the most recent ${_SG_KEEP}"
    fi
fi

# ── Download latest release ───────────────────────────────────────────────────
state "download" 15 "Downloading v${LATEST_VERSION}"
section "Downloading v${LATEST_VERSION}"

DOWNLOADED=false
RELEASE_ZIP="${TMP_DIR}/release.zip"

# 1st attempt: release asset zip (or --url / --version forced URL)
if [[ -n "$DOWNLOAD_URL" ]]; then
    if _download "$DOWNLOAD_URL" "$RELEASE_ZIP" "release zip"; then
        DOWNLOADED=true
    else
        warn "Release asset download failed. Trying source archive…"
    fi
fi

# 2nd attempt: the manifest's declared mirror (GitHub raw when primary is the CDN)
if [[ "$DOWNLOADED" == false ]] && [[ -n "${MIRROR_URL:-}" ]] && [[ "$MIRROR_URL" != "$DOWNLOAD_URL" ]]; then
    if _download "$MIRROR_URL" "$RELEASE_ZIP" "mirror zip"; then
        DOWNLOADED=true
    else
        warn "Mirror download failed."
    fi
fi

# 3rd attempt: conventional dist path on every known channel (covers a manifest
# whose url/mirror are stale but the zip is published under the standard name)
if [[ "$DOWNLOADED" == false ]] && [[ "$LATEST_VERSION" != *"-manual"* ]]; then
    # dist/ first: it is the canonical published path and the one that actually
    # exists. Trying builds/ and v<ver>/ ahead of it produced a wall of 404s on
    # every update -- alarming, and entirely expected, which is the worst
    # combination. A channel that fails its first path is skipped rather than
    # asked three times: a dead host does not become alive for the next URL.
    for _B in "${CHANNELS[@]}"; do
        _SG_CHANNEL_DEAD=false
        for _P in "dist/serverscrub-${LATEST_VERSION}.zip" \
                  "builds/serverscrub-${LATEST_VERSION}.zip" \
                  "v${LATEST_VERSION}/serverscrub-${LATEST_VERSION}.zip"; do
            ALT_URL="${_B}/${_P}"
            [[ "$ALT_URL" == "$DOWNLOAD_URL" || "$ALT_URL" == "${MIRROR_URL:-}" ]] && continue
            if _download "$ALT_URL" "$RELEASE_ZIP" "${_P%%/*} zip"; then
                DOWNLOADED=true; break 2
            fi
            if [[ "$_SG_CHANNEL_DEAD" == false ]]; then
                _SG_CHANNEL_DEAD=true
                continue
            fi
            break          # two failures on one host: move to the next channel
        done
    done
    $DOWNLOADED || warn "Fallback dist downloads also failed."
fi

if [[ "$DOWNLOADED" == false ]]; then
    err "All download attempts failed for v${LATEST_VERSION}."
    echo ""
    info "Manual option: download the zip on another machine and copy it here, then run:"
    info "  bash $0 --url file:///path/to/serverscrub.zip"
    echo ""
    exit 1
fi

ok "Downloaded release archive"

# ── Verify integrity (SHA256) ─────────────────────────────────────────────────
# Refuse to install code we can't verify when a checksum was published. This is
# the line of defence against a tampered/MITM'd zip being run as root.
section "Verifying integrity"
if [[ -n "$EXPECTED_SHA256" ]]; then
    _SHA_TOOL=""
    if command -v sha256sum >/dev/null 2>&1; then _SHA_TOOL="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then _SHA_TOOL="shasum -a 256"; fi
    if [[ -z "$_SHA_TOOL" ]]; then
        die "No sha256 tool (sha256sum/shasum) available — cannot verify download. Install coreutils and retry."
    fi
    ACTUAL_SHA256="$($_SHA_TOOL "$RELEASE_ZIP" | awk '{print $1}' || true)"
    if [[ "${ACTUAL_SHA256,,}" != "${EXPECTED_SHA256,,}" ]]; then
        err "Checksum MISMATCH — refusing to install."
        info "  expected: ${EXPECTED_SHA256}"
        info "  actual:   ${ACTUAL_SHA256}"
        die "Aborting update (possible corruption or tampering)."
    fi
    ok "SHA256 verified: ${ACTUAL_SHA256}"
else
    warn "No checksum to verify against — proceeding without integrity check."
fi

# ── Extract ───────────────────────────────────────────────────────────────────
section "Extracting update"
unzip -q "${TMP_DIR}/release.zip" -d "${TMP_DIR}/extracted"

# Find the root of the extracted content (may be in a subdirectory)
EXTRACTED_ROOT="$(find "${TMP_DIR}/extracted" -maxdepth 1 -mindepth 1 -type d | head -1 || true)"
[[ -z "$EXTRACTED_ROOT" ]] && EXTRACTED_ROOT="${TMP_DIR}/extracted"
ok "Extracted to: $EXTRACTED_ROOT"

# ── Stop the monitor daemon ───────────────────────────────────────────────────
#
# THE DAEMON MUST COME BACK, WHATEVER ELSE HAPPENS.
#
# It used to be stopped here and started again ~400 lines later, with the whole
# rest of the update in between. On 20 Nov a server hung in "Fixing
# permissions" -- which sits between the two -- and the monitor was simply left
# STOPPED. The update had already installed the new code, so the panel reported
# the new version while real-time protection was not running at all, and the
# containment fix that release existed to deliver never executed once. The
# symptom reached the operator as "malware detected in realtime is left Active
# on the server", which looks like a containment bug and is not one.
#
# Two changes. The restart now happens as soon as the files are in place and
# the migrations have run -- that is all the daemon was ever waiting for -- and
# an EXIT trap guarantees it, so an update that dies, hangs and is killed, or
# rolls back still leaves the monitor running. A security daemon that is down
# is the one outcome an updater must never produce.
#
# The comment that used to be here said install.sh --register-only restarts it
# afterwards. It does not: that block is inside `if ! $REGISTER_ONLY`, so on an
# upgrade install.sh never touches the service at all.
SG_MONITOR_WAS_UP=0

sg_monitor_restore() {
    # `restart`, never `start`: start is a NO-OP on a unit that is already
    # active, which would leave the old process -- holding the OLD code in
    # memory -- running after an update whose whole point was to replace it.
    command -v systemctl >/dev/null 2>&1 || return 0
    [[ -f /etc/systemd/system/serverscrub-monitor.service ]] || return 0
    systemctl restart serverscrub-monitor 2>/dev/null \
        && ok "Monitor daemon restarted" \
        || warn "Monitor restart failed — check: journalctl -u serverscrub-monitor"
    systemctl restart serverscrub-scans 2>/dev/null || true
}

# Runs however this script ends: success, failure, rollback, or a kill.
sg_on_exit_restore_monitor() {
    if [[ "${SG_MONITOR_RESTARTED:-0}" != "1" && "$SG_MONITOR_WAS_UP" == "1" ]]; then
        warn "Update ended before the monitor was restarted — starting it now"
        sg_monitor_restore
    fi
    rm -rf "${TMP_DIR:-}" 2>/dev/null || true
}
trap sg_on_exit_restore_monitor EXIT

section "Stopping services"
if systemctl is-active --quiet serverscrub-monitor 2>/dev/null; then
    SG_MONITOR_WAS_UP=1
    systemctl stop serverscrub-monitor 2>/dev/null && ok "Monitor daemon stopped" || true
    # Holds the code it was started with, and the database this update is about
    # to migrate.
    systemctl stop serverscrub-scans 2>/dev/null && ok "Scan pickup stopped" || true
fi

# ── Apply update — overlay files, skip user-data paths ───────────────────────
section "Applying update"

# Directories to update (code only — never user data)
# MUST cover everything make-release.sh packages, or an update silently fails
# to deliver it. This list is checked against that one by
# tests/test_packaging.php, because it was wrong and nothing noticed:
#
#   - `cpanel` was missing, so wp-content of the cPanel user plugin -- the page
#     every CUSTOMER opens from their own control panel -- was never delivered
#     by an update, only by a fresh install. A server updated since that
#     directory was introduced showed an empty menu entry to every cPanel user
#     on it, and the only visible symptom was two lines in the installer log
#     saying "cPanel user page missing from the package".
#   - `test.sh` was missing, so every update ended with "test.sh not found --
#     skipping verification". The post-install check had not run in months.
#   - `upgrade.sh` was missing, so the one script whose entire purpose is to
#     fetch a newer updater could never arrive by update.
#
# Three independent lists described this product: build.py's ITEMS,
# make-release.sh's allowlist, and this. All three disagreed.
# scripts/ joined this list in 4.36.2 so the CDN trio (cdn-sync.sh,
# cdn-setup.sh, cdn-trigger-watch.sh) is refreshed by an update like any other
# code. Before that they reached a server only by hand-copying a raw GitHub
# URL, which is why a cache fix that lived in cdn-sync.sh could not deploy
# itself.
#
# NOTE for the host that serves the releases: cron must invoke the INSTALLED
# copy (${INSTALL_DIR}/scripts/cdn-sync.sh) for this to mean anything. A cron
# line still pointing at a hand-placed path keeps running the old file no
# matter how many updates land.
UPDATE_DIRS=( backend frontend whm cpanel scripts )
UPDATE_FILES=( VERSION install.sh uninstall.sh update.sh upgrade.sh test.sh )

# ── Snapshot the current code so a failure can be undone ─────────────────────
# The existing backup covers USER DATA only. Without a code copy a half-applied
# overlay leaves a mixed-version install with no way back.
state "snapshot" 45 "Snapshotting current version"
CODE_SNAPSHOT="${BACKUP_DIR}/code"
mkdir -p "$CODE_SNAPSHOT"
for dir in "${UPDATE_DIRS[@]}"; do
    [[ -d "${INSTALL_DIR}/${dir}" ]] || continue
    cp -a "${INSTALL_DIR}/${dir}" "${CODE_SNAPSHOT}/" 2>/dev/null || true
done
for file in "${UPDATE_FILES[@]}"; do
    [[ -f "${INSTALL_DIR}/${file}" ]] || continue
    cp -a "${INSTALL_DIR}/${file}" "${CODE_SNAPSHOT}/" 2>/dev/null || true
done
ok "Code snapshot: ${CODE_SNAPSHOT}"

# From here on a failure must undo what has been written.
ROLLBACK_ARMED=true
state "applying" 55 "Applying v${LATEST_VERSION}"

for dir in "${UPDATE_DIRS[@]}"; do
    src="${EXTRACTED_ROOT}/${dir}"
    [[ -d "$src" ]] || continue
    dst="${INSTALL_DIR}/${dir}"
    # Use rsync to overlay: --delete removes old files, but we exclude user-data
    # --checksum, and it is NOT optional.
    #
    # rsync's default quick check is SIZE + MTIME. Every file in the release
    # archive carried the same timestamp (the ZIP epoch, 1980-01-01), so any
    # file whose size had not changed was judged identical and never
    # transferred.
    #
    # On a live server that left backend/config/config.php at 4.10.0 through
    # five consecutive updates, because '4.10.0' and '4.13.3' are both six
    # characters and the file size never moved. frontend/index.html was stuck
    # the same way. The rsync reported success for the directory every time --
    # it had genuinely finished, having decided there was nothing to do -- and
    # the panel reported 4.10.0 while VERSION, the updater and the upgrade
    # script all said otherwise.
    #
    # Comparing checksums costs a hash of ~1 MB of code. Trusting a timestamp
    # we do not control costs a silent non-update.
    rsync -a --checksum --delete \
        --exclude='backend/config/mode.php' \
        --exclude='backend/signatures/custom.sig' \
        "$src/" "$dst/" \
        && ok "Updated: ${dir}/"
done

for file in "${UPDATE_FILES[@]}"; do
    src="${EXTRACTED_ROOT}/${file}"
    [[ -f "$src" ]] || continue
    cp "$src" "${INSTALL_DIR}/${file}"
    ok "Updated: ${file}"
done

# Make scripts executable
chmod +x "${INSTALL_DIR}/install.sh"   2>/dev/null || true
chmod +x "${INSTALL_DIR}/uninstall.sh" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/update.sh"    2>/dev/null || true
chmod +x "${INSTALL_DIR}/backend/daemon/monitor.py" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/backend/cron/scan.php"     2>/dev/null || true
chmod +x "${INSTALL_DIR}/backend/cron/update-check.php" 2>/dev/null || true

# ── Retire the duplicate update-check cron entry ──────────────────────────────
#
# Installs from before 4.7.0 carry a second cron line that runs update-check.php
# at 08:00. The scheduler's 'autoupdate' task now checks AND installs, so that
# line is a second owner of the same job which only ever cached a notice.
#
# Only the exact line this project wrote is removed, matched on the script name,
# and only from the cron file this project owns. Anything an administrator added
# by hand is left alone.
CRON_FILE="/etc/cron.d/serverscrub"
if [[ -f "$CRON_FILE" ]] && grep -q 'cron/update-check\.php' "$CRON_FILE"; then
    cp -a "$CRON_FILE" "${CRON_FILE}.pre-${CURRENT_VERSION:-update}" 2>/dev/null || true
    sed -i -e '/^# Daily update check at 8am$/d' \
           -e '\#cron/update-check\.php#d' "$CRON_FILE" 2>/dev/null \
      && ok "Removed the duplicate update-check cron entry (the scheduler owns updating now)" \
      || warn "Could not tidy ${CRON_FILE} — harmless, it just checks twice"
fi

# ── Restore user data over the fresh install ──────────────────────────────────
state "restore" 75 "Restoring your settings and data"
section "Restoring user data"
for item in "${PRESERVE[@]}"; do
    src="${BACKUP_DIR}/$(basename "$item")"
    [[ -e "$src" ]] || continue
    dst_parent="$(dirname "$item")"
    mkdir -p "$dst_parent"
    cp -a "$src" "$dst_parent/"
    ok "Restored: $item"
done

# ── Run DB migrations ─────────────────────────────────────────────────────────
state "migrate" 85 "Running database migrations"
section "Running database migrations"

# Run from a FILE, not a multi-line `php -r`.
#
# On cPanel, `php` is a Perl wrapper (/var/cpanel/ea4/ea_php_cli.pm). Handed a
# -r argument containing newlines it tries to stat it as a filename and fails
# with "Unsuccessful stat on filename containing newline", exiting non-zero
# before any PHP runs. With `set -euo pipefail` that aborted the update and
# rolled back a perfectly good one. A script file has no such problem.
_SG_MIGRATE="${TMP_DIR}/migrate.php"
cat > "$_SG_MIGRATE" <<MIGEOF
<?php
define('SG_API', true);
// config.php, not mode.php: mode.php records the install paths but not SG_DB,
// SG_LOGS or the rest, and config.php includes it anyway.
require_once '${INSTALL_DIR}/backend/config/config.php';
require_once '${INSTALL_DIR}/backend/lib/Database.php';
Database::get();
echo 'Database migrations applied.' . PHP_EOL;
MIGEOF

# And a real CLI interpreter, for the same reason: on cPanel the `php` on PATH
# may be that wrapper, or a CGI build.
_SG_PHP=""
for _c in /usr/local/cpanel/3rdparty/bin/php \
          /opt/cpanel/ea-php83/root/usr/bin/php \
          /opt/cpanel/ea-php82/root/usr/bin/php \
          /opt/cpanel/ea-php81/root/usr/bin/php \
          /usr/bin/php /usr/local/bin/php php; do
    if command -v "$_c" >/dev/null 2>&1 && [[ "$("$_c" -r 'echo PHP_SAPI;' 2>/dev/null)" == "cli" ]]; then
        _SG_PHP="$_c"; break
    fi
done

if [[ -z "$_SG_PHP" ]]; then
    warn "No CLI PHP found — migrations will run on the next dashboard request."
else
    # Deliberately NOT fatal. Database::get() runs the migrations on first use
    # anyway, so a hiccup here is advisory: discarding a successful code update
    # over it is far worse than letting the next request apply them.
    if _SG_MIG_OUT="$("$_SG_PHP" "$_SG_MIGRATE" 2>&1)"; then
        while IFS= read -r line; do [[ -n "$line" ]] && info "$line"; done <<< "$_SG_MIG_OUT"
    else
        warn "Migrations did not complete here; they will run on the next request."
        while IFS= read -r line; do [[ -n "$line" ]] && warn "  $line"; done <<< "$_SG_MIG_OUT"
    fi
fi

# ── Re-run plugin registration ────────────────────────────────────────────────
# Code changes between versions sometimes touch how the plugin registers with
# WHM/cPanel. Overlaying files alone won't re-register, so the freshly-installed
# install.sh is invoked in --register-only mode (auto-detects mode, no prompts,
# never touches data, never offers uninstall). Non-fatal: a failure here doesn't
# undo the update — it just warns.
section "Re-registering plugin"
if [[ -f "${INSTALL_DIR}/install.sh" ]]; then
    if bash "${INSTALL_DIR}/install.sh" --register-only 2>&1 | sed 's/^/  /'; then
        ok "Plugin re-registered"
    else
        warn "Re-registration reported a problem — check WHM → Plugins after upgrade"
    fi
else
    warn "install.sh not found in install dir — skipping re-registration"
fi

# ── Bring real-time protection back, NOW ──────────────────────────────────────
#
# The daemon was stopped so the files underneath it could be replaced and the
# schema migrated. Both are done. Everything after this point -- permissions,
# cron repair, the unit-file rewrite, update-state bookkeeping -- is tidying
# that the monitor does not need to wait for, and waiting is what hurt:
# stopped at the top of the script and started ~400 lines later, a server that
# hung in "Fixing permissions" was left with no real-time protection at all
# while the panel reported the new version. It is restarted here, and the EXIT
# trap is the backstop if this line is somehow not reached.
section "Restarting real-time protection"
if [[ "$SG_MONITOR_WAS_UP" == "1" ]]; then
    sg_monitor_restore
    SG_MONITOR_RESTARTED=1
    # Prove it is actually up, rather than reporting the restart command's exit
    # status. A unit that starts and immediately dies -- a syntax error in the
    # daemon, a missing Python module -- exits 0 from `systemctl restart`.
    if systemctl is-active --quiet serverscrub-monitor 2>/dev/null; then
        ok "Real-time monitor is running the new code"
    else
        warn "Monitor is NOT running after restart — real-time protection is OFF"
        warn "  Check: journalctl -u serverscrub-monitor -n 50"
    fi
else
    info "Monitor was not running before the update — leaving it as it was"
fi

# ── Did the cron entries actually land? ───────────────────────────────────────
#
# A live server was found running a current version with NO user-scans line in
# /etc/cron.d/serverscrub. Every customer who pressed "Scan my account" saw
# "Queued" and nothing else, for eight hours, because nothing was scheduled to
# pick the request up -- and every update had reported success on its way past.
#
# So: check, and repair rather than merely complain. An update that can see the
# line is missing and leaves it missing has told the operator about a problem
# it could have fixed.
if [[ -f "$CRON_FILE" ]] && [[ -n "${_SG_PHP:-}" ]]; then
    # LOG_DIR is set further down, for the systemd unit. Derive it here rather
    # than reading it empty: "${LOG_DIR}/cron.log" with LOG_DIR unset writes
    # the cron output to /cron.log, at the filesystem root.
    _cron_log="${INSTALL_DIR}/logs/cron.log"
    _added=0
    if ! grep -q 'cron/user-scans\.php' "$CRON_FILE" 2>/dev/null; then
        cp -a "$CRON_FILE" "${CRON_FILE}.pre-cronfix" 2>/dev/null || true
        {
            echo "#"
            echo "# Customer scan requests, every minute. Added by update.sh because this"
            echo "# line was missing: without it a cPanel user's scan request is never"
            echo "# picked up and their page shows \"Queued\" indefinitely."
            echo "* * * * * root ${_SG_PHP} ${INSTALL_DIR}/backend/cron/user-scans.php >> ${_cron_log} 2>&1"
        } >> "$CRON_FILE"
        _added=1
    fi
    if ! grep -q 'cron/scheduler\.php' "$CRON_FILE" 2>/dev/null; then
        cp -a "$CRON_FILE" "${CRON_FILE}.pre-cronfix" 2>/dev/null || true
        {
            echo "#"
            echo "# Task scheduler. Added by update.sh because this line was missing."
            echo "*/15 * * * * root ${_SG_PHP} ${INSTALL_DIR}/backend/cron/scheduler.php >> ${_cron_log} 2>&1"
        } >> "$CRON_FILE"
        _added=1
    fi
    if [[ $_added -eq 1 ]]; then
        chmod 644 "$CRON_FILE" 2>/dev/null || true
        command -v restorecon >/dev/null 2>&1 && restorecon -F "$CRON_FILE" 2>/dev/null || true
        warn "Cron entries were MISSING and have been restored in ${CRON_FILE}"
        warn "  Scheduled scans and customer scan requests were not running."
    else
        ok "Cron entries present (scheduler + customer scan pickup)"
    fi
fi

# ── Fix permissions ───────────────────────────────────────────────────────────
section "Fixing permissions"

# Every walk in this section is BOUNDED and NARRATED, because the unbounded,
# silent version hung an installer on a live server.
#
# It used to be four bare `chmod -R`/`chown -R` calls, one of them over a path
# read out of the database, with nothing printed between "Fixing permissions"
# and "Permissions applied". Two defects, and both bit:
#
#   1. UNBOUNDED. A quarantine_dir of /home -- which moveQuarantine() used to
#      accept, having checked only that the path was absolute and writable --
#      turned the last step into `chmod -R 700 /home`. On a cPanel server
#      /home/virtfs holds a bind-mounted copy of the filesystem for EVERY
#      account, so that walk is multiplied by the account count and re-enters
#      /usr, /lib and /etc through the mounts. It does not finish; and what it
#      does get through has set 700 on customer public_html directories on the
#      way. The rest of this product prunes virtfs in four places -- Scanner,
#      Heuristics, the path walker, the CDN setup -- because we already knew
#      this. The installer was the one place that did not.
#
#   2. SILENT. With no output, an operator watching a stalled installer cannot
#      tell WHICH path is being walked, so the single fact needed to diagnose
#      it is the one fact not on the screen. "Installer stuck on fixing
#      permissions" was all the evidence there was.
#
# So, for every tree: `find -xdev` instead of `chmod -R`, which stops at
# filesystem boundaries and therefore cannot follow a bind mount into another
# volume; a timeout, so a slow or wedged filesystem fails this step rather
# than wedging the update; and a line naming each path before it is walked.

# chmod a whole tree, without leaving this filesystem, within a time bound.
#   $1 mode   $2 directory   $3 label for the log
_sg_chmod_tree() {
    local mode="$1" dir="$2" label="$3" rc=0
    [[ -d "$dir" ]] || return 0
    info "${label}: chmod ${mode} ${dir}"
    if command -v timeout >/dev/null 2>&1; then
        timeout 300 find "$dir" -xdev -exec chmod "$mode" {} + 2>/dev/null
        rc=$?
    else
        find "$dir" -xdev -exec chmod "$mode" {} + 2>/dev/null
        rc=$?
    fi
    if [[ $rc -eq 124 ]]; then
        warn "Timed out after 300s tightening ${dir}"
        warn "  The update itself is fine — only this hardening step was cut short."
        warn "  Finish it by hand:  find ${dir} -xdev -exec chmod ${mode} {} +"
        return 0
    fi
    [[ $rc -eq 0 ]] || warn "Could not fully tighten ${dir} -- check it by hand"
    return 0
}

# Is this path plausibly a quarantine directory at all?
#
# Checked before we walk it, because the path arrives from the database and a
# wrong answer here is a recursive chmod over somebody else's filesystem. A
# quarantine directory is always a NAMED SUBDIRECTORY -- /home/.serverscrub/
# quarantine, /var/serverscrub/quarantine. It is never the top of a volume, so
# a single-component path is refused outright: that is how /home got here.
_sg_quarantine_path_ok() {
    local d="${1%/}"
    [[ -n "$d" && "$d" == /* ]] || return 1
    [[ "$d" == */*/* ]] || return 1          # depth 1 (/home, /usr, /var) is not one
    case "$d" in
        /home/virtfs|/home/virtfs/*) return 1 ;;   # bind mounts of every account
        /proc/*|/sys/*|/dev/*)       return 1 ;;   # not real storage
    esac
    return 0
}


chown -R root:nobody "$INSTALL_DIR" 2>/dev/null || chown -R root:root "$INSTALL_DIR"
_sg_chmod_tree 750 "$INSTALL_DIR" "Install directory"

# Each of these is chmod'ed ONLY IF PRESENT.
#
# quarantine is configurable and routinely lives outside the install directory
# -- the installer on this server put it at /home/.serverscrub/quarantine,
# because /home is the big volume. So ${INSTALL_DIR}/quarantine did not exist,
# chmod exited non-zero, `set -e` called that a failed update, and a v4.4.2
# server that had ALREADY successfully applied v4.7.1 -- files copied, data
# restored, migrations run, plugin re-registered -- was rolled all the way
# back. The update worked. Tightening permissions on an optional directory
# undid it.
#
# A missing directory here is not an error worth reverting an update over. If
# it is absent there is nothing to tighten.
for _SG_D in database quarantine logs; do
    _sg_chmod_tree 700 "${INSTALL_DIR}/${_SG_D}" "${_SG_D}/"
done

# The configured quarantine, wherever it actually is. Read from the database
# rather than assumed -- and the read itself is time-bounded, because
# Database::get() runs migrations on connect and six processes share that
# SQLite file. A locked or mid-migration database used to stall here with the
# section header as the last thing on screen.
info "Reading configured quarantine location"
if command -v timeout >/dev/null 2>&1; then
    _SG_QDIR="$(timeout 60 php -r "define('SG_API', true); require_once '${INSTALL_DIR}/backend/config/mode.php'; require_once '${INSTALL_DIR}/backend/lib/Database.php'; echo Database::setting('quarantine_dir', '');" 2>/dev/null || true)"
else
    _SG_QDIR="$(php -r "define('SG_API', true); require_once '${INSTALL_DIR}/backend/config/mode.php'; require_once '${INSTALL_DIR}/backend/lib/Database.php'; echo Database::setting('quarantine_dir', '');" 2>/dev/null || true)"
fi

if [[ -z "$_SG_QDIR" ]]; then
    info "Quarantine not relocated — nothing further to tighten"
elif ! _sg_quarantine_path_ok "$_SG_QDIR"; then
    # Refusing is the whole point. This is the state that hung the installer,
    # and walking it would do more damage than leaving it alone.
    warn "REFUSING to tighten permissions on quarantine_dir='${_SG_QDIR}'"
    warn "  That is not a quarantine directory — it is a whole volume or a"
    warn "  bind-mount tree, and a recursive chmod over it would reset"
    warn "  permissions on files that are not ours. Nothing was changed."
    warn "  Point it somewhere specific:  serverscrub move-quarantine /var/serverscrub/quarantine"
elif [[ ! -d "$_SG_QDIR" ]]; then
    warn "quarantine_dir='${_SG_QDIR}' is configured but does not exist — skipping"
else
    _sg_chmod_tree 700 "$_SG_QDIR" "Quarantine"
    ok "Quarantine permissions applied: ${_SG_QDIR}"
fi
ok "Permissions applied"

# ── Regenerate systemd service file (paths may have changed) ─────────────────
section "Updating systemd service"
SERVICE_FILE="/etc/systemd/system/serverscrub-monitor.service"
if [[ -f "$SERVICE_FILE" ]] && command -v systemctl >/dev/null 2>&1; then
    LOG_DIR="${INSTALL_DIR}/logs"
    cat > "$SERVICE_FILE" << SVCEOF
[Unit]
Description=ServerScrub Real-Time File Monitor
After=network.target

[Service]
Type=simple
User=root
Environment="SG_ROOT=${INSTALL_DIR}"
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/backend/daemon/monitor.py
Restart=on-failure
RestartSec=10
StandardOutput=append:${LOG_DIR}/monitor.log
StandardError=append:${LOG_DIR}/monitor.log
KillSignal=SIGTERM
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    # The unit file may have changed (paths), so restart again to pick it up.
    # By now the daemon is already running the new code -- it was restarted as
    # soon as the migrations finished -- so this is a refinement, not the thing
    # protection depends on. `restart`, not `start`: see sg_monitor_restore.
    sg_monitor_restore
    SG_MONITOR_RESTARTED=1
else
    info "Systemd service not installed — skipping"
fi

# ── Update version in DB so dashboard shows correct version immediately ───────
# ── Put back the scans this update stopped ───────────────────────────────────
#
# install.sh stops every running scan before replacing the code underneath it,
# which is right -- a detached worker running half-old code against a migrated
# database is worse than a stopped one. Walking away afterwards is not.
#
# update.sh runs install.sh on every update, so each update silently killed
# whatever was scanning. On a server taking several updates in a day the
# nightly /home scan never finished once, and the scan log filled with
# "cancelled" rows that said nothing about who had cancelled them.
#
# The scheduled sweep is the one that matters here: nobody is sitting in front
# of it, so nobody notices it never ran.
section "Resuming interrupted scans"
_SG_RESUME="${INSTALL_DIR}/logs/.resume-scans.json"
if [[ -s "$_SG_RESUME" ]]; then
    _SG_RESUME_PHP="${TMP_DIR:-/tmp}/sg-resume.php"
    cat > "$_SG_RESUME_PHP" <<RESUMEEOF
<?php
define('SG_API', true);
require_once '${INSTALL_DIR}/backend/config/config.php';
require_once '${INSTALL_DIR}/backend/lib/Database.php';
require_once '${INSTALL_DIR}/backend/lib/Logger.php';
require_once '${INSTALL_DIR}/backend/lib/Scanner.php';

\$list = json_decode((string) @file_get_contents('${_SG_RESUME}'), true);
if (!is_array(\$list) || !\$list) { echo "nothing to resume" . PHP_EOL; exit(0); }

// Only one scan per path. Several workers on the same tree is how this
// server ended up with six clamscans at once.
\$seen = [];
\$deferred = [];
\$n = 0;
foreach (\$list as \$j) {
    \$path = (string) (\$j['path'] ?? '');
    if (\$path === '' || isset(\$seen[\$path])) { continue; }
    \$seen[\$path] = true;

    // Do not stack on top of something already running again.
    foreach (Scanner::liveScans() as \$live) {
        if ((string) \$live['scan_path'] === \$path) { continue 2; }
    }

    try {
        \$scanner = new Scanner();
        \$id = \$scanner->startScan(\$path, (string) (\$j['type'] ?? 'full'), false,
                                   (string) (\$j['by'] ?? '@schedule'));
        Logger::info('Resumed scan of ' . \$path . ' as job ' . \$id
                   . ' after the update that stopped it');
        \$n++;
    } catch (Throwable \$e) {
        // A refusal here is usually TRANSIENT: a backup window, or the
        // concurrency cap. The scan is not resumable right now and must not
        // be thrown away -- keep the marker so the scheduler retries it,
        // or the nightly sweep is lost until its next slot a day later.
        \$deferred[] = \$j;
        \$why = \$e->getMessage();

        // A scheduled sweep's scan_path is every account's docroot joined
        // with commas. Printed whole it is 132 paths on one line, which
        // buries the one thing the operator needs: why.
        \$n_paths = substr_count(\$path, ',') + 1;
        \$short = \$n_paths > 1
            ? \$n_paths . ' account(s)'
            : \$path;
        echo "  deferred " . \$short . ": " . \$why . PHP_EOL;
    }
}

// Anything deferred stays on disk for the scheduler to pick up. An empty
// list removes the file, so a successful resume does not leave a marker
// that would re-start the scan on some later run.
if (\$deferred) {
    @file_put_contents('${INSTALL_DIR}/logs/.resume-scans.json', json_encode(\$deferred));
} else {
    @unlink('${INSTALL_DIR}/logs/.resume-scans.json');
}
echo \$n . " scan(s) resumed, " . count(\$deferred) . " deferred" . PHP_EOL;
RESUMEEOF
    if _SG_RESUME_OUT="$(php "$_SG_RESUME_PHP" 2>&1)"; then
        # "deferred" is not success. Printing a tick next to a scan that did
        # not start is how a missed nightly sweep goes unnoticed.
        if [[ "$_SG_RESUME_OUT" == *"0 scan(s) resumed"* ]]; then
            warn "  ${_SG_RESUME_OUT}"
            warn "  The scheduler will retry; nothing has been lost."
        else
            ok "  ${_SG_RESUME_OUT}"
        fi
    else
        warn "  Could not resume the stopped scan(s): ${_SG_RESUME_OUT}"
        warn "  The next scheduled run will cover it."
    fi
    # The marker is removed by the PHP above only when nothing was deferred.
    rm -f "$_SG_RESUME_PHP"
else
    info "  No scans were interrupted by this update"
fi

section "Finalising"
php -r "define('SG_API', true); require_once '${INSTALL_DIR}/backend/config/mode.php'; require_once '${INSTALL_DIR}/backend/lib/Database.php'; Database::setSetting('update_available', '0'); Database::setSetting('update_latest_ver', '${LATEST_VERSION}'); echo 'Update state cleared.' . PHP_EOL;" 2>/dev/null || true

NEW_VERSION="$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null | tr -d '[:space:]' || true)"

# ── Did the code actually land? ───────────────────────────────────────────────
#
# VERSION is a six-byte file copied by a `cp`. config.php is one file among
# thousands delivered by an `rsync`. They can disagree, and on a live server
# they did: VERSION read 4.13.1 while backend/config/config.php still defined
# 4.10.0 -- the top-level files were copied and the backend was not. The panel
# reported 4.10.0 because the API reads SG_VERSION, and the updater had already
# printed "Update complete".
#
# An updater that can leave those out of step and still claim success is worse
# than one that fails: the operator believes they are patched.
_SG_CODE_VER="$(grep -oP "^define\('SG_VERSION',\s*'\K[^']+"                 "${INSTALL_DIR}/backend/config/config.php" 2>/dev/null | head -1 || true)"

if [[ -n "$_SG_CODE_VER" && -n "$NEW_VERSION" && "$_SG_CODE_VER" != "$NEW_VERSION" ]]; then
    err "PARTIAL UPDATE: VERSION says ${NEW_VERSION} but the code says ${_SG_CODE_VER}."
    err "The version file was copied and backend/ was not, so this install is"
    err "running ${_SG_CODE_VER} while reporting ${NEW_VERSION}."
    err ""
    err "Re-run this updater. If it happens again, the rsync of backend/ is"
    err "failing -- check ${LOG_DIR:-${INSTALL_DIR}/logs}/update.log and disk space."
    state_failed "Partial update: VERSION ${NEW_VERSION}, code ${_SG_CODE_VER}"
    exit 1
fi

echo ""
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════╗"
echo -e "║  ✔  Update complete!                  ║"
echo -e "╚═══════════════════════════════════════╝${NC}"
echo ""
ok "Updated from v${CURRENT_VERSION} → ${BOLD}v${NEW_VERSION}${NC}"
ok "All settings, quarantine, and logs preserved"
ok "Backup saved to: ${BACKUP_DIR}"

# Completed — disarm rollback and publish the final state.
ROLLBACK_ARMED=false
state_done "Updated to v${NEW_VERSION}"
echo ""
info "If anything looks wrong, restore your backup:"
info "  cp -a ${BACKUP_DIR}/database ${INSTALL_DIR}/"
echo ""
