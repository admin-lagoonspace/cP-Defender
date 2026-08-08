#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — CDN sync (runs ON the cPanel server, via cron)
#
# Pulls the current release from GitHub into the public docroot. The server
# reaches OUT to GitHub, so nothing has to connect IN: no FTP, no firewall
# exception for rotating CI IPs, and no credentials anywhere on this box.
#
# ── INSTALL ───────────────────────────────────────────────────────────────────
#   1. Copy this script onto the server, e.g.
#        /home/lwss1/bin/cdn-sync.sh
#   2. chmod +x /home/lwss1/bin/cdn-sync.sh
#   3. Add to the cPanel user's crontab (crontab -e):
#        */10 * * * * /home/lwss1/bin/cdn-sync.sh >> /home/lwss1/logs/cdn-sync.log 2>&1
#
# ── COST ──────────────────────────────────────────────────────────────────────
# The common case is a single ~300 byte GET of latest.json. The release zip is
# only fetched when the published version differs from the local one, so a tight
# interval is cheap. Nothing is downloaded on a no-op run.
#
# ── SAFETY ────────────────────────────────────────────────────────────────────
# * flock prevents overlapping runs if one sync is slow.
# * The zip is verified against the sha256 in the manifest BEFORE being placed.
# * Files are written to a temp name and moved into place (mv is atomic within a
#   filesystem), so a half-downloaded artifact is never served.
# * latest.json is written LAST, so a client can never read a manifest that
#   points at a zip which is not on disk yet.
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

# ── Config (override via environment) ─────────────────────────────────────────
DOCROOT="${SG_DOCROOT:-/home/lwss1/public_html/defender.lws-s1.com/sentinel-gate/code}"
REPO="${SG_REPO:-admin-lagoonspace/cP-Defender}"
BRANCH="${SG_BRANCH:-main}"
SRC="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
LOCKFILE="${SG_LOCK:-/tmp/sg-cdn-sync.lock}"
KEEP_VERSIONS="${SG_KEEP_VERSIONS:-0}"   # 0 = keep every version forever
BUILDS_DIR="${SG_BUILDS_DIR:-${DOCROOT}/builds}"   # archive of every release zip
LATEST_DIR="${SG_LATEST_DIR:-${DOCROOT}/latest}"   # newest build, extracted

ts()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { echo "[$(ts)] $*"; }
die() { echo "[$(ts)] ERROR: $*" >&2; exit 1; }

# ── Single instance only ──────────────────────────────────────────────────────
# flock is preferred, but it must NOT be a hard dependency: if it is missing,
# `! flock -n 9` fails as "command not found" and the script would exit 0 while
# logging "another sync is running" — a permanent silent no-op that looks like
# healthy output. Fall back to a PID lock, and stale-lock recovery so a killed
# run cannot wedge the sync forever.
if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCKFILE" || die "cannot open lock $LOCKFILE"
    if ! flock -n 9; then
        log "another sync holds the lock; exiting"
        exit 0
    fi
else
    if [ -f "$LOCKFILE" ]; then
        OLD_PID="$(cat "$LOCKFILE" 2>/dev/null)"
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            log "another sync is running (pid ${OLD_PID}); exiting"
            exit 0
        fi
        log "removing stale lock (pid ${OLD_PID:-unknown} is gone)"
        rm -f "$LOCKFILE"
    fi
    echo $$ > "$LOCKFILE" || die "cannot write lock $LOCKFILE"
    PID_LOCK="$LOCKFILE"
fi

# Single EXIT handler — a second `trap ... EXIT` later would silently replace an
# earlier one and leak whatever the first was responsible for.
TMP=""
PID_LOCK="${PID_LOCK:-}"
cleanup() {
    [ -n "$TMP" ] && [ -d "$TMP" ] && rm -rf "$TMP"
    [ -n "$PID_LOCK" ] && rm -f "$PID_LOCK"
    return 0
}
trap cleanup EXIT

command -v curl >/dev/null 2>&1 || die "curl not found"

fetch()    { curl -fsSL --max-time 30  -H 'Cache-Control: no-cache' "$1"; }
fetch_to() { curl -fsSL --max-time 300 -o "$2" "$1"; }

json_get() { # json_get <json> <key>
    printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]+\"" \
        | head -1 | sed -E 's/.*"([^"]+)"$/\1/'
}

sha_of() {
    if   command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else echo ""; fi
}

# ── What is published upstream? ───────────────────────────────────────────────
REMOTE_JSON="$(fetch "${SRC}/latest.json")" || die "cannot reach ${SRC}/latest.json"
[ -n "$REMOTE_JSON" ] || die "empty manifest from upstream"

NEW_VER="$(json_get "$REMOTE_JSON" version)"
NEW_SHA="$(json_get "$REMOTE_JSON" sha256)"
[ -n "$NEW_VER" ] || die "could not parse version from upstream manifest"

# ── What do we already serve? ─────────────────────────────────────────────────
CUR_VER=""
[ -f "${DOCROOT}/latest.json" ] && CUR_VER="$(json_get "$(cat "${DOCROOT}/latest.json")" version)"

ZIP_NAME="sentinel-gate-${NEW_VER}.zip"

# Fast path: same version AND the artifacts are actually present.
if [ "$CUR_VER" = "$NEW_VER" ] \
   && [ -s "${DOCROOT}/dist/${ZIP_NAME}" ] \
   && [ -s "${DOCROOT}/v${NEW_VER}/${ZIP_NAME}" ] \
   && [ -s "${BUILDS_DIR}/${ZIP_NAME}" ] \
   && [ -f "${LATEST_DIR}/VERSION" ] \
   && [ "$(tr -d '[:space:]' < "${LATEST_DIR}/VERSION" 2>/dev/null)" = "$NEW_VER" ]; then
    exit 0     # silent no-op — keeps the cron log readable
fi

log "sync needed: local='${CUR_VER:-none}' upstream='${NEW_VER}'"

mkdir -p "${DOCROOT}/dist" "${DOCROOT}/v${NEW_VER}" || die "cannot create ${DOCROOT}"

TMP="$(mktemp -d /tmp/sg-sync.XXXXXX)" || die "mktemp failed"

# ── Download the release zip ──────────────────────────────────────────────────
GOT=false
for URL in "${SRC}/dist/${ZIP_NAME}" "${SRC}/v${NEW_VER}/${ZIP_NAME}"; do
    log "downloading ${URL}"
    if fetch_to "$URL" "${TMP}/${ZIP_NAME}" && [ -s "${TMP}/${ZIP_NAME}" ]; then
        GOT=true; break
    fi
    log "  failed, trying next"
done
$GOT || die "could not download ${ZIP_NAME} from any upstream path"

# ── Verify BEFORE publishing ──────────────────────────────────────────────────
if [ -n "$NEW_SHA" ]; then
    GOT_SHA="$(sha_of "${TMP}/${ZIP_NAME}")"
    if [ -n "$GOT_SHA" ] && [ "$GOT_SHA" != "$NEW_SHA" ]; then
        die "checksum mismatch — expected ${NEW_SHA}, got ${GOT_SHA}. NOT publishing."
    fi
    [ -n "$GOT_SHA" ] && log "checksum verified"
else
    log "WARNING: upstream manifest carries no sha256; publishing unverified"
fi

# Sanity-check it is a real zip before it reaches the docroot
if command -v unzip >/dev/null 2>&1; then
    unzip -tq "${TMP}/${ZIP_NAME}" >/dev/null 2>&1 || die "downloaded file is not a valid zip"
fi

# ── Optional extras (absence is not fatal) ────────────────────────────────────
fetch_to "${SRC}/get.sh"                       "${TMP}/get.sh"       || log "note: get.sh not fetched"
fetch_to "${SRC}/v${NEW_VER}/CHANGELOG.md"     "${TMP}/CHANGELOG.md" 2>/dev/null \
  || fetch_to "${SRC}/CHANGELOG.md"            "${TMP}/CHANGELOG.md" 2>/dev/null \
  || log "note: CHANGELOG.md not fetched"

# ── Publish atomically. Manifest LAST. ────────────────────────────────────────
place() { # place <src> <dest>
    [ -s "$1" ] || return 0
    install -m 644 "$1" "$2.tmp" && mv -f "$2.tmp" "$2"
}

place "${TMP}/${ZIP_NAME}"   "${DOCROOT}/v${NEW_VER}/${ZIP_NAME}" || die "publish failed: v${NEW_VER}/${ZIP_NAME}"
place "${TMP}/CHANGELOG.md"  "${DOCROOT}/v${NEW_VER}/CHANGELOG.md"
place "${TMP}/${ZIP_NAME}"   "${DOCROOT}/dist/${ZIP_NAME}"        || die "publish failed: dist/${ZIP_NAME}"
place "${TMP}/get.sh"        "${DOCROOT}/get.sh"

# ── builds/ — every release zip, kept permanently ─────────────────────────────
mkdir -p "${BUILDS_DIR}" || die "cannot create ${BUILDS_DIR}"
place "${TMP}/${ZIP_NAME}" "${BUILDS_DIR}/${ZIP_NAME}" || die "publish failed: builds/${ZIP_NAME}"
log "archived builds/${ZIP_NAME}"

# ── latest/ — newest build, EXTRACTED, previous contents wiped ────────────────
# Extracted into a staging dir and swapped in, rather than wiping latest/ and
# unpacking in place. A wipe-then-extract leaves latest/ empty or half-written
# for the duration, and anything reading it during that window sees a broken
# tree. The swap makes the change effectively instantaneous, and the old tree is
# only deleted once the new one is fully in place.
if command -v unzip >/dev/null 2>&1; then
    STAGE="${DOCROOT}/.latest.staging.$$"
    rm -rf "$STAGE"
    mkdir -p "$STAGE" || die "cannot create staging dir"

    if ! unzip -qo "${TMP}/${ZIP_NAME}" -d "$STAGE" 2>/dev/null; then
        rm -rf "$STAGE"
        die "extraction failed for ${ZIP_NAME}"
    fi

    # The archive wraps everything in a single sentinel-gate/ directory. Lift its
    # contents up so latest/ holds backend/, frontend/, install.sh … directly.
    INNER="$(find "$STAGE" -mindepth 1 -maxdepth 1 -type d | head -1)"
    if [ -n "$INNER" ] && [ "$(find "$STAGE" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1 ]; then
        mv "$INNER" "${STAGE}.inner" && rm -rf "$STAGE" && mv "${STAGE}.inner" "$STAGE"
    fi

    # Confirm the extraction actually produced a build before it replaces a good one
    if [ ! -f "${STAGE}/VERSION" ] || [ ! -f "${STAGE}/install.sh" ]; then
        rm -rf "$STAGE"
        die "extracted tree is missing VERSION/install.sh — refusing to replace latest/"
    fi

    OLD="${DOCROOT}/.latest.old.$$"
    rm -rf "$OLD"
    if [ -d "${LATEST_DIR}" ]; then
        mv "${LATEST_DIR}" "$OLD" || die "cannot move aside existing latest/"
    fi
    if ! mv "$STAGE" "${LATEST_DIR}"; then
        # Roll back so latest/ is never left missing
        [ -d "$OLD" ] && mv "$OLD" "${LATEST_DIR}"
        die "cannot swap in new latest/"
    fi
    rm -rf "$OLD"
    chmod -R a+rX "${LATEST_DIR}" 2>/dev/null || true
    log "extracted latest/ (wiped previous contents)"
else
    log "WARNING: unzip not available — latest/ not refreshed"
fi

printf '%s\n' "$REMOTE_JSON" > "${TMP}/latest.json"
place "${TMP}/latest.json"   "${DOCROOT}/v${NEW_VER}/latest.json"
place "${TMP}/latest.json"   "${DOCROOT}/latest.json"             || die "publish failed: latest.json"

log "published v${NEW_VER}"

# ── Optional retention ────────────────────────────────────────────────────────
if [ "$KEEP_VERSIONS" -gt 0 ] 2>/dev/null; then
    mapfile -t OLD < <(find "${DOCROOT}" -maxdepth 1 -type d -name 'v[0-9]*' -printf '%f\n' 2>/dev/null \
        | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | head -n -"${KEEP_VERSIONS}")
    for v in "${OLD[@]:-}"; do
        [ -n "$v" ] && [ "$v" != "$NEW_VER" ] || continue
        rm -rf "${DOCROOT}/v${v}" && log "pruned old version v${v}"
    done
fi

exit 0
