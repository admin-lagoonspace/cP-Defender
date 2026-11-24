#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — CDN sync (runs ON the cPanel server, via cron)
#
# Pulls the current release from GitHub into the public docroot. The server
# reaches OUT to GitHub, so nothing has to connect IN: no FTP, no firewall
# exception for rotating CI IPs, and no credentials anywhere on this box.
#
# ── INSTALL ───────────────────────────────────────────────────────────────────
#   1. Copy this script onto the server, e.g.
#        /home/serversc/bin/cdn-sync.sh
#   2. chmod +x /home/serversc/bin/cdn-sync.sh
#   3. Add to the cPanel user's crontab (crontab -e):
#        */10 * * * * /home/serversc/bin/cdn-sync.sh >> /home/serversc/logs/cdn-sync.log 2>&1
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
#
# THE PATH IS 'releases', NOT 'serverscrub/code'. Do not move it back.
#
# install.sh writes /etc/apache2/conf.d/serverscrub.conf, which contains
#
#     Alias /serverscrub  ${SG_WEB_DIR}
#
# in conf.d -- so it applies to EVERY vhost on the machine, including the one
# hosting the CDN. Any URL beginning /serverscrub/ is therefore served out of
# the plugin's own directory and never reaches public_html at all.
#
# That is why serverscrub.com/serverscrub/code/latest.json returned 404 for
# six releases while the file sat on disk with correct ownership and
# permissions, under a vhost with the correct DocumentRoot: the product was
# shadowing its own download URL, and only on a server that both runs
# ServerScrub and hosts the CDN -- which is one machine, ours.
DOCROOT="${SG_DOCROOT:-/home/serversc/public_html/releases}"
REPO="${SG_REPO:-admin-lagoonspace/cP-Defender}"
BRANCH="${SG_BRANCH:-main}"
SRC="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
# -- Where this script keeps its own files ------------------------------------
#
# NOT /tmp. This runs as an unprivileged cPanel user on a shared machine, and
# /tmp is shared, world-writable and sticky. Observed on the first live run:
#
#   /home/serversc/bin/cdn-sync.sh: line 53: /tmp/sg-cdn-sync.lock: Permission denied
#
# A fixed name in /tmp belongs to whoever created it first. If that was root --
# or any other account on the box -- this user cannot open it for writing, and
# the sync dies before doing anything, every ten minutes, for ever. Worse, any
# account on the machine can create that name first, as a symlink, and redirect
# whatever this script writes through it.
#
# So everything it writes goes in a directory this user owns.
SG_WORK="${SG_WORK:-}"
if [ -z "$SG_WORK" ]; then
    if [ -n "${HOME:-}" ] && [ -d "${HOME}" ] && [ -w "${HOME}" ]; then
        SG_WORK="${HOME}/.serverscrub-cdn"
    else
        # cron can run with no HOME. cdn-setup.sh installs this script into the
        # user's own home, so its own directory is a safe second choice.
        SG_WORK="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo .)/.serverscrub-cdn"
    fi
fi
mkdir -p "$SG_WORK" 2>/dev/null
chmod 700 "$SG_WORK" 2>/dev/null || true

LOCKFILE="${SG_LOCK:-${SG_WORK}/sync.lock}"
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

# Work from a directory this user can actually read.
#
# cdn-setup.sh starts this with `su -c`, which changes the user but NOT the
# working directory, so the sync runs from root's home. find(1) saves its cwd
# and restores it afterwards, and an unprivileged user cannot stat /root, so
# every run printed two of these into the setup output:
#
#   find: Failed to restore initial working directory: /root: Permission denied
#
# Harmless, but it appears in the middle of a successful publish and reads
# like a fault. SG_WORK is ours and always traversable.
cd "$SG_WORK" 2>/dev/null || cd / 2>/dev/null || true

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

ZIP_NAME="serverscrub-${NEW_VER}.zip"

# Fast path: same version AND the artifacts are actually present.
if [ "$CUR_VER" = "$NEW_VER" ] \
   && [ -s "${DOCROOT}/dist/${ZIP_NAME}" ] \
   && [ -s "${DOCROOT}/v${NEW_VER}/${ZIP_NAME}" ] \
   && [ -s "${BUILDS_DIR}/${ZIP_NAME}" ] \
   && [ -f "${LATEST_DIR}/VERSION" ] \
   && [ "$(tr -d '[:space:]' < "${LATEST_DIR}/VERSION" 2>/dev/null)" = "$NEW_VER" ]; then

    # Version is unchanged, but get.sh is the bootstrap every new install
    # downloads and it ships fixes of its own. Refreshing only on a version bump
    # meant a corrected get.sh sat unpublished until the next release. It is
    # ~17KB, so just fetch and compare on every run.
    # In SG_WORK for the same reason as the lock: a predictable name in a
    # shared directory is not this script's to assume it owns.
    _gcheck="${SG_WORK}/get.sh.check"
    if fetch_to "${SRC}/get.sh" "$_gcheck" 2>/dev/null \
       && [ -s "$_gcheck" ]; then
        if ! cmp -s "$_gcheck" "${DOCROOT}/get.sh" 2>/dev/null; then
            install -m 644 "$_gcheck" "${DOCROOT}/get.sh.tmp" \
              && mv -f "${DOCROOT}/get.sh.tmp" "${DOCROOT}/get.sh" \
              && log "refreshed get.sh (bootstrap updated, version unchanged)"
        fi
    fi
    rm -f "$_gcheck"

    exit 0     # otherwise a silent no-op — keeps the cron log readable
fi

log "sync needed: local='${CUR_VER:-none}' upstream='${NEW_VER}'"

mkdir -p "${DOCROOT}/dist" "${DOCROOT}/v${NEW_VER}" || die "cannot create ${DOCROOT}"

TMP="$(mktemp -d "${SG_WORK}/sync.XXXXXX")" || die "mktemp -d failed under ${SG_WORK}"

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
# Version-specific notes only. The old fallback here was the repo-root
# CHANGELOG.md, so every version folder ended up holding the full project
# history; dropped deliberately — no notes beats the wrong notes.
fetch_to "${SRC}/dist/notes-${NEW_VER}.md"      "${TMP}/CHANGELOG.md" 2>/dev/null \
  || fetch_to "${SRC}/v${NEW_VER}/CHANGELOG.md" "${TMP}/CHANGELOG.md" 2>/dev/null \
  || log "note: no version-specific notes for ${NEW_VER}"

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

    # The archive wraps everything in a single serverscrub/ directory. Lift its
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

    # ── Remove server-executable code from the public tree ────────────────────
    # latest/ lives in the docroot, and Apache EXECUTES PHP from it: on this host
    # backend/lib/*.php returned 200 with an empty body (they ran) and
    # config.php returned 500 (ran and fataled). Two .htaccess approaches were
    # tried — SetHandler none, then SetHandler default-handler with RemoveHandler
    # and ForceType — and BOTH were ignored, because the vhost assigns PHP via a
    # PHP-FPM proxy handler that .htaccess here is not permitted to override.
    #
    # So do not rely on Apache config at all: if the file is not there, it cannot
    # run. Nothing is lost — the complete build stays available as the checksummed
    # zip in builds/, dist/ and v<ver>/, which is what installs actually consume.
    # latest/ exists to serve the shell scripts, VERSION and static assets.
    #
    # Set SG_LATEST_FULL=1 to keep the whole tree, only if you have confirmed
    # PHP execution is genuinely disabled for this directory.
    if [ "${SG_LATEST_FULL:-0}" != "1" ]; then
        STRIPPED=$(find "$STAGE" -type f \
            \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' \
               -o -name '*.phps' -o -name '*.cgi' -o -name '*.pl' \) \
            -print -delete 2>/dev/null | wc -l)
        # Prune directories left empty by the strip
        find "$STAGE" -type d -empty -delete 2>/dev/null || true
        [ "$STRIPPED" -gt 0 ] && log "stripped ${STRIPPED} executable file(s) from latest/ (public docroot)"
    else
        log "SG_LATEST_FULL=1 — keeping PHP in latest/; ensure execution is disabled"
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

    # ── Harden latest/: serve it, never RUN it ────────────────────────────────
    # latest/ sits in the public docroot and contains the product's own PHP.
    # Without this Apache EXECUTES it: backend/lib/*.php run as unauthenticated
    # web requests, and backend/api/index.php + config/config.php fatal with 500s
    # that can leak paths depending on display_errors. Nothing here is meant to
    # run — it is a download tree. Source disclosure is not a concern (the repo
    # is public); execution is.
    #
    # Written on every sync because the wipe-and-replace would otherwise drop it.
    cat > "${LATEST_DIR}/.htaccess" <<'HTACCESS'
# ServerScrub — this tree is for DOWNLOAD ONLY. Never execute anything in it.
# Written automatically by cdn-sync.sh on every publish; edits here are lost.

# SetHandler default-handler — NOT "none". On cPanel EA4 PHP runs as a PHP-FPM
# proxy handler assigned in the vhost; "none" merely unsets the local handler and
# falls through to that inherited one, so .php files kept executing (observed:
# lib/*.php returned 200 with 0 bytes, config.php returned 500).
# "default-handler" explicitly forces Apache's core static-file handler.
<FilesMatch "\.(php|phtml|php[0-9]|phps|cgi|pl|py|sh)$">
    SetHandler default-handler
    ForceType text/plain
    Options -ExecCGI
</FilesMatch>

# Belt and braces: strip any inherited proxy/fcgi handler for these extensions
<IfModule mod_mime.c>
    RemoveHandler .php .phtml .php3 .php4 .php5 .php6 .php7 .php8 .phps
    AddType text/plain .php .phtml .phps .cgi .pl .py .sh
</IfModule>

# mod_php, where present
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
<IfModule mod_php7.c>
    php_flag engine off
</IfModule>
<IfModule mod_php5.c>
    php_flag engine off
</IfModule>

# Directory listings are required: the installer walks this tree as a
# last-resort source when every zip path fails.
Options +Indexes -ExecCGI -FollowSymLinks
HTACCESS
    chmod 644 "${LATEST_DIR}/.htaccess" 2>/dev/null || true

    log "extracted latest/ (wiped previous contents; execution disabled)"
else
    log "WARNING: unzip not available — latest/ not refreshed"
fi

# --- The manifest must not be cacheable --------------------------------------
#
# THIS IS THE DEFECT THAT MADE EVERY RELEASE INVISIBLE FOR A WHILE.
#
# Replacing ${DOCROOT}/latest.json changes the file on disk. It does not change
# what the public url serves, because this docroot sits behind cPanel's nginx
# reverse-proxy cache, and that cache keys on the url. Measured on 2026-11-13,
# after this script had successfully published v4.36.0:
#
#   GET https://serverscrub.com/releases/latest.json            -> 4.35.1
#     Server: nginx
#     Last-Modified: Sat, 07 Nov 2026 02:40:12 GMT   (the 4.35.1 publish)
#   GET .../latest.json -H 'Cache-Control: no-cache' -H 'Pragma: no-cache'
#                                                               -> 4.35.1
#   GET .../latest.json?cb=<timestamp>                          -> 4.36.0
#
# The origin files were correct the whole time. Client revalidation is ignored;
# only a url the proxy has never seen misses the cache.
#
# This was never specific to 4.36.0. EVERY release has had a window in which
# the canonical manifest advertised the previous version, with nothing in any
# log to say so. That is the likely source of the long-standing impression that
# installs "silently fell back to the GitHub mirror": they were not falling
# back, they were being told the old version was the current one. The same
# nginx layer is what served stale WAF-event JSON at 4.35.1.
#
# Three things are done about it, in order of durability:
#
#   1. An .htaccess in this docroot marks the version-bearing files
#      uncacheable, so a proxy that honours origin cache-control stops
#      holding them at all. The zips stay cacheable -- their names contain
#      the version, so a cached serverscrub-4.36.0.zip is by definition the
#      right bytes, and they are the only part of this that is big.
#   2. A best-effort purge after the manifest is in place, for the proxies
#      that ignore (1).
#   3. A read-back of the PUBLIC url, so that when (1) and (2) both fail the
#      publish says so in the log instead of reporting success. update.sh and
#      UpdateChecker.php no longer depend on this cache behaving -- both now
#      cross-check latest/VERSION and cache-bust every fetch -- but the sync
#      should still not claim a release is live when the canonical url says
#      otherwise.
#
# The .htaccess is written as a MARKED BLOCK appended to whatever is already
# there, never as a wholesale overwrite: this docroot is shared with the
# website and may carry rules this script knows nothing about.
_write_docroot_htaccess() {
    local ht="${DOCROOT}/.htaccess"
    local begin='# BEGIN ServerScrub cdn-sync (managed block — edits here are lost)'
    local end='# END ServerScrub cdn-sync'
    local block
    block="$(cat <<HTACCESS
${begin}
# The release manifest and the version stamp are read to decide whether an
# update exists. A cached copy of either tells every installed server that an
# old release is the current one, which is indistinguishable from there being
# no new release at all. They are a few hundred bytes; never cache them.
<FilesMatch "^(latest\.json|VERSION|get\.sh)$">
    <IfModule mod_headers.c>
        Header always set Cache-Control "no-store, no-cache, must-revalidate, max-age=0"
        Header always set Pragma "no-cache"
        Header always set Expires "0"
        # Surfaces which layer answered when this goes wrong again.
        Header always set X-SG-Manifest "origin"
    </IfModule>
</FilesMatch>
# The zips are immutable: the version is in the filename. Cache them hard.
<FilesMatch "\.zip$">
    <IfModule mod_headers.c>
        Header always set Cache-Control "public, max-age=31536000, immutable"
    </IfModule>
</FilesMatch>
${end}
HTACCESS
)"

    if [ -f "$ht" ]; then
        if grep -qF "$begin" "$ht" 2>/dev/null; then
            # A BEGIN with no END means a truncated or hand-edited file. The
            # awk below would treat everything after BEGIN as part of our
            # block and drop it, so refuse: this docroot is shared with the
            # website, and silently deleting its rules is far worse than a
            # cacheable manifest.
            if ! grep -qF "$end" "$ht" 2>/dev/null; then
                log "WARNING: ${ht} has our BEGIN marker but no END marker."
                log "         Refusing to rewrite it — fix the markers by hand."
                return 1
            fi
            # Replace only our own block, leaving everything else untouched.
            awk -v b="$begin" -v e="$end" -v blk="$block" '
                index($0, b) { skip = 1; print blk; next }
                index($0, e) { skip = 0; next }
                !skip        { print }
            ' "$ht" > "${ht}.tmp" 2>/dev/null \
              && mv -f "${ht}.tmp" "$ht" \
              && { chmod 644 "$ht" 2>/dev/null || true; log "refreshed cache-control block in ${ht}"; return 0; }
            rm -f "${ht}.tmp" 2>/dev/null
            log "WARNING: could not update the managed block in ${ht}"
            return 1
        fi
        # Someone else's .htaccess: append, do not replace.
        if { printf '\n%s\n' "$block" >> "$ht"; } 2>/dev/null; then
            log "appended cache-control block to existing ${ht}"
            return 0
        fi
        log "WARNING: cannot append to ${ht} — manifest stays cacheable"
        return 1
    fi

    if printf '%s\n' "$block" > "${ht}.tmp" 2>/dev/null && mv -f "${ht}.tmp" "$ht"; then
        chmod 644 "$ht" 2>/dev/null || true
        log "wrote ${ht} (manifest marked uncacheable)"
        return 0
    fi
    rm -f "${ht}.tmp" 2>/dev/null
    log "WARNING: cannot write ${ht} — manifest stays cacheable"
    return 1
}
_write_docroot_htaccess || true

printf '%s\n' "$REMOTE_JSON" > "${TMP}/latest.json"
place "${TMP}/latest.json"   "${DOCROOT}/v${NEW_VER}/latest.json"
place "${TMP}/latest.json"   "${DOCROOT}/latest.json"             || die "publish failed: latest.json"

# --- Purge the proxy cache in front of the manifest --------------------------
#
# Best effort by design. This runs as an unprivileged cPanel user, and every
# mechanism below needs either root or a purge endpoint that may not exist, so
# a failure here is logged and never fatal -- the publish itself succeeded, and
# the read-back below reports the consequence.
_purge_manifest_cache() {
    local purged=0

    # cPanel's own ea-nginx helper, if this account may run it.
    for _s in /usr/local/cpanel/scripts/clear_nginx_cache /scripts/clear_nginx_cache; do
        if [ -x "$_s" ]; then
            if "$_s" --user="$(id -un 2>/dev/null || echo serversc)" >/dev/null 2>&1 \
            || "$_s" >/dev/null 2>&1; then
                log "purged nginx cache via ${_s}"
                purged=1
                break
            fi
            log "note: ${_s} exists but this account cannot run it (needs root)"
        fi
    done

    # An explicit purge url, if the deployment has one configured.
    if [ "$purged" -eq 0 ] && [ -n "${SG_PURGE_URL:-}" ]; then
        if curl -fsS --max-time 15 -X PURGE "${SG_PURGE_URL}" >/dev/null 2>&1; then
            log "purged ${SG_PURGE_URL}"
            purged=1
        else
            log "note: PURGE ${SG_PURGE_URL} did not succeed"
        fi
    fi

    [ "$purged" -eq 1 ] && return 0

    log "note: no cache purge available to this account; relying on the"
    log "      .htaccess cache-control block and on clients cache-busting"
    return 1
}
_purge_manifest_cache || true

# --- Read back the PUBLIC url, not the file on disk --------------------------
#
# The whole failure was that these two can disagree, so a publish that only
# checks its own disk writes proves nothing about what customers are served.
PUBLIC_BASE="${SG_PUBLIC_BASE:-https://serverscrub.com/releases}"
_verify_public_manifest() {
    local plain busted
    # Deliberately NO cache-buster on the first fetch: this is the url every
    # installed server actually requests.
    plain="$(curl -fsSL --max-time 20 "${PUBLIC_BASE}/latest.json" 2>/dev/null || true)"
    plain="$(json_get "${plain:-}" version || true)"
    busted="$(curl -fsSL --max-time 20 "${PUBLIC_BASE}/latest.json?cb=$(date +%s 2>/dev/null || echo 0)$$" 2>/dev/null || true)"
    busted="$(json_get "${busted:-}" version || true)"

    if [ -z "$plain" ] && [ -z "$busted" ]; then
        log "WARNING: could not read ${PUBLIC_BASE}/latest.json back at all"
        return 1
    fi
    if [ "$plain" = "$NEW_VER" ]; then
        log "verified ${PUBLIC_BASE}/latest.json serves v${NEW_VER}"
        return 0
    fi
    log "WARNING: ${PUBLIC_BASE}/latest.json serves v${plain:-unparseable}, not v${NEW_VER}."
    if [ "$busted" = "$NEW_VER" ]; then
        log "         A cache-busted request DOES return v${NEW_VER}, so the origin is"
        log "         correct and a proxy cache in front of it is holding the old object."
        log "         Purge it as root:  /usr/local/cpanel/scripts/clear_nginx_cache"
    else
        log "         A cache-busted request returns v${busted:-unparseable} too, so this"
        log "         is not a cache — check what was published to ${DOCROOT}."
    fi
    return 1
}
# A FAILED READ-BACK IS A FAILED PUBLISH.
#
# This read-back already existed, already reached the right diagnosis, and
# already logged WARNING -- and the next line logged "published v${NEW_VER}"
# anyway and the script exited 0. So nine releases (4.37.1 ... 4.37.9) were
# reported as mirrored while serverscrub.com/releases stayed on 4.37.0, and
# publish.sh, reading the same cheerful exit status, reported the same thing.
# A release process that can claim a mirror that did not happen is the actual
# defect here; the frozen mirror is only what it hid.
PUBLISH_OK=true
if _verify_public_manifest; then
    log "published v${NEW_VER}"
else
    PUBLISH_OK=false
    log "ERROR: NOT published. v${NEW_VER} was written to ${DOCROOT} but the public"
    log "       url does not serve it, so no installed server can get this build."
    log "       The files are on disk; what is wrong is between ${DOCROOT} and the"
    log "       public url -- a docroot that is no longer the served one, a vhost,"
    log "       or a proxy cache (the lines above say which)."
fi

# ── Optional retention ────────────────────────────────────────────────────────
# Skipped when the publish could not be verified. Deleting old builds while it
# is unclear what the public url is actually serving could remove the only
# version customers can still reach. Flag it and leave the data alone.
if [ "$PUBLISH_OK" = true ] && [ "$KEEP_VERSIONS" -gt 0 ] 2>/dev/null; then
    mapfile -t OLD < <(find "${DOCROOT}" -maxdepth 1 -type d -name 'v[0-9]*' -printf '%f\n' 2>/dev/null \
        | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | head -n -"${KEEP_VERSIONS}")
    for v in "${OLD[@]:-}"; do
        [ -n "$v" ] && [ "$v" != "$NEW_VER" ] || continue
        rm -rf "${DOCROOT}/v${v}" && log "pruned old version v${v}"
    done
fi

# Non-zero so a cron log and a caller can tell a published release from one
# that only reached the disk. publish.sh now waits for the public url itself,
# and both have to agree.
$PUBLISH_OK || exit 1
exit 0
