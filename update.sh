#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Safe Update Script
# Downloads the latest release from GitHub, applies it over the current
# installation, and preserves ALL user data (database, settings, quarantine,
# logs, TLS certs, custom signatures).
#
# Usage:
#   bash /usr/local/sentinel-gate/update.sh
#   bash /usr/local/sentinel-gate/update.sh --yes               # non-interactive
#   bash /usr/local/sentinel-gate/update.sh --version 3.3.7     # skip API, force version
#   bash /usr/local/sentinel-gate/update.sh --url https://...   # use a direct zip URL
#
# Run as: root
# ════════════════════════════════════════════════════════════════════════════════

set -euo pipefail

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
STATE_DIR="${SG_STATE_DIR:-/var/lib/sentinel-gate}"
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
        rsync -a --delete "${CODE_SNAPSHOT}/${dir}/" "${INSTALL_DIR}/${dir}/" 2>/dev/null             && ok "Restored code: ${dir}/"
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
    systemctl start sentinel-gate-monitor 2>/dev/null || true

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
#       "url":     "https://raw.githubusercontent.com/<repo>/main/dist/sentinel-gate-3.5.0.zip",
#       "sha256":  "<hex>",
#       "notes":   "https://..." }
#
# The manifest carries the full download URL, so the updater never has to guess
# the asset filename (kills the old v-prefix / no-prefix naming mismatch).
INSTALL_DIR="${SG_ROOT:-/usr/local/sentinel-gate}"
# Repo is public, so updates are served straight from it — no separate channel,
# no credentials on customer servers. Override via env if you ever split it out.
RELEASES_REPO="${SG_RELEASES_REPO:-admin-lagoonspace/cP-Defender}"
RELEASES_BRANCH="${SG_RELEASES_BRANCH:-main}"
# Primary channel is our own CDN — no API rate limits, and it keeps working on
# servers whose firewall blocks github.com (the exact failure that broke v3.3.6
# updates in the field). GitHub raw stays as an automatic fallback.
CDN_BASE="${SG_CDN_BASE:-https://defender.lws-s1.com/sentinel-gate/code}"
GITHUB_BASE="https://raw.githubusercontent.com/${RELEASES_REPO}/${RELEASES_BRANCH}"
CHANNELS=("$CDN_BASE" "$GITHUB_BASE")
# Explicit override wins and disables channel rotation
[[ -n "${SG_MANIFEST_URL:-}" ]] && CHANNELS=("${SG_MANIFEST_URL%/latest.json}")
MANIFEST_URL="${CHANNELS[0]}/latest.json"
DIST_BASE="${CHANNELS[0]}/dist"
BACKUP_ROOT="/var/backups/sentinel-gate"
TMP_DIR="$(mktemp -d /tmp/sg-update.XXXXXX)"
AUTO_YES=false
FORCE_VERSION=""
FORCE_URL=""
EXPECTED_SHA256=""

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)              AUTO_YES=true ;;
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
[[ -d "$INSTALL_DIR" ]] || die "Sentinel Gate not found at $INSTALL_DIR"

# Cleanup on exit
trap 'rm -rf "$TMP_DIR"' EXIT

echo ""
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════╗"
echo -e "║    Sentinel Gate — Safe Updater       ║"
echo -e "╚═══════════════════════════════════════╝${NC}"
echo ""

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
CURRENT_VERSION="$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null | tr -d '[:space:]')"
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
    DOWNLOAD_URL="${DIST_BASE}/sentinel-gate-${LATEST_VERSION}.zip"
    warn "No checksum available for a forced version — integrity will NOT be verified."

elif [[ -n "$FORCE_URL" ]]; then
    # ── Direct URL supplied — derive version from current install ─────────────
    info "Using direct download URL (--url flag)"
    LATEST_VERSION="${CURRENT_VERSION}-manual"
    DOWNLOAD_URL="$FORCE_URL"
    warn "No checksum available for a direct URL — integrity will NOT be verified."

else
    # ── Fetch the manifest, walking each channel in turn (with retries) ────────
    info "Checking releases channel for latest version…"
    API_RETRIES=2
    API_WAIT=4
    MANIFEST_JSON=""
    ACTIVE_BASE=""
    for BASE in "${CHANNELS[@]}"; do
        # latest/VERSION is the extracted build the channel is actually serving.
        # Six bytes, and it cannot disagree with what is on disk there, so it is
        # used to cross-check the manifest below.
        LIVE_VER="$(curl -fsSL --max-time 10 "${BASE}/latest/VERSION" 2>/dev/null | tr -d '[:space:]')"
        [[ -n "$LIVE_VER" ]] && info "  ${BASE}/latest/ reports v${LIVE_VER}"

        info "  Trying: ${BASE}/latest.json"
        for attempt in $(seq 1 $API_RETRIES); do
            [[ $attempt -gt 1 ]] && { warn "  Retrying in ${API_WAIT}s (${attempt}/${API_RETRIES})…"; sleep $API_WAIT; }
            CURL_ERR_FILE="${TMP_DIR}/curl_err.txt"
            if MANIFEST_JSON="$(curl -fsSL --max-time 15 \
                    -H 'Cache-Control: no-cache' \
                    "${BASE}/latest.json" 2>"$CURL_ERR_FILE")"; then
                break
            else
                CURL_EXIT=$?
                CURL_ERR="$(cat "$CURL_ERR_FILE" 2>/dev/null)"
                warn "  curl exit ${CURL_EXIT}: ${CURL_ERR}"
                MANIFEST_JSON=""
            fi
        done
        if [[ -n "$MANIFEST_JSON" ]]; then
            ACTIVE_BASE="$BASE"
            DIST_BASE="${BASE}/dist"
            ok "Channel reachable: ${BASE}"
            break
        fi
        warn "Channel unreachable, trying next…"
    done

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
        echo -e "  ${BOLD}bash $0 --url https://your-mirror/sentinel-gate.zip${NC}"
        echo ""
        exit 1
    fi

    # Parse manifest (tolerant of whitespace; values are simple strings)
    LATEST_VERSION="$(echo "$MANIFEST_JSON" | grep -oP '"version"\s*:\s*"\K[^"]+' | head -1)"
    DOWNLOAD_URL="$(echo "$MANIFEST_JSON"   | grep -oP '"url"\s*:\s*"\K[^"]+' | head -1)"
    MIRROR_URL="$(echo "$MANIFEST_JSON"     | grep -oP '"mirror"\s*:\s*"\K[^"]+' | head -1)"
    EXPECTED_SHA256="$(echo "$MANIFEST_JSON" | grep -oP '"sha256"\s*:\s*"\K[0-9a-fA-F]+' | head -1)"
    RELEASE_URL="$(echo "$MANIFEST_JSON"    | grep -oP '"notes"\s*:\s*"\K[^"]+' | head -1)"

    # Fall back to the extracted tree if the manifest was unparseable
    if [[ -z "$LATEST_VERSION" && -n "${LIVE_VER:-}" ]]; then
        LATEST_VERSION="$LIVE_VER"
        warn "Manifest unparseable — using v${LATEST_VERSION} from latest/VERSION"
    fi
    [[ -z "$LATEST_VERSION" ]] && die "Could not parse version from manifest."

    # A manifest disagreeing with the deployed tree means the channel is mid-sync
    if [[ -n "${LIVE_VER:-}" && "$LIVE_VER" != "$LATEST_VERSION" ]]; then
        warn "Manifest says v${LATEST_VERSION} but latest/ holds v${LIVE_VER} — channel mid-sync."
    fi
    [[ -z "$DOWNLOAD_URL"   ]] && DOWNLOAD_URL="${DIST_BASE}/sentinel-gate-${LATEST_VERSION}.zip"
fi

info "Latest version:  ${BOLD}v${LATEST_VERSION}${NC}"

# ── Already up to date? ───────────────────────────────────────────────────────
# Skip version comparison when forced via --version or --url flags
if [[ -z "$FORCE_VERSION" && -z "$FORCE_URL" ]]; then
    if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
        ok "Already up to date — v${CURRENT_VERSION}"
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
    _is_newer "$LATEST_VERSION" "$CURRENT_VERSION" || {
        warn "Latest GitHub release (v${LATEST_VERSION}) is not newer than current (v${CURRENT_VERSION})."
        if [[ "$AUTO_YES" == false ]]; then
            read -rp "  Force reinstall anyway? [y/N] " REPLY
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

# ── Backup user data ──────────────────────────────────────────────────────────
state "backup" 30 "Backing up your data"
section "Backing up user data"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}_v${CURRENT_VERSION}"
mkdir -p "$BACKUP_DIR"

# Items to preserve (never overwritten by update)
PRESERVE=(
    "${INSTALL_DIR}/database"
    "${INSTALL_DIR}/logs"
    "${INSTALL_DIR}/quarantine"
    "${INSTALL_DIR}/backend/config/mode.php"
    "${INSTALL_DIR}/backend/signatures/custom.sig"
)

for item in "${PRESERVE[@]}"; do
    [[ -e "$item" ]] && cp -a "$item" "$BACKUP_DIR/" && info "Backed up: $item"
done

# Snapshot installed version for rollback reference
echo "$CURRENT_VERSION" > "${BACKUP_DIR}/from_version.txt"
ok "Backup created at: ${BACKUP_DIR}"

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
    for _B in "${CHANNELS[@]}"; do
        for _P in "builds/sentinel-gate-${LATEST_VERSION}.zip" \
                  "v${LATEST_VERSION}/sentinel-gate-${LATEST_VERSION}.zip" \
                  "dist/sentinel-gate-${LATEST_VERSION}.zip"; do
            ALT_URL="${_B}/${_P}"
            [[ "$ALT_URL" == "$DOWNLOAD_URL" || "$ALT_URL" == "${MIRROR_URL:-}" ]] && continue
            if _download "$ALT_URL" "$RELEASE_ZIP" "${_P%%/*} zip (fallback)"; then
                DOWNLOADED=true; break 2
            fi
        done
    done
    $DOWNLOADED || warn "Fallback dist downloads also failed."
fi

if [[ "$DOWNLOADED" == false ]]; then
    err "All download attempts failed for v${LATEST_VERSION}."
    echo ""
    info "Manual option: download the zip on another machine and copy it here, then run:"
    info "  bash $0 --url file:///path/to/sentinel-gate.zip"
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
    ACTUAL_SHA256="$($_SHA_TOOL "$RELEASE_ZIP" | awk '{print $1}')"
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
EXTRACTED_ROOT="$(find "${TMP_DIR}/extracted" -maxdepth 1 -mindepth 1 -type d | head -1)"
[[ -z "$EXTRACTED_ROOT" ]] && EXTRACTED_ROOT="${TMP_DIR}/extracted"
ok "Extracted to: $EXTRACTED_ROOT"

# ── Stop the monitor daemon ───────────────────────────────────────────────────
section "Stopping services"
if systemctl is-active --quiet sentinel-gate-monitor 2>/dev/null; then
    systemctl stop sentinel-gate-monitor 2>/dev/null && ok "Monitor daemon stopped" || true
fi

# ── Apply update — overlay files, skip user-data paths ───────────────────────
section "Applying update"

# Directories to update (code only — never user data)
UPDATE_DIRS=( backend frontend whm )
UPDATE_FILES=( VERSION install.sh uninstall.sh update.sh )

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
    rsync -a --delete \
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
# Trigger a PHP call that initialises Database (runs all migrations/ALTER guards)
php -r "
define('SG_API', true);
require_once '${INSTALL_DIR}/backend/config/mode.php';
require_once '${INSTALL_DIR}/backend/lib/Database.php';
echo 'Database migrations applied.' . PHP_EOL;
" 2>&1 | while IFS= read -r line; do info "$line"; done

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

# ── Fix permissions ───────────────────────────────────────────────────────────
section "Fixing permissions"
chown -R root:nobody "$INSTALL_DIR" 2>/dev/null || chown -R root:root "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
chmod -R 700 "${INSTALL_DIR}/database"
chmod -R 700 "${INSTALL_DIR}/quarantine"
chmod -R 700 "${INSTALL_DIR}/logs"
ok "Permissions applied"

# ── Regenerate systemd service file (paths may have changed) ─────────────────
section "Updating systemd service"
SERVICE_FILE="/etc/systemd/system/sentinel-gate-monitor.service"
if [[ -f "$SERVICE_FILE" ]] && command -v systemctl >/dev/null 2>&1; then
    LOG_DIR="${INSTALL_DIR}/logs"
    cat > "$SERVICE_FILE" << SVCEOF
[Unit]
Description=Sentinel Gate Real-Time File Monitor
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
    systemctl start sentinel-gate-monitor 2>/dev/null \
        && ok "Monitor daemon restarted" \
        || warn "Monitor restart failed — check: journalctl -u sentinel-gate-monitor"
else
    info "Systemd service not installed — skipping"
fi

# ── Update version in DB so dashboard shows correct version immediately ───────
section "Finalising"
php -r "
define('SG_API', true);
require_once '${INSTALL_DIR}/backend/config/mode.php';
require_once '${INSTALL_DIR}/backend/lib/Database.php';
Database::setSetting('update_available', '0');
Database::setSetting('update_latest_ver', '${LATEST_VERSION}');
echo 'Update state cleared.' . PHP_EOL;
" 2>/dev/null || true

NEW_VERSION="$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null | tr -d '[:space:]')"
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
