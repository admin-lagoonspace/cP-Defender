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

# ── Config ────────────────────────────────────────────────────────────────────
INSTALL_DIR="${SG_ROOT:-/usr/local/sentinel-gate}"
GITHUB_REPO="admin-lagoonspace/cP-Defender"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
BACKUP_ROOT="/var/backups/sentinel-gate"
TMP_DIR="$(mktemp -d /tmp/sg-update.XXXXXX)"
AUTO_YES=false
FORCE_VERSION=""
FORCE_URL=""

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
    # ── Manual version override — skip API entirely ───────────────────────────
    info "Using forced version: ${BOLD}v${FORCE_VERSION}${NC} (--version flag)"
    LATEST_VERSION="$FORCE_VERSION"
    # Release asset URL pattern (built zip) and source archive fallback
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${LATEST_VERSION}/sentinel-gate-v${LATEST_VERSION}.zip"
    RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/tag/v${LATEST_VERSION}"

elif [[ -n "$FORCE_URL" ]]; then
    # ── Direct URL supplied — derive version from current install ─────────────
    info "Using direct download URL (--url flag)"
    LATEST_VERSION="${CURRENT_VERSION}-manual"
    DOWNLOAD_URL="$FORCE_URL"

else
    # ── Fetch latest release from GitHub API (with retries) ───────────────────
    info "Checking GitHub for latest release…"
    API_RETRIES=3
    API_WAIT=5
    RELEASE_JSON=""
    for attempt in $(seq 1 $API_RETRIES); do
        [[ $attempt -gt 1 ]] && { warn "Retrying in ${API_WAIT}s (attempt ${attempt}/${API_RETRIES})…"; sleep $API_WAIT; }
        CURL_ERR_FILE="${TMP_DIR}/curl_err.txt"
        if RELEASE_JSON="$(curl -fsSL --max-time 15 \
                -H 'Accept: application/vnd.github+json' \
                -H 'X-GitHub-Api-Version: 2022-11-28' \
                "$GITHUB_API" 2>"$CURL_ERR_FILE")"; then
            break
        else
            CURL_EXIT=$?
            CURL_ERR="$(cat "$CURL_ERR_FILE" 2>/dev/null)"
            warn "curl exit ${CURL_EXIT}: ${CURL_ERR}"
            RELEASE_JSON=""
        fi
    done

    if [[ -z "$RELEASE_JSON" ]]; then
        err "Cannot reach GitHub API after ${API_RETRIES} attempts."
        echo ""
        echo -e "  ${BOLD}Diagnostics:${NC}"
        info "Testing DNS for api.github.com…"
        if command -v host >/dev/null 2>&1; then
            host api.github.com 2>&1 | head -3 | while IFS= read -r l; do info "  $l"; done
        elif command -v nslookup >/dev/null 2>&1; then
            nslookup api.github.com 2>&1 | head -5 | while IFS= read -r l; do info "  $l"; done
        else
            info "  (no host/nslookup available)"
        fi
        info "Testing HTTPS to github.com…"
        curl -sk --max-time 5 -o /dev/null -w "  HTTP %{http_code} in %{time_total}s\n" \
            "https://github.com" 2>&1 || info "  (connection failed)"
        echo ""
        echo -e "  ${YELLOW}To update without GitHub API access, run:${NC}"
        echo -e "  ${BOLD}bash $0 --version 3.3.7${NC}"
        echo -e "  or download the zip manually and use:"
        echo -e "  ${BOLD}bash $0 --url https://your-mirror/sentinel-gate.zip${NC}"
        echo ""
        exit 1
    fi

    LATEST_VERSION="$(echo "$RELEASE_JSON" | grep -oP '"tag_name"\s*:\s*"\Kv?[^"]+' | head -1 | sed 's/^v//')"
    DOWNLOAD_URL="$(echo "$RELEASE_JSON"   | grep -oP '"browser_download_url"\s*:\s*"\K[^"]+\.zip' | head -1)"
    RELEASE_URL="$(echo "$RELEASE_JSON"    | grep -oP '"html_url"\s*:\s*"\Khttps://github\.com[^"]+/releases/tag[^"]+' | head -1)"

    [[ -z "$LATEST_VERSION" ]] && die "Could not parse latest version from GitHub API response."
fi

info "Latest version:  ${BOLD}v${LATEST_VERSION}${NC}"

# ── Already up to date? ───────────────────────────────────────────────────────
# Skip version comparison when forced via --version or --url flags
if [[ -z "$FORCE_VERSION" && -z "$FORCE_URL" ]]; then
    if [[ "$CURRENT_VERSION" == "$LATEST_VERSION" ]]; then
        ok "Already up to date — v${CURRENT_VERSION}"
        exit 0
    fi

    # Check if update is actually newer
    python3 -c "
import sys
def v(s): return tuple(int(x) for x in s.split('.'))
sys.exit(0 if v('$LATEST_VERSION') > v('$CURRENT_VERSION') else 1)
" 2>/dev/null || {
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

# 2nd attempt: GitHub source archive (works even when release assets are missing)
if [[ "$DOWNLOADED" == false ]] && [[ "$LATEST_VERSION" != *"-manual"* ]]; then
    SOURCE_URL="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${LATEST_VERSION}.zip"
    if _download "$SOURCE_URL" "$RELEASE_ZIP" "source archive"; then
        DOWNLOADED=true
    else
        warn "Source archive download also failed."
    fi
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
section "Running database migrations"
# Trigger a PHP call that initialises Database (runs all migrations/ALTER guards)
php -r "
define('SG_API', true);
require_once '${INSTALL_DIR}/backend/config/mode.php';
require_once '${INSTALL_DIR}/backend/lib/Database.php';
echo 'Database migrations applied.' . PHP_EOL;
" 2>&1 | while IFS= read -r line; do info "$line"; done

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
echo ""
info "If anything looks wrong, restore your backup:"
info "  cp -a ${BACKUP_DIR}/database ${INSTALL_DIR}/"
echo ""
