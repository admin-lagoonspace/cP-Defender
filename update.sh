#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Safe Update Script
# Downloads the latest release from GitHub, applies it over the current
# installation, and preserves ALL user data (database, settings, quarantine,
# logs, TLS certs, custom signatures).
#
# Usage:
#   bash /usr/local/sentinel-gate/update.sh
#   bash /usr/local/sentinel-gate/update.sh --yes        # non-interactive
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

[[ "${1:-}" == "--yes" ]] && AUTO_YES=true

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

# ── Detect current version ────────────────────────────────────────────────────
section "Version check"
CURRENT_VERSION="$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null | tr -d '[:space:]')"
[[ -z "$CURRENT_VERSION" ]] && CURRENT_VERSION="unknown"
info "Current version: ${BOLD}v${CURRENT_VERSION}${NC}"

# ── Fetch latest release from GitHub ─────────────────────────────────────────
info "Checking GitHub for latest release…"
RELEASE_JSON="$(curl -fsSL --max-time 15 \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "$GITHUB_API" 2>/dev/null)" \
    || die "Cannot reach GitHub API. Check network or try again."

LATEST_VERSION="$(echo "$RELEASE_JSON" | grep -oP '"tag_name"\s*:\s*"\Kv?[^"]+' | head -1 | sed 's/^v//')"
DOWNLOAD_URL="$(echo "$RELEASE_JSON"   | grep -oP '"browser_download_url"\s*:\s*"\K[^"]+\.zip' | head -1)"
RELEASE_URL="$(echo "$RELEASE_JSON"    | grep -oP '"html_url"\s*:\s*"\Khttps://github\.com[^"]+/releases/tag[^"]+' | head -1)"

[[ -z "$LATEST_VERSION" ]] && die "Could not parse latest version from GitHub API."

info "Latest version:  ${BOLD}v${LATEST_VERSION}${NC}"

# ── Already up to date? ───────────────────────────────────────────────────────
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
    warn "Latest GitHub release (v${LATEST_VERSION}) is not newer than current (v${CURRENT_VERSION}). Aborting."
    exit 0
}

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

if [[ -n "$DOWNLOAD_URL" ]]; then
    info "Downloading zip from release assets…"
    curl -fsSL --progress-bar --max-time 120 \
        -o "${TMP_DIR}/release.zip" \
        "$DOWNLOAD_URL" \
        || die "Download failed from: $DOWNLOAD_URL"
else
    # Fallback: download source zip from GitHub
    SOURCE_URL="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${LATEST_VERSION}.zip"
    info "No asset found — downloading source archive…"
    curl -fsSL --progress-bar --max-time 120 \
        -o "${TMP_DIR}/release.zip" \
        "$SOURCE_URL" \
        || die "Download failed from: $SOURCE_URL"
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
