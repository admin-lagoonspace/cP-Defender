#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Installer
# Version is read dynamically from the VERSION file in this directory.
# Supports: cPanel/WHM  |  Standalone Linux (any distro)
# Usage:    bash install.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -o pipefail
PLUGIN_NAME="sentinel-gate"
INSTALL_DIR="/usr/local/sentinel-gate"
CRON_FILE="/etc/cron.d/sentinel-gate"
LOG_DIR="${INSTALL_DIR}/logs"
SG_PORT=31150

# ── Arguments ───────────────────────────────────────────────────────────────────
# --register-only : re-run ONLY the WHM/cPanel (or standalone service) registration
#                   against an already-installed copy. Used by update.sh after it
#                   overlays new code, so plugin-registration fixes reach upgrades.
# --mode MODE     : force install mode (cpanel|standalone), skips the prompt.
# --admin-user U  : standalone admin username (default: admin)
# --admin-pass P  : standalone admin password. Supply this for unattended
#                   standalone installs, otherwise one is generated and printed.
#                   Prefer the SG_ADMIN_PASS env var — flags are visible in `ps`.
REGISTER_ONLY=false
INSTALL_MODE=""
SKIP_DEPS=false
ADMIN_USER=""
ADMIN_PASS=""
GENERATED_PASS=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --register-only) REGISTER_ONLY=true ;;
    --no-deps)       SKIP_DEPS=true ;;
    --mode)          shift; INSTALL_MODE="${1:-}" ;;
    --mode=*)        INSTALL_MODE="${1#--mode=}" ;;
    --admin-user)    shift; ADMIN_USER="${1:-}" ;;
    --admin-user=*)  ADMIN_USER="${1#--admin-user=}" ;;
    --admin-pass)    shift; ADMIN_PASS="${1:-}" ;;
    --admin-pass=*)  ADMIN_PASS="${1#--admin-pass=}" ;;
    *) ;;
  esac
  shift
done

# Auto-detect mode from a prior install so re-runs/upgrades never need the prompt
_MODE_PHP="${INSTALL_DIR}/backend/config/mode.php"
if [[ -z "$INSTALL_MODE" && -f "$_MODE_PHP" ]]; then
  if grep -q "INSTALL_MODE', 'standalone'" "$_MODE_PHP" 2>/dev/null; then
    INSTALL_MODE="standalone"
  elif grep -q "INSTALL_MODE', 'cpanel'" "$_MODE_PHP" 2>/dev/null; then
    INSTALL_MODE="cpanel"
  fi
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}${BOLD}── $* ──${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Read version from VERSION file ─────────────────────────────────────────────
VERSION_FILE="${SCRIPT_DIR}/VERSION"
if [[ -f "$VERSION_FILE" ]]; then
  SG_VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
else
  SG_VERSION="unknown"
fi

# ── Banner ─────────────────────────────────────────────────────────────────────
clear
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      "
echo "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║      "
echo "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      "
echo "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      "
echo "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ "
echo "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}SENTINEL GATE v${SG_VERSION}${NC} — Security Suite"
echo ""

# ── Pre-flight checks ──────────────────────────────────────────────────────────
section "Pre-flight checks"
[[ $EUID -ne 0 ]] && error "Must be run as root"

# ── Dependency bootstrap (best-effort, non-fatal) ─────────────────────────────
# Install missing runtime dependencies via the host package manager so a bare
# server reaches full capability instead of silently degrading. Skipped on
# --register-only and --no-deps. PHP is NOT auto-installed on cPanel hosts —
# cPanel manages its own PHP and a distro php would conflict.
if ! $REGISTER_ONLY && ! $SKIP_DEPS; then
  section "Dependency bootstrap"
  _PM=""; _INSTALL=""
  if   command -v apt-get >/dev/null 2>&1; then _PM=apt; _INSTALL="apt-get install -y -q"
  elif command -v dnf     >/dev/null 2>&1; then _PM=dnf; _INSTALL="dnf install -y -q"
  elif command -v yum     >/dev/null 2>&1; then _PM=yum; _INSTALL="yum install -y -q"
  fi
  if [[ -z "$_PM" ]]; then
    warn "No supported package manager (apt/dnf/yum) — skipping dependency bootstrap"
  else
    info "Package manager: ${_PM}"
    declare -a _PKGS=()
    command -v sqlite3   >/dev/null 2>&1 || _PKGS+=( sqlite3 )
    command -v python3   >/dev/null 2>&1 || _PKGS+=( python3 )
    command -v ipset     >/dev/null 2>&1 || _PKGS+=( ipset )
    if [[ "$_PM" == "apt" ]]; then
      command -v inotifywait >/dev/null 2>&1 || _PKGS+=( inotify-tools )
      dpkg -s python3-pip   >/dev/null 2>&1 || _PKGS+=( python3-pip )
    else
      rpm -q python3-pip    >/dev/null 2>&1 || _PKGS+=( python3-pip )
    fi
    # ClamAV — only if no clamscan anywhere (incl. cPanel's 3rdparty path)
    if ! command -v clamscan >/dev/null 2>&1 && [[ ! -x /usr/local/cpanel/3rdparty/bin/clamscan ]]; then
      if [[ "$_PM" == "apt" ]]; then _PKGS+=( clamav clamav-freshclam ); else _PKGS+=( clamav clamav-update ); fi
    fi
    # PHP + sqlite PDO — ONLY on non-cPanel servers
    if [[ ! -d /usr/local/cpanel ]]; then
      command -v php >/dev/null 2>&1 || _PKGS+=( php-cli )
      if [[ "$_PM" == "apt" ]]; then _PKGS+=( php-sqlite3 ); else _PKGS+=( php-pdo ); fi
    fi
    if [[ ${#_PKGS[@]} -eq 0 ]]; then
      ok "All runtime dependencies already present"
    else
      info "Installing: ${_PKGS[*]}"
      [[ "$_PM" == "apt" ]] && { apt-get update -q >/dev/null 2>&1 || true; }
      if $_INSTALL "${_PKGS[@]}" >/dev/null 2>&1; then
        ok "Dependencies installed: ${_PKGS[*]}"
      else
        warn "Some packages failed to install (${_PKGS[*]}) — continuing; features may degrade"
      fi
    fi
  fi
fi

command -v php >/dev/null 2>&1 || error "PHP not found. Install php-cli first."
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION;')
[[ $PHP_VER -lt 7 ]] && error "PHP 7.4+ required (found PHP $PHP_VER)"
ok "PHP $PHP_VER found"

# ── Pre-install cleanup ─────────────────────────────────────────────────────────
# Makes reinstalls clean: stops running services, refreshes code dirs so files
# deleted in newer versions don't linger, and sweeps legacy artifacts from old
# layouts. Data (database, logs, quarantine) is preserved on reinstall —
# uninstall.sh is the only thing that deletes data.
section "Pre-install cleanup"
if $REGISTER_ONLY; then
  info "Register-only mode — skipping cleanup, dirs, files, DB, services"
fi
if ! $REGISTER_ONLY && command -v systemctl >/dev/null 2>&1; then
  for _SVC in sentinel-gate-web sentinel-gate-monitor; do
    if systemctl is-active --quiet "${_SVC}" 2>/dev/null; then
      systemctl stop "${_SVC}" 2>/dev/null || true
      info "Stopped running service: ${_SVC}"
    fi
  done
fi
if ! $REGISTER_ONLY && [[ -d "${INSTALL_DIR}" ]]; then
  info "Existing installation detected — refreshing code, keeping data"
  for _OLD in "${INSTALL_DIR}/backend" "${INSTALL_DIR}/frontend"; do
    [[ -d "${_OLD}" ]] && rm -rf "${_OLD}" && info "Removed stale code dir: ${_OLD}"
  done
fi
# Legacy artifacts from pre-3.2 layouts — harmless to sweep when absent
for _LEGACY in \
  /usr/local/cpanel/whostmgr/docroot/cgi/addon_sentinel_gate.cgi \
  /usr/local/cpanel/whostmgr/docroot/cgi/addon_sentinelgate.cgi \
  /usr/local/cpanel/whostmgr/docroot/cgi/sentinel-gate \
  /usr/local/cpanel/whostmgr/docroot/cgi/addon_plugins/sentinel-gate.conf \
  /usr/local/cpanel/whostmgr/docroot/cgi/addon_plugins/sentinel_gate.conf \
  /var/cpanel/apps/sentinel-gate.conf; do
  [[ -e "${_LEGACY}" ]] && rm -rf "${_LEGACY}" && info "Removed legacy artifact: ${_LEGACY}"
done
ok "Pre-install cleanup complete"

# ── Mode selection ─────────────────────────────────────────────────────────────
section "Installation Mode"
if [[ -n "$INSTALL_MODE" ]]; then
  # Mode already known (--mode flag, --register-only, or detected from mode.php)
  info "Mode: ${BOLD}${INSTALL_MODE}${NC} (auto-detected)"
elif [[ ! -t 0 ]]; then
  # Non-interactive (piped) install with no prior mode. PROBE for cPanel rather
  # than assuming it — blindly defaulting to cpanel on a plain Linux box runs the
  # whole WHM registration path against nothing and leaves no working dashboard.
  if [[ -d /usr/local/cpanel ]]; then
    INSTALL_MODE="cpanel"
    info "Non-interactive — detected /usr/local/cpanel, mode: ${BOLD}cpanel${NC}"
  else
    INSTALL_MODE="standalone"
    info "Non-interactive — no cPanel found, mode: ${BOLD}standalone${NC}"
  fi
else
  echo ""
  echo -e "  ${BOLD}Select where you are installing Sentinel Gate:${NC}"
  echo ""
  echo -e "  ${CYAN}1)${NC} ${BOLD}cPanel / WHM Server${NC}"
  echo "     Integrates into WHM as a plugin. Uses cPanel authentication."
  echo "     Accessed via: WHM → Plugins → Sentinel Gate"
  echo ""
  echo -e "  ${CYAN}2)${NC} ${BOLD}Standalone Linux Server${NC} (no cPanel)"
  echo "     Self-contained browser dashboard on port ${SG_PORT}."
  echo "     Works on any Linux distro. No cPanel required."
  echo "     Accessed via: http://YOUR_SERVER_IP:${SG_PORT}"
  echo ""
  read -rp "  Enter choice [1/2]: " MODE_CHOICE
  case "$MODE_CHOICE" in
    2) INSTALL_MODE="standalone" ;;
    *) INSTALL_MODE="cpanel" ;;
  esac
  echo ""
  info "Mode: ${BOLD}${INSTALL_MODE}${NC}"
fi

# ═══ INSTALL-ONLY SECTIONS (skipped in --register-only mode) ═══════════════════
if ! $REGISTER_ONLY; then

# ── Standalone: collect admin credentials ──────────────────────────────────────
if [[ "$INSTALL_MODE" == "standalone" ]]; then
  section "Admin Account Setup"

  # Credentials may arrive as flags/env (piped installs) — otherwise prompt.
  ADMIN_USER="${ADMIN_USER:-${SG_ADMIN_USER:-}}"
  ADMIN_PASS="${ADMIN_PASS:-${SG_ADMIN_PASS:-}}"

  if [[ -n "$ADMIN_PASS" ]]; then
    ADMIN_USER="${ADMIN_USER:-admin}"
    [[ ${#ADMIN_PASS} -ge 8 ]] || error "Admin password must be at least 8 characters."
    ok "Admin account: ${ADMIN_USER} (supplied via flag/env)"

  elif [[ ! -t 0 ]]; then
    # Non-interactive with no password supplied. NEVER prompt here — `read` would
    # hit EOF on the pipe, leave ADMIN_PASS empty, and spin the length-check loop
    # forever. Generate a strong one and surface it at the end of the install.
    ADMIN_USER="${ADMIN_USER:-admin}"
    if command -v openssl >/dev/null 2>&1; then
      ADMIN_PASS="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)"
    else
      ADMIN_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
    fi
    GENERATED_PASS=true
    warn "Non-interactive install — generated a random admin password."
    warn "It is printed at the end of this install. Save it, then change it."

  else
    echo "  Create the local admin account for the web dashboard."
    echo ""
    read -rp "  Admin username [admin]: " _IN_USER
    ADMIN_USER="${_IN_USER:-admin}"

    while true; do
      read -srp "  Admin password (min 8 chars): " ADMIN_PASS; echo
      [[ ${#ADMIN_PASS} -ge 8 ]] && break
      echo -e "  ${RED}Password too short — minimum 8 characters.${NC}"
    done

    read -srp "  Confirm password: " ADMIN_PASS2; echo
    [[ "$ADMIN_PASS" != "$ADMIN_PASS2" ]] && error "Passwords do not match"
    ok "Admin account: ${ADMIN_USER}"
  fi
fi

# ── Create directories ─────────────────────────────────────────────────────────
section "Creating directories"
mkdir -p "$INSTALL_DIR"/{database,logs,quarantine,tmp}
chmod 750 "$INSTALL_DIR"/{database,quarantine,logs}
ok "Directories created under $INSTALL_DIR"

# ── Copy plugin files ──────────────────────────────────────────────────────────
section "Installing files"
cp -r "${SCRIPT_DIR}/backend"  "$INSTALL_DIR/"
cp -r "${SCRIPT_DIR}/frontend" "$INSTALL_DIR/"
cp    "${SCRIPT_DIR}/VERSION"  "$INSTALL_DIR/"
[[ -f "${SCRIPT_DIR}/install.sh"   ]] && cp "${SCRIPT_DIR}/install.sh"   "$INSTALL_DIR/"
[[ -f "${SCRIPT_DIR}/update.sh"   ]] && cp "${SCRIPT_DIR}/update.sh"   "$INSTALL_DIR/"
[[ -f "${SCRIPT_DIR}/uninstall.sh" ]] && cp "${SCRIPT_DIR}/uninstall.sh" "$INSTALL_DIR/"
# Keep whm/sentinel.conf version in sync with VERSION file
sed -i "s/\"version\":.*\"[0-9.]*\"/\"version\":     \"${SG_VERSION}\"/" "${SCRIPT_DIR}/whm/sentinel.conf" 2>/dev/null || true
# Keep SG_VERSION constant in config.php in sync with VERSION file
sed -i "s/define('SG_VERSION',  '[0-9.]*')/define('SG_VERSION',  '${SG_VERSION}')/" "${INSTALL_DIR}/backend/config/config.php" 2>/dev/null || true
ok "Files installed to $INSTALL_DIR"

# ── Set permissions ────────────────────────────────────────────────────────────
chown -R root:nobody "$INSTALL_DIR" 2>/dev/null || chown -R root:root "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
chmod -R 700 "$INSTALL_DIR/database"
chmod -R 700 "$INSTALL_DIR/quarantine"
chmod -R 700 "$INSTALL_DIR/logs"
chmod +x "$INSTALL_DIR/backend/cron/scan.php"
chmod +x "$INSTALL_DIR/backend/daemon/monitor.py"
[[ -f "$INSTALL_DIR/backend/cli/sentinel.php" ]] && chmod +x "$INSTALL_DIR/backend/cli/sentinel.php"
ok "Permissions set"

# ── Write mode.php ─────────────────────────────────────────────────────────────
cat > "${INSTALL_DIR}/backend/config/mode.php" << MODEPHP
<?php
// Written by install.sh — do not edit manually
define('INSTALL_MODE', '${INSTALL_MODE}');
define('SG_ROOT',      '${INSTALL_DIR}');
define('SG_VERSION',   '${SG_VERSION}');
MODEPHP
ok "Install mode recorded"

# ── Initialize database ────────────────────────────────────────────────────────
section "Initialising database"
php -r "
define('SG_ROOT', '$INSTALL_DIR');
define('SG_DB', '$INSTALL_DIR/database/sentinel.db');
define('SG_LOGS', '$INSTALL_DIR/logs');
define('SG_TMP', '/tmp/sentinel-gate');
define('CPANEL_BASE', '/usr/local/cpanel');
define('CPANEL_USER', 'root');
define('SCAN_MAX_SIZE', 52428800);
define('SIG_DIR', '$INSTALL_DIR/backend/signatures');
define('QUARANTINE_DIR', '$INSTALL_DIR/quarantine');
define('RBL_FEEDS', serialize([]));
define('JWT_SECRET', hash('sha256', gethostname() . 'sentinel_gate_secret_2024'));
define('JWT_EXPIRY', 28800);
define('INSTALL_MODE', '${INSTALL_MODE}');
define('SG_PORT', ${SG_PORT});
require_once '$INSTALL_DIR/backend/lib/Database.php';
\$db = Database::get();
Database::setSetting('install_mode', '${INSTALL_MODE}');
echo 'Database initialised' . PHP_EOL;
"
ok "SQLite database ready"

# ── Set standalone admin credentials ──────────────────────────────────────────
if [[ "$INSTALL_MODE" == "standalone" ]]; then
  PASS_HASH=$(php -r "echo password_hash('${ADMIN_PASS}', PASSWORD_BCRYPT, ['cost'=>12]);")
  php -r "
define('SG_ROOT', '$INSTALL_DIR');
define('SG_DB', '$INSTALL_DIR/database/sentinel.db');
define('SG_LOGS', '$INSTALL_DIR/logs');
define('SG_TMP', '/tmp/sentinel-gate');
define('CPANEL_BASE', '/usr/local/cpanel');
define('CPANEL_USER', 'root');
define('SCAN_MAX_SIZE', 52428800);
define('SIG_DIR', '$INSTALL_DIR/backend/signatures');
define('QUARANTINE_DIR', '$INSTALL_DIR/quarantine');
define('RBL_FEEDS', serialize([]));
define('JWT_SECRET', hash('sha256', gethostname() . 'sentinel_gate_secret_2024'));
define('JWT_EXPIRY', 28800);
define('INSTALL_MODE', 'standalone');
define('SG_PORT', ${SG_PORT});
require_once '$INSTALL_DIR/backend/lib/Database.php';
require_once '$INSTALL_DIR/backend/lib/Auth.php';
Auth::setLocalCredentials('${ADMIN_USER}', '${ADMIN_PASS}');
echo 'Admin credentials stored' . PHP_EOL;
"
  ok "Admin credentials stored (bcrypt)"
fi

# ── ClamAV detection and setup ────────────────────────────────────────────────
section "ClamAV setup"
# cPanel servers often install ClamAV outside the default PATH.
# Check all common locations before giving up.
CLAMSCAN_BIN=""
FRESHCLAM_BIN=""
for _BIN in \
  clamscan \
  /usr/bin/clamscan \
  /usr/local/bin/clamscan \
  /usr/local/cpanel/3rdparty/bin/clamscan \
  /opt/cpanel/ea-php*/root/usr/bin/clamscan \
  /opt/clamav/bin/clamscan; do
  # Expand globs, skip if not executable
  for _EXPANDED in $_BIN; do
    if [[ -x "${_EXPANDED}" ]] || command -v "${_EXPANDED}" >/dev/null 2>&1; then
      CLAMSCAN_BIN="${_EXPANDED}"; break 2
    fi
  done
done

for _BIN in \
  freshclam \
  /usr/bin/freshclam \
  /usr/local/bin/freshclam \
  /usr/local/cpanel/3rdparty/bin/freshclam \
  /opt/cpanel/ea-php*/root/usr/bin/freshclam \
  /opt/clamav/bin/freshclam; do
  for _EXPANDED in $_BIN; do
    if [[ -x "${_EXPANDED}" ]] || command -v "${_EXPANDED}" >/dev/null 2>&1; then
      FRESHCLAM_BIN="${_EXPANDED}"; break 2
    fi
  done
done

if [[ -n "${CLAMSCAN_BIN}" ]]; then
  ok "ClamAV found: ${CLAMSCAN_BIN}"
  # Record path so the scanner backend can use it directly
  php -r "
define('SG_ROOT','${INSTALL_DIR}');
define('SG_DB','${INSTALL_DIR}/database/sentinel.db');
define('SG_LOGS','${INSTALL_DIR}/logs');
define('SG_TMP','/tmp/sentinel-gate');
define('CPANEL_BASE','/usr/local/cpanel');
define('CPANEL_USER','root');
define('SCAN_MAX_SIZE',52428800);
define('SIG_DIR','${INSTALL_DIR}/backend/signatures');
define('QUARANTINE_DIR','${INSTALL_DIR}/quarantine');
define('RBL_FEEDS',serialize([]));
define('JWT_SECRET',hash('sha256',gethostname().'sentinel_gate_secret_2024'));
define('JWT_EXPIRY',28800);
define('INSTALL_MODE','${INSTALL_MODE}');
define('SG_PORT',${SG_PORT});
require_once '${INSTALL_DIR}/backend/lib/Database.php';
Database::setSetting('clamscan_path','${CLAMSCAN_BIN}');
echo 'ClamAV path stored' . PHP_EOL;
" 2>/dev/null || true
  if [[ -n "${FRESHCLAM_BIN}" ]]; then
    info "Updating ClamAV signatures via ${FRESHCLAM_BIN}…"
    "${FRESHCLAM_BIN}" --quiet 2>/dev/null && ok "ClamAV signatures updated" || warn "ClamAV signature update failed (non-critical, will retry via cron)"
  else
    warn "freshclam not found — signatures will not be auto-updated"
  fi
else
  warn "ClamAV not detected in any standard location."
  info "  Checked: /usr/bin, /usr/local/bin, /usr/local/cpanel/3rdparty/bin, /opt/clamav/bin"
  info "  Install on cPanel: yum install -y clamav clamav-update"
  info "  Install on Debian/Ubuntu: apt install -y clamav"
  info "  Pattern-based scanning will be used until ClamAV is installed."
fi

# ── Kernel tuning for the inotify monitor ─────────────────────────────────────
# monitor.py watches the filesystem via inotify. The default per-user watch
# limit (often 8192) is far too low for a busy hosting server — the monitor
# silently stops receiving events once it's exhausted. Raise it persistently.
section "Kernel tuning (inotify watch limit)"
SYSCTL_CONF="/etc/sysctl.d/60-sentinel-gate.conf"
cat > "${SYSCTL_CONF}" << SYSCTLEOF
# Sentinel Gate — raise inotify limits for the real-time file monitor
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 1024
SYSCTLEOF
chmod 644 "${SYSCTL_CONF}"
if command -v sysctl >/dev/null 2>&1; then
  sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1 && \
    ok "inotify limits raised (max_user_watches=1048576)" || \
    warn "sysctl reload failed — limits apply after next reboot"
else
  warn "sysctl not found — ${SYSCTL_CONF} written, applies after reboot"
fi

# ── Real-time monitor: Python dependency + systemd service ────────────────────
section "Real-time file monitor"
if ! command -v python3 >/dev/null 2>&1; then
  warn "Python 3 not found — real-time monitor unavailable"
else
  info "Installing inotify_simple…"
  if pip3 install inotify_simple --break-system-packages -q 2>/dev/null ||
     pip3 install inotify_simple -q 2>/dev/null; then
    ok "inotify_simple installed (kernel inotify engine active)"
  else
    warn "inotify_simple failed — monitor will use polling fallback"
  fi

  if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]]; then
    # Generate the service unit dynamically so paths match this installation
    cat > /etc/systemd/system/sentinel-gate-monitor.service << SVCEOF
[Unit]
Description=Sentinel Gate Real-Time File Monitor
After=network.target
Wants=network.target

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
    chmod 644 /etc/systemd/system/sentinel-gate-monitor.service
    systemctl daemon-reload
    systemctl enable sentinel-gate-monitor 2>/dev/null
    systemctl start  sentinel-gate-monitor 2>/dev/null && \
      ok "Real-time monitor started" || warn "Monitor start failed — check: journalctl -u sentinel-gate-monitor"
  else
    nohup python3 "${INSTALL_DIR}/backend/daemon/monitor.py" \
      >> "${LOG_DIR}/monitor.log" 2>&1 &
    echo $! > "${INSTALL_DIR}/monitor.pid"
    ok "Real-time monitor started (background PID: $(cat ${INSTALL_DIR}/monitor.pid))"
  fi
fi

# ── Cron jobs ──────────────────────────────────────────────────────────────────
section "Cron jobs"
cat > "${CRON_FILE}" << CRONEOF
# Sentinel Gate — scheduled tasks
MAILTO=""
# Hourly quick scan
0 * * * * root /usr/bin/php ${INSTALL_DIR}/backend/cron/scan.php quick >> ${LOG_DIR}/cron.log 2>&1
# Daily full scan at 2am
0 2 * * * root /usr/bin/php ${INSTALL_DIR}/backend/cron/scan.php full  >> ${LOG_DIR}/cron.log 2>&1
# Weekly signature update Sunday 1am
0 1 * * 0 root /usr/bin/php ${INSTALL_DIR}/backend/cron/scan.php update-sigs >> ${LOG_DIR}/cron.log 2>&1
# Daily update check at 8am
0 8 * * * root SG_ROOT=${INSTALL_DIR} /usr/bin/php ${INSTALL_DIR}/backend/cron/update-check.php >> ${LOG_DIR}/cron.log 2>&1
CRONEOF
chmod 644 "${CRON_FILE}"
ok "Cron jobs installed to ${CRON_FILE}"

# On SELinux-enforcing hosts (CloudLinux/RHEL) a freshly written /etc/cron.d
# file lacks the system_cron_spool_t context and crond will refuse to run it.
if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
  if command -v semanage >/dev/null 2>&1; then
    semanage fcontext -a -t system_cron_spool_t "${CRON_FILE}" 2>/dev/null || true
  fi
  command -v restorecon >/dev/null 2>&1 && restorecon -Fv "${CRON_FILE}" 2>/dev/null || true
  ok "SELinux context applied to ${CRON_FILE}"
fi

fi  # ═══ end INSTALL-ONLY SECTIONS ═══════════════════════════════════════════════

# ── Write install manifest (uninstaller reads this) ───────────────────────────
# MANIFEST is always defined (the cpanel block below appends to it). On a fresh
# install we (re)write the base keys; in --register-only we keep the existing one.
MANIFEST="${INSTALL_DIR}/install-manifest.env"
if ! $REGISTER_ONLY; then
  {
    echo "INSTALL_MODE=${INSTALL_MODE}"
    echo "INSTALL_VERSION=${SG_VERSION}"
    echo "INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "INSTALL_DIR=${INSTALL_DIR}"
    echo "CRON_FILE=${CRON_FILE}"
    echo "SOURCE_DIR=${SCRIPT_DIR}"
  } > "${MANIFEST}"
  info "Manifest started: ${MANIFEST}"
else
  info "Register-only — re-registering plugin against existing install"
fi

# ── Firewall & WAF integration (CSF/LFD + ModSecurity) ─────────────────────────
# These wire Sentinel Gate into the server's existing security stack. They are
# idempotent (guarded by grep) so they run safely on both fresh installs and
# --register-only upgrades. All entries are removed by uninstall.sh.
SG_ETC="/etc/sentinel-gate"
mkdir -p "${SG_ETC}"

# ── CSF / LFD (ConfigServer Firewall) ──
# Firewall.php already speaks `csf -a/-d` at runtime; here we register the
# persistent include files CSF reads on every restart, and exempt Sentinel
# Gate's own long-running root daemons from LFD process tracking so they are
# never flagged or killed.
section "CSF / LFD firewall integration"
if [[ -f /usr/sbin/csf ]]; then
  touch "${SG_ETC}/csf_allow.txt" "${SG_ETC}/csf_ignore.txt"
  chmod 600 "${SG_ETC}/csf_allow.txt" "${SG_ETC}/csf_ignore.txt"

  if [[ -f /etc/csf/csf.allow ]] && ! grep -q "sentinel-gate/csf_allow.txt" /etc/csf/csf.allow 2>/dev/null; then
    echo "Include ${SG_ETC}/csf_allow.txt" >> /etc/csf/csf.allow
    ok "Registered allow include in csf.allow"
  fi
  if [[ -f /etc/csf/csf.ignore ]] && ! grep -q "sentinel-gate/csf_ignore.txt" /etc/csf/csf.ignore 2>/dev/null; then
    echo "Include ${SG_ETC}/csf_ignore.txt" >> /etc/csf/csf.ignore
    ok "Registered ignore include in csf.ignore"
  fi
  if [[ -f /etc/csf/csf.pignore ]]; then
    grep -q "sentinel-gate/backend/daemon/monitor.py" /etc/csf/csf.pignore 2>/dev/null || \
      echo "cmd:.*sentinel-gate/backend/daemon/monitor.py" >> /etc/csf/csf.pignore
    grep -q "sentinel-gate/backend/standalone-router.php" /etc/csf/csf.pignore 2>/dev/null || \
      echo "cmd:.*sentinel-gate/backend/standalone-router.php" >> /etc/csf/csf.pignore
    ok "Exempted Sentinel Gate daemons in csf.pignore"
  fi

  # `csf -r` reloads csf AND lfd; fall back to a direct lfd restart if absent.
  if csf -r >/dev/null 2>&1; then
    ok "CSF reloaded (csf.allow/ignore/pignore active)"
  else
    systemctl restart lfd 2>/dev/null || service lfd restart 2>/dev/null || true
    ok "lfd restarted"
  fi
  {
    echo "CSF_ALLOW_INCLUDE=${SG_ETC}/csf_allow.txt"
    echo "CSF_IGNORE_INCLUDE=${SG_ETC}/csf_ignore.txt"
    echo "SG_ETC=${SG_ETC}"
  } >> "${MANIFEST}"
else
  info "CSF not installed — skipping CSF integration (firewalld/iptables fallback stays active)"
fi

# ── ModSecurity Apache hook ──
# WAF.php writes custom SecRules under the modsec vendor configs dir. Apache
# does not load that path automatically, so we add an explicit Include to the
# ModSecurity user config. The Apache restart at the end of install activates it.
section "ModSecurity WAF integration"
MODSEC_USER_CONF=""
for _MSC in \
  /etc/apache2/conf.d/modsec/modsec2.user.conf \
  /etc/apache2/conf.d/modsec2.user.conf \
  /usr/local/apache/conf/modsec2.user.conf \
  /etc/httpd/conf.d/mod_security.conf; do
  [[ -f "${_MSC}" ]] && { MODSEC_USER_CONF="${_MSC}"; break; }
done
if [[ -n "${MODSEC_USER_CONF}" ]]; then
  SG_MODSEC_DIR="/etc/apache2/conf.d/modsec_vendor_configs/sentinel-gate"
  SG_MODSEC_RULES="${SG_MODSEC_DIR}/custom_rules.conf"
  mkdir -p "${SG_MODSEC_DIR}"
  if [[ ! -f "${SG_MODSEC_RULES}" ]]; then
    cat > "${SG_MODSEC_RULES}" << 'MODRULEEOF'
# Sentinel Gate — custom ModSecurity rules (managed by the WAF module).
# Rules added from the dashboard are written here; Apache reload applies them.
MODRULEEOF
    chmod 644 "${SG_MODSEC_RULES}"
  fi
  if ! grep -q "sentinel-gate/custom_rules.conf" "${MODSEC_USER_CONF}" 2>/dev/null; then
    {
      echo ""
      echo "# Sentinel Gate WAF rules"
      echo "Include ${SG_MODSEC_RULES}"
    } >> "${MODSEC_USER_CONF}"
    ok "Registered WAF Include in ${MODSEC_USER_CONF}"
  else
    info "WAF Include already present in ${MODSEC_USER_CONF}"
  fi
  {
    echo "MODSEC_USER_CONF=${MODSEC_USER_CONF}"
    echo "SG_MODSEC_DIR=${SG_MODSEC_DIR}"
  } >> "${MANIFEST}"
else
  info "ModSecurity user config not found — skipping WAF Apache hook (WAF stays app-level)"
fi

# ── CLI entrypoint (`sentinel` command) ───────────────────────────────────────
# Thin bash wrapper in /usr/bin so admins get a `sentinel` command (parity with
# CPGuard's cpgcli). Placed here (not the install-only block) so upgrades run via
# --register-only pick it up too. Points at the installed CLI, not the source.
section "CLI entrypoint"
if [[ -f "${INSTALL_DIR}/backend/cli/sentinel.php" ]]; then
  _PHP_BIN="$(command -v php 2>/dev/null || echo /usr/bin/php)"
  cat > /usr/bin/sentinel << CLIEOF
#!/usr/bin/env bash
# Sentinel Gate CLI — installed by install.sh (do not edit)
exec ${_PHP_BIN} ${INSTALL_DIR}/backend/cli/sentinel.php "\$@"
CLIEOF
  chmod 755 /usr/bin/sentinel
  ok "CLI installed: /usr/bin/sentinel (run: sentinel help)"
  grep -q "^SG_CLI=" "${MANIFEST}" 2>/dev/null || echo "SG_CLI=/usr/bin/sentinel" >> "${MANIFEST}"
else
  info "CLI script not present in install dir — skipping /usr/bin/sentinel"
fi

# ── Mode-specific setup ────────────────────────────────────────────────────────
if [[ "$INSTALL_MODE" == "standalone" ]]; then

  section "Standalone web server (port ${SG_PORT})"

  # ── Open port in firewall ──
  info "Opening port ${SG_PORT}/tcp in firewall…"
  if command -v firewall-cmd >/dev/null 2>&1; then
    info "  Firewall manager: firewall-cmd"
    if firewall-cmd --permanent --add-port=${SG_PORT}/tcp 2>&1 && \
       firewall-cmd --reload 2>&1; then
      ok "Port ${SG_PORT} opened in firewalld"
      echo "FIREWALL_TOOL=firewalld" >> "${MANIFEST}"
    else
      warn "firewall-cmd failed — open port ${SG_PORT}/tcp manually"
    fi
  elif command -v iptables >/dev/null 2>&1; then
    info "  Firewall manager: iptables"
    iptables -C INPUT -p tcp --dport ${SG_PORT} -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -p tcp --dport ${SG_PORT} -j ACCEPT
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    ok "Port ${SG_PORT} opened in iptables"
    echo "FIREWALL_TOOL=iptables" >> "${MANIFEST}"
  else
    warn "No firewall manager found — open port ${SG_PORT}/tcp manually"
  fi

  # ── Systemd web service ──
  WEB_SVC=""
  if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]]; then
    WEB_SVC="/etc/systemd/system/sentinel-gate-web.service"
    info "Installing systemd service: ${WEB_SVC}"
    cp "${SCRIPT_DIR}/whm/sentinel-gate-web.service" "${WEB_SVC}"
    chmod 644 "${WEB_SVC}"
    systemctl daemon-reload
    systemctl enable sentinel-gate-web 2>&1 | sed 's/^/  /'
    if systemctl start sentinel-gate-web 2>&1; then
      ok "Service started: sentinel-gate-web"
      systemctl status sentinel-gate-web --no-pager -l 2>&1 | head -6 | sed 's/^/  /'
    else
      warn "Service start failed — check: journalctl -u sentinel-gate-web -n 20"
    fi
    echo "WEB_SERVICE=${WEB_SVC}" >> "${MANIFEST}"
  else
    info "  systemd not available — starting PHP server in background"
    nohup /usr/bin/php -S 0.0.0.0:${SG_PORT} \
      "${INSTALL_DIR}/backend/standalone-router.php" \
      >> "${LOG_DIR}/web.log" 2>&1 &
    echo $! > "${INSTALL_DIR}/web.pid"
    ok "Web server started (PID: $(cat ${INSTALL_DIR}/web.pid))"
    echo "WEB_PID_FILE=${INSTALL_DIR}/web.pid" >> "${MANIFEST}"
  fi

elif [[ "$INSTALL_MODE" == "cpanel" ]]; then

  section "cPanel / WHM Plugin Registration"

  # ── Detect Apache config directory ──
  info "Detecting Apache config directory…"
  info "  Checking /etc/apache2/conf.d …"
  if [[ -d /etc/apache2/conf.d ]]; then
    APACHE_CONF_D="/etc/apache2/conf.d"
    info "  Found: /etc/apache2/conf.d"
  else
    info "  Checking /usr/local/apache/conf/includes …"
    if [[ -d /usr/local/apache/conf/includes ]]; then
      APACHE_CONF_D="/usr/local/apache/conf/includes"
      info "  Found: /usr/local/apache/conf/includes"
    else
      info "  Checking /etc/httpd/conf.d …"
      if [[ -d /etc/httpd/conf.d ]]; then
        APACHE_CONF_D="/etc/httpd/conf.d"
        info "  Found: /etc/httpd/conf.d"
      else
        APACHE_CONF_D="/etc/apache2/conf.d"
        info "  None found — creating ${APACHE_CONF_D}"
        mkdir -p "$APACHE_CONF_D"
      fi
    fi
  fi
  ok "Apache config dir: ${APACHE_CONF_D}"

  # ── Detect PHP handler for this server ────────────────────────────────────
  # EasyApache 4 (cPanel): handler is per-EA4 PHP version, e.g. ea-php81
  # Standard mod_php / other: application/x-httpd-php
  PHP_HANDLER="application/x-httpd-php"
  if [[ -d /opt/cpanel ]]; then
    _PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION . PHP_MINOR_VERSION;' 2>/dev/null)
    if [[ -n "$_PHP_VER" ]]; then
      PHP_HANDLER="application/x-httpd-ea-php${_PHP_VER}"
      info "Detected EasyApache 4 PHP handler: ${PHP_HANDLER}"
    fi
  else
    # Non-cPanel: try to find the handler from existing Apache config
    _H=$(grep -r "SetHandler.*php\|AddHandler.*php" /etc/apache2/ /etc/httpd/ 2>/dev/null \
         | grep -oP 'application/x-httpd-php\S*' | head -1)
    [[ -n "$_H" ]] && PHP_HANDLER="$_H"
    info "PHP handler: ${PHP_HANDLER}"
  fi

  # ── Write Apache alias config ──
  APACHE_CONF="${APACHE_CONF_D}/sentinel-gate.conf"
  info "Writing Apache alias config: ${APACHE_CONF}"
  cat > "${APACHE_CONF}" << APACHEEOF
# Sentinel Gate v${SG_VERSION} — Apache aliases
# API alias MUST come before the root alias (more-specific path first)
<IfModule mod_alias.c>
  Alias /sentinel-gate/backend/api ${INSTALL_DIR}/backend/api
  Alias /sentinel-gate             ${INSTALL_DIR}/frontend
</IfModule>

<Directory "${INSTALL_DIR}/backend/api">
  Options -Indexes -MultiViews
  AllowOverride FileInfo
  Require all granted
  DirectoryIndex index.php
  <FilesMatch "\.php$">
    SetHandler ${PHP_HANDLER}
  </FilesMatch>
  <IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [QSA,L]
  </IfModule>
</Directory>

<Directory "${INSTALL_DIR}/backend">
  Options -Indexes
  AllowOverride None
  Require all denied
</Directory>

<Directory "${INSTALL_DIR}/frontend">
  Options -Indexes
  AllowOverride None
  Require all granted
  DirectoryIndex index.html
</Directory>
APACHEEOF

  if [[ -f "${APACHE_CONF}" ]]; then
    ok "Apache config written: ${APACHE_CONF} ($(wc -c < "${APACHE_CONF}") bytes)"
    echo "APACHE_CONF=${APACHE_CONF}" >> "${MANIFEST}"
  else
    warn "Apache config write FAILED: ${APACHE_CONF}"
  fi

  # ── Register plugin via AppConfig ────────────────────────────────────────────
  # Follows the exact same pattern as ConfigServer Security & Firewall (CSF),
  # the most widely deployed WHM plugin. Key facts from CSF's installer:
  #   1. CGI + conf live in a named subdirectory of cgi docroot
  #   2. register_appconfig copies the conf to /var/cpanel/apps/ AND restarts cpsrvd
  #   3. No manual cpsrvd restart is needed — register_appconfig handles it
  #   4. Invalid AppConfig fields (like icon=plugin) cause silent rejection
  info "Registering Sentinel Gate with cPanel AppConfig system…"
  if [[ ! -d /usr/local/cpanel ]]; then
    warn "/usr/local/cpanel not found — skipping cPanel registration"
  else
    ok "cPanel found"
    SERVER_HOST=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")
    info "  Server hostname: ${SERVER_HOST}"

    # ── Step 1: Create named CGI subdirectory in WHM docroot ─────────────────
    # CSF uses:  /usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf/
    # We follow: /usr/local/cpanel/whostmgr/docroot/cgi/sentinel_gate/
    WHM_CGI_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/sentinel_gate"
    WHM_CGI="${WHM_CGI_DIR}/sentinel_gate.cgi"
    WHM_PLUGIN_CONF="${WHM_CGI_DIR}/sentinel_gate.conf"
    mkdir -p "${WHM_CGI_DIR}"
    info "  WHM CGI dir: ${WHM_CGI_DIR}"

    # ── Step 2: Write the CGI script ──────────────────────────────────────────
    # Opens the Apache-hosted Sentinel Gate frontend in a new browser tab.
    # The AppConfig conf sets target=_blank so WHM triggers a new tab; the CGI
    # then redirects it to the correct URL.
    # cpsrvd does NOT use the system PATH for CGI — must use absolute Perl path.
    _CPANEL_PERL="/usr/local/cpanel/3rdparty/bin/perl"
    [[ ! -x "${_CPANEL_PERL}" ]] && _CPANEL_PERL=$(command -v perl 2>/dev/null || echo "/usr/bin/perl")
    info "  Perl interpreter for CGI: ${_CPANEL_PERL}"

    info "  Writing CGI: ${WHM_CGI}"
    cat > "${WHM_CGI}" << ENDCGI
#!${_CPANEL_PERL}
use strict;
use warnings;
my \$host = \$ENV{HTTP_HOST} || \$ENV{SERVER_NAME} || '';
unless (\$host) {
    \$host = \`hostname -f 2>/dev/null\`; chomp \$host;
    \$host ||= \`hostname 2>/dev/null\`;  chomp \$host;
    \$host ||= 'localhost';
}
\$host =~ s/:.*//;
my \$url = "https://\$host/sentinel-gate/";
print "Content-Type: text/html\r\n\r\n";
print <<"ENDHTML";
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=\$url">
  <title>Sentinel Gate</title>
  <style>body{background:#020617;color:#e2e8f0;font-family:system-ui,sans-serif;
    display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
    .b{text-align:center} a{color:#38bdf8;text-decoration:none}</style>
</head>
<body><div class="b">
  <div style="font-size:2rem;margin-bottom:12px">&#x1F6E1;</div>
  <h2 style="margin-bottom:8px">Sentinel Gate Security</h2>
  <p style="color:#94a3b8;font-size:.9rem">Opening dashboard&hellip;</p>
  <p style="margin-top:14px;font-size:.8rem"><a href="\$url">Click here if not redirected</a></p>
</div>
<script>window.location.href='\$url';</script>
</body></html>
ENDHTML
ENDCGI
    chmod 755 "${WHM_CGI}"
    if [[ -f "${WHM_CGI}" ]]; then
      ok "  CGI written and executable: ${WHM_CGI}"
      echo "WHM_CGI=${WHM_CGI}" >> "${MANIFEST}"
    else
      warn "  CGI write FAILED: ${WHM_CGI}"
    fi

    # ── Step 3: Write AppConfig conf file ALONGSIDE the CGI ──────────────────
    # Fields follow CSF's exact format (the reference implementation):
    #   url      = path registered with AppConfig (cgi/ prefix required)
    #   entryurl = clickable link shown in WHM nav (relative to cgi/, no prefix)
    #   acls     = all — root + all resellers with the 'all' ACL can access
    # No target= field: WHM opens the plugin in the main content area (embedded),
    # matching how CSF, CPGuard, and MagicSpam appear in WHM.
    # acls=any — visible to ALL authenticated WHM users: root AND every reseller.
    # (acls=all means only users with the 'all' ACL i.e. root + superadmin
    #  resellers; acls=any means every reseller regardless of their ACL set.)
    # target=_blank — opens the plugin in a new browser tab (not embedded in WHM).
    # Do NOT include 'icon=...' unless you have an actual installed icon file.
    # ── Install the plugin icon into WHM's addon_plugins directory ───────────
    # WHM renders the icon referenced by the AppConfig `icon=` field from
    # whostmgr/docroot/addon_plugins/. Without it the plugin shows a blank tile.
    ADDON_PLUGINS_DIR="/usr/local/cpanel/whostmgr/docroot/addon_plugins"
    SG_ICON_SRC="${SCRIPT_DIR}/whm/sentinel_gate.png"
    SG_ICON_DEST="${ADDON_PLUGINS_DIR}/sentinel_gate.png"
    if [[ -f "${SG_ICON_SRC}" && -d "${ADDON_PLUGINS_DIR}" ]]; then
      cp -f "${SG_ICON_SRC}" "${SG_ICON_DEST}"
      chmod 644 "${SG_ICON_DEST}"
      ok "  Plugin icon installed: ${SG_ICON_DEST}"
      echo "WHM_ICON=${SG_ICON_DEST}" >> "${MANIFEST}"
    else
      warn "  Icon source or addon_plugins dir missing — plugin will show no icon"
    fi

    info "  Writing AppConfig conf: ${WHM_PLUGIN_CONF}"
    # Remove any stale /var/cpanel/apps/ copy first so register_appconfig writes fresh
    rm -f /var/cpanel/apps/sentinel_gate.conf 2>/dev/null || true
    cat > "${WHM_PLUGIN_CONF}" << APPEOF
name=sentinel_gate
service=whostmgr
url=/cgi/sentinel_gate/sentinel_gate.cgi
entryurl=sentinel_gate/sentinel_gate.cgi
acls=any
displayname=Sentinel Gate Security
icon=sentinel_gate.png
target=_blank
APPEOF
    chmod 644 "${WHM_PLUGIN_CONF}"
    if [[ -f "${WHM_PLUGIN_CONF}" ]]; then
      ok "  AppConfig conf written: ${WHM_PLUGIN_CONF}"
      info "  Contents: $(tr '\n' ' ' < "${WHM_PLUGIN_CONF}")"
      echo "WHM_PLUGIN_CONF=${WHM_PLUGIN_CONF}" >> "${MANIFEST}"
    else
      warn "  AppConfig conf write FAILED: ${WHM_PLUGIN_CONF}"
    fi

    # ── Step 4: Install Driver files and touch directory ─────────────────────
    # CSF installs Driver files and touches the directory BEFORE calling
    # register_appconfig. The touch updates the directory mtime which signals
    # cpsrvd to rescan and fully load new AppConfig entries into the WHM nav.
    # Without this step the plugin conf may be registered but not shown in nav.
    DRIVER_DEST="/usr/local/cpanel/Cpanel/Config/ConfigObj/Driver"
    DRIVER_SRC="${SCRIPT_DIR}/whm/Driver"
    if [[ -d "${DRIVER_DEST}" && -d "${DRIVER_SRC}" ]]; then
      info "  Installing Driver files to ${DRIVER_DEST}…"
      cp -af "${DRIVER_SRC}/SentinelGate.pm" "${DRIVER_DEST}/"
      mkdir -p "${DRIVER_DEST}/SentinelGate"
      cp -af "${DRIVER_SRC}/SentinelGate/META.pm" "${DRIVER_DEST}/SentinelGate/"
      touch "${DRIVER_DEST}"
      ok "  Driver files installed; directory mtime updated"
      echo "DRIVER_DEST=${DRIVER_DEST}" >> "${MANIFEST}"
    else
      warn "  Driver destination not found (${DRIVER_DEST}) — skipping Driver install"
    fi

    # ── Step 5: Register with AppConfig (exactly as CSF does it) ─────────────
    # register_appconfig:
    #   • Reads conf from the path given
    #   • Copies it to /var/cpanel/apps/<name>.conf
    #   • Restarts cpsrvd automatically
    # We pass the path in the CGI docroot (not /var/cpanel/apps/) —
    # this is the documented, CSF-proven approach.
    info "  Running register_appconfig ${WHM_PLUGIN_CONF}…"
    _REG_OK=false
    if [[ -x /usr/local/cpanel/bin/register_appconfig ]]; then
      _REG_OUT=$(/usr/local/cpanel/bin/register_appconfig "${WHM_PLUGIN_CONF}" 2>&1)
      _REG_EXIT=$?
      echo "${_REG_OUT}" | sed 's/^/    /'
      if [[ $_REG_EXIT -eq 0 ]]; then
        ok "  register_appconfig succeeded"
        _REG_OK=true
        # Verify it landed in /var/cpanel/apps/
        if [[ -f /var/cpanel/apps/sentinel_gate.conf ]]; then
          ok "  Confirmed deployed to /var/cpanel/apps/sentinel_gate.conf"
          echo "APPCONFIG_CONF=/var/cpanel/apps/sentinel_gate.conf" >> "${MANIFEST}"
        fi
      else
        warn "  register_appconfig exited ${_REG_EXIT} — trying --all rescan…"
        /usr/local/cpanel/bin/register_appconfig --all 2>&1 | sed 's/^/    /'
        [[ $? -eq 0 ]] && _REG_OK=true
      fi
    else
      warn "  register_appconfig not found — manually restarting cpsrvd to pick up conf…"
      # Fallback: copy conf directly and restart
      cp -f "${WHM_PLUGIN_CONF}" /var/cpanel/apps/sentinel_gate.conf 2>/dev/null || true
      echo "APPCONFIG_CONF=/var/cpanel/apps/sentinel_gate.conf" >> "${MANIFEST}"
    fi

    # ── Step 6: cPanel user-level plugin (per-account cPanel dashboard) ─────
    # Each cPanel account holder sees a "Sentinel Gate" icon in their dashboard.
    # Clicking it opens the Sentinel Gate dashboard in a new tab.
    # Registered via:
    #   a) install_plugin (modern, 11.44+) — processes install.json
    #   b) dynamicui .conf (legacy fallback) — direct conf file
    #   c) service=cpanel AppConfig entry — security integration
    info "  Installing cPanel user-level plugin…"
    for CPANEL_THEME in paper_lantern jupiter; do
      CPANEL_THEME_BASE="/usr/local/cpanel/base/frontend/${CPANEL_THEME}"
      [[ ! -d "${CPANEL_THEME_BASE}" ]] && { info "  Theme not found: ${CPANEL_THEME} — skip"; continue; }

      # Create plugin directory and PHP redirect page
      CPANEL_PLUGIN_DIR="${CPANEL_THEME_BASE}/sentinel_gate"
      mkdir -p "${CPANEL_PLUGIN_DIR}"
      # Use single-quoted heredoc: bash does NOT expand $variables inside
      cat > "${CPANEL_PLUGIN_DIR}/index.php" << 'PHPEOF'
<?php
// Sentinel Gate — cPanel user entry point (auto-redirect to dashboard)
$host = $_SERVER['HTTP_HOST'] ?? '';
$host = preg_replace('/:[0-9]+$/', '', $host); // strip port number
if (!$host) $host = gethostname();
header('Location: https://' . $host . '/sentinel-gate/');
exit;
PHPEOF
      chmod 644 "${CPANEL_PLUGIN_DIR}/index.php"

      # install.json for the modern install_plugin mechanism (cPanel 11.44+)
      cat > "${CPANEL_PLUGIN_DIR}/install.json" << JSONEOF
[
  {
    "id":       "sentinel_gate",
    "type":     "link",
    "name":     "Sentinel Gate",
    "order":    100,
    "group_id": "security",
    "uri":      "/frontend/${CPANEL_THEME}/sentinel_gate/index.php",
    "feature":  "sentinel_gate"
  }
]
JSONEOF
      chmod 644 "${CPANEL_PLUGIN_DIR}/install.json"

      # Run install_plugin if the binary exists (modern method)
      if [[ -x /usr/local/cpanel/scripts/install_plugin ]]; then
        _INS_OUT=$(/usr/local/cpanel/scripts/install_plugin \
          "${CPANEL_PLUGIN_DIR}" --theme "${CPANEL_THEME}" 2>&1)
        _INS_EXIT=$?
        echo "${_INS_OUT}" | sed 's/^/    /'
        if [[ ${_INS_EXIT} -eq 0 ]]; then
          ok "  install_plugin: ${CPANEL_THEME}"
        else
          warn "  install_plugin failed for ${CPANEL_THEME} — dynamicui fallback active"
        fi
      else
        info "  install_plugin not found — using dynamicui conf only"
      fi

      # Legacy dynamicui conf (works on all cPanel versions, parallel to install_plugin)
      DYNUI_DIR="${CPANEL_THEME_BASE}/dynamicui"
      if [[ -d "${DYNUI_DIR}" ]]; then
        DYNUI_CONF="${DYNUI_DIR}/dynamicui_sentinel_gate.conf"
        cat > "${DYNUI_CONF}" << DYNEOF
group=security
groupdesc=Security
grouporder=30
name=sentinel_gate
itemdesc=Sentinel Gate Security
feature=sentinel_gate
url=/frontend/${CPANEL_THEME}/sentinel_gate/index.php
target=_blank
itemorder=1
DYNEOF
        chmod 644 "${DYNUI_CONF}"
        ok "  DynamicUI conf: ${DYNUI_CONF}"
        echo "DYNUI_${CPANEL_THEME}=${DYNUI_CONF}" >> "${MANIFEST}"
      fi
      echo "CPANEL_PLUGIN_${CPANEL_THEME}=${CPANEL_PLUGIN_DIR}" >> "${MANIFEST}"
    done

    # cPanel-level AppConfig entry (service=cpanel) — integrates with cPanel security framework
    # features=any means ALL cPanel users see it regardless of their feature list
    CPANEL_APPCONF="${WHM_CGI_DIR}/sentinel_gate_cpanel.conf"
    rm -f /var/cpanel/apps/sentinel_gate_cpanel.conf 2>/dev/null || true
    cat > "${CPANEL_APPCONF}" << CPANELEOF
name=sentinel_gate_cpanel
service=cpanel
url=/frontend/jupiter/sentinel_gate/index.php
features=any
displayname=Sentinel Gate Security
CPANELEOF
    chmod 644 "${CPANEL_APPCONF}"
    if [[ -x /usr/local/cpanel/bin/register_appconfig ]]; then
      _CREG_OUT=$(/usr/local/cpanel/bin/register_appconfig "${CPANEL_APPCONF}" 2>&1)
      echo "${_CREG_OUT}" | sed 's/^/    /'
      ok "  cPanel AppConfig registered (service=cpanel, features=any)"
      [[ -f /var/cpanel/apps/sentinel_gate_cpanel.conf ]] && \
        echo "CPANEL_APPCONFIG=/var/cpanel/apps/sentinel_gate_cpanel.conf" >> "${MANIFEST}"
    fi

    # ── Step 7: Feature flags — enable Sentinel Gate for all cPanel users ─────
    # Feature flags control which icons appear in a cPanel user's dashboard.
    # Adding sentinel_gate=1 to the 'default' feature list means it's ON for
    # every account unless an admin or reseller explicitly disables it.
    info "  Writing feature flags…"
    # Modern location (cPanel 11.44+ / CENTOS 7+ — the authoritative path)
    mkdir -p /var/cpanel/features
    grep -q "^sentinel_gate=" /var/cpanel/features/default 2>/dev/null || \
      echo "sentinel_gate=1" >> /var/cpanel/features/default
    ok "  Feature flag: /var/cpanel/features/default"
    echo "FEATURE_FLAG_MODERN=/var/cpanel/features/default" >> "${MANIFEST}"
    # Legacy location (older cPanel — kept for compatibility)
    _LEGACY_FEAT="/usr/local/cpanel/cpanel/features"
    if [[ -d "${_LEGACY_FEAT}" ]]; then
      grep -q "^sentinel_gate=" "${_LEGACY_FEAT}/default" 2>/dev/null || \
        echo "sentinel_gate=1" >> "${_LEGACY_FEAT}/default"
      ok "  Feature flag (legacy): ${_LEGACY_FEAT}/default"
      echo "FEATURE_FLAG_LEGACY=${_LEGACY_FEAT}/default" >> "${MANIFEST}"
    fi

    # ── Step 8: Restart cpsrvd if register_appconfig didn't already do it ────
    # register_appconfig normally handles this, but we restart explicitly as a
    # safety net in case the binary was missing or the conf was copied manually.
    if ! $_REG_OK; then
      info "  Manually restarting cpsrvd (register_appconfig fallback)…"
      if [[ -x /usr/local/cpanel/scripts/restartsrv_cpsrvd ]]; then
        /usr/local/cpanel/scripts/restartsrv_cpsrvd 2>&1 | tail -4 | sed 's/^/    /'
        ok "  cpsrvd restarted"
      fi
    fi

    # ── Step 9: Post-registration verification ────────────────────────────────
    info "  Verifying plugin registration (give cpsrvd 3s to settle)…"
    sleep 3
    _VERIFIED=false
    if command -v whmapi1 >/dev/null 2>&1; then
      _APP_LIST=$(whmapi1 appconfig_get_apps 2>/dev/null)
      if echo "${_APP_LIST}" | grep -q "sentinel_gate"; then
        ok "  VERIFIED via whmapi1: Sentinel Gate is live in WHM Plugins menu"
        _VERIFIED=true
      else
        warn "  whmapi1 does not yet list sentinel_gate"
        warn "  If plugin is not visible in WHM → Plugins, try: Log out and log back in to WHM"
      fi
    fi
    if ! $_VERIFIED && [[ -f /var/cpanel/apps/sentinel_gate.conf ]]; then
      ok "  /var/cpanel/apps/sentinel_gate.conf exists — plugin should appear after WHM re-login"
      _VERIFIED=true
    fi
    $_VERIFIED || warn "  Registration could not be verified — check WHM manually"

  fi  # end: if [[ ! -d /usr/local/cpanel ]]

fi  # end: if standalone / elif cpanel

# ── Apache restart (cpanel mode) ─────────────────────────────────────────────
if [[ "$INSTALL_MODE" == "cpanel" ]]; then
  section "Restarting Apache"
  if command -v /scripts/restartsrv_httpd >/dev/null 2>&1; then
    /scripts/restartsrv_httpd 2>&1 | tail -4 | sed 's/^/  /'
    ok "Apache restarted"
  elif command -v httpd >/dev/null 2>&1; then
    httpd -t 2>&1 && systemctl restart httpd 2>&1 && ok "Apache restarted" || warn "Apache restart failed — restart manually"
  elif command -v apache2 >/dev/null 2>&1; then
    apache2ctl -t 2>&1 && systemctl restart apache2 2>&1 && ok "Apache restarted" || warn "Apache restart failed — restart manually"
  else
    warn "Could not detect Apache — restart it manually to activate the config"
  fi
fi

# ── Post-install test suite ───────────────────────────────────────────────────
section "Post-install verification"

TEST_SCRIPT="${SCRIPT_DIR}/test.sh"
TEST_EXIT=0

if [[ -f "$TEST_SCRIPT" ]]; then
  # Give Apache/cpsrvd a moment to fully apply the new config
  info "Waiting 10 seconds for services to settle…"
  sleep 10
  echo ""
  bash "$TEST_SCRIPT"
  TEST_EXIT=$?
else
  warn "test.sh not found in ${SCRIPT_DIR} — skipping verification"
fi

# ── Outcome ───────────────────────────────────────────────────────────────────
echo ""
if [[ $TEST_EXIT -eq 0 ]]; then
  echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}${BOLD}  Sentinel Gate v${SG_VERSION} installed successfully!${NC}"
  echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"
  echo ""

  if [[ "$INSTALL_MODE" == "cpanel" ]]; then
    echo -e "  ${BOLD}Access:${NC}  WHM → Plugins → Sentinel Gate Security"
    echo -e "  ${BOLD}Also:${NC}    https://$(hostname -f 2>/dev/null || hostname)/sentinel-gate/"
  elif [[ "$INSTALL_MODE" == "standalone" ]]; then
    echo -e "  ${BOLD}Access:${NC}  http://$(hostname -f 2>/dev/null || hostname):${SG_PORT}"
    if $GENERATED_PASS; then
      echo ""
      echo -e "  ${YELLOW}${BOLD}┌─ GENERATED ADMIN PASSWORD — SAVE THIS NOW ─────────────┐${NC}"
      echo -e "  ${YELLOW}${BOLD}│${NC}  Username:  ${BOLD}${ADMIN_USER}${NC}"
      echo -e "  ${YELLOW}${BOLD}│${NC}  Password:  ${BOLD}${ADMIN_PASS}${NC}"
      echo -e "  ${YELLOW}${BOLD}└────────────────────────────────────────────────────────┘${NC}"
      echo -e "  It is not stored anywhere in plaintext. Change it after first login."
    else
      echo -e "  ${BOLD}Login:${NC}   ${ADMIN_USER} / (password you set)"
    fi
  fi

  echo ""
  echo -e "  ${BOLD}Install dir:${NC}  ${INSTALL_DIR}"
  echo -e "  ${BOLD}Manifest:${NC}     ${MANIFEST}"
  echo -e "  ${BOLD}Logs:${NC}         ${LOG_DIR}/"
  echo ""
  echo -e "  To uninstall: ${CYAN}bash ${SCRIPT_DIR}/uninstall.sh${NC}"
  echo ""

else
  echo -e "${RED}${BOLD}══════════════════════════════════════════════════════${NC}"
  echo -e "${RED}${BOLD}  Installation verification failed — ${TEST_EXIT} test(s) failed${NC}"
  echo -e "${RED}${BOLD}══════════════════════════════════════════════════════${NC}"
  echo ""
  # During an upgrade (--register-only) NEVER offer uninstall — that would wipe
  # customer data. Just report and exit non-zero so update.sh can warn.
  if $REGISTER_ONLY; then
    warn "Re-registration self-tests reported failures — install left intact."
    info "Review the FAIL lines above and re-run: bash ${SCRIPT_DIR}/test.sh"
    exit 1
  fi
  echo -e "  The plugin was installed but one or more self-tests failed."
  echo -e "  ${BOLD}What would you like to do?${NC}"
  echo ""
  echo -e "  ${CYAN}1)${NC} Keep the installation — I'll fix the issues manually"
  echo -e "  ${CYAN}2)${NC} Automatically uninstall and clean up everything"
  echo ""
  if [[ -t 0 ]]; then
    read -rp "  Choice [1/2]: " ROLLBACK_CHOICE
  else
    info "Non-interactive shell detected — keeping installation (default)"
    ROLLBACK_CHOICE=1
  fi

  if [[ "${ROLLBACK_CHOICE}" == "2" ]]; then
    echo ""
    warn "Rolling back installation…"
    bash "${SCRIPT_DIR}/uninstall.sh" --auto
    echo ""
    echo -e "${YELLOW}${BOLD}  Uninstall complete. Fix the failed tests above, then re-run install.sh.${NC}"
    echo ""
    exit 1
  else
    echo ""
    info "Installation kept."
    info "Review the FAIL lines above, fix the issues, then run:"
    echo -e "  ${CYAN}bash ${SCRIPT_DIR}/test.sh${NC}"
    echo ""
    exit 1
  fi
fi
