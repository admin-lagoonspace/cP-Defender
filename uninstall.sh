#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Uninstaller
# Reads install-manifest.env to remove exactly what was installed.
# Usage: sudo bash uninstall.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -o pipefail

INSTALL_DIR="/usr/local/sentinel-gate"
MANIFEST="${INSTALL_DIR}/install-manifest.env"
SG_PORT=31150

# --auto flag: skip all interactive prompts, answer yes to everything
AUTO_MODE=false
for _ARG in "$@"; do
  [[ "$_ARG" == "--auto" || "$_ARG" == "--yes" ]] && AUTO_MODE=true
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
skip() { echo -e "        ${YELLOW}(skip)${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; }

[[ $EUID -ne 0 ]] && { echo "Must be run as root"; exit 1; }

echo ""
echo -e "${RED}${BOLD}Sentinel Gate — Uninstaller${NC}"
echo ""

# ── Load install manifest ──────────────────────────────────────────────────────
INSTALL_MODE="unknown"
INSTALL_VERSION="unknown"
APACHE_CONF=""
APPCONFIG_CONF=""
WHM_PLUGIN_CONF=""
WHM_CGI=""
DYNUI_PAPER=""
DYNUI_JUPITER=""
FEATURE_FLAG=""
CRON_FILE="/etc/cron.d/sentinel-gate"
MONITOR_SERVICE="/etc/systemd/system/sentinel-gate-monitor.service"
WEB_SERVICE=""
WEB_PID_FILE=""
FIREWALL_TOOL=""
SOURCE_DIR=""

if [[ -f "${MANIFEST}" ]]; then
  info "Reading install manifest: ${MANIFEST}"
  while IFS='=' read -r KEY VAL; do
    [[ -z "$KEY" || "$KEY" =~ ^# ]] && continue
    case "$KEY" in
      INSTALL_MODE)     INSTALL_MODE="$VAL" ;;
      INSTALL_VERSION)  INSTALL_VERSION="$VAL" ;;
      APACHE_CONF)      APACHE_CONF="$VAL" ;;
      APPCONFIG_CONF)   APPCONFIG_CONF="$VAL" ;;
      WHM_PLUGIN_CONF)  WHM_PLUGIN_CONF="$VAL" ;;
      WHM_CGI)          WHM_CGI="$VAL" ;;
      DYNUI_paper_lantern) DYNUI_PAPER="$VAL" ;;
      DYNUI_jupiter)    DYNUI_JUPITER="$VAL" ;;
      FEATURE_FLAG)     FEATURE_FLAG="$VAL" ;;
      CRON_FILE)        CRON_FILE="$VAL" ;;
      MONITOR_SERVICE)  MONITOR_SERVICE="$VAL" ;;
      WEB_SERVICE)      WEB_SERVICE="$VAL" ;;
      WEB_PID_FILE)     WEB_PID_FILE="$VAL" ;;
      FIREWALL_TOOL)    FIREWALL_TOOL="$VAL" ;;
      SOURCE_DIR)       SOURCE_DIR="$VAL" ;;
    esac
  done < "${MANIFEST}"
  ok "Manifest loaded — mode: ${INSTALL_MODE}, version: ${INSTALL_VERSION}"
else
  warn "No install manifest found — using fallback defaults"
  MODE_FILE="${INSTALL_DIR}/backend/config/mode.php"
  if [[ -f "$MODE_FILE" ]] && grep -q "standalone" "$MODE_FILE" 2>/dev/null; then
    INSTALL_MODE="standalone"
  else
    INSTALL_MODE="cpanel"
  fi
fi

# Detect the source/unzip directory if not in manifest
# (the uninstall.sh itself lives in the source directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${SOURCE_DIR}" ]]; then
  SOURCE_DIR="${SCRIPT_DIR}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# ASK ALL QUESTIONS UPFRONT — no actions taken until all answers collected
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}  What will be removed:${NC}"
echo -e "  • Services, cron jobs, Apache config, WHM registration"
[[ -n "${APACHE_CONF}" ]]    && echo -e "    Apache:   ${APACHE_CONF}"
[[ -n "${WHM_PLUGIN_CONF}" ]] && echo -e "    WHM conf: ${WHM_PLUGIN_CONF}"
[[ -n "${WEB_SERVICE}" ]]    && echo -e "    Service:  ${WEB_SERVICE}"

if [[ -d "${INSTALL_DIR}" ]]; then
  TOTAL_SIZE=$(du -sh "${INSTALL_DIR}" 2>/dev/null | cut -f1)
  QUAR_COUNT=$(find "${INSTALL_DIR}/quarantine" -type f 2>/dev/null | wc -l)
  echo -e "  • All plugin files: ${INSTALL_DIR}/ (${TOTAL_SIZE}, ${QUAR_COUNT} quarantined files)"
fi

if [[ -n "${SOURCE_DIR}" && -d "${SOURCE_DIR}" && "${SOURCE_DIR}" != "${INSTALL_DIR}" ]]; then
  SRC_SIZE=$(du -sh "${SOURCE_DIR}" 2>/dev/null | cut -f1)
  echo -e "  • Source/unzip folder: ${SOURCE_DIR}/ (${SRC_SIZE})"
fi

echo ""

# Q1 — proceed at all?
if $AUTO_MODE; then
  echo -e "  ${YELLOW}[AUTO]${NC} Proceeding with full uninstall (--auto mode)"
  Q1="y"
else
  read -rp "  Uninstall Sentinel Gate v${INSTALL_VERSION}? [y/N]: " Q1
fi
[[ "${Q1,,}" != "y" ]] && { echo "Aborted."; exit 0; }

# Q2 — delete all data?
echo ""
if $AUTO_MODE; then
  Q2="y"
else
  read -rp "  Delete all data (database, logs, quarantine)? [y/N]: " Q2
fi
[[ "${Q2,,}" != "y" ]] && { echo "Aborted."; exit 0; }

# Q3 — remove source/unzip directory?
REMOVE_SOURCE=false
if [[ -n "${SOURCE_DIR}" && -d "${SOURCE_DIR}" && "${SOURCE_DIR}" != "${INSTALL_DIR}" ]]; then
  echo ""
  if $AUTO_MODE; then
    Q3="n"   # keep source dir in auto mode so the installer zip stays available
    echo -e "  ${YELLOW}[AUTO]${NC} Keeping source directory: ${SOURCE_DIR}"
  else
    read -rp "  Remove source/unzip directory ${SOURCE_DIR}? [y/N]: " Q3
  fi
  [[ "${Q3,,}" == "y" ]] && REMOVE_SOURCE=true
fi

echo ""
echo -e "${CYAN}${BOLD}── Starting uninstall… ──${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# NOW EXECUTE — all answers confirmed, begin removal
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. Stop and disable systemd services ──────────────────────────────────────
echo -e "${CYAN}${BOLD}── Stopping services ──${NC}"

stop_service() {
  local svc="$1" svc_file="$2"
  info "Checking service: ${svc}"
  if systemctl is-active --quiet "${svc}" 2>/dev/null; then
    systemctl stop "${svc}" 2>&1 | sed 's/^/  /' && ok "Stopped ${svc}" || warn "Stop failed: ${svc}"
  else
    skip "${svc} is not running"
  fi
  if systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
    systemctl disable "${svc}" 2>&1 | sed 's/^/  /' && ok "Disabled ${svc}" || true
  fi
  if [[ -n "${svc_file}" && -f "${svc_file}" ]]; then
    rm -f "${svc_file}" && ok "Removed service file: ${svc_file}"
  else
    [[ -n "${svc_file}" ]] && skip "Service file not found: ${svc_file}"
  fi
}

if command -v systemctl >/dev/null 2>&1; then
  stop_service "sentinel-gate-web"     "${WEB_SERVICE}"
  stop_service "sentinel-gate-monitor" "${MONITOR_SERVICE}"
  systemctl daemon-reload 2>/dev/null || true
else
  skip "systemctl not available"
fi

# Kill background processes if running without systemd
for PID_FILE in "${WEB_PID_FILE}" "${INSTALL_DIR}/web.pid" "${INSTALL_DIR}/monitor.pid"; do
  [[ -z "${PID_FILE}" || ! -f "${PID_FILE}" ]] && continue
  PID=$(cat "${PID_FILE}" 2>/dev/null)
  [[ -z "${PID}" ]] && continue
  kill "${PID}" 2>/dev/null && ok "Killed background process (PID ${PID})" || skip "PID ${PID} not running"
done

# ── 2. Remove cron jobs ────────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}── Removing cron jobs ──${NC}"
info "Cron file: ${CRON_FILE}"
if [[ -f "${CRON_FILE}" ]]; then
  rm -f "${CRON_FILE}" && ok "Removed ${CRON_FILE}"
else
  skip "Not found: ${CRON_FILE}"
fi

# ── 3. Remove Apache config ────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}── Removing Apache config ──${NC}"
APACHE_REMOVED=false

for CANDIDATE in \
  "${APACHE_CONF}" \
  /etc/apache2/conf.d/sentinel-gate.conf \
  /usr/local/apache/conf/includes/sentinel-gate.conf \
  /etc/httpd/conf.d/sentinel-gate.conf; do
  [[ -z "${CANDIDATE}" || ! -f "${CANDIDATE}" ]] && continue
  rm -f "${CANDIDATE}" && ok "Removed: ${CANDIDATE}"
  APACHE_REMOVED=true
done

if $APACHE_REMOVED; then
  for APACHECTL in /usr/local/apache/bin/apachectl /usr/sbin/apachectl /usr/sbin/apache2ctl /usr/sbin/httpd; do
    [[ -x "${APACHECTL}" ]] || command -v "${APACHECTL}" >/dev/null 2>&1 || continue
    "${APACHECTL}" graceful 2>&1 | sed 's/^/  /' || "${APACHECTL}" -k graceful 2>&1 | sed 's/^/  /' || true
    ok "Apache reloaded"; break
  done
else
  skip "No Apache config found"
fi

# ── 4. Remove WHM plugin registration ─────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}── Removing WHM plugin registration ──${NC}"
WHM_REMOVED=false

# Remove AppConfig registration (the correct cPanel WHM plugin method)
REGISTER_APPCONFIG="/usr/local/cpanel/bin/register_appconfig"
for APPCONF in \
  "${APPCONFIG_CONF}" \
  /var/cpanel/apps/sentinel_gate.conf \
  /var/cpanel/apps/sentinel-gate.conf; do
  [[ -z "${APPCONF}" || ! -f "${APPCONF}" ]] && continue
  if [[ -x "${REGISTER_APPCONFIG}" ]]; then
    "${REGISTER_APPCONFIG}" --remove "${APPCONF}" 2>/dev/null && \
      ok "Unregistered AppConfig: ${APPCONF}" || \
      warn "register_appconfig --remove failed (continuing): ${APPCONF}"
  fi
  rm -f "${APPCONF}" && ok "Removed AppConfig conf: ${APPCONF}"
  WHM_REMOVED=true
done

# Remove CGI subdirectory (current: /usr/local/cpanel/whostmgr/docroot/cgi/sentinel_gate/)
for CGI_DIR in \
  /usr/local/cpanel/whostmgr/docroot/cgi/sentinel_gate \
  /usr/local/cpanel/whostmgr/docroot/cgi/sentinel-gate; do
  if [[ -d "${CGI_DIR}" ]]; then
    rm -rf "${CGI_DIR}" && ok "Removed WHM CGI dir: ${CGI_DIR}"
    WHM_REMOVED=true
  fi
done

# Remove standalone CGI (legacy: root-level addon_sentinel_gate.cgi from pre-3.1.8)
for CGI_FILE in \
  "${WHM_CGI}" \
  /usr/local/cpanel/whostmgr/docroot/cgi/addon_sentinel_gate.cgi; do
  [[ -z "${CGI_FILE}" || ! -f "${CGI_FILE}" ]] && continue
  rm -f "${CGI_FILE}" && ok "Removed legacy WHM CGI: ${CGI_FILE}"
  WHM_REMOVED=true
done

# Legacy paths swept for old installs
for LEGACY in \
  /usr/local/cpanel/whostmgr/docroot/cgi/addon_plugins/sentinel-gate.conf \
  /usr/local/cpanel/whostmgr/docroot/cgi/addon_plugins/sentinel_gate.conf \
  /usr/local/cpanel/whostmgr/docroot/cgi/addon_sentinelgate.cgi \
  /usr/local/cpanel/whostmgr/docroot/cgi/sentinelgate.conf \
  /usr/local/cpanel/base/3rdparty/sentinel-gate; do
  [[ -e "${LEGACY}" ]] && rm -rf "${LEGACY}" && ok "Removed legacy: ${LEGACY}"
done

if $WHM_REMOVED; then
  if [[ -x /usr/local/cpanel/scripts/restartsrv_cpsrvd ]]; then
    info "Restarting cpsrvd to remove plugin from WHM menu…"
    /usr/local/cpanel/scripts/restartsrv_cpsrvd 2>&1 | tail -3 | sed 's/^/  /'
    ok "cpsrvd restarted"
  fi
else
  skip "No WHM plugin files found"
fi

# Remove cPanel user-level dynamicui plugin from all themes
info "Removing cPanel user-level plugin…"
for DYNUI_CONF in \
  "${DYNUI_PAPER}" \
  "${DYNUI_JUPITER}" \
  /usr/local/cpanel/base/frontend/paper_lantern/dynamicui/dynamicui_sentinel_gate.conf \
  /usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_sentinel_gate.conf; do
  [[ -z "${DYNUI_CONF}" || ! -f "${DYNUI_CONF}" ]] && continue
  rm -f "${DYNUI_CONF}" && ok "Removed cPanel user plugin: ${DYNUI_CONF}"
done

# Remove reseller feature flag from feature lists
FEATURES_DIR="/usr/local/cpanel/cpanel/features"
if [[ -d "${FEATURES_DIR}" ]]; then
  info "Removing sentinel_gate feature flag…"
  for FEAT_FILE in "${FEATURES_DIR}"/*; do
    [[ -f "${FEAT_FILE}" ]] && \
      sed -i '/^sentinel_gate=/d' "${FEAT_FILE}" 2>/dev/null || true
  done
  ok "Feature flag removed from feature lists"
fi

# ── 5. Remove firewall rule ────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}── Removing firewall rule ──${NC}"
if [[ "$INSTALL_MODE" == "standalone" ]]; then
  if [[ "$FIREWALL_TOOL" == "firewalld" ]] || command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port=${SG_PORT}/tcp 2>&1 && \
      firewall-cmd --reload 2>&1 && ok "Port ${SG_PORT} removed from firewalld" || \
      skip "Port ${SG_PORT} not in firewalld rules"
  elif [[ "$FIREWALL_TOOL" == "iptables" ]] || command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -p tcp --dport ${SG_PORT} -j ACCEPT 2>/dev/null && \
      ok "iptables rule removed for port ${SG_PORT}" || skip "iptables rule not found"
  fi
else
  skip "cPanel mode — no port rule to remove"
fi

# ── 6. Remove install directory and all data ──────────────────────────────────
echo -e "\n${CYAN}${BOLD}── Removing install directory and all data ──${NC}"
info "Target: ${INSTALL_DIR}"
if [[ -d "${INSTALL_DIR}" ]]; then
  for ITEM in "${INSTALL_DIR}"/*/; do
    [[ -e "${ITEM}" ]] || continue
    rm -rf "${ITEM}" && ok "  Deleted: ${ITEM}"
  done
  find "${INSTALL_DIR}" -maxdepth 1 -type f -delete 2>/dev/null || true
  rm -rf "${INSTALL_DIR}"
  if [[ -d "${INSTALL_DIR}" ]]; then
    fail "Directory still present: ${INSTALL_DIR} — remove manually: rm -rf ${INSTALL_DIR}"
  else
    ok "Confirmed removed: ${INSTALL_DIR}"
  fi
else
  skip "${INSTALL_DIR} not found"
fi

# ── 7. Remove source/unzip directory ──────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}── Removing source/unzip directory ──${NC}"
if $REMOVE_SOURCE && [[ -n "${SOURCE_DIR}" && -d "${SOURCE_DIR}" ]]; then
  info "Scheduling removal of ${SOURCE_DIR} (after script exits)…"
  # Must be deferred — this script lives inside SOURCE_DIR
  nohup bash -c "sleep 2 && rm -rf '${SOURCE_DIR}'" > /dev/null 2>&1 &
  ok "Source directory will be deleted in 2 seconds: ${SOURCE_DIR}"
else
  skip "Source directory kept: ${SOURCE_DIR:-unknown}"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}${BOLD}✅  Sentinel Gate fully uninstalled.${NC}"
$REMOVE_SOURCE && echo -e "  ${GREEN}     Source directory also removed.${NC}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""
