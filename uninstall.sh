#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Uninstaller
# Removes everything: services, cron, Apache config, WHM plugin registration,
# all data (database, logs, quarantine), and the install directory.
#
# Usage:  sudo bash uninstall.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -o pipefail

INSTALL_DIR="/usr/local/sentinel-gate"
MANIFEST="${INSTALL_DIR}/install-manifest.env"
SG_PORT=31150

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
fail() { echo -e "  ${RED}✖${NC}  $*"; }
section() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }

[[ $EUID -ne 0 ]] && { echo "Must be run as root"; exit 1; }

echo ""
echo -e "${BOLD}${RED}╔═══════════════════════════════════════╗"
echo -e "║    Sentinel Gate — Uninstaller        ║"
echo -e "╚═══════════════════════════════════════╝${NC}"
echo ""

# ── Load install manifest ──────────────────────────────────────────────────────
INSTALL_MODE="cpanel"
INSTALL_VERSION="unknown"
APACHE_CONF=""
APPCONFIG_CONF=""
WHM_PLUGIN_CONF=""
WHM_CGI=""
DYNUI_PAPER=""
DYNUI_JUPITER=""
CPANEL_APPCONFIG=""
CPANEL_PLUGIN_PAPER=""
CPANEL_PLUGIN_JUPITER=""
CRON_FILE="/etc/cron.d/sentinel-gate"
MONITOR_SERVICE="/etc/systemd/system/sentinel-gate-monitor.service"
WEB_SERVICE=""
WEB_PID_FILE=""
FIREWALL_TOOL=""
SOURCE_DIR=""

if [[ -f "${MANIFEST}" ]]; then
    info "Reading install manifest…"
    while IFS='=' read -r KEY VAL; do
        [[ -z "$KEY" || "$KEY" =~ ^# ]] && continue
        case "$KEY" in
            INSTALL_MODE)               INSTALL_MODE="$VAL" ;;
            INSTALL_VERSION)            INSTALL_VERSION="$VAL" ;;
            APACHE_CONF)                APACHE_CONF="$VAL" ;;
            APPCONFIG_CONF)             APPCONFIG_CONF="$VAL" ;;
            WHM_PLUGIN_CONF)            WHM_PLUGIN_CONF="$VAL" ;;
            WHM_CGI)                    WHM_CGI="$VAL" ;;
            DYNUI_paper_lantern)        DYNUI_PAPER="$VAL" ;;
            DYNUI_jupiter)              DYNUI_JUPITER="$VAL" ;;
            CPANEL_APPCONFIG)           CPANEL_APPCONFIG="$VAL" ;;
            CPANEL_PLUGIN_paper_lantern) CPANEL_PLUGIN_PAPER="$VAL" ;;
            CPANEL_PLUGIN_jupiter)      CPANEL_PLUGIN_JUPITER="$VAL" ;;
            CRON_FILE)                  CRON_FILE="$VAL" ;;
            MONITOR_SERVICE)            MONITOR_SERVICE="$VAL" ;;
            WEB_SERVICE)                WEB_SERVICE="$VAL" ;;
            WEB_PID_FILE)               WEB_PID_FILE="$VAL" ;;
            FIREWALL_TOOL)              FIREWALL_TOOL="$VAL" ;;
            SOURCE_DIR)                 SOURCE_DIR="$VAL" ;;
        esac
    done < "${MANIFEST}"
    ok "Manifest loaded — mode: ${INSTALL_MODE}, version: ${INSTALL_VERSION}"
else
    warn "No install manifest found — using fallback defaults"
    MODE_FILE="${INSTALL_DIR}/backend/config/mode.php"
    if [[ -f "$MODE_FILE" ]] && grep -q "standalone" "$MODE_FILE" 2>/dev/null; then
        INSTALL_MODE="standalone"
    fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -z "$SOURCE_DIR" ]] && SOURCE_DIR="$SCRIPT_DIR"

echo ""
info "Uninstalling Sentinel Gate v${INSTALL_VERSION} (${INSTALL_MODE} mode)"
info "Install dir: ${INSTALL_DIR}"
echo ""

# ── 1. Stop and disable services ───────────────────────────────────────────────
section "Stopping services"

stop_service() {
    local svc="$1" svc_file="$2"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "${svc}" 2>/dev/null && \
            systemctl stop "${svc}" 2>/dev/null && ok "Stopped ${svc}" || true
        systemctl is-enabled --quiet "${svc}" 2>/dev/null && \
            systemctl disable "${svc}" 2>/dev/null || true
    fi
    [[ -n "${svc_file}" && -f "${svc_file}" ]] && \
        rm -f "${svc_file}" && ok "Removed service file: ${svc_file}" || true
}

stop_service "sentinel-gate-web"     "${WEB_SERVICE}"
stop_service "sentinel-gate-monitor" "${MONITOR_SERVICE}"
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true

# Kill any PID-file processes
for PID_FILE in "${WEB_PID_FILE}" "${INSTALL_DIR}/web.pid" \
                "${INSTALL_DIR}/monitor.pid" "/var/run/sentinel-gate-monitor.pid"; do
    [[ -z "${PID_FILE}" || ! -f "${PID_FILE}" ]] && continue
    PID=$(cat "${PID_FILE}" 2>/dev/null); [[ -z "$PID" ]] && continue
    kill "${PID}" 2>/dev/null && ok "Killed process PID ${PID}" || true
    rm -f "${PID_FILE}" 2>/dev/null || true
done

# ── 2. Remove cron jobs ────────────────────────────────────────────────────────
section "Removing cron jobs"
for _CRON in "${CRON_FILE}" /etc/cron.d/sentinel-gate /etc/cron.d/sentinel_gate; do
    [[ -f "${_CRON}" ]] && rm -f "${_CRON}" && ok "Removed ${_CRON}" || true
done

# ── 3. Remove Apache config ────────────────────────────────────────────────────
section "Removing Apache config"
APACHE_REMOVED=false
for CANDIDATE in \
    "${APACHE_CONF}" \
    /etc/apache2/conf.d/sentinel-gate.conf \
    /usr/local/apache/conf/includes/sentinel-gate.conf \
    /etc/httpd/conf.d/sentinel-gate.conf; do
    [[ -z "${CANDIDATE}" || ! -f "${CANDIDATE}" ]] && continue
    rm -f "${CANDIDATE}" && ok "Removed: ${CANDIDATE}" && APACHE_REMOVED=true
done

if $APACHE_REMOVED; then
    for APACHECTL in \
        /scripts/restartsrv_httpd \
        /usr/local/apache/bin/apachectl \
        /usr/sbin/apachectl /usr/sbin/apache2ctl /usr/sbin/httpd; do
        [[ -x "${APACHECTL}" ]] || command -v "${APACHECTL}" >/dev/null 2>&1 || continue
        "${APACHECTL}" graceful 2>/dev/null || \
        "${APACHECTL}" -k graceful 2>/dev/null || true
        ok "Apache reloaded"; break
    done
else
    info "No Apache config found — skipping reload"
fi

# ── 4. Remove WHM plugin registration ─────────────────────────────────────────
section "Removing WHM plugin registration"

if [[ "$INSTALL_MODE" != "standalone" ]]; then

    # A — Deregister both AppConfig entries via whmapi1
    if command -v whmapi1 >/dev/null 2>&1; then
        for _APPNAME in sentinel_gate sentinel_gate_cpanel sentinel-gate; do
            whmapi1 unregister_appconfig_application appname="${_APPNAME}" 2>/dev/null && \
                ok "whmapi1: deregistered ${_APPNAME}" || true
        done
    fi

    # B — Remove AppConfig conf files from /var/cpanel/apps/ and CGI dir
    REGISTER_APPCONFIG="/usr/local/cpanel/bin/register_appconfig"
    for APPCONF in \
        /var/cpanel/apps/sentinel_gate.conf \
        /var/cpanel/apps/sentinel_gate_cpanel.conf \
        /var/cpanel/apps/sentinel-gate.conf \
        "${APPCONFIG_CONF}" \
        "${WHM_PLUGIN_CONF}" \
        "${CPANEL_APPCONFIG}"; do
        [[ -z "${APPCONF}" || ! -f "${APPCONF}" ]] && continue
        [[ -x "${REGISTER_APPCONFIG}" ]] && \
            "${REGISTER_APPCONFIG}" --remove "${APPCONF}" 2>/dev/null || true
        rm -f "${APPCONF}" && ok "Removed AppConfig: ${APPCONF}"
    done
    # Update mtime so cPanel's scanner sees the change
    [[ -d /var/cpanel/apps ]] && touch /var/cpanel/apps/

    # C — Remove WHM CGI directories
    for CGI_DIR in \
        /usr/local/cpanel/whostmgr/docroot/cgi/sentinel_gate \
        /usr/local/cpanel/whostmgr/docroot/cgi/sentinel-gate; do
        [[ -d "${CGI_DIR}" ]] && rm -rf "${CGI_DIR}" && ok "Removed CGI dir: ${CGI_DIR}" || true
    done

    # D — Remove legacy standalone CGI files
    for CGI_FILE in \
        "${WHM_CGI}" \
        /usr/local/cpanel/whostmgr/docroot/cgi/addon_sentinel_gate.cgi \
        /usr/local/cpanel/whostmgr/docroot/cgi/addon_sentinelgate.cgi; do
        [[ -z "${CGI_FILE}" || ! -f "${CGI_FILE}" ]] && continue
        rm -f "${CGI_FILE}" && ok "Removed legacy CGI: ${CGI_FILE}"
    done

    # E — Remove legacy addon_plugins entries
    for LEGACY in \
        /usr/local/cpanel/whostmgr/docroot/cgi/addon_plugins/sentinel-gate.conf \
        /usr/local/cpanel/whostmgr/docroot/cgi/addon_plugins/sentinel_gate.conf \
        /usr/local/cpanel/whostmgr/docroot/cgi/sentinelgate.conf \
        /usr/local/cpanel/base/3rdparty/sentinel-gate; do
        [[ -e "${LEGACY}" ]] && rm -rf "${LEGACY}" && ok "Removed legacy: ${LEGACY}" || true
    done

    # F — Remove ConfigObj Driver files (WHM nav registration)
    DRIVER_DEST="/usr/local/cpanel/Cpanel/Config/ConfigObj/Driver"
    for _DF in \
        "${DRIVER_DEST}/SentinelGate.pm" \
        "${DRIVER_DEST}/SentinelGate/META.pm"; do
        [[ -f "$_DF" ]] && rm -f "$_DF" && ok "Removed Driver file: $_DF" || true
    done
    [[ -d "${DRIVER_DEST}/SentinelGate" ]] && \
        rmdir "${DRIVER_DEST}/SentinelGate" 2>/dev/null || true

    # G — Remove cPanel user-level plugin from both themes
    for CPANEL_PLUGIN_DIR in \
        "${CPANEL_PLUGIN_PAPER}" \
        "${CPANEL_PLUGIN_JUPITER}" \
        /usr/local/cpanel/base/frontend/paper_lantern/sentinel_gate \
        /usr/local/cpanel/base/frontend/jupiter/sentinel_gate; do
        [[ -z "${CPANEL_PLUGIN_DIR}" || ! -d "${CPANEL_PLUGIN_DIR}" ]] && continue
        if [[ -x /usr/local/cpanel/scripts/uninstall_plugin ]]; then
            _THEME=$(basename "$(dirname "${CPANEL_PLUGIN_DIR}")")
            /usr/local/cpanel/scripts/uninstall_plugin \
                "${CPANEL_PLUGIN_DIR}" --theme "${_THEME}" 2>/dev/null || true
        fi
        rm -rf "${CPANEL_PLUGIN_DIR}" && ok "Removed cPanel plugin dir: ${CPANEL_PLUGIN_DIR}"
    done

    # H — Remove dynamicui confs from both themes
    for DYNUI_CONF in \
        "${DYNUI_PAPER}" \
        "${DYNUI_JUPITER}" \
        /usr/local/cpanel/base/frontend/paper_lantern/dynamicui/dynamicui_sentinel_gate.conf \
        /usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_sentinel_gate.conf; do
        [[ -z "${DYNUI_CONF}" || ! -f "${DYNUI_CONF}" ]] && continue
        rm -f "${DYNUI_CONF}" && ok "Removed dynamicui conf: ${DYNUI_CONF}"
    done

    # I — Remove feature flags from all feature list files
    for _FEAT_DIR in /var/cpanel/features /usr/local/cpanel/cpanel/features; do
        [[ -d "${_FEAT_DIR}" ]] || continue
        for FEAT_FILE in "${_FEAT_DIR}"/*; do
            [[ -f "${FEAT_FILE}" ]] && \
                sed -i '/^sentinel_gate=/d' "${FEAT_FILE}" 2>/dev/null || true
        done
        ok "Feature flags cleared: ${_FEAT_DIR}"
    done

    # J — Clear WHM plugin cache files so nav rebuilds immediately
    for _CACHE in \
        /var/cpanel/pluginscache.yaml \
        /var/cpanel/cache/pluginscache.yaml \
        /var/cpanel/cache/appconfig; do
        if [[ -f "${_CACHE}" ]]; then
            rm -f "${_CACHE}" && ok "Cleared plugin cache: ${_CACHE}"
        elif [[ -d "${_CACHE}" ]]; then
            rm -rf "${_CACHE}" && ok "Cleared plugin cache dir: ${_CACHE}"
        fi
    done

    # K — Restart cpsrvd to flush WHM nav (unconditional in cPanel mode)
    if [[ -x /usr/local/cpanel/scripts/restartsrv_cpsrvd ]]; then
        info "Restarting cpsrvd to flush WHM nav cache…"
        /usr/local/cpanel/scripts/restartsrv_cpsrvd 2>&1 | tail -3 | sed 's/^/    /'
        ok "cpsrvd restarted — Sentinel Gate removed from WHM Plugins menu"
    elif command -v whmapi1 >/dev/null 2>&1; then
        info "restartsrv_cpsrvd not found — rescanning AppConfig entries…"
        [[ -x "${REGISTER_APPCONFIG}" ]] && \
            "${REGISTER_APPCONFIG}" --all 2>&1 | sed 's/^/    /' || true
    else
        warn "Could not restart cpsrvd — you may need to log out and back in to WHM"
    fi

else
    info "Standalone mode — skipping WHM cleanup"
fi

# ── 5. Remove firewall rule (standalone mode) ──────────────────────────────────
section "Removing firewall rule"
if [[ "$INSTALL_MODE" == "standalone" ]]; then
    if [[ "$FIREWALL_TOOL" == "firewalld" ]] || command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port=${SG_PORT}/tcp 2>/dev/null && \
            firewall-cmd --reload 2>/dev/null && \
            ok "Port ${SG_PORT} removed from firewalld" || \
            info "Port ${SG_PORT} not found in firewalld rules"
    elif [[ "$FIREWALL_TOOL" == "iptables" ]] || command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -p tcp --dport ${SG_PORT} -j ACCEPT 2>/dev/null && \
            ok "iptables rule removed for port ${SG_PORT}" || \
            info "iptables rule not found"
    fi
else
    info "cPanel mode — no port rule to remove"
fi

# ── 6. Remove install directory and all data ───────────────────────────────────
section "Removing install directory"
if [[ -d "${INSTALL_DIR}" ]]; then
    rm -rf "${INSTALL_DIR}"
    [[ -d "${INSTALL_DIR}" ]] && \
        fail "Still present: ${INSTALL_DIR} — remove manually: rm -rf ${INSTALL_DIR}" || \
        ok "Removed: ${INSTALL_DIR}"
else
    info "${INSTALL_DIR} not found — already removed"
fi

# ── 7. Remove source/unzip directory ──────────────────────────────────────────
section "Removing source directory"
if [[ -n "${SOURCE_DIR}" && -d "${SOURCE_DIR}" && "${SOURCE_DIR}" != "${INSTALL_DIR}" ]]; then
    info "Scheduling removal of ${SOURCE_DIR}…"
    # Deferred — this script lives inside SOURCE_DIR
    nohup bash -c "sleep 2 && rm -rf '${SOURCE_DIR}'" >/dev/null 2>&1 &
    ok "Source directory will be deleted in 2 seconds: ${SOURCE_DIR}"
else
    info "Source dir same as install dir or not found — already removed"
fi

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════╗"
echo -e "║  ✔  Sentinel Gate fully removed.      ║"
echo -e "╚═══════════════════════════════════════╝${NC}"
echo ""
