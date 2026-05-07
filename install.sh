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
command -v php >/dev/null 2>&1 || error "PHP not found. Install php-cli first."
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION;')
[[ $PHP_VER -lt 7 ]] && error "PHP 7.4+ required (found PHP $PHP_VER)"
ok "PHP $PHP_VER found"

# ── Mode selection ─────────────────────────────────────────────────────────────
section "Installation Mode"
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

# ── Standalone: collect admin credentials ──────────────────────────────────────
if [[ "$INSTALL_MODE" == "standalone" ]]; then
  section "Admin Account Setup"
  echo "  Create the local admin account for the web dashboard."
  echo ""

  read -rp "  Admin username [admin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"

  while true; do
    read -srp "  Admin password (min 8 chars): " ADMIN_PASS; echo
    [[ ${#ADMIN_PASS} -ge 8 ]] && break
    echo -e "  ${RED}Password too short — minimum 8 characters.${NC}"
  done

  read -srp "  Confirm password: " ADMIN_PASS2; echo
  [[ "$ADMIN_PASS" != "$ADMIN_PASS2" ]] && error "Passwords do not match"
  ok "Admin account: ${ADMIN_USER}"
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
ok "Files installed to $INSTALL_DIR"

# ── Set permissions ────────────────────────────────────────────────────────────
chown -R root:nobody "$INSTALL_DIR" 2>/dev/null || chown -R root:root "$INSTALL_DIR"
chmod -R 750 "$INSTALL_DIR"
chmod -R 700 "$INSTALL_DIR/database"
chmod -R 700 "$INSTALL_DIR/quarantine"
chmod -R 700 "$INSTALL_DIR/logs"
chmod +x "$INSTALL_DIR/backend/cron/scan.php"
chmod +x "$INSTALL_DIR/backend/daemon/monitor.py"
ok "Permissions set"

# ── Write mode.php ─────────────────────────────────────────────────────────────
cat > "${INSTALL_DIR}/backend/config/mode.php" << MODEPHP
<?php
// Written by install.sh — do not edit manually
define('INSTALL_MODE', '${INSTALL_MODE}');
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
    cp "${SCRIPT_DIR}/whm/sentinel-gate-monitor.service" /etc/systemd/system/
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
CRONEOF
chmod 644 "${CRON_FILE}"
ok "Cron jobs installed to ${CRON_FILE}"

# ── Write install manifest (uninstaller reads this) ───────────────────────────
MANIFEST="${INSTALL_DIR}/install-manifest.env"
{
  echo "INSTALL_MODE=${INSTALL_MODE}"
  echo "INSTALL_VERSION=${SG_VERSION}"
  echo "INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "INSTALL_DIR=${INSTALL_DIR}"
  echo "CRON_FILE=${CRON_FILE}"
  echo "SOURCE_DIR=${SCRIPT_DIR}"
} > "${MANIFEST}"
info "Manifest started: ${MANIFEST}"

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
  AllowOverride None
  Require all granted
  DirectoryIndex index.php
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

  # ── Register plugin via AppConfig (the correct cPanel method) ────────────────
  # The addon_plugins directory does NOT work — AppConfig + /var/cpanel/apps/ is
  # the definitive registration system used by all real cPanel plugins (CSF, etc.)
  info "Registering Sentinel Gate with cPanel AppConfig system…"
  if [[ ! -d /usr/local/cpanel ]]; then
    warn "/usr/local/cpanel not found — skipping cPanel registration"
  else
    ok "cPanel found"
    SERVER_HOST=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")
    info "  Server hostname: ${SERVER_HOST}"

    # ── Step 1: CGI script (served by cpsrvd on port 2087) ────────────────────
    # MUST be at cgi root with "addon_" prefix — this is what AppConfig url= points to.
    # Pattern confirmed from SpamExperts, Fantastico and other real plugins:
    #   url=/cgi/addon_PLUGIN.cgi  →  file at whostmgr/docroot/cgi/addon_PLUGIN.cgi
    WHM_CGI="/usr/local/cpanel/whostmgr/docroot/cgi/addon_sentinel_gate.cgi"
    info "  Writing CGI: ${WHM_CGI}"

    cat > "${WHM_CGI}" << 'ENDCGI'
#!/usr/bin/perl
use strict;
use warnings;
my $host = `hostname -f 2>/dev/null`; chomp $host;
$host ||= `hostname 2>/dev/null`;     chomp $host;
$host ||= 'localhost';
my $url = "https://$host/sentinel-gate/";
print "Content-Type: text/html\r\n\r\n";
print <<"ENDHTML";
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=$url">
  <title>Sentinel Gate</title>
  <style>body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;
    display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
    .b{text-align:center} a{color:#38bdf8}</style>
</head>
<body><div class="b">
  <h2>&#x26A1; Sentinel Gate Security</h2>
  <p>Opening dashboard&hellip;</p>
  <p><a href="$url">Click here if not redirected</a></p>
</div>
<script>window.location.href='$url';</script>
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

    # ── Step 2: AppConfig conf file in /var/cpanel/apps/ ─────────────────────
    # Confirmed correct method from real plugins (SpamExperts, Fantastico):
    #   • acls=all  (NOT "any" — "any" is not a valid value)
    #   • url=/cgi/addon_PLUGIN.cgi  (root-level CGI with addon_ prefix)
    APPCONFIG_DIR="/var/cpanel/apps"
    APPCONFIG_CONF="${APPCONFIG_DIR}/sentinel_gate.conf"
    mkdir -p "${APPCONFIG_DIR}"
    info "  Writing AppConfig conf: ${APPCONFIG_CONF}"
    cat > "${APPCONFIG_CONF}" << APPEOF
name=sentinel_gate
service=whostmgr
url=/cgi/addon_sentinel_gate.cgi
user=root
acls=all
displayname=Sentinel Gate Security
APPEOF
    chmod 644 "${APPCONFIG_CONF}"

    if [[ -f "${APPCONFIG_CONF}" ]]; then
      ok "  AppConfig conf written: ${APPCONFIG_CONF}"
      info "  Contents: $(tr '\n' ' ' < "${APPCONFIG_CONF}")"
      echo "APPCONFIG_CONF=${APPCONFIG_CONF}" >> "${MANIFEST}"
    else
      warn "  AppConfig conf write FAILED: ${APPCONFIG_CONF}"
    fi

    # ── Step 3: Register with AppConfig ──────────────────────────────────────
    info "  Running register_appconfig…"
    if [[ -x /usr/local/cpanel/bin/register_appconfig ]]; then
      /usr/local/cpanel/bin/register_appconfig "${APPCONFIG_CONF}" 2>&1 | sed 's/^/    /'
      ok "  AppConfig registration complete"
    else
      warn "  register_appconfig not found — plugin will activate after cpsrvd restart"
    fi

    # ── Step 4: cPanel user-level plugin (all hosting accounts) ──────────────
    info "  Installing cPanel user-level plugin (dynamicui)…"
    for CPANEL_THEME in paper_lantern jupiter; do
      DYNUI_DIR="/usr/local/cpanel/base/frontend/${CPANEL_THEME}/dynamicui"
      if [[ -d "${DYNUI_DIR}" ]]; then
        DYNUI_CONF="${DYNUI_DIR}/dynamicui_sentinel_gate.conf"
        cat > "${DYNUI_CONF}" << DYNEOF
group=security
groupdesc=Security
grouporder=30
name=sentinel_gate
itemdesc=Sentinel Gate Security
feature=sentinel_gate
url=https://${SERVER_HOST}/sentinel-gate/
target=_blank
icon=sentinel_gate.png
itemorder=1
DYNEOF
        chmod 644 "${DYNUI_CONF}"
        ok "  cPanel user plugin: ${DYNUI_CONF}"
        echo "DYNUI_${CPANEL_THEME}=${DYNUI_CONF}" >> "${MANIFEST}"
      fi
    done

    # ── Step 5: Reseller feature flag ─────────────────────────────────────────
    FEATURES_DIR="/usr/local/cpanel/cpanel/features"
    if [[ -d "${FEATURES_DIR}" ]]; then
      grep -q "sentinel_gate" "${FEATURES_DIR}/default" 2>/dev/null || \
        echo "sentinel_gate=1" >> "${FEATURES_DIR}/default"
      ok "  Reseller feature flag added: sentinel_gate"
      echo "FEATURE_FLAG=sentinel_gate" >> "${MANIFEST}"
    fi

    # ── Step 6: Restart cPanel services ──────────────────────────────────────
    info "  Restarting cPanel services…"
    for SVC in restartsrv_cpsrvd restartsrv_cpaneld; do
      if [[ -x "/usr/local/cpanel/scripts/${SVC}" ]]; then
        info "    Running ${SVC}…"
        "/usr/local/cpanel/scripts/${SVC}" 2>&1 | tail -4 | sed 's/^/    /'
        ok "    ${SVC} done"
      fi
    done
    ok "Sentinel Gate now visible in WHM → Plugins → Sentinel Gate Security"

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

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Sentinel Gate v${SG_VERSION} installed successfully!${NC}"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$INSTALL_MODE" == "cpanel" ]]; then
  echo -e "  ${BOLD}Access:${NC}  WHM → Plugins → Sentinel Gate Security"
  echo -e "  ${BOLD}Also:${NC}    https://$(hostname -f 2>/dev/null || hostname)/sentinel-gate/"
elif [[ "$INSTALL_MODE" == "standalone" ]]; then
  echo -e "  ${BOLD}Access:${NC}  http://$(hostname -f 2>/dev/null || hostname):${SG_PORT}"
  echo -e "  ${BOLD}Login:${NC}   ${ADMIN_USER} / (password you set)"
fi

echo ""
echo -e "  ${BOLD}Install dir:${NC}  ${INSTALL_DIR}"
echo -e "  ${BOLD}Manifest:${NC}     ${MANIFEST}"
echo -e "  ${BOLD}Logs:${NC}         ${LOG_DIR}/"
echo ""
echo -e "  To uninstall: ${CYAN}bash ${SCRIPT_DIR}/uninstall.sh${NC}"
echo ""
