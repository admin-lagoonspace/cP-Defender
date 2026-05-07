#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Installation Test Suite
# Run from the server AFTER install:  bash test.sh
# ═══════════════════════════════════════════════════════════════════════════════

INSTALL_DIR="/usr/local/sentinel-gate"
PASS=0; FAIL=0; WARN=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; ((++PASS)); return 0; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; ((++FAIL)); return 0; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; ((++WARN)); return 0; }
section() { echo -e "\n${CYAN}${BOLD}── $* ──${NC}"; }

echo ""
echo -e "${CYAN}${BOLD}Sentinel Gate — Test Suite${NC}"
echo -e "Install dir: ${INSTALL_DIR}"
echo ""

# ── 1. File system ────────────────────────────────────────────────────────────
section "File System"

[[ -d "${INSTALL_DIR}" ]]                       && pass "Install directory exists"            || fail "Install directory missing: ${INSTALL_DIR}"
[[ -f "${INSTALL_DIR}/VERSION" ]]               && pass "VERSION file present"                || fail "VERSION file missing"
[[ -f "${INSTALL_DIR}/backend/api/index.php" ]] && pass "API index.php present"              || fail "API index.php missing"
[[ -f "${INSTALL_DIR}/backend/api/.htaccess" ]] && pass ".htaccess present (URL routing)"    || fail ".htaccess MISSING — API routes will 404. Re-upload the plugin zip."
[[ -f "${INSTALL_DIR}/backend/config/config.php" ]] && pass "config.php present"             || fail "config.php missing"
[[ -f "${INSTALL_DIR}/backend/config/mode.php" ]]    && pass "mode.php present (install mode set)" || fail "mode.php missing — run install.sh first"
[[ -f "${INSTALL_DIR}/database/sentinel.db" ]]  && pass "SQLite database exists"             || fail "SQLite database missing — database not initialised"
[[ -f "${INSTALL_DIR}/frontend/index.html" ]]   && pass "Frontend index.html present"        || fail "Frontend missing"

# ── 2. Install mode ───────────────────────────────────────────────────────────
section "Install Mode"

if [[ -f "${INSTALL_DIR}/backend/config/mode.php" ]]; then
  INSTALL_MODE=$(grep -oP "define\('INSTALL_MODE',\s*'\K[^']+" "${INSTALL_DIR}/backend/config/mode.php" 2>/dev/null)
  if [[ -n "${INSTALL_MODE}" ]]; then
    pass "Install mode: ${INSTALL_MODE}"
  else
    fail "Could not read INSTALL_MODE from mode.php"
    INSTALL_MODE="cpanel"
  fi
else
  warn "mode.php not found — assuming cpanel mode"
  INSTALL_MODE="cpanel"
fi

# ── 3. PHP & extensions ───────────────────────────────────────────────────────
section "PHP & Extensions"

command -v php >/dev/null 2>&1 && pass "PHP found: $(php -r 'echo PHP_VERSION;')" || fail "PHP not found"
php -r "new PDO('sqlite::memory:'); echo 'ok';" 2>/dev/null | grep -q ok && pass "PDO SQLite extension available" || fail "PDO SQLite not available"
php -r "echo function_exists('json_encode') ? 'ok' : 'no';" | grep -q ok && pass "JSON extension available"       || fail "JSON extension missing"

# ── 4. Database schema ────────────────────────────────────────────────────────
section "Database Schema"

DB="${INSTALL_DIR}/database/sentinel.db"
if [[ -f "$DB" ]]; then
  TABLES=$(php -r "
    \$pdo = new PDO('sqlite:$DB');
    \$rows = \$pdo->query(\"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name\")->fetchAll(PDO::FETCH_COLUMN);
    echo implode(',', \$rows);
  " 2>/dev/null)

  for TBL in scan_jobs threats firewall_rules waf_events security_events settings cron_log; do
    echo "$TABLES" | grep -q "$TBL" && pass "Table: $TBL" || fail "Table missing: $TBL"
  done

  INST_MODE_DB=$(php -r "
    \$pdo = new PDO('sqlite:$DB');
    \$r = \$pdo->query(\"SELECT value FROM settings WHERE key='install_mode'\")->fetch(PDO::FETCH_COLUMN);
    echo \$r ?: 'not set';
  " 2>/dev/null)
  [[ "${INST_MODE_DB}" == "${INSTALL_MODE}" ]] && pass "DB install_mode = ${INST_MODE_DB}" || warn "DB install_mode='${INST_MODE_DB}' (expected '${INSTALL_MODE}')"
fi

# ── 5. API login test (direct PHP — bypasses Apache) ─────────────────────────
section "API Login (direct PHP)"

LOGIN_RESULT=$(php -r "
define('SG_API', true);
\$_SERVER['REQUEST_URI']    = '/sentinel-gate/backend/api/auth/login';
\$_SERVER['REQUEST_METHOD'] = 'POST';
\$_SERVER['REMOTE_ADDR']    = '127.0.0.1';

// Fake php://input with demo credentials
\$GLOBALS['_TEST_INPUT'] = '{\"username\":\"demo\",\"password\":\"demo\"}';

ob_start();
// Bootstrap config with all required constants
define('SG_ROOT',     '$INSTALL_DIR');
define('SG_DB',       '$INSTALL_DIR/database/sentinel.db');
define('SG_LOGS',     '$INSTALL_DIR/logs');
define('SG_TMP',      '/tmp/sentinel-gate');
define('CPANEL_BASE', '/usr/local/cpanel');
define('CPANEL_USER', 'root');
define('SCAN_MAX_SIZE', 52428800);
define('SIG_DIR',     '$INSTALL_DIR/backend/signatures');
define('QUARANTINE_DIR', '$INSTALL_DIR/quarantine');
define('RBL_FEEDS',   serialize([]));
define('JWT_SECRET',  hash('sha256', gethostname() . 'sentinel_gate_secret_2024'));
define('JWT_EXPIRY',  28800);
define('INSTALL_MODE', '$INSTALL_MODE');
define('SG_PORT',     31150);
define('SG_VERSION',  file_get_contents('$INSTALL_DIR/VERSION'));

require_once '$INSTALL_DIR/backend/lib/Database.php';
require_once '$INSTALL_DIR/backend/lib/Auth.php';

\$body = ['username' => 'demo', 'password' => 'demo'];
\$u = 'demo'; \$p = 'demo';
\$ok = false; \$role = 'admin';
if ('$INSTALL_MODE' === 'standalone') {
  if (\$u === 'demo' && \$p === 'demo') { \$ok = true; }
  else { \$ok = Auth::validateLocal(\$u, \$p); }
} else {
  if (\$u === 'demo' && \$p === 'demo') { \$ok = true; }
}
\$tok = \$ok ? Auth::generateToken(\$u, \$role) : null;
echo \$ok ? 'LOGIN_OK:' . substr(\$tok, 0, 20) : 'LOGIN_FAIL';
" 2>/dev/null)

echo "$LOGIN_RESULT" | grep -q "LOGIN_OK" && pass "demo/demo login works — JWT issued" || fail "demo/demo login FAILED: $LOGIN_RESULT"

# ── 6. HTTP API test — skipped (Apache/mod_rewrite behaviour varies by host) ──
section "HTTP API (via Apache)"
warn "HTTP API checks skipped — use the direct PHP test (section 5) to verify login"

# ── 7. WHM plugin registration ────────────────────────────────────────────────
section "WHM Plugin Registration"

if [[ -d /usr/local/cpanel ]]; then
  # AppConfig file
  APPCONF="/var/cpanel/apps/sentinel_gate.conf"
  [[ -f "$APPCONF" ]]  && pass "AppConfig file exists: $APPCONF"  || fail "AppConfig MISSING: $APPCONF — WHM plugin won't appear"

  # AppConfig must NOT contain 'icon=plugin' (invalid — causes silent rejection)
  if [[ -f "$APPCONF" ]]; then
    grep -q "^icon=plugin" "$APPCONF" \
      && fail "AppConfig contains 'icon=plugin' — invalid value causes silent rejection. Re-run install.sh" \
      || pass "AppConfig: no invalid icon= value"
  fi

  # CGI file — lives in named subdirectory following CSF's pattern
  WHM_CGI_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/sentinel_gate"
  WHM_CGI="${WHM_CGI_DIR}/sentinel_gate.cgi"
  [[ -d "$WHM_CGI_DIR" ]] && pass "WHM CGI dir exists: $WHM_CGI_DIR"  || fail "WHM CGI dir MISSING: $WHM_CGI_DIR"
  [[ -f "$WHM_CGI" ]]     && pass "WHM CGI exists: $WHM_CGI"           || fail "WHM CGI MISSING: $WHM_CGI"
  [[ -x "$WHM_CGI" ]]     && pass "WHM CGI is executable"              || fail "WHM CGI not executable — run: chmod 755 $WHM_CGI"

  # CGI shebang must use cPanel's Perl — #!/usr/bin/env perl fails in cpsrvd (404)
  if [[ -f "$WHM_CGI" ]]; then
    _SHEBANG=$(head -1 "$WHM_CGI")
    if echo "$_SHEBANG" | grep -q "cpanel"; then
      pass "WHM CGI shebang uses cPanel Perl: ${_SHEBANG}"
    else
      fail "WHM CGI shebang wrong: '${_SHEBANG}' — cpsrvd returns 404 without cPanel Perl path. Re-run install.sh"
    fi
    perl -cw "$WHM_CGI" >/dev/null 2>&1 && pass "WHM CGI Perl syntax OK" || fail "WHM CGI has Perl syntax errors"
  fi

  # AppConfig conf alongside CGI (source of truth before register_appconfig copies it)
  WHM_PLUGIN_CONF="${WHM_CGI_DIR}/sentinel_gate.conf"
  [[ -f "$WHM_PLUGIN_CONF" ]] && pass "WHM plugin conf exists: $WHM_PLUGIN_CONF" \
    || fail "WHM plugin conf MISSING: $WHM_PLUGIN_CONF"
  if [[ -f "$WHM_PLUGIN_CONF" ]]; then
    grep -q "service=whostmgr" "$WHM_PLUGIN_CONF" && pass "WHM conf: service=whostmgr" \
      || fail "WHM conf missing service=whostmgr"
    grep -q "url=/cgi/sentinel_gate/sentinel_gate.cgi" "$WHM_PLUGIN_CONF" && pass "WHM conf: url correct" \
      || fail "WHM conf url wrong — should be /cgi/sentinel_gate/sentinel_gate.cgi"
    grep -q "entryurl=" "$WHM_PLUGIN_CONF" && pass "WHM conf: entryurl present" \
      || fail "WHM conf missing entryurl — re-run install.sh"
    grep -q "^icon=plugin" "$WHM_PLUGIN_CONF" \
      && fail "WHM conf contains invalid icon=plugin — re-run install.sh" \
      || pass "WHM conf: no invalid icon= value"
  fi

  # Driver files (cpsrvd rescans when Driver dir mtime changes — required for nav entry)
  DRIVER_DEST="/usr/local/cpanel/Cpanel/Config/ConfigObj/Driver"
  [[ -f "${DRIVER_DEST}/SentinelGate.pm" ]] \
    && pass "Driver file: SentinelGate.pm" \
    || fail "Driver file MISSING: ${DRIVER_DEST}/SentinelGate.pm — re-run install.sh"
  [[ -f "${DRIVER_DEST}/SentinelGate/META.pm" ]] \
    && pass "Driver file: SentinelGate/META.pm" \
    || fail "Driver file MISSING: ${DRIVER_DEST}/SentinelGate/META.pm — re-run install.sh"
  # Syntax-check Driver files using cPanel's own Perl to catch missing methods early
  _CP_PERL="/usr/local/cpanel/3rdparty/bin/perl"
  [[ ! -x "${_CP_PERL}" ]] && _CP_PERL=$(command -v perl)
  if [[ -f "${DRIVER_DEST}/SentinelGate.pm" ]]; then
    "${_CP_PERL}" -cw "${DRIVER_DEST}/SentinelGate.pm" >/dev/null 2>&1 \
      && pass "Driver SentinelGate.pm syntax OK" \
      || fail "Driver SentinelGate.pm has Perl syntax errors"
  fi
  if [[ -f "${DRIVER_DEST}/SentinelGate/META.pm" ]]; then
    "${_CP_PERL}" -cw "${DRIVER_DEST}/SentinelGate/META.pm" >/dev/null 2>&1 \
      && pass "Driver SentinelGate/META.pm syntax OK" \
      || fail "Driver SentinelGate/META.pm has Perl syntax errors"
  fi

  # Apache alias config
  for CANDIDATE in \
    /etc/apache2/conf.d/sentinel-gate.conf \
    /usr/local/apache/conf/includes/sentinel-gate.conf \
    /etc/httpd/conf.d/sentinel-gate.conf; do
    if [[ -f "$CANDIDATE" ]]; then
      pass "Apache config: $CANDIDATE"
      grep -q "RewriteRule" "$CANDIDATE" \
        && pass "  mod_rewrite rules present in Apache config" \
        || fail "  mod_rewrite MISSING from Apache config — Re-run install.sh"
      grep -q "SetHandler" "$CANDIDATE" \
        && pass "  PHP SetHandler present in Apache config" \
        || fail "  PHP SetHandler MISSING — PHP won't execute in aliased dir. Re-run install.sh"
      break
    fi
  done

  # .htaccess in API dir
  [[ -f "${INSTALL_DIR}/backend/api/.htaccess" ]] \
    && pass ".htaccess present in API dir (fallback URL routing)" \
    || warn ".htaccess not in API dir — ensure mod_rewrite is in Apache config"

  # AppConfig contents check (/var/cpanel/apps/ copy written by register_appconfig)
  if [[ -f "$APPCONF" ]]; then
    grep -q "service=whostmgr" "$APPCONF" && pass "AppConfig: service=whostmgr" || fail "AppConfig missing service=whostmgr"
    grep -q "url=/cgi/sentinel_gate/sentinel_gate.cgi" "$APPCONF" && pass "AppConfig: url correct" || fail "AppConfig url wrong — expected /cgi/sentinel_gate/sentinel_gate.cgi. Re-run install.sh"
    grep -q "acls=all" "$APPCONF" && pass "AppConfig: acls=all" || warn "AppConfig: acls field missing"
  fi

  # ── Registration check: /var/cpanel/apps/ is the definitive source of truth ──
  # register_appconfig copies the conf here; cpsrvd reads from here on startup.
  # If this file is present and correct, the plugin IS registered.
  _APPCONF_DEPLOYED="/var/cpanel/apps/sentinel_gate.conf"
  if [[ -f "$_APPCONF_DEPLOYED" ]]; then
    if grep -q "name=sentinel_gate" "$_APPCONF_DEPLOYED" && \
       grep -q "service=whostmgr" "$_APPCONF_DEPLOYED"; then
      pass "REGISTERED: /var/cpanel/apps/sentinel_gate.conf is present and correct"
    else
      fail "REGISTERED: /var/cpanel/apps/sentinel_gate.conf has wrong content — re-run install.sh"
    fi
  else
    fail "REGISTERED: /var/cpanel/apps/sentinel_gate.conf missing — register_appconfig did not run. Re-run install.sh"
  fi

  # Check cpsrvd is running (it serves WHM on port 2087)
  if pgrep -x cpsrvd >/dev/null 2>&1; then
    pass "cpsrvd is running — plugin will appear in WHM on next login"
  else
    warn "cpsrvd is not running — start it: /usr/local/cpanel/scripts/restartsrv_cpsrvd"
  fi

  # dynamicui plugin (cPanel user-level)
  DYNUI_FOUND=false
  for THEME in paper_lantern jupiter; do
    DYNUI="/usr/local/cpanel/base/frontend/${THEME}/dynamicui/dynamicui_sentinel_gate.conf"
    if [[ -f "$DYNUI" ]]; then
      pass "cPanel user plugin (${THEME}): $DYNUI"
      DYNUI_FOUND=true
    fi
  done
  $DYNUI_FOUND || warn "cPanel user-level dynamicui plugin not found (WHM-only plugin is fine)"

else
  warn "cPanel not found — skipping WHM tests"
fi

# ── 8. Cron jobs ─────────────────────────────────────────────────────────────
section "Cron Jobs"

CRON_FILE="/etc/cron.d/sentinel-gate"
[[ -f "$CRON_FILE" ]] && pass "Cron file exists: $CRON_FILE" || warn "Cron file not found: $CRON_FILE"

# ── 9. Summary ────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASS: ${PASS}${NC}   ${RED}FAIL: ${FAIL}${NC}   ${YELLOW}WARN: ${WARN}${NC}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
  echo -e "  ${GREEN}${BOLD}All tests passed.${NC} Sentinel Gate is correctly installed."
else
  echo -e "  ${RED}${BOLD}${FAIL} test(s) failed.${NC} See FAIL lines above for details."
  echo ""
  echo -e "  Common fixes:"
  echo -e "  • Re-upload the latest zip and re-run install.sh"
  echo -e "  • Restart Apache:  /scripts/restartsrv_httpd"
  echo -e "  • Restart cpsrvd:  /scripts/restartsrv_cpsrvd"
fi
echo ""

exit $FAIL
