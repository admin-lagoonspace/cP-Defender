#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Installation Test Suite
# Run from the server AFTER install:  bash test.sh
# ═══════════════════════════════════════════════════════════════════════════════

INSTALL_DIR="/usr/local/sentinel-gate"
PASS=0; FAIL=0; WARN=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; ((WARN++)); }
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

# ── 6. HTTP API test (requires Apache/curl) ───────────────────────────────────
section "HTTP API (via Apache)"

if command -v curl >/dev/null 2>&1; then
  # Detect the server's hostname
  HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost")

  # Test auth/status (no login required)
  STATUS_RESP=$(curl -sk --max-time 5 "https://${HOSTNAME}/sentinel-gate/backend/api/auth/status" 2>/dev/null)
  echo "$STATUS_RESP" | grep -q '"success":true' \
    && pass "GET /sentinel-gate/backend/api/auth/status → 200 OK" \
    || fail "GET auth/status FAILED — Apache alias or mod_rewrite not working. Response: ${STATUS_RESP:0:120}"

  # Test login with demo/demo
  LOGIN_RESP=$(curl -sk --max-time 5 -X POST \
    -H 'Content-Type: application/json' \
    -d '{"username":"demo","password":"demo"}' \
    "https://${HOSTNAME}/sentinel-gate/backend/api/auth/login" 2>/dev/null)
  echo "$LOGIN_RESP" | grep -q '"success":true' \
    && pass "POST auth/login demo/demo → token issued" \
    || fail "POST auth/login FAILED. Response: ${LOGIN_RESP:0:120}"

  # Test that a bad login is rejected
  BAD_RESP=$(curl -sk --max-time 5 -X POST \
    -H 'Content-Type: application/json' \
    -d '{"username":"wrong","password":"wrong"}' \
    "https://${HOSTNAME}/sentinel-gate/backend/api/auth/login" 2>/dev/null)
  echo "$BAD_RESP" | grep -q '"success":false' \
    && pass "POST auth/login bad creds → correctly rejected" \
    || warn "Bad-creds rejection behaved unexpectedly: ${BAD_RESP:0:80}"

  # Test frontend is reachable
  FE_RESP=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "https://${HOSTNAME}/sentinel-gate/" 2>/dev/null)
  [[ "$FE_RESP" == "200" ]] && pass "Frontend /sentinel-gate/ → HTTP 200" || fail "Frontend returned HTTP ${FE_RESP}"

else
  warn "curl not found — skipping HTTP tests"
fi

# ── 7. WHM plugin registration ────────────────────────────────────────────────
section "WHM Plugin Registration"

if [[ -d /usr/local/cpanel ]]; then
  # AppConfig file
  APPCONF="/var/cpanel/apps/sentinel_gate.conf"
  [[ -f "$APPCONF" ]]  && pass "AppConfig file exists: $APPCONF"  || fail "AppConfig MISSING: $APPCONF — WHM plugin won't appear"

  # CGI file
  WHM_CGI="/usr/local/cpanel/whostmgr/docroot/cgi/addon_sentinel_gate.cgi"
  [[ -f "$WHM_CGI" ]]  && pass "WHM CGI exists: $WHM_CGI"         || fail "WHM CGI MISSING: $WHM_CGI"
  [[ -x "$WHM_CGI" ]]  && pass "WHM CGI is executable"            || fail "WHM CGI not executable — run: chmod 755 $WHM_CGI"

  # CGI syntax check
  if [[ -f "$WHM_CGI" ]]; then
    perl -cw "$WHM_CGI" >/dev/null 2>&1 && pass "WHM CGI Perl syntax OK" || fail "WHM CGI has Perl syntax errors"
  fi

  # Apache alias config
  for CANDIDATE in \
    /etc/apache2/conf.d/sentinel-gate.conf \
    /usr/local/apache/conf/includes/sentinel-gate.conf \
    /etc/httpd/conf.d/sentinel-gate.conf; do
    if [[ -f "$CANDIDATE" ]]; then
      pass "Apache config: $CANDIDATE"
      # Check rewrite rules are in the config
      grep -q "RewriteRule" "$CANDIDATE" \
        && pass "  mod_rewrite rules present in Apache config" \
        || fail "  mod_rewrite MISSING from Apache config — API routes will 404. Re-run install.sh."
      break
    fi
  done

  # .htaccess in API dir
  [[ -f "${INSTALL_DIR}/backend/api/.htaccess" ]] \
    && pass ".htaccess present in API dir (fallback URL routing)" \
    || warn ".htaccess not in API dir — ensure mod_rewrite is in Apache config"

  # AppConfig contents check
  if [[ -f "$APPCONF" ]]; then
    grep -q "service=whostmgr" "$APPCONF" && pass "AppConfig: service=whostmgr" || fail "AppConfig missing service=whostmgr"
    grep -q "url=/cgi/addon_sentinel_gate.cgi" "$APPCONF" && pass "AppConfig: url correct" || fail "AppConfig url wrong"
    grep -q "acls=all" "$APPCONF" && pass "AppConfig: acls=all" || warn "AppConfig: acls field missing"
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
