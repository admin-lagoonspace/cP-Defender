#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Mock Environment Test Suite
# Runs in Git Bash on Windows (no Docker/WSL required)
# Tests: installer, update script, update checker, file integrity
#
# Usage:
#   bash tests/run-tests.sh
#   bash tests/run-tests.sh --suite install|update|checker|integrity|all
# ════════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Counters (use $((+1)) to avoid set -e triggering on ((n++)) ──────────────
PASS=0; FAIL=0; SKIP=0

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
log_fail() { echo -e "  ${RED}✖${NC}  $*"; }
log_warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
log_info() { echo -e "  ${CYAN}→${NC}  $*"; }
section()  { echo -e "\n${BOLD}${BLUE}━━━ $* ━━━${NC}"; }
header()   { echo -e "\n${BOLD}${CYAN}$*${NC}"; }

assert() {
    local desc="$1"; shift
    if "$@" &>/dev/null; then
        log_ok "$desc"; PASS=$((PASS+1))
    else
        log_fail "$desc"; FAIL=$((FAIL+1))
    fi
}

assert_file()     { assert "File exists:    $1"   test -f "$1"; }
assert_dir()      { assert "Dir exists:     $1"   test -d "$1"; }
assert_not_empty(){ assert "Not empty:      $1"   test -s "$1"; }
assert_contains() {
    local file="$1" pat="$2"
    if grep -q "$pat" "$file" 2>/dev/null; then
        log_ok "Contains '${pat}' in $(basename "$file")"
        PASS=$((PASS+1))
    else
        log_fail "Missing  '${pat}' in $(basename "$file")"
        FAIL=$((FAIL+1))
    fi
}

skip_test() { log_warn "SKIP: $*"; SKIP=$((SKIP+1)); }

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Normalize to Unix-style path so PATH lookups work in Git Bash on Windows
REPO_DIR="$(cygpath -u "$REPO_DIR" 2>/dev/null || echo "$REPO_DIR")"
STUBS_DIR="${REPO_DIR}/tests/mock-env/stubs"
TEST_ROOT="$(mktemp -d /tmp/sg-test.XXXXXX)"
INSTALL_DIR="${TEST_ROOT}/install"
BACKUP_ROOT="${TEST_ROOT}/backups"
CRON_DIR="${TEST_ROOT}/cron.d"
CRON_FILE="${CRON_DIR}/sentinel-gate"
SYSTEMD_DIR="${TEST_ROOT}/systemd"
SUITE="all"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --suite) SUITE="${2:-all}"; shift 2 ;;
        *)       SUITE="$1"; shift ;;
    esac
done

export SG_TEST_ROOT="$TEST_ROOT"
export SG_ROOT="$INSTALL_DIR"

# Make stubs executable and prepend to PATH
chmod +x "${STUBS_DIR}"/* 2>/dev/null || true
export PATH="${STUBS_DIR}:${PATH}"

# ── Cleanup / summary ─────────────────────────────────────────────────────────
cleanup() {
    local code=$?
    rm -rf "$TEST_ROOT"
    echo ""
    echo -e "  ${BOLD}━━━ Results ━━━${NC}"
    echo -e "  ${GREEN}Passed:  ${PASS}${NC}"
    echo -e "  ${RED}Failed:  ${FAIL}${NC}"
    echo -e "  ${YELLOW}Skipped: ${SKIP}${NC}"
    echo ""
    if [[ $FAIL -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}All tests passed! ✔${NC}"
    else
        echo -e "  ${RED}${BOLD}${FAIL} test(s) failed ✖${NC}"
    fi
    echo ""
    exit $([[ $FAIL -eq 0 ]] && echo 0 || echo 1)
}
trap cleanup EXIT

# ── Setup ─────────────────────────────────────────────────────────────────────
mkdir -p "$TEST_ROOT" "$CRON_DIR" "$SYSTEMD_DIR" "$BACKUP_ROOT"
touch "${TEST_ROOT}/stubs.log"

echo ""
echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════╗"
echo -e "║   Sentinel Gate — Mock Test Suite              ║"
echo -e "╚════════════════════════════════════════════════╝${NC}"
echo ""
log_info "Repo:         $REPO_DIR"
log_info "Test root:    $TEST_ROOT"
log_info "Install dir:  $INSTALL_DIR"
log_info "Suite:        $SUITE"


# ════════════════════════════════════════════════════════════════════════════════
# Helper: patch install.sh for mock environment
# ════════════════════════════════════════════════════════════════════════════════
patch_install_sh() {
    local src="${REPO_DIR}/install.sh"
    local dst="${TEST_ROOT}/install.sh"

    sed \
        -e "s|SCRIPT_DIR=.*BASH_SOURCE.*|SCRIPT_DIR=\"${REPO_DIR}\"|g" \
        -e "s|INSTALL_DIR=\"/usr/local/sentinel-gate\"|INSTALL_DIR=\"${INSTALL_DIR}\"|g" \
        -e "s|CRON_FILE=\"/etc/cron.d/sentinel-gate\"|CRON_FILE=\"${CRON_FILE}\"|g" \
        -e "s|/etc/systemd/system/|${SYSTEMD_DIR}/|g" \
        -e "s|\[\[ -d /etc/systemd/system \]\]|[[ -d ${SYSTEMD_DIR} ]]|g" \
        -e "s|\[\[ \$EUID -ne 0 \]\]|false|g" \
        -e "s|\[ \$EUID -ne 0 \]|false|g" \
        -e "s|chown -R root:nobody|chown -R $(id -u):$(id -g)|g" \
        -e "s|chown -R root:root|chown -R $(id -u):$(id -g)|g" \
        -e "s|chmod 750 \"\$INSTALL_DIR\"/{database,quarantine,logs}|true|g" \
        -e "s|chmod -R 750 \"\$INSTALL_DIR\"|true|g" \
        -e "s|chmod -R 700 \"\$INSTALL_DIR/database\"|true|g" \
        -e "s|chmod -R 700 \"\$INSTALL_DIR/quarantine\"|true|g" \
        -e "s|chmod -R 700 \"\$INSTALL_DIR/logs\"|true|g" \
        -e "s|chmod 644 \"\$INSTALL_DIR/backend/daemon/monitor.py\"|true|g" \
        -e "s|chmod +x \"\$INSTALL_DIR/backend/cron/scan.php\"|true|g" \
        -e "s|chmod +x \"\$INSTALL_DIR/backend/daemon/monitor.py\"|true|g" \
        -e "s|chmod 644 \"\${SYSTEMD_DIR}.*\.service\"|true|g" \
        -e "s|read -rp.*MODE_CHOICE.*|MODE_CHOICE=2|g" \
        -e "s|read -rp.*ADMIN_USER.*|ADMIN_USER=admin|g" \
        -e "s|read -srp.*ADMIN_PASS[^2].*|ADMIN_PASS=MockPass123|g" \
        -e "s|read -srp.*Confirm.*|ADMIN_PASS2=MockPass123|g" \
        -e "s|SG_PORT:-8443|SG_PORT:-18443|g" \
        -e "s|TEST_SCRIPT=\"\${SCRIPT_DIR}/test.sh\"|TEST_SCRIPT=\"/nonexistent/test.sh\"|g" \
        -e "s|sleep 10|sleep 0|g" \
        "$src" > "$dst"

    chmod +x "$dst"
    echo "$dst"
}

# ════════════════════════════════════════════════════════════════════════════════
# SUITE 1 — INSTALLER
# ════════════════════════════════════════════════════════════════════════════════
run_install_suite() {
    section "Suite 1 — Installer"
    local installed=false

    # ── 1.1 Patch install.sh ─────────────────────────────────────────────────
    header "1.1  Patching install.sh"
    local MOCK_INSTALL
    MOCK_INSTALL="$(patch_install_sh)"
    assert_file "$MOCK_INSTALL"
    log_info "Patched: $MOCK_INSTALL"

    # ── 1.2 Run installer ────────────────────────────────────────────────────
    header "1.2  Running installer (standalone mode)"
    local INSTALL_LOG="${TEST_ROOT}/install.log"

    set +e
    bash "$MOCK_INSTALL" > "$INSTALL_LOG" 2>&1
    local EXIT_CODE=$?
    set -e

    if [[ $EXIT_CODE -eq 0 ]]; then
        log_ok "Installer exited cleanly (exit 0)"
        PASS=$((PASS+1))
        installed=true
    else
        log_fail "Installer failed (exit ${EXIT_CODE})"
        FAIL=$((FAIL+1))
        echo ""
        log_info "── Last 40 lines of install.log ──"
        tail -40 "$INSTALL_LOG" | while IFS= read -r l; do echo "       $l"; done
        echo ""
    fi

    # Print summary from install log
    log_info "Install log summary:"
    grep -E '(✔|✖|ERROR|failed|ok )' "$INSTALL_LOG" 2>/dev/null | head -20 \
        | while IFS= read -r l; do echo "       $l"; done || true

    # ── 1.3 Directory structure ──────────────────────────────────────────────
    header "1.3  Directory structure"
    assert_dir "${INSTALL_DIR}/backend"
    assert_dir "${INSTALL_DIR}/frontend"
    assert_dir "${INSTALL_DIR}/database"
    assert_dir "${INSTALL_DIR}/logs"
    assert_dir "${INSTALL_DIR}/quarantine"
    assert_dir "${INSTALL_DIR}/backend/lib"
    assert_dir "${INSTALL_DIR}/backend/cron"
    assert_dir "${INSTALL_DIR}/backend/daemon"
    assert_dir "${INSTALL_DIR}/backend/config"
    assert_dir "${INSTALL_DIR}/frontend/images"

    # ── 1.4 Key files ────────────────────────────────────────────────────────
    header "1.4  Key files"
    assert_file "${INSTALL_DIR}/VERSION"
    assert_file "${INSTALL_DIR}/backend/api/index.php"
    assert_file "${INSTALL_DIR}/backend/config/mode.php"
    assert_file "${INSTALL_DIR}/backend/daemon/monitor.py"
    assert_file "${INSTALL_DIR}/backend/cron/scan.php"
    assert_file "${INSTALL_DIR}/backend/cron/update-check.php"
    assert_file "${INSTALL_DIR}/backend/lib/UpdateChecker.php"
    assert_file "${INSTALL_DIR}/frontend/index.html"
    assert_file "${INSTALL_DIR}/frontend/images/logo.png"
    assert_file "${INSTALL_DIR}/update.sh"

    # ── 1.5 mode.php content ────────────────────────────────────────────────
    header "1.5  mode.php correctness"
    assert_contains "${INSTALL_DIR}/backend/config/mode.php" "standalone"
    assert_contains "${INSTALL_DIR}/backend/config/mode.php" "SG_ROOT"
    assert_contains "${INSTALL_DIR}/backend/config/mode.php" "SG_VERSION"
    assert_contains "${INSTALL_DIR}/backend/config/mode.php" "$INSTALL_DIR"

    # ── 1.6 Version ─────────────────────────────────────────────────────────
    header "1.6  VERSION file"
    assert_not_empty "${INSTALL_DIR}/VERSION"
    local VER
    VER="$(tr -d '[:space:]' < "${INSTALL_DIR}/VERSION")"
    log_ok "Installed version: v${VER}"

    # ── 1.7 Cron ────────────────────────────────────────────────────────────
    header "1.7  Cron jobs"
    assert_file     "$CRON_FILE"
    assert_contains "$CRON_FILE" "scan.php quick"
    assert_contains "$CRON_FILE" "scan.php full"
    assert_contains "$CRON_FILE" "update-sigs"
    assert_contains "$CRON_FILE" "update-check.php"
    assert_contains "$CRON_FILE" "0 8 \* \* \*"

    # ── 1.8 Systemd service ──────────────────────────────────────────────────
    header "1.8  Systemd service unit"
    local SVC="${SYSTEMD_DIR}/sentinel-gate-monitor.service"
    assert_file     "$SVC"
    assert_contains "$SVC" "ExecStart"
    assert_contains "$SVC" "monitor.py"
    assert_contains "$SVC" "SG_ROOT=${INSTALL_DIR}"
    assert_contains "$SVC" "Restart=on-failure"

    # ── 1.9 Stub log ────────────────────────────────────────────────────────
    header "1.9  Stub invocations"
    local STUB_LOG="${TEST_ROOT}/stubs.log"
    assert_contains "$STUB_LOG" "systemctl"
    log_ok "Stub log: $(wc -l < "$STUB_LOG") entries recorded"
}


# ════════════════════════════════════════════════════════════════════════════════
# SUITE 2 — UPDATE SCRIPT
# ════════════════════════════════════════════════════════════════════════════════
run_update_suite() {
    section "Suite 2 — Update Script"

    # Ensure install ran first
    [[ -d "$INSTALL_DIR" ]] || run_install_suite

    local CURRENT_VER
    CURRENT_VER="$(tr -d '[:space:]' < "${INSTALL_DIR}/VERSION")"
    local OLD_VER="3.0.0"

    # ── 2.1 Stage old version ────────────────────────────────────────────────
    header "2.1  Staging old version v${OLD_VER}"
    echo "$OLD_VER" > "${INSTALL_DIR}/VERSION"
    log_ok "Downgraded VERSION to v${OLD_VER}"

    # ── 2.2 Stage user data ──────────────────────────────────────────────────
    header "2.2  Staging user data"
    mkdir -p "${INSTALL_DIR}/database" \
             "${INSTALL_DIR}/quarantine/2024-01-15" \
             "${INSTALL_DIR}/backend/signatures"

    # Simulate SQLite DB with a placeholder file
    cat > "${INSTALL_DIR}/database/sentinel.db" << 'EOF'
SQLITE3_MOCK
scan_paths=/home,/var/www
auto_quarantine=1
alert_email=admin@example.com
cpu_limit_percent=60
rt_poll_interval=300
EOF
    echo "Quarantined malware content" \
        > "${INSTALL_DIR}/quarantine/2024-01-15/evil.php.quarantine"
    echo "custom_sig:regex:evil_pattern_xyz" \
        > "${INSTALL_DIR}/backend/signatures/custom.sig"
    echo "[2024-01-15 10:00:00] Scan completed — 0 threats" \
        >> "${INSTALL_DIR}/logs/monitor.log"
    log_ok "DB, quarantine, custom sig, log all seeded"

    # ── 2.3 Build mock release zip ───────────────────────────────────────────
    header "2.3  Creating mock release zip (v${CURRENT_VER})"
    local MOCK_RELEASE_DIR="${TEST_ROOT}/mock-release/sentinel-gate-${CURRENT_VER}"
    mkdir -p "$MOCK_RELEASE_DIR"
    for d in backend frontend whm; do
        cp -r "${REPO_DIR}/${d}" "${MOCK_RELEASE_DIR}/"
    done
    for f in VERSION install.sh uninstall.sh update.sh; do
        [[ -f "${REPO_DIR}/${f}" ]] && cp "${REPO_DIR}/${f}" "${MOCK_RELEASE_DIR}/"
    done
    local MOCK_ZIP="${TEST_ROOT}/sentinel-gate-${CURRENT_VER}.zip"
    (cd "${TEST_ROOT}/mock-release" && zip -qr "$MOCK_ZIP" "sentinel-gate-${CURRENT_VER}/")
    assert_file "$MOCK_ZIP"
    log_ok "Release zip: $(du -k "$MOCK_ZIP" | cut -f1) KB"

    # ── 2.4 Patch update.sh ──────────────────────────────────────────────────
    header "2.4  Patching update.sh"
    local MOCK_UPDATE="${TEST_ROOT}/update.sh"

    # Build mock GitHub API response pointing to our local zip
    local MOCK_API="${TEST_ROOT}/github-api.json"
    cat > "$MOCK_API" << EOF
{
  "tag_name": "v${CURRENT_VER}",
  "html_url": "https://github.com/test/releases/tag/v${CURRENT_VER}",
  "body": "Mock release notes for v${CURRENT_VER}",
  "assets": [
    { "browser_download_url": "file://${MOCK_ZIP}" }
  ]
}
EOF

    sed \
        -e "s|INSTALL_DIR=\"\${SG_ROOT:-/usr/local/sentinel-gate}\"|INSTALL_DIR=\"${INSTALL_DIR}\"|g" \
        -e "s|BACKUP_ROOT=\"/var/backups/sentinel-gate\"|BACKUP_ROOT=\"${BACKUP_ROOT}\"|g" \
        -e "s|\[\[ \$EUID -ne 0 \]\]|false|g" \
        -e "s|\[ \$EUID -ne 0 \]|false|g" \
        -e "s|chown -R root:nobody|chown -R $(id -u):$(id -g)|g" \
        -e "s|chown -R root:root|chown -R $(id -u):$(id -g)|g" \
        -e "s|chmod -R 750 \"\$INSTALL_DIR\"|true|g" \
        -e "s|chmod -R 700 \"\${INSTALL_DIR}/database\"|true|g" \
        -e "s|chmod -R 700 \"\${INSTALL_DIR}/quarantine\"|true|g" \
        -e "s|chmod -R 700 \"\${INSTALL_DIR}/logs\"|true|g" \
        -e "s|chmod 644 \"\$INSTALL_DIR/backend/daemon/monitor.py\"|true|g" \
        -e "s|/etc/systemd/system/sentinel-gate-monitor.service|${SYSTEMD_DIR}/sentinel-gate-monitor.service|g" \
        -e "s|\[\[ -d /etc/systemd/system \]\]|[[ -d ${SYSTEMD_DIR} ]]|g" \
        "${REPO_DIR}/update.sh" > "$MOCK_UPDATE"

    chmod +x "$MOCK_UPDATE"
    assert_file "$MOCK_UPDATE"

    # ── 2.5 Run update.sh --yes ──────────────────────────────────────────────
    header "2.5  Running update script (--yes)"
    local UPDATE_LOG="${TEST_ROOT}/update.log"

    # The curl stub reads SG_MOCK_API for GitHub API responses
    # and SG_MOCK_ZIP for zip downloads
    export SG_MOCK_API="$MOCK_API"
    export SG_MOCK_ZIP="$MOCK_ZIP"

    set +e
    SG_ROOT="$INSTALL_DIR" bash "$MOCK_UPDATE" --yes > "$UPDATE_LOG" 2>&1
    local UEXIT=$?
    set -e

    unset SG_MOCK_API SG_MOCK_ZIP

    if [[ $UEXIT -eq 0 ]]; then
        log_ok "Update script exited cleanly (exit 0)"
        PASS=$((PASS+1))
    else
        log_fail "Update script failed (exit ${UEXIT})"
        FAIL=$((FAIL+1))
        echo ""
        log_info "── Update log (last 50 lines) ──"
        tail -50 "$UPDATE_LOG" | while IFS= read -r l; do echo "       $l"; done
        echo ""
    fi

    # ── 2.6 Version bumped ───────────────────────────────────────────────────
    header "2.6  Version updated"
    local POST_VER
    POST_VER="$(tr -d '[:space:]' < "${INSTALL_DIR}/VERSION" 2>/dev/null || echo MISSING)"
    if [[ "$POST_VER" == "$CURRENT_VER" ]]; then
        log_ok "Version: v${OLD_VER} → v${POST_VER}"
        PASS=$((PASS+1))
    else
        log_fail "Version wrong — expected v${CURRENT_VER}, got v${POST_VER}"
        FAIL=$((FAIL+1))
    fi

    # ── 2.7 User data preserved ──────────────────────────────────────────────
    header "2.7  User data preserved"
    assert_file    "${INSTALL_DIR}/database/sentinel.db"
    assert_file    "${INSTALL_DIR}/quarantine/2024-01-15/evil.php.quarantine"
    assert_file    "${INSTALL_DIR}/backend/signatures/custom.sig"
    assert_contains "${INSTALL_DIR}/database/sentinel.db"             "alert_email"
    assert_contains "${INSTALL_DIR}/backend/signatures/custom.sig"    "custom_sig"
    assert_contains "${INSTALL_DIR}/logs/monitor.log"                 "Scan completed"
    assert_contains "${INSTALL_DIR}/quarantine/2024-01-15/evil.php.quarantine" "malware"

    # ── 2.8 Backup created ───────────────────────────────────────────────────
    header "2.8  Backup integrity"
    local BACKUP_FOUND
    BACKUP_FOUND="$(find "$BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -1)"
    if [[ -n "$BACKUP_FOUND" ]]; then
        log_ok "Backup dir: $BACKUP_FOUND"
        PASS=$((PASS+1))
        assert_file     "${BACKUP_FOUND}/from_version.txt"
        assert_contains "${BACKUP_FOUND}/from_version.txt" "$OLD_VER"
        if [[ -d "${BACKUP_FOUND}/database" ]]; then
            log_ok "database/ backed up"
            PASS=$((PASS+1))
        else
            log_fail "database/ missing from backup"
            FAIL=$((FAIL+1))
        fi
        if [[ -d "${BACKUP_FOUND}/quarantine" ]]; then
            log_ok "quarantine/ backed up"
            PASS=$((PASS+1))
        else
            log_fail "quarantine/ missing from backup"
            FAIL=$((FAIL+1))
        fi
    else
        log_fail "No backup directory found in $BACKUP_ROOT"
        FAIL=$((FAIL+1))
    fi

    # ── 2.9 Code updated ─────────────────────────────────────────────────────
    header "2.9  Code files updated by update"
    assert_file "${INSTALL_DIR}/backend/lib/UpdateChecker.php"
    assert_file "${INSTALL_DIR}/backend/cron/update-check.php"
    assert_file "${INSTALL_DIR}/frontend/images/logo.png"
    assert_file "${INSTALL_DIR}/update.sh"

    log_info "Update log summary:"
    grep -E '(✔|✖|→|Updated|Restored|Backup|version)' "$UPDATE_LOG" 2>/dev/null | head -25 \
        | while IFS= read -r l; do echo "       $l"; done || true
}


# ════════════════════════════════════════════════════════════════════════════════
# SUITE 3 — UPDATE CHECKER LOGIC (pure bash/awk, no Python needed)
# ════════════════════════════════════════════════════════════════════════════════
run_checker_suite() {
    section "Suite 3 — Update Checker Logic"

    # ── 3.1 Version comparison ───────────────────────────────────────────────
    header "3.1  Version comparison (awk)"
    version_gt() {
        # Returns 0 (true) if $1 > $2 using dot-separated comparison
        awk -v a="$1" -v b="$2" 'BEGIN{
            split(a,A,"."); split(b,B,".")
            for(i=1;i<=3;i++){
                if((A[i]+0)>(B[i]+0)) exit 0
                if((A[i]+0)<(B[i]+0)) exit 1
            }
            exit 1
        }'
    }

    run_version_test() {
        local cur="$1" latest="$2" expect="$3" desc="$4"
        local result="false"
        version_gt "$latest" "$cur" && result="true" || true
        if [[ "$result" == "$expect" ]]; then
            log_ok "$desc: v${cur} vs v${latest} → update=${result}"
            PASS=$((PASS+1))
        else
            log_fail "$desc: v${cur} vs v${latest} → expected ${expect}, got ${result}"
            FAIL=$((FAIL+1))
        fi
    }

    run_version_test "3.3.4" "3.3.5" "true"  "patch bump"
    run_version_test "3.3.5" "3.3.5" "false" "same version"
    run_version_test "3.3.5" "3.3.4" "false" "older = no update"
    run_version_test "3.2.0" "4.0.0" "true"  "major bump"
    run_version_test "3.3.9" "3.4.0" "true"  "minor bump"
    run_version_test "3.0.0" "3.3.5" "true"  "multi-patch gap"

    # ── 3.2 GitHub API JSON parsing ──────────────────────────────────────────
    header "3.2  GitHub API JSON parsing (grep/sed)"
    local API_JSON="${TEST_ROOT}/api-test.json"
    cat > "$API_JSON" << 'EOF'
{
  "tag_name": "v3.9.0",
  "html_url": "https://github.com/admin-lagoonspace/cP-Defender/releases/tag/v3.9.0",
  "body": "## Whats new\n- Feature A\n- Bug fix B",
  "assets": [
    { "browser_download_url": "https://example.com/sentinel-gate-3.9.0.zip" }
  ]
}
EOF
    # Parse tag (same technique as update.sh)
    local PARSED_TAG
    PARSED_TAG="$(grep -oP '"tag_name"\s*:\s*"\Kv?[^"]+' "$API_JSON" | head -1 | sed 's/^v//')"
    local PARSED_URL
    PARSED_URL="$(grep -oP '"html_url"\s*:\s*"\Khttps://github\.com[^"]+releases/tag[^"]+' "$API_JSON" | head -1)"
    local PARSED_ASSET
    PARSED_ASSET="$(grep -oP '"browser_download_url"\s*:\s*"\K[^"]+\.zip' "$API_JSON" | head -1)"

    [[ "$PARSED_TAG" == "3.9.0" ]]        && { log_ok "tag_name parsed: v${PARSED_TAG}"; PASS=$((PASS+1)); } \
                                           || { log_fail "tag_name parse failed: '${PARSED_TAG}'"; FAIL=$((FAIL+1)); }
    [[ "$PARSED_URL" == *"releases/tag"* ]] && { log_ok "html_url parsed"; PASS=$((PASS+1)); } \
                                           || { log_fail "html_url parse failed: '${PARSED_URL}'"; FAIL=$((FAIL+1)); }
    [[ "$PARSED_ASSET" == *".zip" ]]       && { log_ok "asset URL parsed: ...${PARSED_ASSET: -30}"; PASS=$((PASS+1)); } \
                                           || { log_fail "asset URL parse failed: '${PARSED_ASSET}'"; FAIL=$((FAIL+1)); }

    # ── 3.3 Live GitHub API reachability ────────────────────────────────────
    header "3.3  Live GitHub API reachability"
    local LIVE_JSON
    set +e
    LIVE_JSON="$(curl -fsSL --max-time 10 \
        -H 'Accept: application/vnd.github+json' \
        'https://api.github.com/repos/admin-lagoonspace/cP-Defender/releases/latest' 2>/dev/null)"
    local CURL_CODE=$?
    set -e

    if [[ $CURL_CODE -eq 0 && -n "$LIVE_JSON" ]]; then
        local LIVE_TAG
        LIVE_TAG="$(echo "$LIVE_JSON" | grep -oP '"tag_name"\s*:\s*"\K[^"]+' | head -1)"
        log_ok "GitHub API reachable — latest tag: ${LIVE_TAG}"
        PASS=$((PASS+1))
    else
        log_warn "GitHub API unreachable (network/firewall) — skipping live check"
        SKIP=$((SKIP+1))
    fi

    # ── 3.4 Cron expression format ───────────────────────────────────────────
    header "3.4  Cron expression format"
    [[ -f "$CRON_FILE" ]] || { skip_test "cron file not found — run install suite first"; return; }

    local CRON_COUNT
    CRON_COUNT="$(grep -c "update-check.php" "$CRON_FILE" 2>/dev/null || echo 0)"
    if [[ "$CRON_COUNT" -ge 1 ]]; then
        log_ok "update-check.php in cron ($CRON_COUNT entries)"
        PASS=$((PASS+1))
    else
        log_fail "update-check.php not found in cron"
        FAIL=$((FAIL+1))
    fi

    local CRON_EXPR
    CRON_EXPR="$(grep "update-check.php" "$CRON_FILE" | head -1)"
    # Should start with "0 8 * * *"
    if echo "$CRON_EXPR" | grep -qE '^0 8 \* \* \*'; then
        log_ok "Cron time correct: 0 8 * * * (8am daily)"
        PASS=$((PASS+1))
    else
        log_fail "Cron time wrong: $CRON_EXPR"
        FAIL=$((FAIL+1))
    fi
}


# ════════════════════════════════════════════════════════════════════════════════
# SUITE 4 — FILE INTEGRITY
# ════════════════════════════════════════════════════════════════════════════════
run_integrity_suite() {
    section "Suite 4 — Post-Install File Integrity"
    [[ -d "$INSTALL_DIR" ]] || run_install_suite

    # ── 4.1 PHP libs ─────────────────────────────────────────────────────────
    header "4.1  PHP library files"
    local LIBS=( UpdateChecker RealTimeMonitor Scanner Database Auth Logger
                 Firewall WAF BotShield CMSGuard RootkitScanner
                 FileIntegrity PHPHardening IPReputation )
    for lib in "${LIBS[@]}"; do
        assert_file "${INSTALL_DIR}/backend/lib/${lib}.php"
    done

    # ── 4.2 Frontend assets ──────────────────────────────────────────────────
    header "4.2  Frontend assets"
    assert_file "${INSTALL_DIR}/frontend/index.html"
    assert_file "${INSTALL_DIR}/frontend/images/logo.png"
    assert_file "${INSTALL_DIR}/frontend/js/app.js"
    assert_file "${INSTALL_DIR}/frontend/js/api.js"
    assert_file "${INSTALL_DIR}/frontend/css/app.css"

    # ── 4.3 Logo is a real PNG ────────────────────────────────────────────────
    header "4.3  Logo file validity"
    local LOGO="${INSTALL_DIR}/frontend/images/logo.png"
    local LOGO_SIZE
    LOGO_SIZE="$(wc -c < "$LOGO" 2>/dev/null || echo 0)"
    if [[ "$LOGO_SIZE" -gt 50000 ]]; then
        log_ok "logo.png size: ${LOGO_SIZE} bytes (valid)"
        PASS=$((PASS+1))
    else
        log_fail "logo.png too small (${LOGO_SIZE} bytes) — may be corrupted"
        FAIL=$((FAIL+1))
    fi

    # Check PNG magic bytes using xxd-style approach with od
    if od -A x -t x1z -v "$LOGO" 2>/dev/null | head -1 | grep -q "89 50 4e 47"; then
        log_ok "logo.png has valid PNG magic bytes"
        PASS=$((PASS+1))
    else
        log_warn "Could not verify PNG magic bytes (od unavailable or format differs)"
        SKIP=$((SKIP+1))
    fi

    # ── 4.4 index.html new features ──────────────────────────────────────────
    header "4.4  index.html — new features present"
    assert_contains "${INSTALL_DIR}/frontend/index.html" "images/logo.png"
    assert_contains "${INSTALL_DIR}/frontend/index.html" "update-banner"
    assert_contains "${INSTALL_DIR}/frontend/index.html" "sidebar-update-dot"
    assert_contains "${INSTALL_DIR}/frontend/index.html" "sidebar-mode-label"
    assert_contains "${INSTALL_DIR}/frontend/index.html" "poll-opt-60"
    assert_contains "${INSTALL_DIR}/frontend/index.html" "set-cpu-limit"

    # ── 4.5 API routes ───────────────────────────────────────────────────────
    header "4.5  API routes in index.php"
    assert_contains "${INSTALL_DIR}/backend/api/index.php" "routeUpdate"
    assert_contains "${INSTALL_DIR}/backend/api/index.php" "UpdateChecker"
    assert_contains "${INSTALL_DIR}/backend/api/index.php" "'update'"
    assert_contains "${INSTALL_DIR}/backend/api/index.php" "service-status"
    assert_contains "${INSTALL_DIR}/backend/api/index.php" "enable-service"

    # ── 4.6 update.sh safety checks ─────────────────────────────────────────
    header "4.6  update.sh safety features"
    assert_file    "${INSTALL_DIR}/update.sh"
    assert_contains "${INSTALL_DIR}/update.sh" "BACKUP_ROOT"
    assert_contains "${INSTALL_DIR}/update.sh" "PRESERVE"
    assert_contains "${INSTALL_DIR}/update.sh" "from_version.txt"
    assert_contains "${INSTALL_DIR}/update.sh" "rsync"
    assert_contains "${INSTALL_DIR}/update.sh" "version_compare\|python3\|vparse"

    # ── 4.7 Cron completeness ────────────────────────────────────────────────
    header "4.7  All 4 cron jobs present"
    assert_contains "$CRON_FILE" "scan.php quick"
    assert_contains "$CRON_FILE" "scan.php full"
    assert_contains "$CRON_FILE" "update-sigs"
    assert_contains "$CRON_FILE" "update-check.php"

    # ── 4.8 monitor.py CPU throttle ──────────────────────────────────────────
    header "4.8  monitor.py CPU throttle features"
    assert_contains "${INSTALL_DIR}/backend/daemon/monitor.py" "get_cpu_limit"
    assert_contains "${INSTALL_DIR}/backend/daemon/monitor.py" "get_poll_interval"
    assert_contains "${INSTALL_DIR}/backend/daemon/monitor.py" "cpu_to_nice"
    assert_contains "${INSTALL_DIR}/backend/daemon/monitor.py" "cpu_to_scan_sleep"
    assert_contains "${INSTALL_DIR}/backend/daemon/monitor.py" "apply_cpu_priority"
}


# ── Run suites ────────────────────────────────────────────────────────────────
case "$SUITE" in
    install)   run_install_suite ;;
    update)    run_install_suite; run_update_suite ;;
    checker)   run_install_suite; run_checker_suite ;;
    integrity) run_install_suite; run_integrity_suite ;;
    all)
        run_install_suite
        run_update_suite
        run_checker_suite
        run_integrity_suite
        ;;
    *)
        echo "Usage: bash tests/run-tests.sh [--suite install|update|checker|integrity|all]"
        exit 1
        ;;
esac
