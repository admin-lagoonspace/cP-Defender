#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — publish the staged release to the public CDN
#
# Uploads dist/upload/  →  the web root behind https://defender.lws-s1.com/sentinel-gate/code
# so the tree lines up 1:1:
#     <docroot>/latest.json
#     <docroot>/get.sh
#     <docroot>/dist/sentinel-gate-<version>.zip
#
# Run scripts/make-release.sh first (it produces dist/upload/).
#
# ── CREDENTIALS ───────────────────────────────────────────────────────────────
# Read from the environment at runtime ONLY. Never commit them, never hardcode
# them in this file. Put them in a gitignored file and source it:
#
#     # ~/.sentinel-cdn.env   (chmod 600, OUTSIDE the repo)
#     export SG_CDN_USER='your-ftp-user'
#     export SG_CDN_PASS='your-ftp-password'
#
#     source ~/.sentinel-cdn.env && bash scripts/upload-cdn.sh
#
# Prefer SFTP (SSH) when the host allows it — plain FTP sends the password in
# cleartext. Choose the transport with SG_CDN_PROTO=sftp|ftps|ftp.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPLOAD_DIR="${REPO_DIR}/dist/upload"

# ── Upload target vs. public URL are DIFFERENT hosts, deliberately ────────────
# The server's FTPS certificate is issued for host.lws-s1.com (CN is actually
# autoconfig.host.lws-s1.com, with host.lws-s1.com in the SANs). Connecting to
# defender.lws-s1.com therefore fails TLS hostname verification:
#     verify error:num=62: hostname mismatch
# which is what made lftp burn its retries and die with "max-retries exceeded".
#
# host.lws-s1.com resolves to the SAME server (51.68.163.24) and validates
# cleanly, so we upload there — certificate verification stays ON — while the
# files are still published under defender.lws-s1.com over HTTPS.
SG_CDN_FTP_HOST="${SG_CDN_FTP_HOST:-host.lws-s1.com}"   # where we upload TO
SG_CDN_HOST="${SG_CDN_HOST:-defender.lws-s1.com}"       # where it is SERVED from
SG_CDN_PROTO="${SG_CDN_PROTO:-ftps}"                    # sftp | ftps | ftp
# Path relative to the FTP user's home (/home/lwss1). The addon domain has its
# own docroot, so the domain name IS part of the path — confirmed against the
# live server's directory tree:
#   /home/lwss1/public_html/defender.lws-s1.com/sentinel-gate/code
SG_CDN_PATH="${SG_CDN_PATH:-/public_html/defender.lws-s1.com/sentinel-gate/code}"
SG_CDN_PORT="${SG_CDN_PORT:-}"
# Last resort only. Skips TLS certificate validation — traffic stays encrypted
# but is no longer MITM-proof. Prefer fixing SG_CDN_FTP_HOST.
SG_CDN_INSECURE="${SG_CDN_INSECURE:-0}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "  ${RED}✖${NC}  $*" >&2; exit 1; }

# ── Preconditions ─────────────────────────────────────────────────────────────
[[ -d "$UPLOAD_DIR" ]] || die "No staged upload tree at ${UPLOAD_DIR}. Run: bash scripts/make-release.sh"
[[ -f "${UPLOAD_DIR}/latest.json" ]] || die "Missing ${UPLOAD_DIR}/latest.json"

: "${SG_CDN_USER:?SG_CDN_USER is not set — see the header of this script}"
: "${SG_CDN_PASS:?SG_CDN_PASS is not set — see the header of this script}"

VERSION="$(tr -d '[:space:]' < "${REPO_DIR}/VERSION")"
ZIP_NAME="sentinel-gate-${VERSION}.zip"
[[ -f "${UPLOAD_DIR}/dist/${ZIP_NAME}" ]] || die "Missing ${UPLOAD_DIR}/dist/${ZIP_NAME}"

echo ""
echo -e "${BOLD}Publishing Sentinel Gate v${VERSION}${NC}"
info "Upload host : ${SG_CDN_FTP_HOST}  (${SG_CDN_PROTO})"
info "Served from : https://${SG_CDN_HOST}/sentinel-gate/code"
info "Remote path : ${SG_CDN_PATH}"
[[ "$SG_CDN_PROTO" == "ftp" ]] && warn "Plain FTP sends your password in CLEARTEXT. Prefer ftps."
[[ "$SG_CDN_INSECURE" == "1" ]] && warn "SG_CDN_INSECURE=1 — TLS certificate will NOT be validated."
echo ""

# ── Upload ────────────────────────────────────────────────────────────────────
# lftp handles all three transports and mirrors whole trees. Preferred.
if command -v lftp >/dev/null 2>&1; then
  case "$SG_CDN_PROTO" in
    sftp) URL="sftp://${SG_CDN_FTP_HOST}${SG_CDN_PORT:+:$SG_CDN_PORT}" ;;
    ftps) URL="ftps://${SG_CDN_FTP_HOST}${SG_CDN_PORT:+:$SG_CDN_PORT}" ;;
    ftp)  URL="ftp://${SG_CDN_FTP_HOST}${SG_CDN_PORT:+:$SG_CDN_PORT}"  ;;
    *)    die "Unknown SG_CDN_PROTO: ${SG_CDN_PROTO} (use sftp|ftps|ftp)" ;;
  esac

  VERIFY_CERT=yes
  [[ "$SG_CDN_INSECURE" == "1" ]] && VERIFY_CERT=no

  info "Uploading via lftp…"
  # Script fed on stdin so the password never lands in the process list (ps aux).
  # Passive mode is forced: a CI runner sits behind NAT, so an active-mode data
  # channel back to the runner cannot be established.
  set +e
  lftp -u "${SG_CDN_USER},${SG_CDN_PASS}" "$URL" <<LFTPEOF 2>&1 | tee /tmp/lftp.log
set ssl:verify-certificate ${VERIFY_CERT}
set ftp:ssl-force true
set ftp:ssl-protect-data true
set ftp:passive-mode true
set net:max-retries 3
set net:timeout 25
set net:reconnect-interval-base 5
set mirror:parallel-transfer-count 1
mkdir -p ${SG_CDN_PATH}
mkdir -p ${SG_CDN_PATH}/dist
mkdir -p ${SG_CDN_PATH}/v${VERSION}
mirror -R --verbose --overwrite ${UPLOAD_DIR}/ ${SG_CDN_PATH}/
bye
LFTPEOF
  RC=${PIPESTATUS[0]}
  set -e

  if [[ $RC -ne 0 ]]; then
    echo ""
    err_msg="$(cat /tmp/lftp.log 2>/dev/null | tail -5)"
    echo -e "  ${RED}✖${NC}  lftp failed (exit ${RC}):"
    printf '      %s\n' "$err_msg"
    echo ""
    if grep -qiE 'certificate|verify|hostname' /tmp/lftp.log 2>/dev/null; then
      warn "This looks like a TLS certificate problem."
      warn "The cert is valid for host.lws-s1.com, NOT defender.lws-s1.com."
      warn "Upload via the cert's hostname:  SG_CDN_FTP_HOST=host.lws-s1.com"
      warn "Or, as a last resort:            SG_CDN_INSECURE=1"
    elif grep -qiE 'max-retries|timeout|refused' /tmp/lftp.log 2>/dev/null; then
      warn "Connection could not be established. Check that port 21 is reachable"
      warn "and that the FTP account is not IP-restricted in cPanel."
    fi
    die "Upload aborted — nothing was published."
  fi
  ok "Upload complete via lftp"

elif command -v curl >/dev/null 2>&1; then
  case "$SG_CDN_PROTO" in
    sftp) SCHEME="sftp"; EXTRA=() ;;
    ftps) SCHEME="ftp";  EXTRA=(--ssl-reqd); [[ "$SG_CDN_INSECURE" == "1" ]] && EXTRA+=(-k) ;;
    ftp)  SCHEME="ftp";  EXTRA=() ;;
    *)    die "Unknown SG_CDN_PROTO: ${SG_CDN_PROTO}" ;;
  esac
  warn "lftp not found — using curl (uploads file-by-file, no mirroring)"
  # --ftp-create-dirs makes remote dirs if absent.
  # Credentials go via a config file on stdin so they stay out of `ps` output.
  upload_one() { # upload_one <local> <remote-rel>
    local src="$1" rel="$2"
    info "  ${rel}"
    curl --fail --silent --show-error "${EXTRA[@]}" \
      --ftp-create-dirs \
      --config <(printf 'user = "%s:%s"\n' "$SG_CDN_USER" "$SG_CDN_PASS") \
      --upload-file "$src" \
      "${SCHEME}://${SG_CDN_FTP_HOST}${SG_CDN_PORT:+:$SG_CDN_PORT}${SG_CDN_PATH}/${rel}" \
      || die "Upload failed: ${rel}"
  }
  # ORDER MATTERS: every artifact goes up BEFORE latest.json. Until the manifest
  # flips, no client can be pointed at a zip that is still mid-transfer.
  upload_one "${UPLOAD_DIR}/v${VERSION}/${ZIP_NAME}"   "v${VERSION}/${ZIP_NAME}"
  [[ -f "${UPLOAD_DIR}/v${VERSION}/CHANGELOG.md" ]] && \
    upload_one "${UPLOAD_DIR}/v${VERSION}/CHANGELOG.md" "v${VERSION}/CHANGELOG.md"
  upload_one "${UPLOAD_DIR}/v${VERSION}/latest.json"   "v${VERSION}/latest.json"
  upload_one "${UPLOAD_DIR}/dist/${ZIP_NAME}"          "dist/${ZIP_NAME}"
  [[ -f "${UPLOAD_DIR}/get.sh" ]] && upload_one "${UPLOAD_DIR}/get.sh" "get.sh"
  upload_one "${UPLOAD_DIR}/latest.json"               "latest.json"
  ok "Upload complete via curl"

else
  die "Need lftp or curl to upload. Install one:  yum install -y lftp  |  apt install -y lftp"
fi

# ── Verify the live channel actually serves what we just pushed ───────────────
echo ""
info "Verifying live channel…"
BASE_URL="${SG_CDN_URL:-https://${SG_CDN_HOST}/sentinel-gate/code}"

LIVE_JSON="$(curl -fsSL --max-time 20 "${BASE_URL}/latest.json" 2>/dev/null)" \
  || die "latest.json is not readable at ${BASE_URL}/latest.json — check the remote path and that the dir is web-accessible."
LIVE_VER="$(printf '%s' "$LIVE_JSON" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
[[ "$LIVE_VER" == "$VERSION" ]] \
  && ok "latest.json live and reports v${LIVE_VER}" \
  || die "Live manifest reports v${LIVE_VER}, expected v${VERSION}."

# Confirm every published copy is fetchable and matches the manifest checksum
WANT_SHA="$(printf '%s' "$LIVE_JSON" | grep -oE '"sha256"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
TMP_ZIP="$(mktemp)"; trap 'rm -f "$TMP_ZIP"' EXIT
for REL in "dist/${ZIP_NAME}" "v${VERSION}/${ZIP_NAME}"; do
  if curl -fsSL --max-time 300 -o "$TMP_ZIP" "${BASE_URL}/${REL}"; then
    GOT_SHA="$(sha256sum "$TMP_ZIP" | awk '{print $1}')"
    [[ "$GOT_SHA" == "$WANT_SHA" ]] \
      && ok "${REL} — downloads, checksum matches" \
      || die "${REL} checksum MISMATCH — expected ${WANT_SHA}, got ${GOT_SHA}."
  else
    die "Not fetchable: ${BASE_URL}/${REL}"
  fi
done

# get.sh must be live — it is the one URL with no fallback, since nothing has
# run yet at the moment a user curls it.
curl -fsSL --max-time 20 "${BASE_URL}/get.sh" -o /dev/null \
  && ok "get.sh — served" \
  || die "get.sh NOT reachable at ${BASE_URL}/get.sh — the install one-liner will 404."

echo ""
ok "Channel live: ${BASE_URL}"
echo ""
echo -e "  ${BOLD}Install (any server type):${NC}"
echo -e "    bash <(curl -fsSL ${BASE_URL}/get.sh)"
echo ""
echo -e "  ${BOLD}Pin this exact version:${NC}"
echo -e "    SG_VERSION=${VERSION} bash <(curl -fsSL ${BASE_URL}/get.sh)"
echo ""
echo -e "  ${BOLD}Archived at:${NC} ${BASE_URL}/v${VERSION}/"
echo ""
