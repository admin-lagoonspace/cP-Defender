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

SG_CDN_HOST="${SG_CDN_HOST:-defender.lws-s1.com}"
SG_CDN_PROTO="${SG_CDN_PROTO:-ftps}"          # sftp | ftps | ftp
SG_CDN_PATH="${SG_CDN_PATH:-/public_html/sentinel-gate/code}"
SG_CDN_PORT="${SG_CDN_PORT:-}"

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
echo -e "${BOLD}Publishing Sentinel Gate v${VERSION} to ${SG_CDN_HOST}${NC}"
info "Transport: ${SG_CDN_PROTO}   Remote path: ${SG_CDN_PATH}"
[[ "$SG_CDN_PROTO" == "ftp" ]] && warn "Plain FTP sends your password in CLEARTEXT. Use sftp or ftps if the host supports it."
echo ""

# ── Upload ────────────────────────────────────────────────────────────────────
# lftp handles all three transports and does atomic-ish mirroring. Preferred.
if command -v lftp >/dev/null 2>&1; then
  case "$SG_CDN_PROTO" in
    sftp) URL="sftp://${SG_CDN_HOST}${SG_CDN_PORT:+:$SG_CDN_PORT}" ;;
    ftps) URL="ftps://${SG_CDN_HOST}${SG_CDN_PORT:+:$SG_CDN_PORT}" ;;
    ftp)  URL="ftp://${SG_CDN_HOST}${SG_CDN_PORT:+:$SG_CDN_PORT}"  ;;
    *)    die "Unknown SG_CDN_PROTO: ${SG_CDN_PROTO} (use sftp|ftps|ftp)" ;;
  esac
  info "Uploading via lftp…"
  # -f script via stdin so the password never appears in the process list (ps aux)
  lftp -u "${SG_CDN_USER},${SG_CDN_PASS}" "$URL" <<LFTPEOF
set ssl:verify-certificate yes
set net:max-retries 3
set net:timeout 20
mkdir -p ${SG_CDN_PATH}/dist
mirror -R --verbose --only-newer ${UPLOAD_DIR}/ ${SG_CDN_PATH}/
bye
LFTPEOF
  ok "Upload complete via lftp"

elif command -v curl >/dev/null 2>&1; then
  case "$SG_CDN_PROTO" in
    sftp) SCHEME="sftp"; EXTRA=() ;;
    ftps) SCHEME="ftp";  EXTRA=(--ssl-reqd) ;;
    ftp)  SCHEME="ftp";  EXTRA=() ;;
    *)    die "Unknown SG_CDN_PROTO: ${SG_CDN_PROTO}" ;;
  esac
  warn "lftp not found — using curl (uploads file-by-file, no mirroring)"
  # --ftp-create-dirs makes the remote dist/ if absent.
  # Credentials go via a config file on stdin so they stay out of `ps` output.
  upload_one() { # upload_one <local> <remote-rel>
    local src="$1" rel="$2"
    info "  ${rel}"
    curl --fail --silent --show-error "${EXTRA[@]}" \
      --ftp-create-dirs \
      --config <(printf 'user = "%s:%s"\n' "$SG_CDN_USER" "$SG_CDN_PASS") \
      --upload-file "$src" \
      "${SCHEME}://${SG_CDN_HOST}${SG_CDN_PORT:+:$SG_CDN_PORT}${SG_CDN_PATH}/${rel}" \
      || die "Upload failed: ${rel}"
  }
  # Zip first, manifest LAST — until latest.json flips, no client can be pointed
  # at a zip that isn't fully uploaded yet.
  upload_one "${UPLOAD_DIR}/dist/${ZIP_NAME}" "dist/${ZIP_NAME}"
  [[ -f "${UPLOAD_DIR}/get.sh" ]] && upload_one "${UPLOAD_DIR}/get.sh" "get.sh"
  upload_one "${UPLOAD_DIR}/latest.json" "latest.json"
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

# Confirm the zip is fetchable and matches the manifest checksum
WANT_SHA="$(printf '%s' "$LIVE_JSON" | grep -oE '"sha256"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
TMP_ZIP="$(mktemp)"; trap 'rm -f "$TMP_ZIP"' EXIT
if curl -fsSL --max-time 300 -o "$TMP_ZIP" "${BASE_URL}/dist/${ZIP_NAME}"; then
  GOT_SHA="$(sha256sum "$TMP_ZIP" | awk '{print $1}')"
  [[ "$GOT_SHA" == "$WANT_SHA" ]] \
    && ok "Zip downloads and checksum matches" \
    || die "Live zip checksum MISMATCH — expected ${WANT_SHA}, got ${GOT_SHA}."
else
  die "Zip not fetchable at ${BASE_URL}/dist/${ZIP_NAME}"
fi

echo ""
ok "Channel live: ${BASE_URL}"
echo -e "  Install command:"
echo -e "  ${BOLD}bash <(curl -fsSL ${BASE_URL}/get.sh)${NC}"
echo ""
