#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Release builder
# Builds the distributable zip, computes its SHA256, and writes latest.json so the
# update channel is always internally consistent (kills filename/hash drift).
#
# Usage:
#   bash scripts/make-release.sh                 # build for the version in ./VERSION
#   bash scripts/make-release.sh --out dist      # write zip + manifest into dist/
#   SG_RELEASES_REPO=owner/repo bash scripts/make-release.sh
#
# Output (default ./dist):
#   dist/sentinel-gate-<version>.zip
#   dist/latest.json
#
# Publish step (manual, to the PUBLIC releases repo):
#   cp dist/sentinel-gate-<v>.zip  <releases-repo>/dist/
#   cp dist/latest.json            <releases-repo>/latest.json
#   git -C <releases-repo> add -A && git commit -m "release <v>" && git push
# ════════════════════════════════════════════════════════════════════════════════

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${REPO_DIR}/dist"
RELEASES_REPO="${SG_RELEASES_REPO:-admin-lagoonspace/cP-Defender}"
RELEASES_BRANCH="${SG_RELEASES_BRANCH:-main}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) shift; OUT_DIR="${1:?--out needs a path}" ;;
    --out=*) OUT_DIR="${1#--out=}" ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }

VERSION="$(tr -d '[:space:]' < "${REPO_DIR}/VERSION")"
[[ -n "$VERSION" ]] || { echo "VERSION file empty"; exit 1; }
info "Building Sentinel Gate v${VERSION}"

# ── Stage the payload (code only — mirrors what install.sh consumes) ───────────
STAGE="$(mktemp -d /tmp/sg-rel.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT
PKG="${STAGE}/sentinel-gate"
mkdir -p "$PKG"
for item in backend frontend whm install.sh uninstall.sh update.sh test.sh VERSION; do
  [[ -e "${REPO_DIR}/${item}" ]] && cp -r "${REPO_DIR}/${item}" "${PKG}/"
done

mkdir -p "$OUT_DIR"
ZIP_NAME="sentinel-gate-${VERSION}.zip"
ZIP_PATH="${OUT_DIR}/${ZIP_NAME}"
rm -f "$ZIP_PATH"
( cd "$STAGE" && zip -rq "$ZIP_PATH" sentinel-gate )
ok "Built ${ZIP_PATH} ($(wc -c < "$ZIP_PATH") bytes)"

# ── Checksum ──────────────────────────────────────────────────────────────────
if command -v sha256sum >/dev/null 2>&1; then
  SHA="$(sha256sum "$ZIP_PATH" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  SHA="$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')"
else
  echo "No sha256 tool available" >&2; exit 1
fi
ok "SHA256: ${SHA}"

# ── Manifest ──────────────────────────────────────────────────────────────────
# Primary download is our own CDN (no API limits, reachable when GitHub is
# firewalled); get.sh/update.sh fall back to the GitHub raw mirror on failure.
CDN_BASE="${SG_CDN_BASE:-https://defender.lws-s1.com/sentinel-gate/code}"
DL_URL="${CDN_BASE}/dist/${ZIP_NAME}"
MIRROR_URL="https://raw.githubusercontent.com/${RELEASES_REPO}/${RELEASES_BRANCH}/dist/${ZIP_NAME}"
NOTES_URL="https://github.com/${RELEASES_REPO}/blob/${RELEASES_BRANCH}/CHANGELOG.md"
cat > "${OUT_DIR}/latest.json" << JSON
{
  "version": "${VERSION}",
  "url": "${DL_URL}",
  "mirror": "${MIRROR_URL}",
  "sha256": "${SHA}",
  "notes": "${NOTES_URL}"
}
JSON
ok "Wrote ${OUT_DIR}/latest.json  (primary: CDN, mirror: GitHub raw)"

# ── Stage an upload tree matching the CDN layout exactly ──────────────────────
# Upload the CONTENTS of this dir to ${CDN_BASE}/ so paths line up 1:1:
#
#   <cdn>/get.sh                          bootstrap installer (always current)
#   <cdn>/latest.json                     pointer to the newest release
#   <cdn>/dist/sentinel-gate-<v>.zip      flat path — get.sh/update.sh build this
#                                         URL by convention when a manifest is
#                                         stale, so it must keep working
#   <cdn>/v<v>/sentinel-gate-<v>.zip      permanent per-version archive
#   <cdn>/v<v>/latest.json                version-pinned manifest
#   <cdn>/v<v>/CHANGELOG.md               notes as shipped for that version
#
# The zip is written to BOTH dist/ and v<v>/ deliberately: dist/ preserves the
# conventional fallback path for already-deployed clients, v<v>/ gives every
# release a permanent home so old versions stay installable via
# `SG_VERSION=<v>` and update.sh --version <v>.
UPLOAD_DIR="${OUT_DIR}/upload"
VER_DIR="${UPLOAD_DIR}/v${VERSION}"
rm -rf "$UPLOAD_DIR"
mkdir -p "${UPLOAD_DIR}/dist" "$VER_DIR"

cp -f "$ZIP_PATH"              "${UPLOAD_DIR}/dist/${ZIP_NAME}"
cp -f "$ZIP_PATH"              "${VER_DIR}/${ZIP_NAME}"
cp -f "${OUT_DIR}/latest.json" "${UPLOAD_DIR}/latest.json"
cp -f "${OUT_DIR}/latest.json" "${VER_DIR}/latest.json"
[[ -f "${REPO_DIR}/CHANGELOG.md" ]] && cp -f "${REPO_DIR}/CHANGELOG.md" "${VER_DIR}/CHANGELOG.md"
# get.sh is served from the CDN too so the one-line installer needs no GitHub
[[ -f "${REPO_DIR}/get.sh" ]] && cp -f "${REPO_DIR}/get.sh" "${UPLOAD_DIR}/get.sh"

ok "Staged upload tree: ${UPLOAD_DIR}"
find "$UPLOAD_DIR" -type f | sed "s|${UPLOAD_DIR}|      <cdn>|" | sort

echo ""
info "Next: publish to the PUBLIC releases repo (${RELEASES_REPO}):"
echo "    cp ${ZIP_PATH} <releases-repo>/dist/"
echo "    cp ${OUT_DIR}/latest.json <releases-repo>/latest.json"
echo "    (cd <releases-repo> && git add -A && git commit -m 'release v${VERSION}' && git push)"
echo ""
warn "Servers update only AFTER latest.json is live on the public channel."
