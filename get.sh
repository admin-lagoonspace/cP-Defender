#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Online bootstrap installer
# Downloads the latest build from the release channel and runs the installer in
# one step. Works on cPanel/WHM servers and plain Linux servers alike — the mode
# is auto-detected (cPanel if /usr/local/cpanel exists, else standalone).
#
# ── INSTALL (one line, as root) ───────────────────────────────────────────────
#   bash <(curl -fsSL https://defender.lws-s1.com/sentinel-gate/code/get.sh)
#
# Or piped (identical result — the installer never prompts when piped):
#   curl -fsSL https://defender.lws-s1.com/sentinel-gate/code/get.sh | bash
#
# ── OPTIONS ───────────────────────────────────────────────────────────────────
# Anything after `bash -s --` is passed straight through to install.sh:
#   curl -fsSL .../get.sh | bash -s -- --mode standalone
#   curl -fsSL .../get.sh | bash -s -- --mode cpanel --no-deps
#
# Unattended standalone install with a chosen admin password (env keeps it out
# of `ps` output; without it a strong one is generated and printed at the end):
#   curl -fsSL .../get.sh | SG_ADMIN_PASS='your-password' bash -s -- --mode standalone
#
# Pin a specific version instead of latest:
#   SG_VERSION=3.7.0 bash <(curl -fsSL .../get.sh)
#
# ── CHANNELS ──────────────────────────────────────────────────────────────────
# Tried in order; the sha256 in latest.json is verified regardless of source:
#   1. https://defender.lws-s1.com/sentinel-gate/code   (primary)
#   2. raw.githubusercontent.com/<repo>/main            (mirror)
# Override with SG_BASE_URL=<base> (pins to that one channel).
# ═══════════════════════════════════════════════════════════════════════════════

set -o pipefail

REPO="${SG_REPO:-admin-lagoonspace/cP-Defender}"
BRANCH="${SG_BRANCH:-main}"
PIN_VERSION="${SG_VERSION:-}"

# ── Release channels, tried in order ───────────────────────────────────────────
# Primary is our own CDN: no API rate limits, and it stays reachable on servers
# whose firewall blocks github.com / api.github.com. GitHub raw is the fallback.
# Each base must serve:  <base>/latest.json  and  <base>/dist/sentinel-gate-<v>.zip
PRIMARY_BASE="${SG_BASE_URL:-https://defender.lws-s1.com/sentinel-gate/code}"
GITHUB_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
MIRRORS=("$PRIMARY_BASE" "$GITHUB_BASE")

# Explicit override wins and disables mirror rotation
[[ -n "${SG_MANIFEST_URL:-}" ]] && MIRRORS=("${SG_MANIFEST_URL%/latest.json}")

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

echo -e "${CYAN}${BOLD}Sentinel Gate — online installer${NC}"

# ── Must be root (install.sh needs it anyway; fail early with a clear message) ──
[[ $EUID -ne 0 ]] && die "Run as root:  curl -fsSL ${PRIMARY_BASE}/get.sh | sudo bash"

# ── Ensure the tools this bootstrap itself needs (curl already ran us if piped) ─
ensure_tool() {
  local bin="$1" pkg="$2"
  command -v "$bin" >/dev/null 2>&1 && return 0
  warn "'$bin' not found — attempting to install ($pkg)…"
  if   command -v apt-get >/dev/null 2>&1; then apt-get update -q >/dev/null 2>&1; apt-get install -y -q "$pkg" >/dev/null 2>&1
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q "$pkg" >/dev/null 2>&1
  elif command -v yum     >/dev/null 2>&1; then yum install -y -q "$pkg" >/dev/null 2>&1
  fi
  command -v "$bin" >/dev/null 2>&1 || die "Could not install '$bin'. Install it manually and re-run."
}

# Need a downloader (curl or wget) and an unzipper.
if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  ensure_tool curl curl
fi
ensure_tool unzip unzip

# ── Download helper (curl first, wget fallback) ────────────────────────────────
fetch() { # fetch <url> -> stdout
  if command -v curl >/dev/null 2>&1; then curl -fsSL --max-time 30 "$1"; else wget -qO- --timeout=30 "$1"; fi
}
fetch_to() { # fetch_to <url> <dest>
  if command -v curl >/dev/null 2>&1; then curl -fL --max-time 300 -o "$2" "$1"
  else wget -q --timeout=300 -O "$2" "$1"; fi
}

# ── Resolve version + download URL + checksum ──────────────────────────────────
VERSION=""; URL=""; SHA=""
if [[ -n "$PIN_VERSION" ]]; then
  VERSION="$PIN_VERSION"
  warn "Pinned version ${VERSION} — checksum not verified."
else
  # Walk the mirror list until one serves a usable manifest
  for BASE in "${MIRRORS[@]}"; do
    info "Fetching release manifest: ${BASE}/latest.json"
    MANIFEST="$(fetch "${BASE}/latest.json")" || { warn "Unreachable: ${BASE}"; continue; }
    [[ -n "$MANIFEST" ]] || { warn "Empty manifest at ${BASE}"; continue; }
    # Parse JSON without jq
    VERSION="$(printf '%s' "$MANIFEST" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
    URL="$(printf '%s' "$MANIFEST"     | grep -oE '"url"[[:space:]]*:[[:space:]]*"[^"]+"'     | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
    SHA="$(printf '%s' "$MANIFEST"     | grep -oE '"sha256"[[:space:]]*:[[:space:]]*"[^"]+"'  | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
    [[ -n "$VERSION" ]] || { warn "Malformed manifest at ${BASE}"; continue; }
    ok "Latest version: v${VERSION}  (channel: ${BASE})"
    break
  done
  [[ -n "$VERSION" ]] || die "Cannot reach any release channel. Tried: ${MIRRORS[*]}"
fi

# ── Download the package ───────────────────────────────────────────────────────
TMP="$(mktemp -d /tmp/sg-get.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
ZIP="${TMP}/sentinel-gate-${VERSION}.zip"

# Try the manifest's own URL first, then each mirror's dist/ path. The checksum
# below is what makes cross-mirror fallback safe.
CANDIDATES=()
[[ -n "$URL" ]] && CANDIDATES+=("$URL")
for BASE in "${MIRRORS[@]}"; do
  CANDIDATES+=("${BASE}/dist/sentinel-gate-${VERSION}.zip")
done

DOWNLOADED=false
for CAND in "${CANDIDATES[@]}"; do
  info "Downloading: ${CAND}"
  if fetch_to "$CAND" "$ZIP" && [[ -s "$ZIP" ]]; then
    DOWNLOADED=true
    ok "Downloaded ($(wc -c < "$ZIP") bytes)"
    break
  fi
  warn "Failed: ${CAND}"
done
$DOWNLOADED || die "Download failed from every source. Tried: ${CANDIDATES[*]}"

# ── Verify checksum when the manifest provided one ─────────────────────────────
if [[ -n "$SHA" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then GOT="$(sha256sum "$ZIP" | awk '{print $1}')"
  elif command -v shasum  >/dev/null 2>&1; then GOT="$(shasum -a 256 "$ZIP" | awk '{print $1}')"
  else GOT=""; warn "No sha256 tool — skipping integrity check."; fi
  if [[ -n "$GOT" ]]; then
    [[ "$GOT" == "$SHA" ]] || die "Checksum mismatch! expected ${SHA} got ${GOT}. Aborting."
    ok "Checksum verified"
  fi
fi

# ── Extract and hand off to install.sh ─────────────────────────────────────────
info "Extracting…"
unzip -q "$ZIP" -d "$TMP" || die "Extraction failed."
SRC="$(find "$TMP" -maxdepth 2 -name install.sh -type f | head -1)"
[[ -n "$SRC" ]] || die "install.sh not found in package."
SRC_DIR="$(dirname "$SRC")"
ok "Package ready: ${SRC_DIR}"

echo ""
info "Launching installer (v${VERSION})…"
echo ""
chmod +x "${SRC_DIR}/install.sh"
exec bash "${SRC_DIR}/install.sh" "$@"
