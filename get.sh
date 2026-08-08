#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — Online bootstrap installer
# Downloads the latest build from the release channel and runs the installer in
# one step. Works on cPanel/WHM servers and plain Linux servers alike — the mode
# is auto-detected (cPanel if /usr/local/cpanel exists, else standalone).
#
# ── INSTALL (one line, as root) ───────────────────────────────────────────────
# curl — present by default on RHEL/CentOS/AlmaLinux/CloudLinux (all cPanel hosts):
#   bash <(curl -fsSL https://defender.lws-s1.com/sentinel-gate/code/get.sh)
#
# wget — present by default on Debian/Ubuntu:
#   bash <(wget -qO- https://defender.lws-s1.com/sentinel-gate/code/get.sh)
#
# Both forms behave identically. Once this script is running it uses whichever of
# curl/wget exists, so only the bootstrap line differs.
#
# The `bash <(...)` form is preferred over piping. Piping attaches the download to
# stdin, which leaves the installer no terminal to read from — it then takes the
# fully non-interactive path (auto-detected mode, generated admin password).
# Process substitution keeps stdin on the terminal so prompts still work:
#   curl -fsSL .../get.sh | bash      # non-interactive
#   wget -qO- .../get.sh | bash       # non-interactive
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
# Suggest whichever downloader this box actually has.
if [[ $EUID -ne 0 ]]; then
  if command -v curl >/dev/null 2>&1; then
    die "Run as root:  sudo bash <(curl -fsSL ${PRIMARY_BASE}/get.sh)"
  else
    die "Run as root:  sudo bash <(wget -qO- ${PRIMARY_BASE}/get.sh)"
  fi
fi

# ── Ensure the tools this bootstrap itself needs ───────────────────────────────
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

# ── Version discovery from a directory listing ─────────────────────────────────
# Fallback for when latest.json is absent or unreadable: the release directory
# holds one v<major>.<minor>.<patch>/ folder per release, so the newest build can
# be derived straight from an Apache/nginx autoindex. Sorted numerically per
# field — a plain lexical sort would rank v3.9.0 above v3.10.0.
discover_latest() { # discover_latest <base> -> version | empty
  local base="$1" idx
  idx="$(fetch "${base}/" 2>/dev/null)" || return 1
  printf '%s' "$idx" \
    | grep -oE 'href="v?[0-9]+\.[0-9]+\.[0-9]+/?"' \
    | sed -E 's/.*"v?([0-9]+\.[0-9]+\.[0-9]+)\/?"/\1/' \
    | sort -t. -k1,1n -k2,2n -k3,3n \
    | tail -1
}

parse_manifest() { # parse_manifest <json> <field> -> value
  printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]+\"" \
    | head -1 | sed -E 's/.*"([^"]+)"$/\1/'
}

# ── Resolve version + download URL + checksum ──────────────────────────────────
VERSION=""; URL=""; SHA=""; SRC_BASE=""
if [[ -n "$PIN_VERSION" ]]; then
  VERSION="$PIN_VERSION"
  info "Pinned version: v${VERSION}"
  # Still try for a version-pinned manifest so the checksum can be verified
  for BASE in "${MIRRORS[@]}"; do
    VM="$(fetch "${BASE}/v${VERSION}/latest.json" 2>/dev/null)" || continue
    SHA="$(parse_manifest "$VM" sha256)"
    [[ -n "$SHA" ]] && { SRC_BASE="$BASE"; ok "Checksum found for v${VERSION}"; break; }
  done
  [[ -z "$SHA" ]] && warn "No checksum published for v${VERSION} — integrity will NOT be verified."
else
  for BASE in "${MIRRORS[@]}"; do
    info "Checking channel: ${BASE}"

    # 0. latest/VERSION — the extracted build that is actually deployed. Six
    #    bytes, and it cannot disagree with what is being served, because the
    #    sync writes it by extracting the very zip it just verified. Used as a
    #    cross-check against the manifest below.
    LIVE_VER="$(fetch "${BASE}/latest/VERSION" 2>/dev/null | tr -d '[:space:]')"
    [[ -n "$LIVE_VER" ]] && info "  latest/ reports v${LIVE_VER}"

    # 1. Preferred: latest.json — authoritative and carries the checksum
    MANIFEST="$(fetch "${BASE}/latest.json" 2>/dev/null)"
    if [[ -n "$MANIFEST" ]]; then
      VERSION="$(parse_manifest "$MANIFEST" version)"
      URL="$(parse_manifest "$MANIFEST" url)"
      SHA="$(parse_manifest "$MANIFEST" sha256)"
      if [[ -n "$VERSION" ]]; then
        SRC_BASE="$BASE"
        # A manifest that disagrees with the deployed tree means the sync was
        # interrupted between writing the zip and re-extracting latest/. Trust
        # the manifest (it carries the checksum) but say so, because installing
        # a version the channel is not actually serving is worth knowing about.
        if [[ -n "$LIVE_VER" && "$LIVE_VER" != "$VERSION" ]]; then
          warn "  manifest says v${VERSION} but latest/ holds v${LIVE_VER} — channel mid-sync"
        fi
        ok "Latest version: v${VERSION}  (from latest.json)"
        break
      fi
      warn "  Malformed manifest — trying directory listing…"
    elif [[ -n "$LIVE_VER" ]]; then
      # 2. No manifest, but the extracted build tells us the version directly.
      VERSION="$LIVE_VER"
      SRC_BASE="$BASE"
      ok "Latest version: v${VERSION}  (from latest/VERSION)"
      VM="$(fetch "${BASE}/v${VERSION}/latest.json" 2>/dev/null)"
      [[ -n "$VM" ]] && SHA="$(parse_manifest "$VM" sha256)"
      [[ -n "$SHA" ]] && ok "  Checksum published for v${VERSION}" \
                      || warn "  No checksum for v${VERSION} — integrity will NOT be verified."
      break
    else
      info "  No latest.json — trying directory listing…"
    fi

    # 2. Fallback: derive the newest version from the directory listing
    DISCOVERED="$(discover_latest "$BASE" 2>/dev/null)"
    if [[ -n "$DISCOVERED" ]]; then
      VERSION="$DISCOVERED"
      SRC_BASE="$BASE"
      ok "Latest version: v${VERSION}  (discovered from directory listing)"
      # Pick up the checksum from the version folder if one is published
      VM="$(fetch "${BASE}/v${VERSION}/latest.json" 2>/dev/null)"
      [[ -n "$VM" ]] && SHA="$(parse_manifest "$VM" sha256)"
      [[ -n "$SHA" ]] && ok "  Checksum published for v${VERSION}" \
                      || warn "  No checksum for v${VERSION} — integrity will NOT be verified."
      break
    fi
    warn "  Channel unusable: ${BASE}"
  done
  [[ -n "$VERSION" ]] || die "Cannot determine the latest version from any channel. Tried: ${MIRRORS[*]}"
fi

# ── Download the package ───────────────────────────────────────────────────────
TMP="$(mktemp -d /tmp/sg-get.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
ZIP="${TMP}/sentinel-gate-${VERSION}.zip"

# Order: the manifest's own URL, then the channel that resolved the version, then
# every remaining channel. Both the per-version folder and the flat dist/ path are
# tried since releases are published to both. The checksum verified below is what
# makes falling across channels safe.
CANDIDATES=()
[[ -n "$URL" ]] && CANDIDATES+=("$URL")
[[ -n "$SRC_BASE" ]] && CANDIDATES+=(
  "${SRC_BASE}/builds/sentinel-gate-${VERSION}.zip"
  "${SRC_BASE}/v${VERSION}/sentinel-gate-${VERSION}.zip"
  "${SRC_BASE}/dist/sentinel-gate-${VERSION}.zip"
)
for BASE in "${MIRRORS[@]}"; do
  CANDIDATES+=(
    "${BASE}/builds/sentinel-gate-${VERSION}.zip"
    "${BASE}/v${VERSION}/sentinel-gate-${VERSION}.zip"
    "${BASE}/dist/sentinel-gate-${VERSION}.zip"
  )
done

# ── Last resort: copy the extracted latest/ tree file by file ────────────────
# Only used when every zip path has failed. This is deliberately the last
# option: it costs ~40 requests instead of one, has no checksum to verify
# against, and is not atomic — a mirror updating mid-fetch yields a mixed tree.
# It exists because latest/ is the one source that is guaranteed to reflect what
# the channel is actually serving, so it can still rescue an install when the
# archives are missing or corrupt.
fetch_latest_tree() { # fetch_latest_tree <base> <dest-dir> -> 0 ok
  local base="$1" dest="$2"
  local list item
  mkdir -p "$dest" || return 1

  # A subdirectory that refuses to list must not abort the whole copy — it is
  # recorded and reported instead. An earlier version returned 1 on the first
  # failure, so a single unlistable directory silently produced a tree with only
  # the files fetched before it.
  TREE_FAILED=0
  _walk() { # _walk <url-path> <local-dir>
    local url="$1" dir="$2" idx entries e
    if ! idx="$(fetch "${url}/" 2>/dev/null)"; then
      warn "    cannot list ${url}/ — skipping"
      TREE_FAILED=$((TREE_FAILED + 1))
      return 0
    fi
    # Pull hrefs, skipping parent links, query-sort links and absolute paths
    entries="$(printf '%s' "$idx" \
      | grep -oE 'href="[^"?/][^"?]*/?"' \
      | sed -E 's/^href="//; s/"$//' \
      | grep -v '^\.\.' || true)"
    if [[ -z "$entries" ]]; then
      warn "    empty listing at ${url}/"
      TREE_FAILED=$((TREE_FAILED + 1))
      return 0
    fi
    while IFS= read -r e; do
      [[ -z "$e" ]] && continue
      if [[ "$e" == */ ]]; then
        mkdir -p "${dir}/${e%/}"
        _walk "${url}/${e%/}" "${dir}/${e%/}"
      else
        # </dev/null so curl cannot consume the loop's stdin
        fetch_to "${url}/${e}" "${dir}/${e}" </dev/null || {
          warn "    failed: ${e}"
          TREE_FAILED=$((TREE_FAILED + 1))
        }
      fi
    done <<< "$entries"
    return 0
  }

  _walk "${base}/latest" "$dest"
  [[ $TREE_FAILED -gt 0 ]] && warn "    ${TREE_FAILED} item(s) could not be copied"
  return 0
}

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

TREE_DIR=""
if [[ "$DOWNLOADED" == false ]]; then
  warn "Every archive source failed — falling back to the extracted latest/ tree."
  for BASE in "${MIRRORS[@]}"; do
    info "Copying tree from: ${BASE}/latest/"
    CAND_DIR="${TMP}/from-latest"
    rm -rf "$CAND_DIR"
    if fetch_latest_tree "$BASE" "$CAND_DIR" \
       && [[ -f "${CAND_DIR}/VERSION" && -f "${CAND_DIR}/install.sh" ]]; then
      TREE_DIR="$CAND_DIR"
      VERSION="$(tr -d '[:space:]' < "${CAND_DIR}/VERSION")"
      SHA=""     # nothing to verify a loose tree against
      ok "Copied latest/ tree (v${VERSION}) — checksum NOT verified"
      break
    fi
    warn "  tree copy failed or incomplete"
  done
fi

[[ "$DOWNLOADED" == true || -n "$TREE_DIR" ]] \
  || die "Could not obtain the package from any source. Tried: ${CANDIDATES[*]} and latest/"

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
if [[ -n "$TREE_DIR" ]]; then
  # Came from latest/ — already a tree, nothing to unpack
  SRC_DIR="$TREE_DIR"
  chmod +x "${SRC_DIR}/install.sh" 2>/dev/null || true
  ok "Package ready: ${SRC_DIR}"
  echo ""
  info "Launching installer (v${VERSION})…"
  echo ""
  exec bash "${SRC_DIR}/install.sh" "$@"
fi

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
