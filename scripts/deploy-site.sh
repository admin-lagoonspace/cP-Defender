#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# ServerScrub — publish the marketing site and the download directory
#
# Run as ROOT on the server that hosts serverscrub.com.
#
#   bash deploy-site.sh                 # fetch from GitHub and publish
#   SG_SITE_SRC=/path/to/website bash deploy-site.sh    # publish a local copy
#
# It does two separate things, because the domain serves two separate things:
#
#   1. The marketing site        -> /home/serversc/public_html/
#   2. The download directory    -> /home/serversc/public_html/serverscrub/code/
#
# The second is what every installed server fetches updates from, so this
# script never deletes anything underneath it. Wiping a docroot that other
# machines depend on, to publish a website, is not a trade worth making.
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

CP_USER="${SG_CP_USER:-serversc}"
DOMAIN="${SG_DOMAIN:-serverscrub.com}"
HOME_DIR="/home/${CP_USER}"
DOCROOT="${HOME_DIR}/public_html"
CODE_DIR="${DOCROOT}/serverscrub/code"
REPO_RAW="https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/website"

[[ $EUID -eq 0 ]] || die "run as root"
[[ -d "$HOME_DIR" ]] || die "no such account: ${HOME_DIR} (is the cPanel account created?)"

# ── Where the site files come from ────────────────────────────────────────────
PAGES=(index.html features.html pricing.html install.html)
ASSETS=(assets/css/site.css assets/img/logo.svg assets/img/hero.svg)

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

if [[ -n "${SG_SITE_SRC:-}" ]]; then
  [[ -d "$SG_SITE_SRC" ]] || die "SG_SITE_SRC is not a directory: $SG_SITE_SRC"
  info "Using local source: ${SG_SITE_SRC}"
  for f in "${PAGES[@]}" "${ASSETS[@]}"; do
    [[ -f "${SG_SITE_SRC}/${f}" ]] || die "missing from source: ${f}"
    mkdir -p "${STAGE}/$(dirname "$f")"
    cp -f "${SG_SITE_SRC}/${f}" "${STAGE}/${f}"
  done
else
  info "Fetching the site from GitHub…"
  for f in "${PAGES[@]}" "${ASSETS[@]}"; do
    mkdir -p "${STAGE}/$(dirname "$f")"
    curl -fsSL --max-time 30 "${REPO_RAW}/${f}" -o "${STAGE}/${f}" \
      || die "could not fetch ${f} — if the repository is private, re-run with SG_SITE_SRC=<local copy>"
    [[ -s "${STAGE}/${f}" ]] || die "fetched ${f} but it is empty"
  done
fi

# Every page must be whole. A truncated download that still exits 0 would
# otherwise publish a half-written page over a working one.
for f in "${PAGES[@]}"; do
  grep -q '</html>' "${STAGE}/${f}" || die "${f} looks truncated — not publishing"
done
ok "Staged $(( ${#PAGES[@]} + ${#ASSETS[@]} )) file(s), all complete"

# ── Publish ───────────────────────────────────────────────────────────────────
info "Publishing to ${DOCROOT}…"
mkdir -p "${DOCROOT}/assets/css" "${DOCROOT}/assets/img" "${CODE_DIR}"

for f in "${PAGES[@]}" "${ASSETS[@]}"; do
  install -m 644 "${STAGE}/${f}" "${DOCROOT}/${f}"
  echo "      ${f}"
done

# cPanel serves as the account user; files owned by root are a 403 waiting to
# happen the first time something needs to write one.
chown -R "${CP_USER}:${CP_USER}" "${DOCROOT}/index.html" "${DOCROOT}/features.html" \
      "${DOCROOT}/pricing.html" "${DOCROOT}/install.html" "${DOCROOT}/assets" \
      "${DOCROOT}/serverscrub" 2>/dev/null || true
find "${DOCROOT}/assets" -type d -exec chmod 755 {} + 2>/dev/null || true
ok "Site published"

# ── The download directory ────────────────────────────────────────────────────
# Created, never emptied. Servers in the field fetch updates from here.
chown "${CP_USER}:${CP_USER}" "${DOCROOT}/serverscrub" "${CODE_DIR}" 2>/dev/null || true
chmod 755 "${DOCROOT}/serverscrub" "${CODE_DIR}"
if [[ -f "${CODE_DIR}/latest.json" ]]; then
  ok "Download directory present: ${CODE_DIR} (latest.json found, left untouched)"
else
  warn "Download directory is EMPTY: ${CODE_DIR}"
  warn "  Until latest.json and dist/ are there, https://${DOMAIN}/serverscrub/code/"
  warn "  serves nothing and installs fall back to the GitHub mirror."
  warn "  Populate it with scripts/cdn-sync.sh (see its header)."
fi

# ── Check it actually serves ──────────────────────────────────────────────────
info "Checking the site responds…"
for p in "" features.html pricing.html install.html assets/css/site.css; do
  code="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 15 \
          "https://${DOMAIN}/${p}" 2>/dev/null || echo 000)"
  case "$code" in
    200) ok   "  200  /${p}" ;;
    000) warn "  ---  /${p}  (no response — DNS or TLS not ready yet)" ;;
    *)   warn "  ${code}  /${p}" ;;
  esac
done

echo
ok "Done."
echo "   Site:      https://${DOMAIN}/"
echo "   Downloads: https://${DOMAIN}/serverscrub/code/"
echo
echo "   If TLS is not valid yet, issue it with:"
echo "     /usr/local/cpanel/bin/autossl_check --user=${CP_USER}"
