#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — one-command release publisher
# Builds the release, commits the artifacts, pushes main, and cuts the GitHub
# Release/tag that the in-app updater watches. Run from the repo root.
#
#   bash scripts/publish.sh            # publish the version in ./VERSION
#   bash scripts/publish.sh 3.7.1      # publish a specific version
#
# AUTH (never stored in the repo — pick one):
#   • export GH_TOKEN=<pat>            # fine-grained PAT, Contents: read/write
#   • gh auth login                    # GitHub CLI (script uses it if present)
#   • an existing git credential helper that can push to origin
#
# The token is read from the environment at runtime only. Do NOT hardcode it.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# ── Locate repo root ───────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
[[ -d .git ]] || die "Not a git repo: $REPO_ROOT"

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

# ── Resolve owner/repo from origin ─────────────────────────────────────────────
ORIGIN_URL="$(git config --get remote.origin.url)"
SLUG="$(printf '%s' "$ORIGIN_URL" | sed -E 's#(git@github.com:|https://github.com/)##; s#\.git$##')"
[[ "$SLUG" == */* ]] || die "Could not parse owner/repo from origin: $ORIGIN_URL"
info "Repository: ${BOLD}${SLUG}${NC}"

# ── Version ────────────────────────────────────────────────────────────────────
VER="${1:-$(tr -d '[:space:]' < VERSION)}"
[[ -n "$VER" ]] || die "No version (pass one or populate ./VERSION)"
TAG="v${VER}"
info "Publishing ${BOLD}${TAG}${NC}"

# ── Guard: on main, artifacts consistent ───────────────────────────────────────
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[[ "$BRANCH" == "main" ]] || warn "Current branch is '${BRANCH}', not 'main' — continuing anyway"

# Abort if this tag/release already exists remotely (avoid clobbering a release)
if git ls-remote --tags origin "refs/tags/${TAG}" 2>/dev/null | grep -q "${TAG}"; then
    die "Tag ${TAG} already exists on origin. Bump VERSION or delete the tag first."
fi

# ── 1. Build the package + manifest ────────────────────────────────────────────
info "Building release artifacts…"
bash scripts/make-release.sh >/dev/null
ZIP="dist/sentinel-gate-${VER}.zip"
[[ -f "$ZIP" ]] || die "Build did not produce ${ZIP}"
# update.sh reads latest.json from the repo ROOT
cp -f "dist/latest.json" "latest.json"
SHA="$(sha256sum "$ZIP" | awk '{print $1}')"
ok "Built ${ZIP} ($(wc -c < "$ZIP") bytes), sha256 ${SHA:0:16}…"

# ── 2. Clean known junk so it never gets committed ─────────────────────────────
rm -f _wtest.txt __probe_root.txt dist/__probe_new.txt dist/zivb4myo 2>/dev/null || true
# stray zero-byte zips from interrupted builds
find dist -maxdepth 1 -name 'sentinel-gate-*.zip' -size 0 -delete 2>/dev/null || true

# ── 3. Stage exactly the release files ─────────────────────────────────────────
info "Staging files…"
STAGE_LIST=(
  VERSION CHANGELOG.md install.sh uninstall.sh update.sh get.sh
  backend/config/config.php backend/cli/sentinel.php
  frontend/index.html whm/sentinel.conf whm/sentinel_gate.png
  scripts/make-release.sh scripts/publish.sh
  "$ZIP" latest.json
)
for f in "${STAGE_LIST[@]}"; do [[ -e "$f" ]] && git add "$f"; done
git add -u install.sh uninstall.sh update.sh 2>/dev/null || true

if git diff --cached --quiet; then
    warn "Nothing new to commit — proceeding to push/release with existing HEAD"
else
    git commit -m "Release ${TAG}"
    ok "Committed ${TAG}"
fi

# ── 4. Push main ───────────────────────────────────────────────────────────────
info "Pushing to origin/main…"
if [[ -n "$TOKEN" ]]; then
    # Inject auth per-command via header; keeps the token out of remote config/URL
    git -c http.extraheader="Authorization: Bearer ${TOKEN}" push origin HEAD:main
else
    git push origin HEAD:main
fi
ok "Pushed to origin/main"

# ── 5. Extract release notes for this version from CHANGELOG ────────────────────
NOTES="$(awk -v hdr="## [${VER}]" '
    index($0, hdr) == 1 {grab=1; next}
    grab && index($0, "## [") == 1 {exit}
    grab {print}
' CHANGELOG.md)"
[[ -n "$NOTES" ]] || NOTES="Sentinel Gate ${TAG}"

# ── 6. Create the GitHub Release (this is what the updater watches) ─────────────
info "Creating GitHub Release ${TAG}…"
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    printf '%s' "$NOTES" | gh release create "$TAG" "$ZIP" \
        --title "Sentinel Gate ${TAG}" --notes-file - --target main
    ok "Release created via gh (asset attached)"
elif [[ -n "$TOKEN" ]]; then
    # Build JSON body safely
    if command -v python3 >/dev/null 2>&1; then
        BODY="$(NOTES="$NOTES" TAG="$TAG" python3 -c 'import json,os;print(json.dumps({"tag_name":os.environ["TAG"],"target_commitish":"main","name":"Sentinel Gate "+os.environ["TAG"],"body":os.environ["NOTES"],"draft":False,"prerelease":False}))')"
    elif command -v jq >/dev/null 2>&1; then
        BODY="$(jq -n --arg t "$TAG" --arg n "Sentinel Gate $TAG" --arg b "$NOTES" \
            '{tag_name:$t,target_commitish:"main",name:$n,body:$b,draft:false,prerelease:false}')"
    else
        die "Need python3 or jq to build the release JSON (or install gh)"
    fi
    RESP="$(curl -sS -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${SLUG}/releases" -d "$BODY")"
    UPLOAD_URL="$(printf '%s' "$RESP" | sed -n 's/.*"upload_url":[[:space:]]*"\([^{"]*\).*/\1/p')"
    REL_HTML="$(printf '%s' "$RESP"   | sed -n 's/.*"html_url":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    [[ -n "$UPLOAD_URL" ]] || die "Release creation failed: $(printf '%s' "$RESP" | head -c 300)"
    ok "Release created: ${REL_HTML}"
    # Attach the zip as a release asset (optional but nice for the Releases page)
    info "Uploading asset…"
    curl -sS -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/zip" \
        --data-binary @"$ZIP" \
        "${UPLOAD_URL}?name=sentinel-gate-${VER}.zip" >/dev/null && ok "Asset uploaded" || warn "Asset upload failed (release + tag still valid; updater uses dist/)"
else
    warn "No gh and no GH_TOKEN — pushed code, but DID NOT create the Release."
    warn "Create it manually: repo → Releases → new release, tag ${TAG} on main, attach ${ZIP}."
fi

# ── 7. CDN mirror ──────────────────────────────────────────────────────────────
# The CDN no longer needs an FTP push from here. The server runs
# scripts/cdn-sync.sh on a cron and PULLS this release from GitHub, so there is
# nothing to upload and no credential to hold. See scripts/cdn-sync.sh.
info "CDN mirrors automatically (server-side pull, every 10 min)."
info "  Force an immediate sync on the server with:  ~/bin/cdn-sync.sh"

echo ""
ok "Published ${TAG}. CDN will pick it up within ~10 min."
echo -e "  Install command now live:"
echo -e "  ${BOLD}bash <(curl -fsSL https://raw.githubusercontent.com/${SLUG}/main/get.sh)${NC}"
