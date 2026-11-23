#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — one-command release publisher
# Builds the release, commits the artifacts, pushes main, pushes the annotated
# tag, and cuts the GitHub Release the in-app updater watches. Run from the
# repo root.
#
# The tag (step 4b) and the GitHub Release (step 6) are SEPARATE steps. The
# tag always happens and the release fails without it; the Release page needs
# gh or GH_TOKEN and is skipped with a loud notice when neither is present.
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

# Every assignment below that reads from a pipeline carries `|| true`.
#
# Under `set -e` plus pipefail an assignment takes the pipeline's exit
# status, so one failing stage ends the release silently and part-way, with
# no message at all -- the exact failure this project was already bitten by
# in update.sh on 2026-10-20. Each of these is followed by an emptiness
# check, so the code was written expecting an empty value; the shell options
# were quietly defeating that intent.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
# err() was called in the zip-coverage failure path below but never defined, so
# the one branch that has to explain itself clearly died with
# "publish.sh: line NNN: err: command not found" and never printed the file
# list. tests/test_cron_and_cdn.php pins that call site, which is right -- the
# missing piece was the function, not the call.
err()  { echo -e "${RED}[x]${NC} $*" >&2; }

# ── Locate repo root ───────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
[[ -d .git ]] || die "Not a git repo: $REPO_ROOT"

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
TAG_PUSHED=no

# ── Resolve owner/repo from origin ─────────────────────────────────────────────
ORIGIN_URL="$(git config --get remote.origin.url)"
SLUG="$(printf '%s' "$ORIGIN_URL" | sed -E 's#(git@github.com:|https://github.com/)##; s#\.git$##' || true)"
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

# Abort if this tag/release already exists remotely (avoid clobbering a
# release) -- UNLESS it is the same tag object, on this same commit, in which
# case this run is a RESUME.
#
# WHY A RESUME EXISTS AT ALL. Section 7b fails the release when the CDN never
# serves the new version, and it fails AFTER the tag has been pushed, because
# a mirror cannot be checked before the thing it mirrors is on origin. Git is
# deliberately left alone. But this guard then refused the re-run, and the two
# routes it offered were both bad: burn a version number, or delete a pushed
# tag that update.sh now treats as THE authoritative version source. So a
# release blocked on a frozen mirror -- which is the live situation -- was
# unfinishable. The local guard further down already makes exactly this
# distinction ("already exists locally on <sha> -- reusing it"); this is the
# same rule against origin.
#
# The identity check is strict: the remote tag OBJECT must be byte-identical
# to the local one, and the local tag must point at HEAD. A tag of this name
# created by anyone else, or on any other commit, is still a hard refusal.
RESUMING=no
_remote_tag_sha="$(git ls-remote --tags origin "refs/tags/${TAG}" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
if [[ -n "$_remote_tag_sha" ]]; then
    _local_tag_sha="$(git rev-parse -q --verify "refs/tags/${TAG}" 2>/dev/null || true)"
    _local_tag_commit="$(git rev-parse -q --verify "refs/tags/${TAG}^{commit}" 2>/dev/null || true)"
    _head_commit="$(git rev-parse HEAD)"
    if [[ -n "$_local_tag_sha" && "$_local_tag_sha" == "$_remote_tag_sha" \
          && "$_local_tag_commit" == "$_head_commit" ]]; then
        RESUMING=yes
        warn "Tag ${TAG} is already on origin, as the same object, on HEAD (${_head_commit:0:7})."
        warn "  Treating this run as a RESUME of a release that got as far as the push."
        warn "  Nothing already on origin is re-created; the CDN mirror is re-checked."
    else
        echo "" >&2
        err "Tag ${TAG} already exists on origin, and it is not this commit's tag."
        echo "    origin: ${_remote_tag_sha:0:7}    local: ${_local_tag_sha:0:7}" >&2
        echo "    local tag commit: ${_local_tag_commit:0:7}    HEAD: ${_head_commit:0:7}" >&2
        echo "" >&2
        echo "    This is a real conflict, not a resume. Either bump VERSION, or" >&2
        echo "    delete the tag on origin if you are certain it is wrong -- but note" >&2
        echo "    that update.sh resolves versions FROM tags, so deleting a published" >&2
        echo "    one withdraws that release from every server in the field." >&2
        echo "" >&2
        exit 1
    fi
fi

# ── 0. Version bump sanity check ───────────────────────────────────────────────
# Fails the release when the bump does not match the commits. The convention was
# documented in CHANGELOG.md and still drifted three times, so it is enforced
# here rather than trusted to memory. SG_SKIP_VERSION_CHECK=1 overrides.
VERSION_CHECK=skipped
if [[ "${SG_SKIP_VERSION_CHECK:-0}" != "1" ]]; then
    bash "${REPO_ROOT}/scripts/check-version-bump.sh" --strict || exit 1
    VERSION_CHECK=passed
else
    warn "Version bump check SKIPPED via SG_SKIP_VERSION_CHECK=1"
fi

# ── 1. Build the package + manifest ────────────────────────────────────────────
info "Building release artifacts…"
bash scripts/make-release.sh >/dev/null
ZIP="dist/serverscrub-${VER}.zip"
[[ -f "$ZIP" ]] || die "Build did not produce ${ZIP}"
# update.sh reads latest.json from the repo ROOT
cp -f "dist/latest.json" "latest.json"
SHA="$(sha256sum "$ZIP" | awk '{print $1}' || true)"
ok "Built ${ZIP} ($(wc -c < "$ZIP") bytes), sha256 ${SHA:0:16}…"

# ── 2. Clean known junk so it never gets committed ─────────────────────────────
rm -f _wtest.txt __probe_root.txt dist/__probe_new.txt dist/zivb4myo 2>/dev/null || true
# stray zero-byte zips from interrupted builds
find dist -maxdepth 1 -name 'serverscrub-*.zip' -size 0 -delete 2>/dev/null || true

# ── 3. Stage exactly the release files ─────────────────────────────────────────
info "Staging files…"
STAGE_LIST=(
  VERSION CHANGELOG.md install.sh uninstall.sh update.sh upgrade.sh get.sh test.sh
  backend/config/config.php backend/cli/serverscrub.php
  frontend/index.html whm/serverscrub.conf whm/serverscrub.png
  scripts/make-release.sh scripts/publish.sh scripts/extract-notes.sh
  scripts/check-version-bump.sh "dist/notes-${VER}.md"
  "$ZIP" latest.json
  # Generated by make-release.sh and tracked, so it has to be staged too.
  # It was not, and sat at 4.1.5 while three releases shipped -- a tracked
  # manifest that lies is a trap for anyone pointing a mirror at dist/.
  dist/latest.json
)
for f in "${STAGE_LIST[@]}"; do [[ -e "$f" ]] && git add "$f"; done
git add -u install.sh uninstall.sh update.sh 2>/dev/null || true

# ── Stage the source the zip was actually built from ──────────────────────────
#
# The list above is the release METADATA. It does not include backend/lib,
# backend/daemon, frontend/js or tests, so for v4.6.0 this script built a zip
# containing two new library modules, pushed it, and committed a repository
# that did not contain them. The shipped product and the source of record
# disagreed, and nothing said so.
#
# make-release.sh packages from the WORKING TREE, so whatever is on disk is
# what customers get. The commit therefore has to cover the same trees, or the
# tag is a lie about what shipped. Untracked files are included deliberately:
# a brand-new module is exactly the thing that went missing.
# cpanel/ was missing from this list, which is the whole customer-facing
# plugin. Its index.live.php had not been committed since v4.27.0 while
# six releases shipped changes to it -- the scan log, the Started-by
# column, the threat dialog. The zips were correct; the repository was
# not, so a fresh clone would have built a product missing all of it.
SRC_TREES=(backend frontend whm scripts tests cpanel)
for d in "${SRC_TREES[@]}"; do [[ -d "$d" ]] && git add -A -- "$d"; done

SRC_STAGED=$(git diff --cached --name-only -- "${SRC_TREES[@]}" | wc -l | tr -d ' ' || true)
if [[ "$SRC_STAGED" -gt 0 ]]; then
    info "Staging ${SRC_STAGED} source file(s) the zip was built from:"
    git diff --cached --name-only -- "${SRC_TREES[@]}" | sed 's/^/      /'
fi

# ── Does the commit actually cover what the zip contains? ────────────────────
#
# Both lists above are hand-maintained, and both have been wrong. v4.6.0
# shipped two library modules that were never committed; the fix was to
# enumerate SRC_TREES, which then omitted cpanel/ and test.sh for six
# releases. Enumerating is the bug, not the specific list.
#
# So stop trusting the lists and ask the artifact. make-release.sh packages
# from the WORKING TREE, so every path inside the zip is a path customers
# receive. If any of them is dirty or untracked after staging, the tag is
# about to claim something the repository does not contain.
# A guard that quietly does nothing when a tool is missing is not a guard.
# Say so, because the release still goes out and somebody has to know the
# check did not happen.
if [[ ! -f "$ZIP" ]]; then
    warn "No zip at ${ZIP} — cannot verify the commit covers what shipped."
elif ! command -v unzip >/dev/null 2>&1; then
    warn "unzip not available — cannot verify the commit covers what shipped."
fi
if [[ -f "$ZIP" ]] && command -v unzip >/dev/null 2>&1; then
    _unstaged=""
    while IFS= read -r _zp; do
        # Paths inside the archive are prefixed with serverscrub/ and mirror
        # the repo. Directories and the generated dist/ tree are not source.
        _rp="${_zp#serverscrub/}"
        [[ -z "$_rp" || "$_rp" == */ ]] && continue
        case "$_rp" in dist/*|database/*|logs/*|quarantine/*) continue ;; esac
        [[ -e "$_rp" ]] || continue
        # porcelain is "XY path": X is the index, Y is the working tree.
        #
        # Any output at all is NOT the test. A file that is staged reads as
        # "M " and is about to be committed -- treating that as a failure
        # refuses every release, which is how a guard gets switched off.
        #
        # What matters is the working tree column: if Y is not a space the
        # file on disk differs from what will be committed, and the zip was
        # built from the disk. "??" has Y="?" and is caught by the same test.
        _st="$(git status --porcelain -- "$_rp" 2>/dev/null | head -1 || true)"
        if [[ -n "$_st" && "${_st:1:1}" != " " ]]; then
            _unstaged="${_unstaged}    ${_rp}  [${_st:0:2}]
"
        fi
    done < <(unzip -Z1 "$ZIP" 2>/dev/null || true)

    if [[ -n "$_unstaged" ]]; then
        echo ""
        err "These files are IN THE ZIP but not in the commit:"
        printf '%s' "$_unstaged"
        echo ""
        echo -e "  The tag would claim a source tree that does not contain what"
        echo -e "  shipped. Add them to SRC_TREES or STAGE_LIST in this script,"
        echo -e "  or stage them by hand, and run again."
        echo ""
        exit 1
    fi
    ok "Every file in the zip is committed"
fi

if git diff --cached --quiet; then
    warn "Nothing new to commit — proceeding to push/release with existing HEAD"
elif [[ "$RESUMING" == "yes" ]]; then
    # A resume re-runs the build, and a rebuild that comes out byte-identical
    # stages nothing. If something DID change, committing it would move HEAD
    # away from the tag that is already on origin, and the tag guard below
    # would then refuse -- after another push. Stop here instead, where
    # nothing has left the machine.
    echo "" >&2
    err "Resuming ${TAG}, but the rebuild changed tracked files."
    git diff --cached --name-only | sed 's/^/      /' >&2
    echo "" >&2
    echo "    ${TAG} on origin describes the previous commit, so these changes" >&2
    echo "    cannot go out under it. Either:" >&2
    echo "      git checkout -- \$(git diff --cached --name-only | tr '\\n' ' ')" >&2
    echo "    and re-run to finish the mirror step for the release as tagged, or" >&2
    echo "    bump VERSION and publish these changes as a new release." >&2
    echo "" >&2
    exit 1
else
    git commit -m "Release ${TAG}"
    ok "Committed ${TAG}"
fi

# ── 3b. The tree must be clean before anything leaves this machine ─────────────
#
# This gate used to live further down, next to the tag. That meant a dirty tree
# failed the release AFTER the commit had already been pushed to origin/main --
# a pushed release commit with no tag, which is the exact half-finished state
# this script is being fixed to stop producing. Check it here, while refusing
# still costs nothing.
TAG_COMMIT="$(git rev-parse HEAD)"
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo ""
    err "Working tree is dirty — refusing to publish ${TAG}."
    git status --porcelain | grep -v '^??' | sed 's/^/      /' >&2
    echo "" >&2
    echo "  HEAD is ${TAG_COMMIT:0:7}; these tracked files on disk differ from it," >&2
    echo "  and the zip was built from the disk. Nothing has been pushed." >&2
    echo "  Commit or discard these and run again." >&2
    exit 1
fi
ok "Working tree clean at ${TAG_COMMIT:0:7}"

# ── 4. Push main ───────────────────────────────────────────────────────────────
info "Pushing to origin/main…"
if [[ -n "$TOKEN" ]]; then
    # Inject auth per-command via header; keeps the token out of remote config/URL
    git -c http.extraheader="Authorization: Bearer ${TOKEN}" push origin HEAD:main
else
    git push origin HEAD:main
fi
ok "Pushed to origin/main"

# ── 4b. Create and push the annotated tag ──────────────────────────────────────
#
# THE TAG IS ITS OWN STEP. It used to exist only as a side effect of creating
# the GitHub Release, and that step is skipped whenever gh and GH_TOKEN are
# both absent -- which is the normal state of the release machine. So every
# release took the `else` branch, printed a warning about the Release PAGE,
# and silently created no tag at all. v4.25.1 through v4.35.1 -- 38 releases
# -- pushed a release commit and no tag, locally or on origin. Nobody noticed
# because the warning only ever mentioned the Release page.
#
# Tagging now happens here, before the Release step, unconditionally, and
# fails the release if it cannot be done. The GitHub Release is a page on a
# website; the tag is the thing the repository is built on and the thing
# check-version-bump.sh uses as its baseline. It does not get to be optional.
info "Tagging ${BOLD}${TAG}${NC}…"

# Gate 1: the version bump check must have passed. Reaching this line already
# implies it (step 0 exits otherwise), but it is stated rather than inferred so
# that reordering the script cannot quietly drop the gate.
if [[ "$VERSION_CHECK" == "failed" ]]; then
    die "Version bump check failed — refusing to tag."
fi

# Gate 2: the working tree must still be clean for every TRACKED file. Step 3b
# already established this before the push; re-checking costs one git call and
# means the tag can never point at a tree that drifted in between. Untracked
# files outside the source trees are not a reason to refuse -- SRC_TREES
# staging already swept those -- but a tracked modification is.
if [[ "$(git rev-parse HEAD)" != "$TAG_COMMIT" ]]; then
    die "HEAD moved during the release ($TAG_COMMIT -> $(git rev-parse --short HEAD)) — refusing to tag."
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo ""
    err "Working tree went dirty mid-release — refusing to tag ${TAG}."
    git status --porcelain | grep -v '^??' | sed 's/^/      /' >&2
    echo "" >&2
    echo "  The tag would point at ${TAG_COMMIT:0:7}, which no longer matches the" >&2
    echo "  tree on disk. Commit or discard these and run again." >&2
    exit 1
fi

# An existing local tag is fine only if it already points where we are about to
# point it. A tag of this name on a different commit is a real conflict and the
# release stops; the remote was already checked near the top of this script.
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
    EXISTING="$(git rev-parse "refs/tags/${TAG}^{commit}")"
    if [[ "$EXISTING" != "$TAG_COMMIT" ]]; then
        die "Tag ${TAG} already exists locally on ${EXISTING:0:7}, but HEAD is ${TAG_COMMIT:0:7}. Delete it or bump VERSION."
    fi
    info "Tag ${TAG} already exists locally on ${TAG_COMMIT:0:7} — reusing it"
else
    # Annotated, deliberately: annotated tags carry a tagger, a date and a
    # message, and `git describe` and --sort=v:refname both behave properly
    # with them. The release notes go in the message so the tag stands on its
    # own even if the GitHub Release page is never made.
    git tag -a "$TAG" -m "ServerScrub ${TAG}" "$TAG_COMMIT"
    ok "Created annotated tag ${TAG} on ${TAG_COMMIT:0:7}"
fi

info "Pushing tag ${TAG} to origin…"
if [[ -n "$TOKEN" ]]; then
    git -c http.extraheader="Authorization: Bearer ${TOKEN}" push origin "refs/tags/${TAG}"
else
    git push origin "refs/tags/${TAG}"
fi
ok "Pushed tag ${TAG} to origin"
TAG_PUSHED=yes

# ── 5. Extract release notes for this version from CHANGELOG ────────────────────
NOTES="$(awk -v hdr="## [${VER}]" '
    index($0, hdr) == 1 {grab=1; next}
    grab && index($0, "## [") == 1 {exit}
    grab {print}
' CHANGELOG.md)"
[[ -n "$NOTES" ]] || NOTES="ServerScrub ${TAG}"

# ── 6. Create the GitHub Release (this is what the updater watches) ─────────────
info "Creating GitHub Release ${TAG}…"
# On a resume the Release page may already exist, and creating a release for a
# tag that already has one fails -- `gh release create` non-zero, the API 422 --
# which under `set -e` would end the run before the mirror step this resume
# exists to reach. Checked through whichever credential this machine has.
_release_exists=no
if [[ "$RESUMING" == "yes" ]]; then
    if command -v gh >/dev/null 2>&1 && gh release view "$TAG" >/dev/null 2>&1; then
        _release_exists=yes
    elif [[ -n "$TOKEN" ]] && curl -fsS --max-time 15 \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "https://api.github.com/repos/${SLUG}/releases/tags/${TAG}" \
            >/dev/null 2>&1; then
        _release_exists=yes
    fi
fi
if [[ "$_release_exists" == "yes" ]]; then
    ok "Release ${TAG} already exists on GitHub — left alone (resume)"
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    printf '%s' "$NOTES" | gh release create "$TAG" "$ZIP" \
        --title "ServerScrub ${TAG}" --notes-file - --target main
    ok "Release created via gh (asset attached)"
elif [[ -n "$TOKEN" ]]; then
    # Build JSON body safely
    if command -v python3 >/dev/null 2>&1; then
        BODY="$(NOTES="$NOTES" TAG="$TAG" python3 -c 'import json,os;print(json.dumps({"tag_name":os.environ["TAG"],"target_commitish":"main","name":"ServerScrub "+os.environ["TAG"],"body":os.environ["NOTES"],"draft":False,"prerelease":False}))')"
    elif command -v jq >/dev/null 2>&1; then
        BODY="$(jq -n --arg t "$TAG" --arg n "ServerScrub $TAG" --arg b "$NOTES" \
            '{tag_name:$t,target_commitish:"main",name:$n,body:$b,draft:false,prerelease:false}')"
    else
        die "Need python3 or jq to build the release JSON (or install gh)"
    fi
    RESP="$(curl -sS -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${SLUG}/releases" -d "$BODY")"
    UPLOAD_URL="$(printf '%s' "$RESP" | sed -n 's/.*"upload_url":[[:space:]]*"\([^{"]*\).*/\1/p' || true)"
    REL_HTML="$(printf '%s' "$RESP"   | sed -n 's/.*"html_url":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1 || true)"
    [[ -n "$UPLOAD_URL" ]] || die "Release creation failed: $(printf '%s' "$RESP" | head -c 300)"
    ok "Release created: ${REL_HTML}"
    # Attach the zip as a release asset (optional but nice for the Releases page)
    info "Uploading asset…"
    curl -sS -X POST \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/zip" \
        --data-binary @"$ZIP" \
        "${UPLOAD_URL}?name=serverscrub-${VER}.zip" >/dev/null && ok "Asset uploaded" || warn "Asset upload failed (release + tag still valid; updater uses dist/)"
else
    # Say precisely which of the two things is missing. The old wording was
    # "pushed code, but DID NOT create the Release", which read as one missing
    # item and hid the fact that no tag existed either. The tag is pushed by
    # step 4b above, before this point, so the ONLY thing missing here is the
    # Release page on github.com.
    warn "No gh and no GH_TOKEN — the GitHub RELEASE PAGE was not created."
    warn ""
    warn "  Tag ${TAG}:        PUSHED to origin (step 4b) — nothing to do."
    warn "  Release commit:    PUSHED to origin/main — nothing to do."
    warn "  Release page:      MISSING — this is the only outstanding item."
    warn ""
    warn "  The tag is what the repository and the version-bump check rely on,"
    warn "  and it is already in place. The Release page is the download page"
    warn "  the in-app updater reads; make it by hand:"
    warn "    repo → Releases → Draft a new release → choose the EXISTING tag"
    warn "    ${TAG} (do not create a new one) → attach ${ZIP} → publish."
fi

# ── 6b. Verify the release actually left a tag ─────────────────────────────────
#
# The whole point of this check: a release is not a release without a tag, and
# for 38 consecutive releases this script reported success while leaving none.
# A step that can silently not happen needs an assertion after it, not a
# warning inside it.
#
# NOTE ON SORTING: plain `git tag | tail -1` is NOT the newest tag. git tag
# sorts lexicographically, so in this repo today it returns v4.9.0 -- "v4.9.0"
# sorts after "v4.36.0" because "9" > "3" one character at a time. Every check
# here uses --sort=v:refname, which sorts by version number. Getting this wrong
# is how a check like this passes while testing nothing.
info "Verifying the tag…"
VERIFY_FAIL=""

if ! git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
    VERIFY_FAIL="${VERIFY_FAIL}    Tag ${TAG} does not exist locally.
"
else
    _tagged="$(git rev-parse "refs/tags/${TAG}^{commit}" || true)"
    if [[ "$_tagged" != "$TAG_COMMIT" ]]; then
        VERIFY_FAIL="${VERIFY_FAIL}    Tag ${TAG} points at ${_tagged:0:7}, not the released commit ${TAG_COMMIT:0:7}.
"
    fi
    if [[ "$(git cat-file -t "refs/tags/${TAG}" 2>/dev/null || true)" != "tag" ]]; then
        VERIFY_FAIL="${VERIFY_FAIL}    Tag ${TAG} is lightweight, not annotated.
"
    fi
fi

# The newest tag by version must be the one just released. If it is not, either
# the tag did not get made or a higher version is already tagged -- both mean
# the baseline check-version-bump.sh reads is not this release.
NEWEST_TAG="$(git tag --sort=v:refname | tail -1 || true)"
if [[ "$NEWEST_TAG" != "$TAG" ]]; then
    VERIFY_FAIL="${VERIFY_FAIL}    Newest tag is ${NEWEST_TAG:-<none>}, expected ${TAG}.
"
fi

# And it has to be on origin, since that is what everyone else and the CDN see.
# A network failure here is reported but is not treated as a release failure:
# the local tag is correct and `git push origin ${TAG}` is all that is left.
_remote_tag="$(timeout 30 git ls-remote --tags origin "refs/tags/${TAG}" 2>/dev/null | head -1 || true)"
if [[ -z "$_remote_tag" ]]; then
    if [[ "$TAG_PUSHED" == "yes" ]]; then
        warn "Could not confirm ${TAG} on origin (network?). Verify with: git ls-remote --tags origin ${TAG}"
    else
        VERIFY_FAIL="${VERIFY_FAIL}    Tag ${TAG} is not on origin.
"
    fi
fi

if [[ -n "$VERIFY_FAIL" ]]; then
    echo ""
    err "RELEASE FAILED ITS TAG CHECK — ${TAG} is not correctly tagged:"
    printf '%s' "$VERIFY_FAIL" >&2
    echo "" >&2
    echo "  The commit and any GitHub Release above may already be pushed." >&2
    echo "  Fix the tag before announcing this release:" >&2
    echo "    git tag -a ${TAG} -m \"ServerScrub ${TAG}\" ${TAG_COMMIT:0:7}" >&2
    echo "    git push origin refs/tags/${TAG}" >&2
    echo "" >&2
    exit 1
fi
ok "Tag ${TAG} verified: annotated, on ${TAG_COMMIT:0:7}, newest by version, on origin"

# ── 7. The GitHub channel, verified THROUGH THE TAG ─────────────────
#
# Not through .../main/latest.json. MEASURED 2026-11-23, same object, two
# consecutive requests to raw.githubusercontent.com:
#
#   .../main/latest.json                   -> X-Cache: MISS  ETag "f7a7cab..."
#   .../main/latest.json?cb=17954488137754 -> X-Cache: HIT   ETag "f7a7cab..."
#
# The query string is not part of Fastly's cache key for raw, and the branch
# path is served with max-age=300. A check against that url can be satisfied
# by a cached copy of the PREVIOUS release -- which is to say it can pass
# without the release having happened. The tag path is written once and cannot
# be stale, so this is the only version of this check that proves anything.
info "Verifying the GitHub channel through the tag..."
GH_TAG_BASE="https://raw.githubusercontent.com/${SLUG}/${TAG}"
_gh_tries="${SG_GH_POLL_TRIES:-6}"
_gh_wait="${SG_GH_POLL_SECS:-10}"
_gh_ver=""
for _try in $(seq 1 "$_gh_tries"); do
    _gh_ver="$(curl -fsS --max-time 15 "${GH_TAG_BASE}/latest.json" 2>/dev/null \
               | grep -o '"version"[^,]*' | head -1 \
               | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
    [[ "$_gh_ver" == "$VER" ]] && break
    if [[ "$_try" -lt "$_gh_tries" ]]; then
        info "  tag path not readable yet (${_try}/${_gh_tries}); ${_gh_wait}s..."
        sleep "$_gh_wait"
    fi
done
if [[ "$_gh_ver" == "$VER" ]]; then
    ok "GitHub channel serves ${VER} at ${GH_TAG_BASE}/latest.json"
else
    echo "" >&2
    err "RELEASE NOT READABLE ON THE GITHUB CHANNEL"
    echo "    ${GH_TAG_BASE}/latest.json served ${_gh_ver:-nothing}, expected ${VER}." >&2
    echo "" >&2
    echo "    The commit and the tag ARE pushed -- git is not the problem and" >&2
    echo "    nothing here rolls that back. What is missing is latest.json at" >&2
    echo "    that tag, so every installed server resolving the release through" >&2
    echo "    the tag path will not see ${VER}." >&2
    echo "" >&2
    echo "    Check: git show ${TAG}:latest.json | head -5" >&2
    echo "    and:   curl -fsS ${GH_TAG_BASE}/latest.json" >&2
    echo "" >&2
    exit 1
fi

# ── 7b. The CDN mirror, WAITED FOR and then verified ────────────
#
# The rule is that a release is not done until the build is in git AND in a
# v<version>/ folder on the CDN. This step used to ask the CDN exactly once,
# immediately after the push -- the one moment it is guaranteed to still be
# serving the previous version -- and then print
#
#   "CDN is live, serving 4.37.0 - it pulls 4.37.9 within ~10 min"
#   "Published v4.37.9. CDN will pick it up within ~10 min."
#
# and exit 0. Nothing ever looked again. Nine releases (4.37.1 ... 4.37.9) went
# out that way; the mirror has been frozen at 4.37.0 since September and nobody
# found out for a month. A sentence that promises a mirror nobody has observed
# is the defect, not the frozen mirror.
#
# So: wait for the sync (cron is */10) and then require BOTH halves of the
# user's definition of done, or fail the release.
CDN_BASE="${SG_CDN_BASE:-https://serverscrub.com/releases}"
CDN_ACCT="${SG_CDN_ACCOUNT:-serversc}"
# Defaults are the stated bound: every 30s for 12 minutes, which covers one
# full */10 cron cycle plus the sync's own runtime. Overridable so a test can
# exercise this without a 12-minute wait.
CDN_TRIES="${SG_CDN_POLL_TRIES:-24}"
CDN_WAIT="${SG_CDN_POLL_SECS:-30}"
info "Waiting for the CDN mirror (every ${CDN_WAIT}s, up to ${CDN_TRIES} times)..."

_cdn_code=000
_cdn_ver=""
_cdn_pinned=000
_cdn_ok=false
for _try in $(seq 1 "$CDN_TRIES"); do
    # NO cache-buster. This is the url every installed server actually
    # requests, so this is the url that has to be right.
    _cdn_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
                 "${CDN_BASE}/latest.json" 2>/dev/null || true)"
    [[ "$_cdn_code" =~ ^[0-9]{3}$ ]] || _cdn_code=000
    _cdn_ver=""
    if [[ "$_cdn_code" == "200" ]]; then
        _cdn_ver="$(curl -fsS --max-time 15 "${CDN_BASE}/latest.json" 2>/dev/null \
                    | grep -o '"version"[^,]*' | head -1 \
                    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
    fi
    # Half the definition of done: the per-version folder. update.sh reads
    # v<ver>/latest.json when the top-level manifest looks stale, and that is
    # the path that carries this build's own checksum.
    _cdn_pinned="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
                   "${CDN_BASE}/v${VER}/latest.json" 2>/dev/null || true)"
    [[ "$_cdn_pinned" =~ ^[0-9]{3}$ ]] || _cdn_pinned=000
    if [[ "$_cdn_ver" == "$VER" && "$_cdn_pinned" == "200" ]]; then
        _cdn_ok=true
        break
    fi
    if [[ "$_try" -lt "$CDN_TRIES" ]]; then
        info "  ${CDN_BASE}/latest.json -> ${_cdn_ver:-HTTP $_cdn_code}, v${VER}/latest.json -> HTTP ${_cdn_pinned} (${_try}/${CDN_TRIES})"
        sleep "$CDN_WAIT"
    fi
done

if $_cdn_ok; then
    ok "CDN mirror verified: ${CDN_BASE}/latest.json serves ${VER} on a plain request"
    ok "  and ${CDN_BASE}/v${VER}/latest.json returns 200"
else
    echo "" >&2
    err "RELEASE IS IN GIT BUT NOT MIRRORED"
    echo "" >&2
    echo "    ${TAG} is committed, tagged and pushed, and readable on the" >&2
    echo "    GitHub channel. Nothing below rolls any of that back." >&2
    echo "" >&2
    if [[ "$_cdn_code" != "200" ]]; then
        # Different diagnosis, different fix: a CDN that is not answering is a
        # vhost/DNS problem, not a sync that has fallen behind.
        echo "    CDN IS NOT SERVING ANYTHING: ${CDN_BASE}/latest.json -> HTTP ${_cdn_code}." >&2
        echo "    Every serverscrub.com install and update url is failing right now." >&2
        echo "    One-time setup, as ROOT on the server that serves the domain:" >&2
        echo "      bash <(curl -fsSL https://raw.githubusercontent.com/${SLUG}/main/scripts/cdn-setup.sh)" >&2
    else
        echo "    The CDN IS answering, with the WRONG release:" >&2
        echo "      ${CDN_BASE}/latest.json          -> v${_cdn_ver:-unparseable}  (expected v${VER})" >&2
        echo "      ${CDN_BASE}/v${VER}/latest.json  -> HTTP ${_cdn_pinned}" >&2
        echo "    The sync has not published since, or is publishing to a path" >&2
        echo "    nothing serves." >&2
    fi
    echo "" >&2
    echo "    Force the sync now, as ${CDN_ACCT}:" >&2
    echo "      /home/${CDN_ACCT}/bin/cdn-sync.sh" >&2
    echo "" >&2
    echo "    Then diagnose, read-only, as root:" >&2
    echo "      crontab -l -u ${CDN_ACCT} | grep -i cdn" >&2
    echo "      tail -n 60 /home/${CDN_ACCT}/logs/cdn-sync.log" >&2
    echo "      grep -hE '^documentroot:' /var/cpanel/userdata/${CDN_ACCT}/* | sort -u" >&2
    echo "      bash /home/${CDN_ACCT}/bin/cdn-setup.sh --check" >&2
    echo "" >&2
    echo "    Installs still work -- they fall back to the GitHub mirror -- but" >&2
    echo "    this release is NOT mirrored, and no output above says it is." >&2
    echo "" >&2
    # A failure that does not say how to finish is how a blocked release
    # becomes a burned version number.
    echo "    TO FINISH THIS RELEASE once the CDN serves ${VER}:" >&2
    echo "      bash scripts/publish.sh ${VER}" >&2
    echo "" >&2
    echo "    The commit and tag are already on origin; the re-run recognises its" >&2
    echo "    own tag on this commit, re-creates nothing, and re-checks the mirror." >&2
    echo "    Do NOT bump VERSION and do NOT delete the tag -- update.sh resolves" >&2
    echo "    versions from tags, so deleting this one withdraws the release." >&2
    echo "" >&2
    exit 1
fi

echo ""
ok "Published ${TAG}: in git, readable at the tag, and mirrored on the CDN."

# UPGRADE FIRST, install second.
#
# This script used to print only the get.sh line, which is for a FRESH install.
# Every existing server -- which is every server that matters after the first
# release -- needs update.sh instead, and four consecutive releases went out
# reporting the wrong one because this is the text everybody copies from.
# The command an operator actually needs is the one printed first.
echo -e "  ${BOLD}Upgrade an existing server:${NC}"
echo -e "  ${BOLD}bash /usr/local/serverscrub/update.sh --yes${NC}"
echo ""
echo -e "  Fresh install (new server only):"
echo -e "  bash <(curl -fsSL https://raw.githubusercontent.com/${SLUG}/main/get.sh)"
