#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — version bump sanity check
#
# Compares the version bump in ./VERSION against the commits since the last tag
# and complains when they disagree.
#
# This exists because the convention was already written at the top of
# CHANGELOG.md and was still not followed: 3.14.0, 3.16.0 and 3.17.0 all bumped
# the MINOR for what were fixes or UI work on an existing feature — 3.16.0's own
# commit subject begins with "fix:". A rule that lives only in a document gets
# ignored; this one fails the release instead.
#
#   z (patch) — fixes, UI work on an existing feature, docs, refactors
#   y (minor) — new features, or architectural change
#   x (major) — reserved
#
# Usage:  bash scripts/check-version-bump.sh [--strict]
#         --strict exits non-zero on a mismatch (used by publish.sh)
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

STRICT=false
[[ "${1:-}" == "--strict" ]] && STRICT=true

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
err()  { echo -e "  ${RED}✖${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }

NEW="$(tr -d '[:space:]' < VERSION)"
LAST_TAG="$(git tag --sort=-v:refname | head -1)"
OLD="${LAST_TAG#v}"

if [[ -z "$OLD" ]]; then
    ok "No previous tag — nothing to compare"
    exit 0
fi
if [[ "$NEW" == "$OLD" ]]; then
    info "VERSION unchanged since ${LAST_TAG} — nothing to check"
    exit 0
fi

IFS=. read -r nx ny nz <<< "$NEW"
IFS=. read -r ox oy oz <<< "$OLD"

BUMP="none"
if   (( nx > ox )); then BUMP="major"
elif (( ny > oy )); then BUMP="minor"
elif (( nz > oz )); then BUMP="patch"
fi

echo ""
echo -e "${BOLD}Version bump check${NC}"
info "${OLD} → ${NEW}  (${BUMP})"

# ── Classify the commits since the last tag ───────────────────────────────────
SUBJECTS="$(git log --format=%s "${LAST_TAG}..HEAD" 2>/dev/null)"
if [[ -z "$SUBJECTS" ]]; then
    warn "No commits since ${LAST_TAG} — is this bump intentional?"
    exit 0
fi

N_FEAT=0; N_FIX=0; N_OTHER=0
while IFS= read -r s; do
    [[ -z "$s" ]] && continue
    case "$s" in
        feat*|feature*)                      N_FEAT=$((N_FEAT+1)) ;;
        fix*|bugfix*|perf*|revert*)          N_FIX=$((N_FIX+1)) ;;
        docs*|chore*|style*|refactor*|test*) N_OTHER=$((N_OTHER+1)) ;;
        *)                                   N_OTHER=$((N_OTHER+1)) ;;
    esac
done <<< "$SUBJECTS"

info "Commits since ${LAST_TAG}:  ${N_FEAT} feat · ${N_FIX} fix · ${N_OTHER} other"
echo "$SUBJECTS" | sed 's/^/      /'
echo ""

# ── Verdict ───────────────────────────────────────────────────────────────────
RC=0
if [[ "$BUMP" == "minor" && $N_FEAT -eq 0 ]]; then
    err "MINOR bumped, but no commit is a feature."
    err "Fixes and UI work on an existing feature are PATCH releases."
    err "Expected: ${ox}.${oy}.$((oz+1))"
    RC=1
elif [[ "$BUMP" == "patch" && $N_FEAT -gt 0 ]]; then
    warn "PATCH bumped, but ${N_FEAT} commit(s) look like features."
    warn "New capability should bump the minor: ${ox}.$((oy+1)).0"
    # A warning, not a failure — a small addition inside an existing feature is
    # a legitimate patch, and this heuristic reads commit subjects, not intent.
elif [[ "$BUMP" == "minor" ]]; then
    ok "MINOR bump with ${N_FEAT} feature commit(s) — consistent"
elif [[ "$BUMP" == "patch" ]]; then
    ok "PATCH bump with no feature commits — consistent"
elif [[ "$BUMP" == "major" ]]; then
    warn "MAJOR bump — make sure this is deliberate"
fi

# Skipping a number usually means a forgotten bump somewhere
if [[ "$BUMP" == "patch" ]] && (( nz > oz + 1 )); then
    warn "Patch jumped ${oz} → ${nz}; a release may have been missed"
fi
if [[ "$BUMP" == "minor" ]] && (( ny > oy + 1 )); then
    warn "Minor jumped ${oy} → ${ny}; a release may have been missed"
fi

echo ""
if [[ $RC -ne 0 ]] && $STRICT; then
    err "Refusing to publish. Correct VERSION, or re-run with SG_SKIP_VERSION_CHECK=1."
    exit 1
fi
[[ $RC -ne 0 ]] && warn "Continuing (not strict mode)"
exit 0
