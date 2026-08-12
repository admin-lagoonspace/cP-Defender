#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Gate — extract ONE version's notes from CHANGELOG.md
#
# CHANGELOG.md in the repo is the full history, which is correct for the repo and
# wrong for everything else: the per-version folder on the CDN was receiving a
# verbatim copy of all 600+ lines, so someone opening the notes for the release
# they just installed got the entire project history instead of what changed.
#
# This prints only the requested version's section. Used by make-release.sh to
# produce dist/notes-<version>.md, which is what the CDN and the in-app
# "what's new" actually serve.
#
#   bash scripts/extract-notes.sh 3.18.2
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VER="${1:-$(tr -d '[:space:]' < "${REPO_DIR}/VERSION")}"
SRC="${REPO_DIR}/CHANGELOG.md"
[[ -f "$SRC" ]] || { echo "No CHANGELOG.md at ${SRC}" >&2; exit 1; }

# The body between "## [<ver>]" and the next "## [" heading.
BODY="$(awk -v hdr="## [${VER}]" '
    index($0, hdr) == 1 { grab = 1; next }
    grab && index($0, "## [") == 1 { exit }
    grab { print }
' "$SRC")"

# Trim leading/trailing blank lines without collapsing the blanks inside.
BODY="$(printf '%s\n' "$BODY" | sed -e '/./,$!d' | sed -e ':a' -e '/^\s*$/{$d;N;ba' -e '}')"

if [[ -z "$BODY" ]]; then
    echo "No CHANGELOG section found for ${VER}" >&2
    exit 2
fi

# The heading line as written, so a date suffix survives.
HEADING="$(grep -m1 -F "## [${VER}]" "$SRC")"

cat << EOF
# Sentinel Gate ${VER}

${HEADING#\#\# }

${BODY}

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
EOF
