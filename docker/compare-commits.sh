#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — is this failure pre-existing, or did we just cause it?
#
# "Some of them are pre-existing" is not an answer anybody can act on. This
# answers it per assertion, by running THE SAME TEST SUITE against TWO
# different product trees inside the same image.
#
#   A   candidate code + candidate tests   what we are being asked to ship
#   B   parent code    + candidate tests   the control: only the product differs
#   C   parent code    + parent tests      what the previous build really did
#
# A failure present in both A and B is PRE-EXISTING: the same assertion, the
# same test file, fails against the older product too, so the change under
# review did not cause it.
#
# A failure in A and not in B was INTRODUCED by the product change.
#
# A failure in B and not in A was FIXED by it.
#
# C is there only so the report can give the count "both ways" honestly --
# the parent's own suite is a different set of assertions and comparing raw
# totals between A and C proves nothing on its own.
#
# Usage:
#   docker/compare-commits.sh <php-stream> <candidate-dir> <parent-dir> <outdir>
#
# Run it from the host; it drives `docker run` itself because the compose file
# mounts one fixed tree and this needs two.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

STREAM="${1:-8.2}"
CAND="${2:?candidate tree}"
PARENT="${3:?parent tree}"
OUT="${4:?output dir}"
IMAGE="serverscrub-test:php${STREAM}"

mkdir -p "$OUT"

# No anonymous-volume masks here, deliberately. compose uses them to shadow the
# repo's WINDOWS python.exe/php.exe, but Docker cannot create a mountpoint
# inside a read-only bind when the directory is absent, and the parent tree has
# no logs/ -- which made every run against it die with
#   runc create failed: make mountpoint "/opt/serverscrub-src/logs":
#   read-only file system
# and exit 125. Two of the three legs produced no output at all, and the first
# version of this script cheerfully reported every failure in A as "INTRODUCED"
# because B had no failures to compare against. A comparison whose control did
# not run is worse than no comparison.
#
# The working copy below is writable anyway, so the interpreters are simply
# deleted from it and logs/ is created.
run_suite () {
    local code_tree="$1" test_tree="$2" label="$3"
    echo "── ${label} (php ${STREAM}) ──"
    docker run --rm \
        -v "${code_tree}:/opt/serverscrub-src:ro" \
        -v "${test_tree}:/opt/tests-src:ro" \
        --entrypoint bash "$IMAGE" -c '
            set -u
            /usr/local/bin/seed-cpanel.sh 8 >/dev/null 2>&1
            /usr/local/bin/seed-logs.sh      >/dev/null 2>&1
            # Work on a WRITABLE copy: the suite writes into tests/ and logs/,
            # and the product tree is mounted read-only on purpose.
            cp -a /opt/serverscrub-src /tmp/run
            rm -rf /tmp/run/tests /tmp/run/python /tmp/run/php
            mkdir -p /tmp/run/logs
            cp -a /opt/tests-src/tests /tmp/run/tests
            cd /tmp/run
            php tests/run.php 2>&1
        ' > "${OUT}/${label}.log" 2>&1
    local rc=$?

    # A leg that did not run must not be read as "nothing failed here".
    if ! grep -qE 'assertions? (passed|failed)' "${OUT}/${label}.log"; then
        echo "    !! ${label} DID NOT RUN (exit ${rc}) — comparison is invalid"
        head -3 "${OUT}/${label}.log" | sed 's/^/       /'
        echo "DID_NOT_RUN" > "${OUT}/${label}.fails"
        return 1
    fi

    # One normalised line per failing assertion: "<file>: <assertion>".
    # The runner prints failures as "  - <file>: <text>"; sandbox paths and
    # pids differ between runs and must not look like different failures.
    grep -E '^  - ' "${OUT}/${label}.log" \
        | sed -e 's/^  - //' \
              -e 's#/tmp/sg-test-[0-9]*-[0-9]*#SANDBOX#g' \
              -e 's/[0-9]\+\.[0-9]\+ms/TIMEms/g' \
              -e 's/(worst [0-9.]*ms)/(worst TIMEms)/g' \
              -e 's/pid [0-9]*/pid N/g' \
        | sort -u > "${OUT}/${label}.fails"

    local total failed
    total=$(grep -oE '[0-9]+ (of [0-9]+ )?assertions? (passed|failed)' "${OUT}/${label}.log" | tail -1)
    failed=$(wc -l < "${OUT}/${label}.fails")
    echo "    ${total:-no total line}  |  distinct failing assertions: ${failed}  | exit ${rc}"
}

run_suite "$CAND"   "$CAND"   "A-candidate"
run_suite "$PARENT" "$CAND"   "B-parentcode-candidatetests"
run_suite "$PARENT" "$PARENT" "C-parent-own"

echo
echo "══════ php ${STREAM}: per-assertion verdict ══════"
echo
echo "INTRODUCED by the product change (fails in A, passes in B):"
comm -23 "${OUT}/A-candidate.fails" "${OUT}/B-parentcode-candidatetests.fails" \
    | sed 's/^/  [INTRODUCED] /' || true
echo
echo "PRE-EXISTING (fails in A and in B — same assertion, older product):"
comm -12 "${OUT}/A-candidate.fails" "${OUT}/B-parentcode-candidatetests.fails" \
    | sed 's/^/  [PRE-EXISTING] /' || true
echo
echo "FIXED by the product change (failed in B, passes in A):"
comm -13 "${OUT}/A-candidate.fails" "${OUT}/B-parentcode-candidatetests.fails" \
    | sed 's/^/  [FIXED] /' || true
echo
echo "Counts both ways:"
printf '  candidate (A)               : %s failing assertions\n' "$(wc -l < "${OUT}/A-candidate.fails")"
printf '  parent code, same tests (B) : %s\n' "$(wc -l < "${OUT}/B-parentcode-candidatetests.fails")"
printf '  parent, its own suite (C)   : %s\n' "$(wc -l < "${OUT}/C-parent-own.fails")"
