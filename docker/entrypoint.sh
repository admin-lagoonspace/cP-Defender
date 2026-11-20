#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub test container — entrypoint
#
#   seed      build the cPanel-shaped server and the log fixtures
#   lint      parse every PHP file with THIS container's php, and nothing else
#   install   seed, then run the real install.sh from /opt/serverscrub-src
#   serve     install, then serve the panel on :8777 for UI tests
#   test      lint, install, then run the regression suite inside the container
#   upgrade   install an OLDER release from dist/, then upgrade to the mounted
#             tree, then check the database survived it
#   shell     an interactive shell with everything seeded
#
# install.sh runs in STANDALONE mode here, and that is a stated limitation
# rather than a detail: cpanel mode registers with AppConfig, drops CGI
# wrappers into WHM's docroot and is served by cpsrvd. None of that exists in
# a container, and faking it would produce a pass for the one path a real
# server actually uses. What this exercises is the code; the cPanel
# integration is still only proven by installing on a cPanel box.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SRC=/opt/serverscrub-src
DEST=/usr/local/serverscrub
ADMIN_USER="${SG_ADMIN_USER:-admin}"
# Fixed so UI runs are repeatable. A throwaway container on a developer's
# laptop, never a server: install.sh generates and prints a random one when
# --admin-pass is not given, which a browser-driven test cannot predict.
ADMIN_PASS="${SG_ADMIN_PASS:-dockertest-not-a-real-password}"

banner() { echo; echo "════ $* ════"; echo; }

do_seed() {
    banner "seeding"
    /usr/local/bin/seed-cpanel.sh "${SEED_ACCOUNTS:-8}"
    # seed-logs.sh was never COPYed into the image and never called, so every
    # log-ingest test ran against files that did not exist -- and passed,
    # because "no entries" is indistinguishable from "nothing to parse".
    /usr/local/bin/seed-logs.sh
}

# ── Parse gate, at THIS container's PHP version ───────────────────────────────
#
# scripts/preflight.py lints with whatever interpreter it finds, which on the
# developer's machine is PHP 8.5. So it reported "all 55 PHP files parse" for a
# tree containing match() expressions -- PHP 8.0 syntax -- while install.sh
# claims a floor of 7.4. At 7.4 the suite did not fail, it CRASHED: 70 test
# files, every one of them with the same parse error, and the real cause buried
# in the repetition.
#
# One file, one line, said once, before anything else runs.
do_lint() {
    banner "parse check — php $(php -r 'echo PHP_VERSION;')"
    cd "$SRC"
    local bad=0
    while read -r f; do
        if ! out=$(php -l "$f" 2>&1); then
            echo "  PARSE FAIL  $f"
            echo "              $(echo "$out" | head -1)"
            bad=$((bad + 1))
        fi
    done < <(find backend cpanel whm -name '*.php' 2>/dev/null | sort; ls *.php 2>/dev/null)
    if [[ $bad -gt 0 ]]; then
        echo
        echo "  ${bad} file(s) do not parse at PHP $(php -r 'echo PHP_VERSION;')."
        echo "  install.sh:360 requires 'PHP 7.4+'. Either that claim is wrong or"
        echo "  the syntax is. Nothing below this point has been exercised."
        return 1
    fi
    echo "  all files parse"
}

do_install() {
    [[ -f /var/cpanel/users/addons ]] || do_seed
    banner "installing from ${SRC}"
    [[ -d "$SRC" ]] || { echo "No source at ${SRC} — mount the repo there"; exit 1; }
    cd "$SRC"
    # NOT --yes: install.sh has no such flag and its arg loop ends in `*) ;;`,
    # so it was silently ignored. --mode is what actually skips the prompt.
    #
    # And NOT allowed to abort this function. install.sh exits 1 after a
    # perfectly good --mode standalone install, because its self-test checks
    # for the WHM AppConfig, the CGI wrapper and the ConfigObj driver even
    # though it was told this is standalone. Under `set -e` that killed the
    # entrypoint before `exec php -S` ever ran, so `up panel` started,
    # installed successfully, and then exited 1 with no server. The exit code
    # is a finding; it must not also be a blocker for the test target.
    set +e
    bash install.sh --mode standalone \
                    --admin-user "$ADMIN_USER" --admin-pass "$ADMIN_PASS"
    local rc=$?
    set -e
    echo
    echo "install.sh exit: ${rc} (non-zero is expected in standalone — WHM self-test)"
    [[ -f "${DEST}/VERSION" ]] || { echo "install genuinely failed: no ${DEST}/VERSION"; exit 1; }
    echo
    echo "installed version: $(cat "${DEST}/VERSION" 2>/dev/null || echo '?')"
    ls -la "${DEST}/database/" 2>/dev/null || true
}

do_serve() {
    [[ -f "${DEST}/VERSION" ]] || do_install
    banner "serving on :8777"
    # install.sh copies backend/, frontend/ and VERSION -- NOT docker-router.php.
    # `php -S` with a router script it cannot open exits immediately, so the
    # panel never came up. Copy it in from the (read-only) mount.
    cp -f "${SRC}/docker-router.php" "${DEST}/docker-router.php"
    cd "${DEST}"
    exec php -S 0.0.0.0:8777 -t "${DEST}/frontend" "${DEST}/docker-router.php"
}

do_test() {
    do_lint
    [[ -f /var/cpanel/users/addons ]] || do_seed
    banner "regression suite, inside the container"
    cd "$SRC"

    # The packaging assertions need an artifact to assert against.
    #
    # scripts/preflight.py builds one into a temp directory on the host and
    # hands it to the suite in SG_PACKAGE_ZIP. That temp directory does not
    # exist in here, and the mounted dist/ only carries RELEASED zips -- so
    # the packaging test failed inside the container for the current version
    # every time, on a check that is perfectly satisfiable. Build our own,
    # exactly as the host does. Written to /tmp, never to the read-only mount.
    local pkg_stage; pkg_stage="$(mktemp -d)"
    local want_ver;  want_ver="$(cat "$SRC/VERSION" 2>/dev/null | tr -d '[:space:]')"
    if [[ -n "$want_ver" && ! -f "$SRC/dist/serverscrub-${want_ver}.zip" ]]; then
        echo "building serverscrub-${want_ver}.zip for the packaging checks…"
        if bash "$SRC/scripts/make-release.sh" --out "$pkg_stage" >/dev/null 2>&1 \
           && [[ -f "${pkg_stage}/serverscrub-${want_ver}.zip" ]]; then
            export SG_PACKAGE_ZIP="${pkg_stage}/serverscrub-${want_ver}.zip"
            echo "  built $(stat -c %s "$SG_PACKAGE_ZIP") bytes"
        else
            echo "  WARNING: could not build a package; the packaging checks will fail"
        fi
    fi

    php tests/run.php

    # run.php already globs tests/test_*.py and runs them. Running them again
    # here only doubled the output -- and `|| echo FAILED` meant a Python
    # failure could not change this function's exit status, so `docker compose
    # run --rm test` returned 0 with failures on screen. The harness must be
    # able to fail.
    echo
    echo "python checks: run by tests/run.php above (python $(python3 -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])'))"
}

# ── Upgrade, not just install ────────────────────────────────────────────────
#
# The one-time migrations are the riskiest code in the product and an upgrade
# is the path nobody exercises. SG_FROM picks the baseline release out of
# dist/; it must be one that predates whatever table is under test.
do_upgrade() {
    local from="${SG_FROM:-4.35.0}"
    local zip="${SRC}/dist/serverscrub-${from}.zip"
    [[ -f "$zip" ]] || { echo "No baseline release at ${zip}"; exit 1; }

    [[ -f /var/cpanel/users/addons ]] || do_seed

    banner "installing BASELINE ${from}"
    rm -rf /tmp/baseline && mkdir -p /tmp/baseline
    unzip -q "$zip" -d /tmp/baseline
    local base
    base=$(find /tmp/baseline -maxdepth 2 -name install.sh -printf '%h\n' | head -1)
    [[ -n "$base" ]] || { echo "No install.sh inside ${zip}"; exit 1; }
    # install.sh exits NON-ZERO here, and not because the install failed: its
    # self-test insists on the WHM AppConfig, the CGI wrapper and the ConfigObj
    # driver even when it was asked for --mode standalone. None of those can
    # exist in a container, so 8 FAIL lines and "Installation verification
    # failed" are expected -- and are themselves a finding, not a reason to
    # abandon the upgrade test. Record the code and carry on.
    set +e
    ( cd "$base" && bash install.sh --mode standalone \
        --admin-user "$ADMIN_USER" --admin-pass "$ADMIN_PASS" ) \
        >/tmp/baseline-install.log 2>&1
    echo "baseline install.sh exit: $?"
    set -e
    { grep -ciE '\[FAIL\]' /tmp/baseline-install.log || true; }         | sed 's/^/    self-test FAIL lines: /'
    echo "baseline version: $(cat "${DEST}/VERSION" 2>/dev/null || echo '?')"

    banner "baseline database shape"
    sqlite3 "${DEST}/database/serverscrub.db" \
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" \
        | tr '\n' ' '; echo
    echo "waf_exclusions present in baseline: $(sqlite3 "${DEST}/database/serverscrub.db" \
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='waf_exclusions';")"

    # Something to lose. If an upgrade drops or rewrites these, say so.
    sqlite3 "${DEST}/database/serverscrub.db" \
        "INSERT INTO settings (key, value) VALUES ('shakaal_upgrade_canary','4.35.0');" \
        2>/dev/null || true

    banner "UPGRADING to the mounted tree"
    set +e
    ( cd "$SRC" && bash install.sh --mode standalone ) >/tmp/upgrade-install.log 2>&1
    echo "upgrade install.sh exit: $?"
    set -e
    # `|| true` on every grep: a grep that matches nothing exits 1, and under
    # `set -e` that aborted this function before any of the post-upgrade
    # database checks ran -- the checks this command exists for.
    { grep -ciE '\[FAIL\]' /tmp/upgrade-install.log || true; } \
        | sed 's/^/    self-test FAIL lines: /'
    { grep -iE 'migrat|corrupt|integrity' /tmp/upgrade-install.log || true; } \
        | head -10 | sed 's/^/    /'
    echo "upgraded version: $(cat "${DEST}/VERSION" 2>/dev/null || echo '?')"

    banner "post-upgrade database"
    echo "integrity_check : $(sqlite3 "${DEST}/database/serverscrub.db" 'PRAGMA integrity_check;')"
    echo "foreign_key_check: $(sqlite3 "${DEST}/database/serverscrub.db" 'PRAGMA foreign_key_check;' | head -3)"
    echo "waf_exclusions   : $(sqlite3 "${DEST}/database/serverscrub.db" \
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='waf_exclusions';")"
    echo "canary survived  : $(sqlite3 "${DEST}/database/serverscrub.db" \
        "SELECT value FROM settings WHERE key='shakaal_upgrade_canary';")"
    echo "db dir perms     : $(stat -c '%a %U:%G' "${DEST}/database")"

    banner "the new CLI, on an UPGRADED database"
    local CLI="${DEST}/backend/cli/serverscrub.php"
    echo "── list (empty state) ──"
    php "$CLI" waf exclude list || true
    echo
    echo "── add, server-wide ──"
    php "$CLI" waf exclude add 420047 --reason="shakaal upgrade-path check" || true
    echo
    echo "── add, narrowed to host+path ──"
    php "$CLI" waf exclude add 942100 --domain=shopfront.test \
        --uri=/shop/checkout --reason="POST checkout false positive" || true
    echo
    echo "── list (populated) ──"
    php "$CLI" waf exclude list || true
    echo
    echo "── show: the config fragment that would be written ──"
    php "$CLI" waf exclude show || true
    echo
    echo "── rows actually in the upgraded database ──"
    sqlite3 -header -column "${DEST}/database/serverscrub.db" \
        'SELECT id, rule_id, domain, uri_prefix FROM waf_exclusions ORDER BY id;' || true
    echo
    echo "── integrity after the new table was written ──"
    echo "integrity_check : $(sqlite3 "${DEST}/database/serverscrub.db" 'PRAGMA integrity_check;')"
    echo
    echo "── db-check ──"
    php "$CLI" db-check || true
}

case "${1:-shell}" in
    seed)    do_seed ;;
    lint)    do_lint ;;
    install) do_install ;;
    serve)   do_serve ;;
    test)    do_test ;;
    upgrade) do_upgrade ;;
    shell)   do_seed; banner "ready"; cat /etc/serverscrub-test-env; exec /bin/bash ;;
    *)       exec "$@" ;;
esac
