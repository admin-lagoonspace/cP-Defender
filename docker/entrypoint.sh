#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub test container — entrypoint
#
#   seed      build the cPanel-shaped server and the log fixtures
#   install   seed, then run the real install.sh from /opt/serverscrub-src
#   serve     install, then serve the panel on :8777 for UI tests
#   test      install, then run the regression suite inside the container
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

banner() { echo; echo "════ $* ════"; echo; }

do_seed() {
    banner "seeding"
    /usr/local/bin/seed-cpanel.sh "${SEED_ACCOUNTS:-8}"
}

do_install() {
    [[ -f /var/cpanel/users/addons ]] || do_seed
    banner "installing from ${SRC}"
    [[ -d "$SRC" ]] || { echo "No source at ${SRC} — mount the repo there"; exit 1; }
    cd "$SRC"
    bash install.sh --mode standalone --yes
    echo
    echo "installed version: $(cat "${DEST}/VERSION" 2>/dev/null || echo '?')"
    ls -la "${DEST}/database/" 2>/dev/null || true
}

do_serve() {
    [[ -f "${DEST}/VERSION" ]] || do_install
    banner "serving on :8777"
    # The panel is a static front end plus a PHP API. PHP's built-in server
    # routes everything through the API entry point so /api/* resolves the way
    # cpsrvd would, which is enough for the UI to be driven for real.
    cd "${DEST}"
    exec php -S 0.0.0.0:8777 -t "${DEST}/frontend" "${DEST}/docker-router.php"
}

do_test() {
    [[ -f /var/cpanel/users/addons ]] || do_seed
    banner "regression suite, inside the container"
    cd "$SRC"
    php tests/run.php
    echo
    banner "python checks"
    for t in tests/test_*.py; do
        [[ -e "$t" ]] || continue
        echo "── $t"
        python3 "$t" || echo "FAILED: $t"
    done
}

case "${1:-shell}" in
    seed)    do_seed ;;
    install) do_install ;;
    serve)   do_serve ;;
    test)    do_test ;;
    shell)   do_seed; banner "ready"; cat /etc/serverscrub-test-env; exec /bin/bash ;;
    *)       exec "$@" ;;
esac
