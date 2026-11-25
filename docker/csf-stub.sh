#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# csf — A STUB. NOT CONFIGSERVER FIREWALL. NO IPTABLES RULE IS EVER TOUCHED.
#
# ── WHY THIS EXISTS ───────────────────────────────────────────────────────────
#
# install.sh and uninstall.sh both decide what to do by whether /usr/sbin/csf
# exists, and both reload it. With no csf in the container, the whole CSF
# section of install.sh took its "CSF not installed" branch and none of it was
# exercised -- including the cleanup of the old product's stale (legacy) includes in
# csf.allow / csf.ignore -- see the legacy-CSF-include spec under docs/specs/.
#
# It is NOT installed at /usr/sbin/csf by the image. seed-csf.sh puts it there,
# so every other test in this container still runs against a server without
# CSF, as before.
#
# ── WHAT IT DOES ──────────────────────────────────────────────────────────────
#
# 1. Appends every invocation to $LOG, one line each:
#        <epoch> csf <args...>
#    so a test can count reloads per install run (`grep -c ' csf -r$'`).
#
# 2. On a reload (-r, -ra, --restart, --restartall) it walks /etc/csf/csf.allow
#    and /etc/csf/csf.ignore for `Include <path>` lines and, for each path that
#    does not exist, prints the error real CSF printed on prod:
#        *Error* File does not exist: [<path>] at /usr/sbin/csf line 2448.
#    Like real CSF it then carries on and exits 0.
#
# It does NOT:
#   - parse CSF's grammar, or match exactly how real csf recognises `Include`
#     (this matches `^[[:space:]]*Include[[:space:]]+`; csf's own regex may be
#     stricter or looser);
#   - look at csf.deny, csf.pignore, csf.conf or any other file;
#   - start lfd, load iptables, or validate a single rule.
#
# A CLEAN RELOAD FROM THIS STUB IS NOT EVIDENCE THAT REAL CSF RELOADS CLEANLY.
# Acceptance check A10 needs a real CSF, and says so if there was none.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

LOG=/var/log/serverscrub-csf-stub.log
echo "$(date +%s) csf $*" >> "${LOG}" 2>/dev/null || true

case "${1:-}" in
    -r|-ra|--restart|--restartall)
        for f in /etc/csf/csf.allow /etc/csf/csf.ignore; do
            [[ -f "$f" ]] || continue
            while read -r _kw path _rest; do
                path="${path%$'\r'}"
                [[ -n "${path}" && ! -e "${path}" ]] && \
                    echo "*Error* File does not exist: [${path}] at /usr/sbin/csf line 2448."
            done < <(grep -E '^[[:space:]]*Include[[:space:]]+' "$f" 2>/dev/null)
        done
        echo "csf stub: '$*' -- no firewall was reloaded, this is a test container"
        ;;
    *)
        # -a/-d/-g/-x/-v and the rest: nothing to do, nothing to report.
        ;;
esac
exit 0
