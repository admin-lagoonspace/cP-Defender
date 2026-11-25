#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — seed a migrated server's /etc/csf inside the test container
#
# Reproduces what prod looked like on 2026-11-23, after the pre-rename product had
# been migrated to ServerScrub and its /etc/sentinel-gate (legacy) deleted:
#
#   /etc/csf/csf.allow   line 72:  Include /etc/sentinel-gate/csf_allow.txt   (legacy)
#   /etc/csf/csf.ignore  line 30:  Include /etc/sentinel-gate/csf_ignore.txt  (legacy)
#
# surrounded by entries and comments that must survive the cleanup untouched:
# IPs, advanced rules, blank lines, a commented-out sentinel-gate (legacy) include
# and a user comment that mentions the legacy name. csf.pignore carries a stale
# cmd: line from the old product and csf.deny an ordinary entry; both are out of scope
# and must come through every install byte-for-byte.
#
# Usage:
#   seed-csf.sh                 seed /etc/csf and install the csf stub at /usr/sbin/csf
#   seed-csf.sh --with-ours     ...and include the /etc/serverscrub includes too,
#                               as a server that has already upgraded once has
#   seed-csf.sh --no-binary     seed /etc/csf but NO /usr/sbin/csf (CSF removed,
#                               config left behind)
#   seed-csf.sh --absent        remove /etc/csf and /usr/sbin/csf entirely
#
# Every run resets: it rewrites the files, truncates the stub log, and keeps a
# pristine copy under $PRISTINE so a test can diff seed against result:
#   diff /var/lib/serverscrub-test/csf-seed/csf.allow /etc/csf/csf.allow
#
# Fresh installs without the stub at /usr/sbin/csf will try to install
# cpanel-csf from dnf; pass --no-csf to install.sh to keep that out of the run.
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

STUB=/usr/local/lib/serverscrub-test/csf-stub
PRISTINE=/var/lib/serverscrub-test/csf-seed
LOG=/var/log/serverscrub-csf-stub.log
OLD=/etc/sentinel-gate      # the legacy (pre-rename) config directory

MODE=seed; OURS=false; BINARY=true
for a in "$@"; do
    case "$a" in
        --with-ours) OURS=true ;;
        --no-binary) BINARY=false ;;
        --absent)    MODE=absent ;;
        *) echo "seed-csf.sh: unknown option $a" >&2; exit 2 ;;
    esac
done

: > "${LOG}"
rm -rf "${OLD}"          # gone on prod; the legacy includes point at nothing

if [[ "${MODE}" == absent ]]; then
    rm -rf /etc/csf "${PRISTINE}"
    rm -f /usr/sbin/csf
    echo "[seed-csf] /etc/csf and /usr/sbin/csf removed"
    exit 0
fi

mkdir -p /etc/csf "${PRISTINE}"

# Pad with distinct documentation-range entries until the next line is $1.
pad_to() {
    local want="$1" prefix="$2" n=0
    while [[ $(( ${#L[@]} + 1 )) -lt ${want} ]]; do
        n=$((n + 1))
        L+=("${prefix}.${n} # client ${n}")
    done
}

# ── csf.allow ────────────────────────────────────────────────────────────────
L=(
"###############################################################################"
"# csf.allow -- seeded by docker/seed-csf.sh to mirror a migrated server"
"###############################################################################"
"# The following IP addresses will be allowed through iptables."
"# One IP address per line, CIDR addressing allowed, or an advanced"
"# port/IP filter of the form tcp|in|d=22|s=198.51.100.7"
"#"
""
"# migrated from ${OLD##*/} -- operator note, must survive"
"# Include ${OLD}/csf_allow.txt"
""
"tcp|in|d=22|s=198.51.100.7 # jump host"
"tcp|in|d=2087|s=198.51.100.8 # WHM from office"
"192.0.2.250 # office"
""
)
pad_to 72 "203.0.113"
L+=("Include ${OLD}/csf_allow.txt")
L+=("" "# backup server" "198.51.100.200")
$OURS && L+=("Include /etc/serverscrub/csf_allow.txt")
printf '%s\n' "${L[@]}" > /etc/csf/csf.allow

# ── csf.ignore ───────────────────────────────────────────────────────────────
L=(
"###############################################################################"
"# csf.ignore -- seeded by docker/seed-csf.sh to mirror a migrated server"
"###############################################################################"
"# lfd will ignore these IP addresses"
""
"127.0.0.1"
"# Include ${OLD}/csf_ignore.txt"
""
)
pad_to 30 "192.0.2"
L+=("Include ${OLD}/csf_ignore.txt")
L+=("" "# monitoring" "198.51.100.50")
$OURS && L+=("Include /etc/serverscrub/csf_ignore.txt")
printf '%s\n' "${L[@]}" > /etc/csf/csf.ignore

# ── out of scope: must not change ────────────────────────────────────────────
printf '%s\n' "# lfd process ignore list" "exe:/usr/sbin/sshd" \
    "cmd:.*${OLD##*/}/backend/daemon/monitor.py" > /etc/csf/csf.pignore
printf '%s\n' "# csf.deny" "198.51.100.66 # seeded deny" > /etc/csf/csf.deny

chmod 600 /etc/csf/csf.allow /etc/csf/csf.ignore /etc/csf/csf.pignore /etc/csf/csf.deny
cp -p /etc/csf/csf.allow /etc/csf/csf.ignore /etc/csf/csf.pignore /etc/csf/csf.deny "${PRISTINE}/"

# Refuse to hand over a seed that does not match the prod line numbers.
[[ "$(sed -n 72p /etc/csf/csf.allow)" == "Include ${OLD}/csf_allow.txt" ]] \
    || { echo "[seed-csf] csf.allow line 72 is not the stale include" >&2; exit 1; }
[[ "$(sed -n 30p /etc/csf/csf.ignore)" == "Include ${OLD}/csf_ignore.txt" ]] \
    || { echo "[seed-csf] csf.ignore line 30 is not the stale include" >&2; exit 1; }

if $BINARY; then
    install -m 0755 "${STUB}" /usr/sbin/csf
    echo "[seed-csf] /etc/csf seeded; csf stub at /usr/sbin/csf, logging to ${LOG}"
else
    rm -f /usr/sbin/csf
    echo "[seed-csf] /etc/csf seeded; NO /usr/sbin/csf"
fi
