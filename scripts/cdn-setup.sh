#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — one-time CDN setup. Run as ROOT on the cPanel server that
# serves serverscrub.com.
#
# WHY THIS EXISTS RATHER THAN FIVE COMMANDS IN A RELEASE NOTE
#
# Every serverscrub.com download URL has been returning 404 since the domain
# moved to a different hosting account. Installs kept working, because they
# fall back to the GitHub mirror, so nothing broke loudly and nothing said a
# word about it -- release after release.
#
# The five-command version of this setup hard-codes a docroot:
#
#     /home/serversc/public_html/serverscrub/code
#
# which is right only if serverscrub.com is that account's MAIN domain. If it
# is an addon or a subdomain, cPanel put its docroot somewhere else, and
# cdn-sync.sh will happily publish into a directory no vhost serves, log
# "published v4.28.0", and exit 0. The CDN would still 404 and the operator
# would have a success message saying otherwise. That is the exact failure
# shape this project keeps being bitten by, so this script asks cPanel where
# the docroot actually is, and then checks the public URL afterwards.
#
#   bash cdn-setup.sh            # set it up, then verify
#   bash cdn-setup.sh --check    # verify only, change nothing
#   bash cdn-setup.sh --diagnose # the files are published and the URL still
#                                # 404s: find out where it is being lost
#
# Override with SG_CDN_ACCOUNT / SG_CDN_DOMAIN if either ever changes.
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

ACCT="${SG_CDN_ACCOUNT:-serversc}"
DOMAIN="${SG_CDN_DOMAIN:-serverscrub.com}"
SUBPATH="${SG_CDN_SUBPATH:-serverscrub/code}"
REPO="${SG_REPO:-admin-lagoonspace/cP-Defender}"
RAW="https://raw.githubusercontent.com/${REPO}/main"

CHECK_ONLY=false
DIAGNOSE=false
case "${1:-}" in
    --check)    CHECK_ONLY=true ;;
    --diagnose) DIAGNOSE=true ;;
esac

R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[1;33m'
C=$'\033[0;36m'; B=$'\033[1m';    N=$'\033[0m'
say()  { echo "${C}[*]${N} $*"; }
ok()   { echo "${G}[+]${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
die()  { echo "${R}[x]${N} $*" >&2; exit 1; }

[[ "$(id -u)" == "0" ]] \
  || die "run this as root — it reads /var/cpanel/userdata and writes a user crontab"

# ── Where does cPanel actually serve this domain from? ────────────────────────
#
# Asked, not assumed. The userdata file is cPanel's own record and is what the
# Apache vhost is generated from, so it cannot disagree with what is served.
DOCROOT_BASE=""
for _f in "/var/cpanel/userdata/${ACCT}/${DOMAIN}" \
          "/var/cpanel/userdata/${ACCT}/${DOMAIN}_SSL"; do
    [[ -r "$_f" ]] || continue
    _dr="$(grep -E '^documentroot:' "$_f" | head -1 \
           | sed -E 's/^documentroot:[[:space:]]*//' | tr -d '"' || true)"
    if [[ -n "$_dr" ]]; then DOCROOT_BASE="$_dr"; break; fi
done

if [[ -z "$DOCROOT_BASE" ]]; then
    warn "cPanel has no userdata for ${DOMAIN} under the account '${ACCT}'."
    warn "Either that account name is wrong, or the domain is not on this server."
    warn "  list the accounts:  ls /var/cpanel/userdata/"
    warn "  then re-run:        SG_CDN_ACCOUNT=<account> bash \$0"
    die "refusing to guess a docroot — publishing into a directory nothing serves is how this went unnoticed before"
fi

ok "cPanel serves ${DOMAIN} from ${DOCROOT_BASE}"

DOCROOT="${DOCROOT_BASE%/}/${SUBPATH}"
HOMEDIR="$(getent passwd "$ACCT" | cut -d: -f6 || true)"
[[ -n "$HOMEDIR" ]] || die "no such system user: ${ACCT}"

BIN="${HOMEDIR}/bin"
LOGS="${HOMEDIR}/logs"
SYNC="${BIN}/cdn-sync.sh"
SELF="${BIN}/cdn-setup.sh"
WORK="${HOMEDIR}/.serverscrub-cdn"

# SG_WORK is pinned in the cron line, not left to the sync's own fallback.
# cron frequently runs with no HOME, in which case the sync falls back to its
# own directory -- so the cron run and the one-off run below would lock
# different files and could not see each other at all. A lock two processes
# cannot both see is not a lock.
CRON_LINE="*/10 * * * * SG_WORK=${WORK} SG_DOCROOT=${DOCROOT} ${SYNC} >> ${LOGS}/cdn-sync.log 2>&1"

# ── Verification, used after setup and by --check ─────────────────────────────
#
# This asks the question the way a customer's server asks it: the product reads
# the same URL to decide whether an update exists.
verify() {
    local url="https://${DOMAIN}/${SUBPATH}/latest.json"
    local code body ver zurl zcode

    code="$(curl -sS -o "/tmp/sg-cdn-check.$$" -w '%{http_code}' --max-time 20 "$url" 2>/dev/null || true)"
    [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
    body="$(cat "/tmp/sg-cdn-check.$$" 2>/dev/null || true)"
    rm -f "/tmp/sg-cdn-check.$$"

    if [[ "$code" != "200" ]]; then
        warn "${url} → HTTP ${code}"
        return 1
    fi

    ver="$(printf '%s' "$body" \
           | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 \
           | sed -E 's/.*"([^"]+)"$/\1/' || true)"
    if [[ -z "$ver" ]]; then
        warn "${url} → HTTP 200, but the body is not a manifest"
        return 1
    fi
    ok "${url} → HTTP 200, serving v${ver}"

    # The zip it names must be fetchable too. A manifest pointing at a file
    # that 404s is worse than a 404 manifest: the updater believes an update
    # exists, announces it, and then fails downloading it.
    zurl="https://${DOMAIN}/${SUBPATH}/dist/serverscrub-${ver}.zip"
    zcode="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 "$zurl" 2>/dev/null || true)"
    [[ "$zcode" =~ ^[0-9]{3}$ ]] || zcode=000
    if [[ "$zcode" != "200" ]]; then
        warn "but the build it points at 404s: ${zurl} → HTTP ${zcode}"
        return 1
    fi
    ok "and the build downloads: dist/serverscrub-${ver}.zip"
    return 0
}

# ── --diagnose: the files are there, the URL is not ──────────────────────────
#
# For the case this script's own failure message describes and cannot resolve:
# the sync published, latest.json is on disk with the right owner and mode, and
# the public URL still 404s. That is a web-server question, and the answer is
# almost always one of four things. Each is checked rather than listed, because
# a list of things to check is what the operator already has.
#
# The decisive one is asking APACHE directly, with the Host header, bypassing
# whatever is in front of it. A 200 from Apache and a 404 from the public URL
# means the proxy or its cache is the problem. A 404 from both means Apache is
# not serving this directory, and its DocumentRoot is not what cPanel's
# userdata says.
if $DIAGNOSE; then
    TARGET="/${SUBPATH}/latest.json"
    DOC="${DOCROOT_BASE%/}/${SUBPATH}"

    say "1. The file on disk"
    if [[ -s "${DOC}/latest.json" ]]; then
        ls -la "${DOC}/latest.json"
    else
        warn "${DOC}/latest.json is missing — run this script with no arguments first"
    fi

    # A file the web server cannot traverse to is as absent as one that is not
    # there. Every directory from / down needs o+x, and this is invisible in an
    # ls of the file itself.
    echo
    say "2. Can the web server walk down to it?"
    _p=""
    for _seg in $(echo "$DOC" | tr '/' ' '); do
        _p="${_p}/${_seg}"
        printf '    %s  ' "$(stat -c '%A %U:%G' "$_p" 2>/dev/null || echo '???')"
        echo "$_p"
    done
    warn "    every one of those needs o+x (the x on the last triplet)"

    echo
    say "3. What does cPanel think, and does anything else claim the domain?"
    for _f in /var/cpanel/userdata/*/"${DOMAIN}" /var/cpanel/userdata/*/"${DOMAIN}_SSL"; do
        [[ -r "$_f" ]] || continue
        echo "    ${_f}"
        grep -E '^(documentroot|user|servername|serveralias):' "$_f" 2>/dev/null | sed 's/^/        /'
    done
    # Two ACCOUNTS claiming one domain is the quiet cause of "the file is there
    # and Apache 404s": the vhost that wins is not the one just published into.
    # Counting FILES said "2" for a perfectly normal account, because every
    # domain has both a plain and an _SSL vhost -- a number that looks like a
    # finding and is not. Count the accounts.
    _accts="$(grep -rlE "^(servername|serveralias):.*(^| )${DOMAIN}( |$)" \
                   /var/cpanel/userdata/ 2>/dev/null \
              | sed -E 's#^/var/cpanel/userdata/([^/]+)/.*#\1#' | sort -u || true)"
    _n="$(printf '%s\n' "$_accts" | grep -c . || true)"
    echo "    accounts claiming ${DOMAIN}: ${_n} ($(printf '%s' "$_accts" | tr '\n' ' '))"
    [[ "$_n" -gt 1 ]] && warn "    MORE THAN ONE — the winning vhost may not be ${ACCT}'s"

    echo
    say "3b. What is in Apache's RUNNING config, not cPanel's source for it"
    # THE GAP THIS SCRIPT HAD. /var/cpanel/userdata is what cPanel will GENERATE
    # httpd.conf from; it is not what Apache is running. They diverge whenever
    # the config has not been rebuilt since the domain was created or moved --
    # and then the userdata reads perfectly while Apache serves something else,
    # or no vhost for the domain at all and the request falls through to the
    # default one, which 404s everything.
    #
    # Reading the source and calling it the state is the same mistake as
    # writing a cron and not reading it back.
    _conf=""
    for _c in /etc/apache2/conf/httpd.conf /usr/local/apache/conf/httpd.conf; do
        [[ -r "$_c" ]] && { _conf="$_c"; break; }
    done
    if [[ -z "$_conf" ]]; then
        warn "    no httpd.conf found in the usual places — is this EA4?"
    else
        echo "    ${_conf}"
        _live="$(awk -v d="$DOMAIN" '
            /<VirtualHost/            { inb=1; nm=""; rt="" }
            inb && $1=="ServerName"   { nm=$2 }
            inb && $1=="DocumentRoot" { rt=$2; gsub(/"/,"",rt) }
            /<\/VirtualHost>/         { if (inb && nm==d) print rt; inb=0 }
        ' "$_conf" 2>/dev/null | sort -u || true)"
        if [[ -z "$_live" ]]; then
            warn "    NO VirtualHost for ${DOMAIN} in the running config."
            warn "    Apache has nothing to match this Host against, so the request"
            warn "    falls through to the default vhost and 404s whatever it is."
            warn "    cPanel has the data (step 3); httpd.conf was never rebuilt from it."
            warn ""
            warn "    Fix:  /scripts/rebuildhttpdconf && /scripts/restartsrv_httpd"
        else
            printf '    DocumentRoot in the running config: %s\n' "$(printf '%s' "$_live" | tr '\n' ' ')"
            if [[ "$_live" != "${DOCROOT_BASE%/}" ]]; then
                warn "    THIS DOES NOT MATCH cPanel's ${DOCROOT_BASE}."
                warn "    The published files are under cPanel's path; Apache is serving"
                warn "    the other one. httpd.conf is stale."
                warn "    Fix:  /scripts/rebuildhttpdconf && /scripts/restartsrv_httpd"
            else
                ok "    matches cPanel's docroot"
            fi
        fi
    fi

    echo
    say "4. .htaccess between the docroot and the file"
    # The docroot's OWN .htaccess is checked first. An earlier version appended
    # the first path segment before testing, so the one file most likely to
    # contain the rewrite -- public_html/.htaccess -- was the one it skipped.
    _found=false
    _p="${DOCROOT_BASE%/}"
    _segs="$(echo "${SUBPATH}" | tr '/' ' ')"
    while :; do
        if [[ -f "${_p}/.htaccess" ]]; then
            _found=true
            echo "    ${_p}/.htaccess"
            # Printed whole, not grepped. The grep was for Rewrite, Deny and
            # friends, and it matched NOTHING in a .htaccess that was
            # nevertheless sitting right there -- so the output named a file
            # and then said nothing about it, which reads as "this file is
            # fine". These are a few lines; show them.
            sed -n '1,40p' "${_p}/.htaccess" 2>/dev/null | sed 's/^/        | /'
        fi
        [[ -n "$_segs" ]] || break
        _p="${_p}/${_segs%% *}"
        [[ "$_segs" == *" "* ]] && _segs="${_segs#* }" || _segs=""
    done
    $_found || echo "    none"

    echo
    say "5. Apache directly, bypassing whatever is in front of it"
    # cPanel keeps Apache's real port here when a proxy is in front of it.
    _aport="$(grep -E '^apache_port=' /var/cpanel/cpanel.config 2>/dev/null | tail -1 | sed -E 's/.*:([0-9]+)$|.*=([0-9]+)$/\1\2/' || true)"
    [[ "$_aport" =~ ^[0-9]+$ ]] || _aport=""
    # No `|| echo "no answer"`: curl exits non-zero when it cannot connect AND
    # still prints its -w line, so both fire and the output reads
    # "HTTP 000" followed by "no answer". That is the same print-both-branches
    # bug that made publish.sh say "404000"; 000 already means no answer.
    # Both the target AND the site root, because one number cannot tell the
    # two apart: a 404 for the file alone means that path is missing from a
    # vhost that otherwise works; a 404 for BOTH means Apache has no working
    # vhost for this Host at all, and the request is landing on the default
    # one. Those have entirely different fixes, and the first version of this
    # asked only about the file.
    # WHICH VHOST IS ANSWERING. The question the first version skipped.
    #
    # Apache selects a vhost by IP:port FIRST and ServerName second. cPanel
    # binds each account's vhost to that account's IP, so a request sent to
    # 127.0.0.1 can match no vhost on that address at all and fall through to
    # the DEFAULT one -- which happily answers 200 for / (the server's own
    # page) and 404 for every other path.
    #
    # That is indistinguishable, by status code alone, from "Apache cannot
    # see this directory". It produced exactly that reading on a live server:
    # 200 for /, 404 for a brand-new file beside the working homepage, and a
    # confident conclusion about bind mounts that was about the wrong vhost.
    #
    # So: send to the vhost's own IP, and fingerprint / to prove which site
    # answered.
    _vip="$(grep -hE '^ip:' "/var/cpanel/userdata/${ACCT}/${DOMAIN}" 2>/dev/null \
            | head -1 | sed -E 's/^ip:[[:space:]]*//' || true)"
    [[ "$_vip" =~ ^[0-9.]+$ ]] || _vip=""
    echo "    vhost IP from cPanel: ${_vip:-unknown}"

    # The public site is the reference: whatever answers / out there is the
    # vhost we are trying to reach.
    _pubmd5="$(curl -sS --max-time 20 "https://${DOMAIN}/" 2>/dev/null | md5sum 2>/dev/null | awk '{print $1}' || true)"
    echo "    fingerprint of the real site's /: ${_pubmd5:0:12}"

    APORT=""; AHOST=""
    for _host in ${_vip} 127.0.0.1; do
    for _port in ${_aport} 8080 80; do
        printf '    apache %-15s :%-5s ' "$_host" "$_port"
        _c="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
                   -H "Host: ${DOMAIN}" "http://${_host}:${_port}${TARGET}" 2>/dev/null || true)"
        [[ "$_c" =~ ^[0-9]{3}$ ]] || _c=000
        if [[ "$_c" == "000" ]]; then
            echo "no answer"
            continue
        fi
        _r="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
                   -H "Host: ${DOMAIN}" "http://${_host}:${_port}/" 2>/dev/null || true)"
        [[ "$_r" =~ ^[0-9]{3}$ ]] || _r=000
        _m="$(curl -sS --max-time 10 -H "Host: ${DOMAIN}" \
                   "http://${_host}:${_port}/" 2>/dev/null | md5sum 2>/dev/null | awk '{print $1}' || true)"
        _same="different site"
        if [[ -n "$_pubmd5" && "$_m" == "$_pubmd5" ]]; then
            _same="SAME site"
            # Only a probe that reaches the real vhost is worth believing.
            [[ -n "$APORT" ]] || { APORT="$_port"; AHOST="$_host"; }
        fi
        echo "HTTP ${_c} for the file, HTTP ${_r} for / (${_same})"
    done
    done

    if [[ -z "$APORT" ]]; then
        warn "    NOTHING REACHED THIS SITE'S VHOST."
        warn "    Every probe above answered with a page that is not ${DOMAIN}'s"
        warn "    home page, so each was served by some other vhost -- most"
        warn "    likely the default one, which answers 200 for / and 404 for"
        warn "    everything else. No conclusion about the published directory"
        warn "    can be drawn from those numbers."
        warn ""
        warn "    What is listening, and which vhost is the default:"
        if command -v httpd >/dev/null 2>&1 || command -v apachectl >/dev/null 2>&1; then
            _hs="$(httpd -S 2>/dev/null || apachectl -S 2>/dev/null || true)"
            printf '%s\n' "$_hs" | grep -iE "default server|${DOMAIN}|namevhost ${DOMAIN}" \
              | head -8 | sed 's/^/        /'
        else
            warn "        (no httpd/apachectl on PATH to ask)"
        fi
    else
        ok "    reached ${DOMAIN}'s own vhost at ${AHOST}:${APORT}"
    fi

    # ── 5b. Is it this PATH, or everything Apache has not seen before? ───────
    #
    # The case this script kept landing in: the vhost works (/ is 200), the
    # DocumentRoot is right, the permissions are right, the file is on disk --
    # and Apache 404s it. Reading those five facts in turn does not separate
    # "something is rewriting this path" from "Apache is not looking at the
    # same filesystem I am", and that second one is real on cPanel: with
    # jailed Apache the vhost is served out of a per-account bind mount under
    # /home/virtfs, and a mount made before the directory existed, or gone
    # stale, shows an older view of the home.
    #
    # Two files settle it. One at the docroot root beside the working
    # homepage, one in the published directory. Both brand new, both removed
    # straight afterwards.
    if [[ -n "$APORT" ]]; then
        echo
        say "5b. Two brand-new files: is it this path, or Apache's view of the disk?"
        _stamp="sg-probe-$$-$(date +%s).txt"
        _pr1="${DOCROOT_BASE%/}/${_stamp}"
        _pr2="${DOC}/${_stamp}"
        _mk() { printf 'serverscrub probe\n' > "$1" 2>/dev/null \
                && chown "${ACCT}:${ACCT}" "$1" 2>/dev/null \
                && chmod 644 "$1" 2>/dev/null; }
        _ask() {
            local c
            # AHOST, not 127.0.0.1: the address that was PROVEN to reach this
            # site's vhost, by fingerprint. Asking the loopback tests whatever
            # vhost happens to own that address.
            c="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
                      -H "Host: ${DOMAIN}" "http://${AHOST}:${APORT}$1" 2>/dev/null || true)"
            [[ "$c" =~ ^[0-9]{3}$ ]] || c=000
            printf '%s' "$c"
        }

        # These are written into somebody's live public_html. A ^C between
        # creating one and removing it would leave litter in a customer's
        # document root, so the removal is registered before the first write
        # rather than trusted to be reached.
        trap 'rm -f "$_pr1" "$_pr2" 2>/dev/null' EXIT INT TERM

        _a=skip; _b=skip
        _mk "$_pr1" && _a="$(_ask "/${_stamp}")"
        _mk "$_pr2" && _b="$(_ask "/${SUBPATH}/${_stamp}")"
        rm -f "$_pr1" "$_pr2"
        trap - EXIT INT TERM

        echo "    new file at the docroot root     → HTTP ${_a}"
        echo "    new file in ${SUBPATH} → HTTP ${_b}"
        echo

        if [[ "$_a" == "200" && "$_b" == "200" ]]; then
            warn "    Both served. Apache CAN read new files in that directory, so"
            warn "    the published files themselves are what it will not serve."
            warn "    Compare their ownership and mode with the probe's (644 ${ACCT})."
        elif [[ "$_a" == "200" && "$_b" != "200" ]]; then
            warn "    The docroot root works and ${SUBPATH} does not."
            warn "    Something is specific to that path: an Alias, a Location or a"
            warn "    rewrite in the vhost include. Look there:"
            warn "      grep -rn '${SUBPATH%%/*}' /etc/apache2/conf.d/userdata/ 2>/dev/null"
            warn "      grep -rn '${SUBPATH%%/*}' /etc/apache2/conf/httpd.conf"
        elif [[ "$_a" != "200" ]]; then
            warn "    A brand-new file beside the working homepage is ALSO 404,"
            warn "    on a connection that DID reach this site's vhost."
            warn "    So Apache is not reading the directory this script writes to."
            if [[ -d "/home/virtfs/${ACCT}" ]]; then
                warn "    /home/virtfs/${ACCT} exists — jailed Apache is in use, and"
                warn "    the vhost is served from a per-account bind mount that is"
                warn "    stale or predates this directory."
                warn "    Fix:  /scripts/clear_orphaned_virtfs_mounts"
                warn "          /usr/local/cpanel/scripts/rebuildhttpdconf"
                warn "          /scripts/restartsrv_httpd"
            else
                warn "    No /home/virtfs/${ACCT}, so this is not VirtFS. What is"
                warn "    mounted under the docroot:"
                if command -v findmnt >/dev/null 2>&1; then
                    findmnt -T "${DOCROOT_BASE}" 2>/dev/null | sed 's/^/        /' \
                      || warn "        (findmnt returned nothing)"
                else
                    warn "        (no findmnt; try: grep ' /home ' /proc/mounts)"
                    grep ' /home ' /proc/mounts 2>/dev/null | sed 's/^/        /' || true
                fi
            fi
        fi
    fi

    echo
    say "6. The public URL, for comparison"
    printf '    %-22s ' "${DOMAIN}${TARGET}"
    _c="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "https://${DOMAIN}${TARGET}" 2>/dev/null || true)"
    [[ "$_c" =~ ^[0-9]{3}$ ]] || _c=000
    echo "HTTP ${_c}"
    printf '    %-22s ' "what is answering"
    _srv="$(curl -sSI --max-time 20 "https://${DOMAIN}/" 2>/dev/null | grep -i '^server:' | head -1 | tr -d '\r' || true)"
    echo "${_srv:-unknown}"

    echo
    warn "READING THIS:"
    warn "  Step 5 says 'different site' everywhere → the probes never reached"
    warn "                            this account's vhost, so their 404s mean"
    warn "                            nothing. Read the httpd -S lines instead."
    warn "  Apache 200, public 404  → the proxy in front of Apache, or its cache."
    warn "                            On cPanel: WHM → NGINX Manager → clear cache,"
    warn "                            or rebuild the vhost for ${ACCT}."
    warn "  Apache 404 on the right vhost, file present → Apache is not reading"
    warn "                            that directory; see step 5b's mount output."
    warn "  Directory without o+x    → chmod o+x it; the file is unreachable."
    exit 0
fi

if $CHECK_ONLY; then
    say "Checking ${DOMAIN}…"
    if verify; then
        echo
        ok "${B}CDN is serving.${N}"
        exit 0
    fi
    echo
    warn "CDN is NOT serving. Run this script without --check to set it up."
    exit 1
fi

# ── Install the sync ──────────────────────────────────────────────────────────
say "Installing into ${BIN}…"
mkdir -p "$BIN" "$LOGS" "$DOCROOT" || die "cannot create directories under ${HOMEDIR}"

curl -fsSL --max-time 60 "${RAW}/scripts/cdn-sync.sh" -o "${SYNC}.tmp" \
  || die "could not download cdn-sync.sh from ${RAW}"
[[ -s "${SYNC}.tmp" ]] || die "the cdn-sync.sh that downloaded is empty"
head -1 "${SYNC}.tmp" | grep -q '^#!' || die "what downloaded is not a script"
mv -f "${SYNC}.tmp" "$SYNC"
chmod +x "$SYNC"

# Keep a copy of this script beside it, so --check is available later without
# hunting for the URL again.
curl -fsSL --max-time 60 "${RAW}/scripts/cdn-setup.sh" -o "${SELF}.tmp" 2>/dev/null \
  && [[ -s "${SELF}.tmp" ]] && mv -f "${SELF}.tmp" "$SELF" && chmod +x "$SELF"
rm -f "${SELF}.tmp"

chown -R "${ACCT}:${ACCT}" "$BIN" "$LOGS"
chown -R "${ACCT}:${ACCT}" "$DOCROOT" 2>/dev/null || true
ok "installed ${SYNC}"

# ── The cron, under the cPanel user, idempotently ─────────────────────────────
#
# Rewritten rather than appended: a second copy would run two syncs forever,
# and flock would make one of them a silent no-op, which looks healthy.
say "Installing the 10-minute sync cron for ${ACCT}…"
EXISTING="$(crontab -u "$ACCT" -l 2>/dev/null || true)"
CLEANED="$(printf '%s\n' "$EXISTING" | grep -v 'cdn-sync\.sh' || true)"
printf '%s\n%s\n' "$CLEANED" "$CRON_LINE" | sed '/^$/d' | crontab -u "$ACCT" - \
  || die "could not write the crontab for ${ACCT}"

# Read back, not assumed. Writing a cron and reporting success without checking
# is the exact habit that left a live server with no user-scans line at all.
if crontab -u "$ACCT" -l 2>/dev/null | grep -q 'cdn-sync\.sh'; then
    ok "cron installed, every 10 minutes"
else
    die "the cron line is NOT in ${ACCT}'s crontab after writing it"
fi

# ── First run, now, as the user ───────────────────────────────────────────────
#
# The same SG_WORK the cron line pins, for the same reason: `su -c` without
# `-` does not reset HOME reliably, so leaving the sync to work it out means
# this run and the cron run can lock different files.
mkdir -p "$WORK"
chown "${ACCT}:${ACCT}" "$WORK"
chmod 700 "$WORK"

say "Running the first sync — this downloads the current release…"
SYNC_OK=true
if su -s /bin/bash -c "SG_WORK='${WORK}' SG_DOCROOT='${DOCROOT}' '${SYNC}'" "$ACCT"; then
    ok "sync completed"
else
    SYNC_OK=false
    warn "the sync exited non-zero; its output is above, and ${LOGS}/cdn-sync.log has the rest"
fi

# ── Does the public URL actually serve it? ────────────────────────────────────
echo
say "Checking what ${DOMAIN} is serving…"
if verify; then
    echo
    ok "${B}CDN is live.${N} Installs and updates will use serverscrub.com,"
    ok "with the GitHub mirror still behind it as a fallback."
    echo
    echo "  Re-check at any time:"
    echo "  ${B}bash ${SELF} --check${N}"
    exit 0
fi

echo

# Which failure this is, before guessing at causes.
#
# The first version of this printed "The sync did its job; something between
# that directory and the web has not" and then, four lines later, "latest.json
# is NOT in ${DOCROOT} -- the sync did not publish". Both, in that order, in
# the same output. Printing a diagnosis and its own contradiction underneath it
# is exactly how the CDN 404 survived six releases; it does not get to happen
# in the script written to end that.
if [[ ! -s "${DOCROOT}/latest.json" ]]; then
    warn "NOTHING WAS PUBLISHED. latest.json is not in ${DOCROOT}."
    warn "The URL 404s because there is no file to serve — the web side is not"
    warn "the problem, the sync is. Its error is in the output above, and in"
    warn "  ${LOGS}/cdn-sync.log"
    echo
    warn "Run it again on its own to see the failure in isolation:"
    warn "  su -s /bin/bash -c \"SG_WORK='${WORK}' SG_DOCROOT='${DOCROOT}' '${SYNC}'\" ${ACCT}"
    exit 1
fi

if ! $SYNC_OK; then
    warn "The sync exited non-zero, but ${DOCROOT}/latest.json exists — so a"
    warn "previous run published and this one failed partway. Check the log"
    warn "before trusting what is being served:  ${LOGS}/cdn-sync.log"
    echo
fi

warn "The files ARE on disk at ${DOCROOT}, and the URL still does not serve"
warn "them. The sync did its job; the web server is not reaching what it wrote."
echo
warn "What is on disk:"
ls -la "${DOCROOT}/latest.json"
echo
# A list of things to go and check is what the operator already had. Run them.
warn "Find out where it is being lost:"
warn "  ${B}bash ${SELF} --diagnose${N}"
warn "That asks Apache directly, bypassing anything in front of it, walks the"
warn "directory permissions down to the file, and shows every vhost on this"
warn "machine that claims ${DOMAIN}."
exit 1
