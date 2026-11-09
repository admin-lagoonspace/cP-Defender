#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — seed a cPanel-shaped server inside the test container
#
# The product reads a cPanel server through FILES, not through an API, for
# almost everything that matters: /var/cpanel/users for the account list,
# /var/cpanel/userdata for document roots, /etc/trueuserdomains for the domain
# map, and a spread of log files whose paths differ between cPanel versions.
# That is what makes a useful local target possible at all.
#
# So this builds those files, at the real paths, in the real shapes. It is not
# a mock library the product has been taught about: the code under test cannot
# tell the difference, because there is nothing to tell.
#
# WHAT IT DELIBERATELY DOES NOT FAKE: cpsrvd, WHM's AppConfig, the LiveAPI
# socket, real ModSecurity under Apache, and a real Exim queue. Those have
# behaviour, not just a file format, and a fake that returns what the product
# hopes for is worse than no test -- it reports a pass for a path nobody has
# exercised. Shakaal's report names them as untested rather than silently
# counting them as covered.
#
# Usage:  seed-cpanel.sh [account-count]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

ACCOUNTS="${1:-8}"

echo "[seed] building a cPanel-shaped server with ${ACCOUNTS} accounts"

mkdir -p /var/cpanel/users /var/cpanel/userdata /var/cpanel/hulkd/conf \
         /etc/apache2/conf.d/modsec_vendor_configs/OWASP3 \
         /etc/apache2/conf.d/modsec \
         /etc/apache2/conf.d/includes \
         /etc/apache2/conf /etc/apache2/logs /etc/apache2/modules \
         /usr/local/apache/logs /usr/local/apache/domlogs \
         /usr/local/cpanel/logs /usr/local/cpanel/3rdparty/bin \
         /var/log/apache2 /var/log/exim /etc/exim

: > /etc/trueuserdomains
: > /etc/exim/localdomains

# ── Accounts ──────────────────────────────────────────────────────────────────
#
# Named rather than numbered where it matters. Two of them carry the shapes
# that have actually caused bugs on the live server:
#
#   addons   — several domains under ONE account, each with its own docroot
#              inside public_html. This is the layout that made the WP sweep
#              report "0 of 0 installs" when it was keyed on the wrong field.
#   deepnest — a docroot several levels down, to catch anything that assumes
#              /home/<user>/public_html and nothing else.
for i in $(seq 1 "$ACCOUNTS"); do
    case "$i" in
        1) user="addons"   ;;
        2) user="deepnest" ;;
        *) user="acct${i}" ;;
    esac
    domain="${user}.test"

    id -u "$user" >/dev/null 2>&1 || useradd -m -d "/home/${user}" -s /bin/bash "$user" 2>/dev/null || true
    mkdir -p "/home/${user}/public_html"

    # /var/cpanel/users/<user> — the account file, in cPanel's key=value shape.
    cat > "/var/cpanel/users/${user}" <<EOF
DNS=${domain}
IP=51.68.163.24
OWNER=root
PLAN=default
USER=${user}
SUSPENDED=0
EOF

    echo "${domain}: ${user}" >> /etc/trueuserdomains
    echo "${domain}" >> /etc/exim/localdomains

    # /var/cpanel/userdata/<user>/<domain> — YAML-ish, read for documentroot.
    mkdir -p "/var/cpanel/userdata/${user}"
    cat > "/var/cpanel/userdata/${user}/${domain}" <<EOF
---
documentroot: /home/${user}/public_html
group: ${user}
homedir: /home/${user}
servername: ${domain}
user: ${user}
EOF
    cat > "/var/cpanel/userdata/${user}/main" <<EOF
---
main_domain: ${domain}
addon_domains: {}
parked_domains: []
sub_domains: []
EOF

    # A WordPress install, convincing enough for the CMS detector: the version
    # constant, a wp-config with a database name, and the directory layout the
    # scanners walk.
    wproot="/home/${user}/public_html"
    mkdir -p "${wproot}/wp-admin" "${wproot}/wp-includes" \
             "${wproot}/wp-content/plugins" "${wproot}/wp-content/themes" \
             "${wproot}/wp-content/uploads"
    cat > "${wproot}/wp-includes/version.php" <<'EOF'
<?php
$wp_version = '6.4.2';
$wp_db_version = 56657;
EOF
    cat > "${wproot}/wp-config.php" <<EOF
<?php
define( 'DB_NAME', '${user}_wp' );
define( 'DB_USER', '${user}_wp' );
define( 'DB_PASSWORD', 'not-a-real-password' );
define( 'DB_HOST', 'localhost' );
\$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
EOF
    cat > "${wproot}/index.php" <<'EOF'
<?php
/** Front to the WordPress application. */
define( 'WP_USE_THEMES', true );
require __DIR__ . '/wp-blog-header.php';
EOF
    touch "${wproot}/wp-load.php" "${wproot}/wp-login.php" "${wproot}/xmlrpc.php"

    chown -R "${user}:${user}" "/home/${user}" 2>/dev/null || true
done

# ── The addon-domain layout ───────────────────────────────────────────────────
#
# Three more sites inside one account, each a separate WordPress with its own
# docroot under public_html. Keyed into userdata as addon domains, which is
# where the field-name mismatch in the WP sweep was hiding.
for extra in shopfront blogsite clientco; do
    root="/home/addons/public_html/${extra}.test"
    mkdir -p "${root}/wp-includes" "${root}/wp-content/plugins" "${root}/wp-admin"
    cat > "${root}/wp-includes/version.php" <<'EOF'
<?php
$wp_version = '5.9.8';
EOF
    cat > "${root}/wp-config.php" <<EOF
<?php
define( 'DB_NAME', 'addons_${extra}' );
\$table_prefix = 'wp_';
EOF
    cat > "/var/cpanel/userdata/addons/${extra}.test" <<EOF
---
documentroot: ${root}
servername: ${extra}.test
user: addons
EOF
    echo "${extra}.test: addons" >> /etc/trueuserdomains
done
chown -R addons:addons /home/addons 2>/dev/null || true

# A docroot that is NOT public_html, several levels down.
mkdir -p /home/deepnest/sites/live/current/public
cat > /var/cpanel/userdata/deepnest/deep.test <<'EOF'
---
documentroot: /home/deepnest/sites/live/current/public
servername: deep.test
user: deepnest
EOF
echo "deep.test: deepnest" >> /etc/trueuserdomains
chown -R deepnest:deepnest /home/deepnest 2>/dev/null || true

# ── The directories that make `find` multiplicative ───────────────────────────
#
# /home/virtfs is a tree of bind mounts on a real cPanel server: every account
# appears under every other, so an unpruned walk of /home is quadratic. It was
# the cause of a scan that never finished, and of a shell-hunt command that
# took so long the operator asked whether it was broken.
#
# Seeded as ordinary directories with enough depth and file count to be
# noticeable, so a scan that forgets to prune them is SLOW here too and gets
# caught locally instead of on a server with 132 accounts.
echo "[seed] planting the traps that make scans slow"
for u in addons deepnest acct3; do
    for inner in addons deepnest acct3 acct4; do
        d="/home/virtfs/${u}/home/${inner}/public_html"
        mkdir -p "$d"
        for n in $(seq 1 25); do echo "<?php // virtfs filler ${n}" > "${d}/file${n}.php"; done
    done
done

# Maildirs: thousands of tiny files, which is where the inodes actually are.
for u in addons acct3 acct4; do
    for box in inbox sent spam; do
        d="/home/${u}/mail/${u}.test/${box}/cur"
        mkdir -p "$d"
        for n in $(seq 1 120); do echo "Subject: filler ${n}" > "${d}/${n}.msg"; done
    done
    mkdir -p "/home/${u}/tmp/analog" "/home/${u}/.cagefs/tmp" "/home/${u}/.trash"
    for n in $(seq 1 60); do echo "stat filler" > "/home/${u}/tmp/analog/${n}.html"; done
done

# ── Apache, ModSecurity ───────────────────────────────────────────────────────
touch /etc/apache2/modules/mod_security2.so

cat > /etc/apache2/conf/httpd.conf <<'EOF'
ServerRoot "/etc/apache2"
Listen 80
ServerName host.test

# Written in the shape cPanel writes it: mod_remoteip pointed at a
# SECRET-SUFFIXED header name, which is why it rightly ignores the plain
# X-Forwarded-For that nginx sends -- and why WAF events carried the proxy
# address until 4.35.1 read the header itself.
<IfModule remoteip_module>
    RemoteIPHeader X-Forwarded-For-TESTSUFFIXTESTSUFFIXTESTSUFFIX
    RemoteIPInternalProxy host.test
    RemoteIPInternalProxy 51.68.163.24
    RemoteIPInternalProxy 51.68.163.25
</IfModule>

Include "/etc/apache2/conf.d/*.conf"
EOF

cat > /etc/apache2/conf.d/includes/cloudflare.conf <<'EOF'
<IfModule remoteip_module>
    RemoteIPHeader CF-Connecting-IP
    RemoteIPTrustedProxy 173.245.48.0/20
    RemoteIPTrustedProxy 162.158.0.0/15
    RemoteIPTrustedProxy 104.16.0.0/13
</IfModule>
EOF

cat > /etc/apache2/conf.d/includes/zz-local-proxy.conf <<'EOF'
<IfModule remoteip_module>
  RemoteIPTrustedProxy 127.0.0.1
  RemoteIPTrustedProxy ::1
</IfModule>
EOF

cat > /etc/apache2/conf.d/modsec_vendor_configs/modsecurity.conf <<'EOF'
SecRuleEngine DetectionOnly
SecAuditEngine RelevantOnly
SecAuditLogParts ABIJDEFHZ
SecAuditLog /etc/apache2/logs/modsec_audit.log
EOF
cp /etc/apache2/conf.d/modsec_vendor_configs/modsecurity.conf \
   /etc/apache2/conf.d/modsec/modsecurity.conf
cat > /etc/apache2/conf.d/modsec_vendor_configs/OWASP3/crs-setup.conf <<'EOF'
SecAction "id:900990,phase:1,nolog,pass,t:none,setvar:tx.crs_setup_version=4070"
EOF

# ── Logs ──────────────────────────────────────────────────────────────────────
/usr/local/bin/seed-logs.sh 2>/dev/null || true
for f in /etc/apache2/logs/modsec_audit.log /var/log/apache2/access.log \
         /usr/local/apache/logs/access_log /var/log/secure /var/log/messages \
         /var/log/maillog /var/log/exim_mainlog /usr/local/cpanel/logs/login_log \
         /var/log/lfd.log; do
    [[ -e "$f" ]] || { mkdir -p "$(dirname "$f")"; : > "$f"; }
done
ln -sf /etc/apache2/logs/modsec_audit.log /var/log/apache2/modsec_audit.log 2>/dev/null || true
ln -sf /etc/apache2/logs/modsec_audit.log /usr/local/apache/logs/modsec_audit.log 2>/dev/null || true

# ── Stubs for binaries the product looks for ──────────────────────────────────
#
# clamscan is stubbed, not installed: a real ClamAV database is 250 MB and
# downloading it would make the image unusable. The stub reports a clean scan
# unless the file it is handed contains the EICAR test string, which is enough
# to exercise the detection path, the quarantine path and the verdict gate
# without shipping a virus.
cat > /usr/local/cpanel/3rdparty/bin/clamscan <<'EOF'
#!/usr/bin/env bash
# Stub clamscan. Flags anything containing the EICAR test signature.
#
# IT MUST UNDERSTAND --file-list. Scanner::scanBatch() does NOT pass file
# paths as arguments; it writes them to a temp file and runs:
#
#   timeout N nice -nX ionice -c3 clamscan --infected --no-summary #       --max-filesize=50M --max-scansize=200M --file-list=/tmp/sg-scan-XXXX
#
# The first version of this stub only looked at positional arguments, so it
# received a list file it ignored, scanned nothing, printed nothing, and every
# scan reported "0 threats found" -- with the seeded EICAR file sitting in
# /home/acct3/public_html the whole time. A stub that silently agrees that
# there is nothing wrong is worse than no stub.
#
# --infected / -i means print ONLY infected files. --no-summary suppresses the
# trailer. Scanner parses `^(.+):\s+(.+)\s+FOUND$`, so that is the only line
# shape that matters.
found=0
quiet=0
declare -a TARGETS=()

for arg in "$@"; do
    case "$arg" in
        --file-list=*)
            lf="${arg#--file-list=}"
            [[ -f "$lf" ]] || continue
            while IFS= read -r line; do
                [[ -n "$line" ]] && TARGETS+=("$line")
            done < "$lf"
            ;;
        -i|--infected)   quiet=1 ;;
        --no-summary)    nosum=1 ;;
        -*)              ;;   # every other flag is accepted and ignored
        *)               TARGETS+=("$arg") ;;
    esac
done

scan_one() {
    local f="$1"
    [[ -f "$f" ]] || return 0
    if grep -qa 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' "$f" 2>/dev/null; then
        echo "${f}: Eicar-Test-Signature FOUND"
        found=$(( found + 1 ))
    elif [[ "$quiet" != "1" ]]; then
        echo "${f}: OK"
    fi
}

for t in "${TARGETS[@]}"; do
    if [[ -d "$t" ]]; then
        while IFS= read -r f; do scan_one "$f"; done < <(find "$t" -type f 2>/dev/null)
    else
        scan_one "$t"
    fi
done

if [[ "${nosum:-0}" != "1" ]]; then
    echo "----------- SCAN SUMMARY -----------"
    echo "Infected files: ${found}"
fi
# Real clamscan: 0 = clean, 1 = virus found, 2 = error.
[[ "$found" -gt 0 ]] && exit 1
exit 0
EOF
chmod +x /usr/local/cpanel/3rdparty/bin/clamscan

# A signature DATABASE, or the stub binary is never called.
#
# Scanner::runClamScan() starts with:
#
#     if ($bin === null || !self::clamSignaturesPresent()) {
#         return $this->runPatternScan($path, $jobId);
#     }
#
# and clamSignaturesPresent() looks for main.cvd/main.cld/daily.cvd/daily.cld
# in four fixed directories. With the stub binary present but no database, that
# returned false and EVERY scan silently took the pattern-engine fallback. So
# the ClamAV detection path, the quarantine path and the verdict gate behind it
# were never executed here -- while the seeded EICAR file sat unflagged and the
# scan reported "0 threats found" as a success.
#
# These are empty placeholder files. They make clamSignaturesPresent() true;
# the stub binary does the deciding, and it only ever flags EICAR. This is NOT
# a real signature match and the report must keep saying so.
mkdir -p /usr/local/cpanel/3rdparty/share/clamav
: > /usr/local/cpanel/3rdparty/share/clamav/daily.cld
: > /usr/local/cpanel/3rdparty/share/clamav/main.cld
ln -sf "$(command -v php)" /usr/local/cpanel/3rdparty/bin/php 2>/dev/null || true

# One genuinely-flagged file, so a scan that finds nothing is distinguishable
# from a scan that found nothing because it never ran.
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' \
    > /home/acct3/public_html/wp-content/uploads/suspicious.php

echo "[seed] done"
echo "[seed] accounts:   $(ls /var/cpanel/users | wc -l)"
echo "[seed] domains:    $(wc -l < /etc/trueuserdomains)"
echo "[seed] home files: $(find /home -type f 2>/dev/null | wc -l)"
cat /etc/serverscrub-test-env 2>/dev/null || true
