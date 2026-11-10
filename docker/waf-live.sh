#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — the WAF checks that need a real parser.
#
# Everything here was listed as "not tested" in the 2026-11-09 report because
# the container had no Apache and no ModSecurity. AlmaLinux 8 AppStream has
# both, so there is no longer a reason to accept "it matches the documentation"
# as evidence.
#
#   crs       download the REAL OWASP CRS 4.7.0 and run duplicateRuleIds()
#             against it. Must find NOTHING. A false positive here makes
#             installCrs() refuse a good tree, which means nobody can install
#             the WAF at all.
#   dupe      plant the production server's actual fault -- 913100 defined
#             twice -- and confirm it IS caught. The check has to be right in
#             BOTH directions.
#   syntax    generate exclusions and a custom rule, then hand the config to
#             REAL httpd + mod_security2 via `apachectl -t`.
#   install   run installCrs() for real, over the network, end to end.
#   ladder    the rollback-failure ladder as root: restore blocked by a
#             directory, then by chattr +i, then by a full filesystem.
#   all       every one of the above.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SRC=/opt/serverscrub-src
WORK=/tmp/waf-live
CRS_VER=4.7.0
CRS_URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VER}.tar.gz"

banner() { echo; echo "════════ $* ════════"; echo; }
note()   { echo "    $*"; }

prepare() {
    mkdir -p "$WORK"
    [[ -d /var/cpanel/users ]] || /usr/local/bin/seed-cpanel.sh 8 >/dev/null 2>&1
    # seed-cpanel.sh touches a FAKE /etc/apache2/modules/mod_security2.so. With
    # the real module installed that fake is worse than useless: it makes
    # modsecPresent() true via a file that is not a module. Point it at the
    # real one so detection and loading agree.
    ln -sf /usr/lib64/httpd/modules/mod_security2.so \
           /etc/apache2/modules/mod_security2.so 2>/dev/null
    # A minimal real httpd config that LOADS ModSecurity, so `apachectl -t`
    # actually parses SecRule directives instead of skipping an <IfModule> that
    # is never true.
    cat > /etc/httpd/conf.d/00-modsecurity.conf <<'EOF'
LoadModule security2_module modules/mod_security2.so
LoadModule unique_id_module modules/mod_unique_id.so
EOF
    # The mod_security_crs PACKAGE ships its own CRS 3.3.4 at
    # /etc/httpd/modsecurity.d/, loaded by mod_security.conf's
    # `IncludeOptional modsecurity.d/*.conf`. Its crs-setup.conf defines
    # id:900990, and so does CRS 4.7.0's, so loading ours on top produced:
    #
    #   AH00526: Syntax error on line 818 of .../coreruleset/crs-setup.conf:
    #   ModSecurity: Found another rule with the same id
    #
    # That collision is REAL and worth knowing about -- it is what happens on
    # any server that already has a vendor ruleset, which includes cPanel. It
    # is recorded as a finding. But while it is present, every apachectl -t
    # fails for that reason and nothing can be learned about OUR directives,
    # so the distro ruleset is moved aside here and the collision is tested
    # deliberately in do_dupe instead of accidentally in every run.
    if [[ -d /etc/httpd/modsecurity.d && ! -d /etc/httpd/modsecurity.d.disabled ]]; then
        mv /etc/httpd/modsecurity.d /etc/httpd/modsecurity.d.disabled
        mkdir -p /etc/httpd/modsecurity.d
    fi

    cp -a "$SRC" /tmp/product 2>/dev/null || true
    rm -rf /tmp/product/python /tmp/product/php
    mkdir -p /tmp/product/logs
}

# Run a PHP snippet with the product bootstrapped against a scratch SG_ROOT.
php_product() {
    php -r "
        define('SG_ROOT', '/tmp/sgroot');
        define('SG_DB', '/tmp/sgroot/database/serverscrub.db');
        define('SG_LOGS', '/tmp/sgroot/logs');
        define('SG_TMP', '/tmp/sgroot/tmp');
        define('INSTALL_MODE','standalone');
        require '/tmp/product/backend/config/config.php';
        // require_once throughout: WAFInstaller.php already pulls in
        // WAFExclusions.php, and a plain require declared the class twice.
        require_once '/tmp/product/backend/lib/Database.php';
        require_once '/tmp/product/backend/lib/WAFInstaller.php';
        require_once '/tmp/product/backend/lib/WAFExclusions.php';
        $1
    "
}

sgroot() { mkdir -p /tmp/sgroot/{database,logs,tmp,quarantine}; }

# ── 1. duplicateRuleIds() against the genuine article ────────────────────────
do_crs() {
    banner "REAL OWASP CRS ${CRS_VER} vs duplicateRuleIds()"
    sgroot
    if [[ ! -d "${WORK}/coreruleset" ]]; then
        note "downloading ${CRS_URL}"
        curl -fsSL --max-time 180 -o "${WORK}/crs.tar.gz" "$CRS_URL" || {
            echo "    DOWNLOAD FAILED — this check did NOT run"; return 1; }
        mkdir -p "${WORK}/x" && tar -xzf "${WORK}/crs.tar.gz" -C "${WORK}/x"
        mv "${WORK}/x/coreruleset-${CRS_VER}" "${WORK}/coreruleset"
        cp "${WORK}/coreruleset/crs-setup.conf.example" \
           "${WORK}/coreruleset/crs-setup.conf" 2>/dev/null || true
    fi
    note "tree:        ${WORK}/coreruleset"
    note "rule files:  $(ls "${WORK}/coreruleset/rules/"*.conf 2>/dev/null | wc -l)"
    note "total ids:   $(grep -rhoE '\bid:[0-9]+' "${WORK}/coreruleset/rules/"*.conf 2>/dev/null | wc -l)"
    echo
    note "duplicateRuleIds() says:"
    php_product "
        \$d = WAFInstaller::duplicateRuleIds('${WORK}/coreruleset');
        if (!\$d) { echo '    NONE — a genuine CRS ${CRS_VER} tree is accepted', PHP_EOL; }
        else {
            echo '    ', count(\$d), ' DUPLICATE(S) REPORTED — FALSE POSITIVE:', PHP_EOL;
            foreach (\$d as \$id => \$w) { echo '      id ', \$id, ' in ', implode(', ', \$w), PHP_EOL; }
        }
    "
    echo
    note "independent cross-check (sort | uniq -d over non-comment id: lines):"
    grep -rhoE '^[^#]*[[:space:],"]id:[0-9]+' "${WORK}/coreruleset/rules/"*.conf 2>/dev/null \
        | grep -oE 'id:[0-9]+' | sort | uniq -d | sed 's/^/      /' \
        || true
    echo "      (nothing above = the tree genuinely has no duplicate ids)"
}

# ── 2. The production fault, planted deliberately ────────────────────────────
do_dupe() {
    banner "THE 6 OCT FAULT: 913100 defined twice — must be CAUGHT"
    sgroot
    [[ -d "${WORK}/coreruleset" ]] || { echo "    run 'crs' first"; return 1; }
    rm -rf "${WORK}/broken"; cp -a "${WORK}/coreruleset" "${WORK}/broken"
    # Exactly the shape the server had: a stale rule file left behind beside
    # the new one, both defining the same id.
    cp "${WORK}/broken/rules/REQUEST-913-SCANNER-DETECTION.conf" \
       "${WORK}/broken/rules/REQUEST-913-SCANNER-DETECTION-OLD.conf"
    note "planted: REQUEST-913-SCANNER-DETECTION-OLD.conf (a stale copy)"
    php_product "
        \$d = WAFInstaller::duplicateRuleIds('${WORK}/broken');
        if (!\$d) { echo '    NOT CAUGHT — the check missed a real duplicate', PHP_EOL; }
        else {
            echo '    CAUGHT: ', count(\$d), ' duplicate id(s)', PHP_EOL;
            \$n=0; foreach (\$d as \$id => \$w) { if (\$n++ < 4) echo '      id ', \$id, ' in ', implode(', ', \$w), PHP_EOL; }
        }
    "
    echo
    note "and REAL apachectl on the broken tree:"
    cat > /etc/apache2/conf.d/zz-dupe-test.conf <<EOF
<IfModule security2_module>
    SecRuleEngine DetectionOnly
    IncludeOptional ${WORK}/broken/crs-setup.conf
    IncludeOptional ${WORK}/broken/rules/*.conf
</IfModule>
EOF
    apachectl -t 2>&1 | sed 's/^/      /' | head -5
    note "apachectl exit: ${PIPESTATUS[0]}"
    rm -f /etc/apache2/conf.d/zz-dupe-test.conf
}

# ── 3. Our generated directives, under a real parser ─────────────────────────
do_syntax() {
    banner "GENERATED DIRECTIVES vs REAL httpd ${*} + mod_security2"
    sgroot
    note "httpd:       $(httpd -v | head -1)"
    note "modsecurity: $(rpm -q --qf '%{VERSION}' mod_security)"
    echo

    # Seed exclusions of every shape render() can produce.
    php_product "
        Database::get();
        WAFExclusions::add('420047', '', '', 'global');
        WAFExclusions::add('942100', 'shopfront.test', '/shop/checkout', 'host and path');
        WAFExclusions::add('941100', 'blogsite.test', '', 'host only');
        WAFExclusions::add('913100', '', '/wp-admin/', 'path only');
        echo '    seeded ', count(WAFExclusions::all()), ' exclusion(s)', PHP_EOL;
    "

    WAFCONF=/etc/serverscrub/waf
    mkdir -p "$WAFCONF"
    cp -a "${WORK}/coreruleset" "${WAFCONF}/coreruleset" 2>/dev/null || true

    # seed-cpanel.sh plants a STUB crs-setup.conf at the cPanel vendor path,
    # and crsPath() tests that path first -- correctly, because on a real
    # cPanel box the vendor tree is the live one. Here it meant our config
    # included the stub vendor tree while the EA4 shim also included it, so
    # ModSecurity saw every id twice and rejected the lot:
    #
    #   AH00526: Syntax error on line 1 of .../OWASP3/crs-setup.conf:
    #   ModSecurity: Found another rule with the same id
    #
    # setMode() then rolled back -- correctly -- and the apachectl -t that
    # followed was checking a config our file was no longer in. It printed
    # "Syntax OK" and proved exactly nothing. Remove the stub so crsPath()
    # resolves to the REAL CRS 4.7.0 tree and the check has something to check.
    rm -f /etc/apache2/conf.d/modsec_vendor_configs/OWASP3/crs-setup.conf

    note "writing the config through the product's own setMode()"
    php_product "
        Database::get();
        WAFInstaller::setConfDir('${WAFCONF}');
        WAFInstaller::setIncludeDir('/etc/apache2/conf.d');
        \$r = WAFInstaller::setMode('detectiononly');
        echo '    setMode: ', json_encode(\$r), PHP_EOL;
    "
    echo
    note "the exclusion fragment that landed in the config:"
    sed -n '/Rule exclusions/,/^<\/IfModule>/p' "${WAFCONF}/serverscrub-waf.conf" \
        | sed 's/^/      /' | head -30
    echo
    # A verdict is only worth printing if our config is actually on disk and
    # actually included. Check that FIRST, or a rollback leaves apachectl
    # validating a configuration our rules are no longer part of -- "Syntax OK"
    # for a file that is not there.
    if [[ ! -f "${WAFCONF}/serverscrub-waf.conf" ]]; then
        note "==> INCONCLUSIVE: setMode() did not leave a config on disk, so"
        note "    apachectl would be validating a configuration without our"
        note "    rules in it. Nothing is proved either way."
        return 1
    fi
    if ! grep -qr "serverscrub-waf.conf" /etc/apache2/conf.d/ 2>/dev/null; then
        note "==> INCONCLUSIVE: no Apache include points at our config."
        return 1
    fi
    note "confirmed: config present and included; exclusions in it: $(grep -c 'ruleRemoveById\|SecRuleRemoveById' "${WAFCONF}/serverscrub-waf.conf")"
    note "REAL apachectl -t on it:"
    apachectl -t 2>&1 | sed 's/^/      /' | head -10
    local rc=${PIPESTATUS[0]}
    note "apachectl exit: ${rc}"
    if [[ $rc -eq 0 ]]; then
        note "==> Apache AND ModSecurity ACCEPT WAFExclusions::render() output."
    else
        note "==> REJECTED. The generated exclusions are not valid ModSecurity."
    fi

    echo
    banner "CUSTOM RULE directive vs real ModSecurity"
    php_product "
        Database::get();
        require '/tmp/product/backend/lib/WAF.php';
        \$w = new WAF();
        \$r = \$w->addCustomRule('20010', '(?i)union[[:space:]]+select', 'block');
        echo '    addCustomRule: ', json_encode(\$r), PHP_EOL;
    " 2>&1 | head -6
    for f in /etc/apache2/conf.d/modsec_vendor_configs/serverscrub/custom_rules.conf \
             /etc/serverscrub/waf/custom_rules.conf; do
        [[ -f "$f" ]] && { note "custom rules file: $f"; sed 's/^/      /' "$f" | head -6; }
    done
    echo
    note "REAL apachectl -t with the custom rule included:"
    CUSTOM=$(ls /etc/apache2/conf.d/modsec_vendor_configs/serverscrub/custom_rules.conf \
                /etc/serverscrub/waf/custom_rules.conf 2>/dev/null | head -1)
    if [[ -n "$CUSTOM" ]]; then
        cat > /etc/apache2/conf.d/zz-custom-test.conf <<EOF
<IfModule security2_module>
    SecRuleEngine DetectionOnly
    IncludeOptional ${CUSTOM}
</IfModule>
EOF
        apachectl -t 2>&1 | sed 's/^/      /' | head -8
        note "apachectl exit: ${PIPESTATUS[0]}"
        rm -f /etc/apache2/conf.d/zz-custom-test.conf
    else
        note "no custom rules file was written — nothing to validate"
    fi
}

# ── 4. installCrs() for real ─────────────────────────────────────────────────
do_install() {
    banner "installCrs() — executed for the first time, over the network"
    sgroot
    rm -rf /tmp/crsinstall && mkdir -p /tmp/crsinstall
    php_product "
        Database::get();
        WAFInstaller::setConfDir('/tmp/crsinstall');
        WAFInstaller::setIncludeDir('/etc/apache2/conf.d');
        \$m = new ReflectionMethod('WAFInstaller', 'installCrs');
        \$m->setAccessible(true);
        \$t0 = microtime(true);
        \$r = \$m->invoke(null);
        printf('    installCrs(): %s  (%.1fs)%s', json_encode(\$r), microtime(true)-\$t0, PHP_EOL);
        echo '    crsPath(): ', var_export(WAFInstaller::crsPath(), true), PHP_EOL;
    "
    note "resulting tree:"
    ls /tmp/crsinstall/coreruleset 2>/dev/null | head -8 | sed 's/^/      /'
    note "rule files: $(ls /tmp/crsinstall/coreruleset/rules/*.conf 2>/dev/null | wc -l)"
    note "version marker: $(cat /tmp/crsinstall/coreruleset/.crs-version 2>/dev/null || echo none)"
    note "staging dirs left behind: $(ls -d /tmp/crsinstall/*stag* /tmp/crsinstall/*.old 2>/dev/null | wc -l)"
}

# ── 5. The rollback-failure ladder, as root ──────────────────────────────────
do_ladder() {
    banner "ROLLBACK-FAILURE LADDER (as root, real apachectl)"
    sgroot
    WAFCONF=/etc/serverscrub/waf
    CONF="${WAFCONF}/serverscrub-waf.conf"
    INC=/etc/apache2/conf.d/zz-serverscrub-waf.conf
    mkdir -p "$WAFCONF"

    php_product "
        Database::get();
        WAFInstaller::setConfDir('${WAFCONF}');
        WAFInstaller::setIncludeDir('/etc/apache2/conf.d');
        WAFInstaller::setMode('detectiononly');
    " >/dev/null 2>&1
    cp "$CONF" /tmp/good.conf 2>/dev/null
    note "baseline: $(grep -m1 -o 'SecRuleEngine .*' "$CONF" 2>/dev/null)"

    for rung in directory immutable; do
        echo
        note "── rung: restore blocked by ${rung} ──"
        cp /tmp/good.conf "$CONF" 2>/dev/null
        chattr -i "$CONF" 2>/dev/null

        # A runner that rejects AND sabotages the restore target in the same
        # breath -- i.e. inside the window between writeConfig() and the
        # restore, which is where every real-world cause lands.
        php_product "
            Database::get();
            WAFInstaller::setConfDir('${WAFCONF}');
            WAFInstaller::setIncludeDir('/etc/apache2/conf.d');
            \$done = false;
            WAFInstaller::setRunner(function(\$cmd) use (&\$done) {
                if (!\$done) {
                    \$done = true;
                    \$c = '${CONF}';
                    if ('${rung}' === 'directory') { @unlink(\$c); @mkdir(\$c, 0755, true); }
                    else { exec('chattr +i ' . escapeshellarg(\$c) . ' 2>/dev/null'); }
                }
                return ['out' => \"AH00526: Syntax error on line 56\nModSecurity: Found another rule with the same id\", 'code' => 1];
            });
            \$r = WAFInstaller::setMode('on');
            echo '      success     : ', var_export(!empty(\$r['success']), true), PHP_EOL;
            echo '      rolled_back : ', var_export(\$r['rolled_back'] ?? null, true), PHP_EOL;
            echo '      error       : ', substr((string)(\$r['error'] ?? ''), 0, 600), PHP_EOL;
        "
        chattr -i "$CONF" 2>/dev/null
        echo "      --- what is actually on disk ---"
        if [[ -d "$CONF" ]]; then echo "      conf path is a DIRECTORY (restore wrote nothing)"; rmdir "$CONF" 2>/dev/null
        elif [[ -f "$CONF" ]]; then
            echo "      conf mode: $(grep -m1 -o 'SecRuleEngine .*' "$CONF" 2>/dev/null || echo '(none)')"
            cmp -s "$CONF" /tmp/good.conf && echo "      conf is byte-identical to the pre-change file" \
                                          || echo "      conf DIFFERS from the pre-change file"
        else echo "      conf is ABSENT"; fi
        echo "      include present: $([[ -f $INC ]] && echo yes || echo no)"
        echo "      apachectl -t   : $(apachectl -t 2>&1 | head -1)"
    done

    echo
    note "── rung: filesystem full ──"
    chattr -i "$CONF" 2>/dev/null; cp /tmp/good.conf "$CONF" 2>/dev/null
    mkdir -p /tmp/tiny && mount -t tmpfs -o size=20k tmpfs /tmp/tiny 2>/dev/null && {
        cp /tmp/good.conf /tmp/tiny/serverscrub-waf.conf 2>/dev/null
        php_product "
            Database::get();
            WAFInstaller::setConfDir('/tmp/tiny');
            WAFInstaller::setIncludeDir('/etc/apache2/conf.d');
            \$done=false;
            WAFInstaller::setRunner(function(\$cmd) use (&\$done) {
                if (!\$done) { \$done=true; @file_put_contents('/tmp/tiny/filler', str_repeat('x', 200000)); }
                return ['out' => 'AH00526: Syntax error', 'code' => 1];
            });
            \$r = WAFInstaller::setMode('on');
            echo '      rolled_back : ', var_export(\$r['rolled_back'] ?? null, true), PHP_EOL;
            echo '      error       : ', substr((string)(\$r['error'] ?? ''), 0, 500), PHP_EOL;
        "
        echo "      on-disk size: $(stat -c %s /tmp/tiny/serverscrub-waf.conf 2>/dev/null) bytes (good = $(stat -c %s /tmp/good.conf))"
        cmp -s /tmp/tiny/serverscrub-waf.conf /tmp/good.conf \
            && echo "      restored byte-identical" || echo "      RESTORE IS NOT BYTE-IDENTICAL (truncated write)"
        umount /tmp/tiny 2>/dev/null
    } || note "      tmpfs mount unavailable in this container — ENOSPC rung SKIPPED"
}

# ── 6. The N4 collision sentence, from a REAL colliding configuration ────────
#
# foreignRuleIdCollisions() scans a FIXED list of locations. Wasooli tested it
# and its three wordings against fixtures it wrote itself and never reproduced
# a real distro-CRS-plus-ours server to read the sentence that comes out. Two
# cases matter and they are different:
#
#   identified   the other ruleset IS on the list  -> name it
#   off-list     the other ruleset is NOT          -> say plainly that it could
#                                                     not be identified, and
#                                                     must not blame our tree
do_collide() {
    banner "N4: the sentence a REAL collision produces"
    sgroot
    [[ -d "${WORK}/coreruleset" ]] || { echo "    run 'crs' first"; return 1; }

    WAFCONF=/etc/serverscrub/waf
    mkdir -p "$WAFCONF"
    rm -rf "${WAFCONF}/coreruleset"
    cp -a "${WORK}/coreruleset" "${WAFCONF}/coreruleset"
    rm -f /etc/apache2/conf.d/modsec_vendor_configs/OWASP3/crs-setup.conf

    # ── case 1: the genuine distro ruleset, restored to where it ships ──
    note "── case 1: distro mod_security_crs 3.3.4, at its real path ──"
    if [[ -d /etc/httpd/modsecurity.d.disabled ]]; then
        rm -rf /etc/httpd/modsecurity.d
        mv /etc/httpd/modsecurity.d.disabled /etc/httpd/modsecurity.d
    fi
    note "distro crs-setup: $(ls /etc/httpd/modsecurity.d/crs-setup.conf 2>/dev/null || echo MISSING)"
    note "ids it shares with ours: $(grep -ohE 'id:[0-9]+' /etc/httpd/modsecurity.d/crs-setup.conf 2>/dev/null | head -3 | tr '\n' ' ')"
    echo
    php_product "
        Database::get();
        WAFInstaller::setConfDir('${WAFCONF}');
        WAFInstaller::setIncludeDir('/etc/apache2/conf.d');
        \$r = WAFInstaller::setMode('detectiononly');
        echo '    success: ', var_export(!empty(\$r['success']), true), PHP_EOL, PHP_EOL;
        echo '    ── THE OPERATOR-FACING SENTENCE ──', PHP_EOL;
        /* Printed WHOLE, newlines folded. Splitting it on '|' is how the first
         * version of this harness showed only Apache's raw tail and made a
         * perfectly good explanation look like it had never been added. */
        echo str_replace(\"\n\", ' ~ ', (string)(\$r['error'] ?? '(no error key)')), PHP_EOL;
    "
    echo
    note "and the collision list the scanner built:"
    php_product "
        Database::get();
        WAFInstaller::setConfDir('${WAFCONF}');
        \$c = WAFInstaller::foreignRuleIdCollisions('${WAFCONF}/coreruleset');
        echo '      ', count(\$c), ' colliding id(s)', PHP_EOL;
        \$n = 0; foreach (\$c as \$id => \$w) { if (\$n++ < 3) echo '        ', \$id, ' <- ', implode(', ', \$w), PHP_EOL; }
    "

    # ── case 2: a ruleset in a place the fixed list does NOT know ──
    echo
    note "── case 2: a ruleset OFF the fixed list ──"
    rm -rf /etc/httpd/modsecurity.d && mkdir -p /etc/httpd/modsecurity.d
    mkdir -p /opt/somebodys-rules
    # Same id our tree defines, somewhere nothing in FOREIGN_RULE_GLOBS looks.
    grep -hE '^[^#]*SecAction .*id:900990' "${WAFCONF}/coreruleset/crs-setup.conf" \
        > /opt/somebodys-rules/extra.conf 2>/dev/null \
        || echo 'SecAction "id:900990,phase:1,nolog,pass,t:none"' > /opt/somebodys-rules/extra.conf
    cat > /etc/httpd/conf.d/zz-foreign.conf <<'EOF'
<IfModule security2_module>
    IncludeOptional /opt/somebodys-rules/*.conf
</IfModule>
EOF
    note "planted: /opt/somebodys-rules/extra.conf (not in FOREIGN_RULE_GLOBS)"
    note "defines: $(grep -ohE 'id:[0-9]+' /opt/somebodys-rules/extra.conf | head -1)"
    echo
    php_product "
        Database::get();
        WAFInstaller::setConfDir('${WAFCONF}');
        WAFInstaller::setIncludeDir('/etc/apache2/conf.d');
        \$r = WAFInstaller::setMode('on');
        echo '    success: ', var_export(!empty(\$r['success']), true), PHP_EOL, PHP_EOL;
        echo '    ── THE OPERATOR-FACING SENTENCE ──', PHP_EOL;
        /* Printed WHOLE, newlines folded. Splitting it on '|' is how the first
         * version of this harness showed only Apache's raw tail and made a
         * perfectly good explanation look like it had never been added. */
        echo str_replace(\"\n\", ' ~ ', (string)(\$r['error'] ?? '(no error key)')), PHP_EOL;
    "
    rm -f /etc/httpd/conf.d/zz-foreign.conf
    rm -rf /opt/somebodys-rules
}

prepare
case "${1:-all}" in
    collide) do_collide ;;
    crs)     do_crs ;;
    dupe)    do_dupe ;;
    syntax)  do_syntax ;;
    install) do_install ;;
    ladder)  do_ladder ;;
    shell)   exec /bin/bash ;;
    all)     do_crs; do_dupe; do_syntax; do_install; do_ladder ;;
    *)       exec "$@" ;;
esac
