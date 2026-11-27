#!/usr/bin/env bash
# Shakaal: acceptance 7 + 8 of docs/specs/2026-11-23-website-redesign-logo-canonical-https.md
#
# Runs INSIDE serverscrub-waf:live (AlmaLinux 8, httpd 2.4.37) with the repo at /src (ro):
#   docker run --rm -v "<repo>:/src:ro" --entrypoint bash serverscrub-waf:live /src/docker/site-apache-test.sh
#
# Real Apache, real deploy-site.sh run as root against a cPanel-shaped docroot,
# serverscrub.com + www resolved to 127.0.0.1 with a locally trusted CA so the
# script's own probe and R20 checks run unmodified (no -k anywhere in deploy).
set -uo pipefail
PASS=0; FAILS=0
ok()   { PASS=$((PASS+1)); echo "PASS $*"; }
bad()  { FAILS=$((FAILS+1)); echo "FAIL $*"; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1   [$2]"; fi; }
sec()  { echo; echo "== $* =="; }

sec setup
dnf -q -y install mod_ssl openssl >/dev/null 2>&1 || { echo "cannot install mod_ssl"; exit 2; }
rm -f /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/mod_security.conf \
      /etc/httpd/conf.modules.d/10-mod_security.conf 2>/dev/null
# the waf image includes /etc/apache2/conf.d; empty it so ModSecurity rules don't interfere
rm -rf /etc/apache2/conf.d/* 2>/dev/null || true
useradd -m serversc >/dev/null 2>&1 || true
chmod 711 /home/serversc
D=/home/serversc/public_html
mkdir -p "$D/releases/latest" /usr/local/serverscrub/frontend
echo '{"version":"9.9.9","zip":"https://serverscrub.com/releases/dist/x.zip"}' > "$D/releases/latest.json"
echo '9.9.9' > "$D/releases/latest/VERSION"
echo '<?php // webhook' > "$D/releases/webhook.php"
echo 'alias-ok' > /usr/local/serverscrub/frontend/index.html
mkdir -p "$D/.well-known/acme-challenge"; echo token > "$D/.well-known/acme-challenge/x"
chown -R serversc:serversc "$D"

# CA + server cert, trusted system-wide (curl and PHP both use the system bundle)
cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Shakaal Test CA" -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=serverscrub.com" -keyout srv.key -out srv.csr 2>/dev/null
printf 'subjectAltName=DNS:serverscrub.com,DNS:www.serverscrub.com,DNS:cpanel.serverscrub.com\n' > san.ext
openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext -out srv.crt 2>/dev/null
cp ca.crt /etc/pki/ca-trust/source/anchors/shakaal.crt && update-ca-trust
cp srv.crt srv.key /etc/pki/tls/
echo "127.0.0.1 serverscrub.com www.serverscrub.com cpanel.serverscrub.com" >> /etc/hosts

cat > /etc/httpd/conf.d/zz-site.conf <<'EOF'
Listen 443 https
ServerName localhost
Alias /serverscrub /usr/local/serverscrub/frontend
<Directory /usr/local/serverscrub/frontend>
  Require all granted
</Directory>
<Directory /home/serversc/public_html>
  AllowOverride All
  Options -Indexes +FollowSymLinks
  Require all granted
</Directory>
<VirtualHost *:80>
  ServerName serverscrub.com
  ServerAlias www.serverscrub.com cpanel.serverscrub.com
  DocumentRoot /home/serversc/public_html
</VirtualHost>
<VirtualHost *:443>
  ServerName serverscrub.com
  ServerAlias www.serverscrub.com cpanel.serverscrub.com
  DocumentRoot /home/serversc/public_html
  SSLEngine on
  SSLCertificateFile /etc/pki/tls/srv.crt
  SSLCertificateKeyFile /etc/pki/tls/srv.key
</VirtualHost>
EOF
apachectl -t 2>&1 | tail -1
httpd -k start; sleep 1

# A cPanel-shaped .htaccess, no trailing newline, as cPanel writes it
CPANEL='# php -- BEGIN cPanel-generated handler, do not edit
# Set the "ea-php81" package as the default "PHP" programming language.
<IfModule mime_module>
  AddHandler application/x-httpd-ea-php81 .php .php8 .phtml
</IfModule>
# php -- END cPanel-generated handler, do not edit'
printf '%s' "$CPANEL" > "$D/.htaccess"; chown serversc:serversc "$D/.htaccess"
printf '%s' "$CPANEL" > /tmp/cpanel.orig
cp -r /src/website /tmp/website
DEP=/src/scripts/deploy-site.sh

sec "acceptance 8: bash -n"
chk "bash -n deploy-site.sh" "bash -n $DEP"

sec "acceptance 8: deploy run 1 (local source, www reachable)"
SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/run1.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/run1.log
chk "deploy run 1 exits 0" "[ $rc -eq 0 ]"
chk "no 'missing from source'" "! grep -q 'missing from source' /tmp/run1.log"
chk "probe found www usable" "grep -q 'answers over HTTPS with a valid certificate' /tmp/run1.log"
chk "htaccess.site NOT published into the docroot" "[ ! -e $D/htaccess.site ]"
for f in index.html features.html pricing.html install.html status.html assets/css/site.css \
         assets/img/logo.svg assets/img/mark.svg assets/img/favicon.svg assets/img/favicon.png \
         assets/img/icon-180.png assets/img/mark-64.png favicon.ico robots.txt sitemap.xml; do
  chk "owner serversc: $f" "[ \"\$(stat -c %U:%G $D/$f)\" = serversc:serversc ]"
done
chk "owner serversc: .htaccess" "[ \"\$(stat -c %U:%G $D/.htaccess)\" = serversc:serversc ]"
chk ".htaccess mode 644" "[ \"\$(stat -c %a $D/.htaccess)\" = 644 ]"
chk "exactly one backup after run 1" "[ \$(ls $D/.htaccess.ss-bak-* | wc -l) -eq 1 ]"
chk "backup holds the original bytes" "cmp -s $D/.htaccess.ss-bak-* /tmp/cpanel.orig"
chk "block is prepended (line 1 is BEGIN)" "[ \"\$(head -1 $D/.htaccess)\" = '# BEGIN ServerScrub site' ]"
END=$(grep -n '^# END ServerScrub site$' $D/.htaccess | cut -d: -f1)
tail -n +$((END+2)) $D/.htaccess > /tmp/cpanel.after
chk "cPanel section byte-identical after merge" "cmp -s /tmp/cpanel.after /tmp/cpanel.orig"
cp $D/.htaccess /tmp/ht.run1

sec "acceptance 7: the curl matrix (www enabled)"
H() { curl -sS -o /dev/null -D - --max-redirs 0 --max-time 10 "$@" 2>&1 | tr -d '\r'; }
code() { H "$@" | awk 'toupper($1) ~ /^HTTP\// {c=$2} END {print c}'; }
loc()  { H "$@" | awk 'tolower($1)=="location:" {print $2}'; }
hdr()  { H "$@" | grep -i "^$1:" ; }
show() { echo "  $(code "$@") $(loc "$@")   <- $*"; }
for u in http://serverscrub.com/ "http://www.serverscrub.com/pricing.html?x=1" https://serverscrub.com/features.html \
         https://www.serverscrub.com/ https://serverscrub.com/releases/latest.json http://serverscrub.com/releases/latest.json \
         https://serverscrub.com/releases http://serverscrub.com/.well-known/acme-challenge/x \
         http://cpanel.serverscrub.com/ http://127.0.0.1/ https://serverscrub.com/serverscrub/ \
         "http://serverscrub.com/foo%20bar.html?a=1&b=%26" https://www.serverscrub.com/releases/latest.json \
         http://serverscrub.com/RELEASES/latest.json http://serverscrub.com/releasesX ; do show "$u"; done
chk "http apex / -> 301 https://www/" "[ \"\$(code http://serverscrub.com/) \$(loc http://serverscrub.com/)\" = '301 https://www.serverscrub.com/' ]"
chk "http www pricing?x=1 -> 301 keeps query" "[ \"\$(loc 'http://www.serverscrub.com/pricing.html?x=1')\" = 'https://www.serverscrub.com/pricing.html?x=1' ]"
chk "https apex features -> 301 www" "[ \"\$(code https://serverscrub.com/features.html) \$(loc https://serverscrub.com/features.html)\" = '301 https://www.serverscrub.com/features.html' ]"
chk "https www / -> 200" "[ \"\$(code https://www.serverscrub.com/)\" = 200 ]"
chk "https www / has HSTS max-age=31536000" "hdr Strict-Transport-Security https://www.serverscrub.com/ | grep -qx 'Strict-Transport-Security: max-age=31536000'"
chk "http www (redirect) has NO HSTS" "! hdr Strict-Transport-Security http://www.serverscrub.com/ | grep -q ."
chk "https apex releases/latest.json 200" "[ \"\$(code https://serverscrub.com/releases/latest.json)\" = 200 ]"
chk "  ...no Location" "[ -z \"\$(loc https://serverscrub.com/releases/latest.json)\" ]"
chk "  ...ACAO *" "hdr Access-Control-Allow-Origin https://serverscrub.com/releases/latest.json | grep -q 'Access-Control-Allow-Origin: \*'"
chk "http apex releases/latest.json 200 no Location" "[ \"\$(code http://serverscrub.com/releases/latest.json)\" = 200 ] && [ -z \"\$(loc http://serverscrub.com/releases/latest.json)\" ]"
chk "http apex releases/latest/VERSION 200" "[ \"\$(code http://serverscrub.com/releases/latest/VERSION)\" = 200 ]"
chk "https apex /releases not redirected to www" "! loc https://serverscrub.com/releases | grep -q www"
chk "http .well-known not redirected" "[ \"\$(code http://serverscrub.com/.well-known/acme-challenge/x)\" = 200 ]"
chk "Host cpanel.serverscrub.com not redirected" "[ \"\$(code http://cpanel.serverscrub.com/)\" = 200 ]"
chk "Host 127.0.0.1 not redirected" "[ \"\$(code http://127.0.0.1/)\" = 200 ]"
chk "X-Forwarded-Proto https on :80 www -> 200 (no loop)" "[ \"\$(code -H 'X-Forwarded-Proto: https' http://www.serverscrub.com/)\" = 200 ]"
chk "POST webhook over http not redirected" "[ -z \"\$(curl -sS -o /dev/null -D - -X POST -d x=1 --max-redirs 0 http://serverscrub.com/releases/webhook.php | tr -d '\r' | grep -i '^location:')\" ]"
chk "Host with port (serverscrub.com:80) redirected" "[ \"\$(code -H 'Host: serverscrub.com:80' http://127.0.0.1/)\" = 301 ]"
chk "Host upper-case SERVERSCRUB.COM redirected" "[ \"\$(code -H 'Host: SERVERSCRUB.COM' http://127.0.0.1/)\" = 301 ]"
chk "Host trailing dot serverscrub.com. redirected" "[ \"\$(code -H 'Host: serverscrub.com.' http://127.0.0.1/)\" = 301 ]"
chk "no HSTS on cpanel.serverscrub.com over https" "! hdr Strict-Transport-Security https://cpanel.serverscrub.com/ | grep -q ."
chk "follow http apex features.html: 200 in <=2 hops" "[ \"\$(curl -sS -o /dev/null -L --max-redirs 5 -w '%{http_code} %{num_redirects}' http://serverscrub.com/features.html)\" = '200 1' ] || [ \"\$(curl -sS -o /dev/null -L --max-redirs 5 -w '%{http_code} %{num_redirects}' http://serverscrub.com/features.html)\" = '200 2' ]"
echo "  hops: $(curl -sS -o /dev/null -L --max-redirs 5 -w '%{http_code} %{num_redirects} %{url_effective}' http://serverscrub.com/features.html)"

sec "acceptance 7: UpdateChecker's real fetch path"
cat > /tmp/uc.php <<'EOF'
<?php
require '/src/backend/lib/UpdateChecker.php';
$m = new ReflectionMethod('UpdateChecker', 'httpGet'); $m->setAccessible(true);
foreach ($argv as $i => $u) { if ($i === 0) continue;
  $b = $m->invoke(null, $u);
  echo $u, ' => ', $b === null ? 'NULL (unreadable)' : ('OK version=' . (json_decode($b, true)['version'] ?? '?')), "\n"; }
EOF
php /tmp/uc.php https://serverscrub.com/releases/latest.json https://serverscrub.com/index.html 2>&1 | tee /tmp/uc.out
chk "UpdateChecker::httpGet reads latest.json (200, version 9.9.9)" "grep -q 'latest.json => OK version=9.9.9' /tmp/uc.out"
chk "control: a redirected URL IS unreadable to it (proves the test bites)" "grep -q 'index.html => NULL' /tmp/uc.out"

sec "acceptance 8: idempotent re-run"
sleep 1
SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/run2.log 2>&1; rc=$?
chk "deploy run 2 exits 0" "[ $rc -eq 0 ]"
chk "run 2 .htaccess byte-identical to run 1" "cmp -s $D/.htaccess /tmp/ht.run1"
chk "run 2 reports unchanged" "grep -q 'unchanged:' /tmp/run2.log"
chk "run 2 wrote no extra backup" "[ \$(ls $D/.htaccess.ss-bak-* | wc -l) -eq 1 ]"

sec "R14j / D7: www NOT reachable (www removed from DNS)"
sed 's/ www.serverscrub.com//' /etc/hosts > /tmp/hosts.new; cat /tmp/hosts.new > /etc/hosts
sleep 1
SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/run3.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/run3.log | grep -E 'www|301|200|404|wrote|unchanged|x\]|Done' | head -30
chk "deploy (www down) exits 0" "[ $rc -eq 0 ]"
chk "probe warned www not usable" "grep -q 'is not usable yet' /tmp/run3.log"
chk "https apex / -> 200 (no www redirect)" "[ \"\$(code https://serverscrub.com/)\" = 200 ]"
chk "http apex / -> 301 https://serverscrub.com/" "[ \"\$(loc http://serverscrub.com/)\" = 'https://serverscrub.com/' ]"
chk "no www anywhere in the live block" "! sed -n '/^# BEGIN ServerScrub/,/^# END ServerScrub/p' $D/.htaccess | grep -v '^#' | grep -q 'www\\.serverscrub\\.com/\\?%'"
chk "releases still 200 no Location (www off)" "[ \"\$(code http://serverscrub.com/releases/latest.json)\" = 200 ] && [ -z \"\$(loc http://serverscrub.com/releases/latest.json)\" ]"
chk "HSTS on https apex when www off" "hdr Strict-Transport-Security https://serverscrub.com/ | grep -q ."
END=$(grep -n '^# END ServerScrub site$' $D/.htaccess | cut -d: -f1)
tail -n +$((END+2)) $D/.htaccess > /tmp/cpanel.after
chk "cPanel section still byte-identical after www toggle" "cmp -s /tmp/cpanel.after /tmp/cpanel.orig"
echo "127.0.0.1 www.serverscrub.com" >> /etc/hosts
sleep 1; SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/run4.log 2>&1
chk "toggled back to www: identical to run 1" "cmp -s $D/.htaccess /tmp/ht.run1"

sec "malformed markers"
cp $D/.htaccess /tmp/ht.pre
printf '\n# BEGIN ServerScrub site\n' >> $D/.htaccess; cp $D/.htaccess /tmp/ht.malformed
sleep 1; SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/run5.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/run5.log | grep -E 'refus|line|not changed'
chk "malformed: deploy exits non-zero" "[ $rc -ne 0 ]"
chk "malformed: file byte-identical" "cmp -s $D/.htaccess /tmp/ht.malformed"
chk "malformed: pages still published" "grep -q 'Site published' /tmp/run5.log"
cp /tmp/ht.pre $D/.htaccess
# END without BEGIN
printf '# END ServerScrub site\n%s' "$CPANEL" > /tmp/ht.endonly; cp /tmp/ht.endonly $D/.htaccess
SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/run5b.log 2>&1; rc=$?
chk "END-only: refused and unchanged" "[ $rc -ne 0 ] && cmp -s $D/.htaccess /tmp/ht.endonly"
cp /tmp/ht.pre $D/.htaccess

sec "rollback: a block that 301s /releases/"
rm -rf /tmp/broken; cp -r /tmp/website /tmp/broken
# drop the /releases exemption from the plain-HTTP rule only
awk 'NR==1{print; next} /^RewriteCond %\{REQUEST_URI\} !\^\/\(releases/ && !done {done=1; next} {print}' /tmp/website/htaccess.site > /tmp/broken/htaccess.site
diff /tmp/website/htaccess.site /tmp/broken/htaccess.site
cp /tmp/ht.pre $D/.htaccess
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/run6.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/run6.log | grep -E 'releases|Restored|rolled|Removed' | head
chk "rollback: exits non-zero" "[ $rc -ne 0 ]"
chk "rollback: .htaccess restored byte-identical" "cmp -s $D/.htaccess /tmp/ht.pre"
chk "rollback: releases 200 again" "[ \"\$(code http://serverscrub.com/releases/latest.json)\" = 200 ]"
# The real-world break: only the HTTPS rule touches /releases (what the panel actually fetches)
awk '/ss:www-begin/{w=1} w && /^RewriteCond %\{REQUEST_URI\} !\^\/\(releases/ {w=0; next} {print}' /tmp/website/htaccess.site > /tmp/broken/htaccess.site
cp /tmp/ht.pre $D/.htaccess
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/run6b.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/run6b.log | grep -E 'releases|Restored|rolled|Removed' | head
chk "rollback (https rule breaks releases): exits non-zero + restored" "[ $rc -ne 0 ] && cmp -s $D/.htaccess /tmp/ht.pre"
# No .htaccess before + broken block -> file removed
rm -f $D/.htaccess
awk 'NR==1{print; next} /^RewriteCond %\{REQUEST_URI\} !\^\/\(releases/ && !done {done=1; next} {print}' /tmp/website/htaccess.site > /tmp/broken/htaccess.site
awk '/ss:www-begin/{w=1} w && /^RewriteCond %\{REQUEST_URI\} !\^\/\(releases/ {w=0; next} {print}' /tmp/broken/htaccess.site > /tmp/broken/h2; mv /tmp/broken/h2 /tmp/broken/htaccess.site
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/run7.log 2>&1; rc=$?
chk "rollback with no prior .htaccess: removed, exit non-zero" "[ $rc -ne 0 ] && [ ! -e $D/.htaccess ]"
# Broken block when the broken block was ALREADY live (unchanged on re-run): what happens?
cp /tmp/ht.pre $D/.htaccess
SG_FORCE_WWW=1 bash "$DEP" render-block 1 /tmp/broken/htaccess.site > /tmp/bb
bash "$DEP" merge-htaccess $D/.htaccess /tmp/bb >/dev/null
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/run8.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/run8.log | grep -E 'No backup|Restored|rolled' | head -3
chk "broken block already live + re-run: exits non-zero (loud)" "[ $rc -ne 0 ]"
cp /tmp/ht.pre $D/.htaccess

sec "retest 2026-11-26: http-only breaks of each exemption"
HTTPONLY_REL="awk 'NR==1{print; next} /^RewriteCond %\{REQUEST_URI\} !\^\/\(releases/ && !done {done=1; next} {print}' /tmp/website/htaccess.site"
# releases, no prior .htaccess
eval "$HTTPONLY_REL" > /tmp/broken/htaccess.site
rm -f $D/.htaccess
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/r12.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/r12.log | grep -E '\[x\]' | head -4
chk "http-only releases break, no prior file: removed + non-zero" "[ $rc -ne 0 ] && [ ! -e $D/.htaccess ]"
# releases, broken block already live (re-run unchanged)
cp /tmp/ht.pre $D/.htaccess
bash "$DEP" render-block 1 /tmp/broken/htaccess.site > /tmp/bb; bash "$DEP" merge-htaccess $D/.htaccess /tmp/bb >/dev/null
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/r13.log 2>&1; rc=$?
chk "http-only releases break already live: non-zero" "[ $rc -ne 0 ]"
# releases, no manifest on disk (404 carve-out must not hide a 301)
cp /tmp/ht.pre $D/.htaccess; mv $D/releases/latest.json /tmp/lj
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/r14.log 2>&1; rc=$?
chk "http-only releases break + no manifest: rolled back" "[ $rc -ne 0 ] && cmp -s $D/.htaccess /tmp/ht.pre"
mv /tmp/lj $D/releases/latest.json
# .well-known on http
awk '/well-known\/ \[NC\]/ && !done {done=1; next} {print}' /tmp/website/htaccess.site > /tmp/broken/htaccess.site
diff /tmp/website/htaccess.site /tmp/broken/htaccess.site | head -3
cp /tmp/ht.pre $D/.htaccess
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/r15.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/r15.log | grep -E 'well-known' | head -4
chk "http-only .well-known break: rolled back" "[ $rc -ne 0 ] && cmp -s $D/.htaccess /tmp/ht.pre"
# www-disabled variant with http releases break
eval "$HTTPONLY_REL" > /tmp/broken/htaccess.site
cp /tmp/ht.pre $D/.htaccess
sleep 1; SG_FORCE_WWW=0 SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/r16.log 2>&1; rc=$?
chk "www off + http releases break: rolled back" "[ $rc -ne 0 ] && cmp -s $D/.htaccess /tmp/ht.pre"
# the good block passes the new probes cleanly (no false rollback)
sleep 1; SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/r17.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/r17.log | sed -n '/Verifying/,/verified/p'
chk "good block: new http/https probes pass, exit 0" "[ $rc -eq 0 ] && ! grep -q '\[x\]' /tmp/r17.log"
chk "good block: no warnings in verification" "! sed -n '/Verifying/,/verified/p' /tmp/r17.log | grep -q '\[!\]'"
cp /tmp/ht.pre $D/.htaccess

sec "/releases 404 with no latest.json: warning not rollback"
mv $D/releases/latest.json /tmp/lj
sleep 1; SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/run9.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/run9.log | grep -E 'latest.json' | head -3
chk "no manifest: 404 is a warning, exit 0" "[ $rc -eq 0 ] && grep -q '404  https://serverscrub.com/releases/latest.json (not redirected' /tmp/run9.log"
# combined: no manifest AND broken block -> 404 hidden behind a 301? must still roll back
awk 'NR==1{print; next} /^RewriteCond %\{REQUEST_URI\} !\^\/\(releases/ && !done {done=1; next} {print}' /tmp/website/htaccess.site > /tmp/broken/htaccess.site
awk '/ss:www-begin/{w=1} w && /^RewriteCond %\{REQUEST_URI\} !\^\/\(releases/ {w=0; next} {print}' /tmp/broken/htaccess.site > /tmp/broken/h2; mv /tmp/broken/h2 /tmp/broken/htaccess.site
sleep 1; SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/run10.log 2>&1; rc=$?
chk "no manifest + broken block: still rolls back" "[ $rc -ne 0 ] && cmp -s $D/.htaccess /tmp/ht.pre"
mv /tmp/lj $D/releases/latest.json

sec "backup retention (keep 5)"
# alternate www on/off so every run changes the block; no sleeps, so names collide unless made unique
bash "$DEP" render-block 1 /tmp/website/htaccess.site > /tmp/b1; bash "$DEP" render-block 0 /tmp/website/htaccess.site > /tmp/b0
cp /tmp/ht.pre $D/.htaccess; rm -f $D/.htaccess.ss-bak-*
for i in 1 2 3 4 5 6 7 8; do cp $D/.htaccess /tmp/pre.$i; bash "$DEP" merge-htaccess $D/.htaccess /tmp/b$((i%2)) > /dev/null; done
ls -1 $D/.htaccess.ss-bak-*
chk "at most 5 backups kept (8 fast changes)" "[ \$(ls $D/.htaccess.ss-bak-* | wc -l) -eq 5 ]"
NEWEST=$(ls -1 $D/.htaccess.ss-bak-* | sort -t- -k3,3n | tail -1)
chk "newest backup holds the state before the last change" "cmp -s $NEWEST /tmp/pre.8"
OLDEST=$(ls -1 $D/.htaccess.ss-bak-* | sort -t- -k3,3n | head -1)
chk "oldest kept backup is change 4 (none overwritten)" "cmp -s $OLDEST /tmp/pre.4"
cp /tmp/ht.pre $D/.htaccess

sec "retest R1: rollback after rapid merges with future-dated backups"
cp /tmp/ht.pre $D/.htaccess; rm -f $D/.htaccess.ss-bak-*
NOW=$(date +%s); for k in 1 2 3 4 5; do echo "future $k" > $D/.htaccess.ss-bak-$((NOW+k)); done
for i in 2 3 4 5 6 7 8; do { head -1 /tmp/b1; echo "# rapid $i"; tail -n +2 /tmp/b1; } > /tmp/blk; bash "$DEP" merge-htaccess $D/.htaccess /tmp/blk > /tmp/m.$i; done
LASTB=$(sed -n 's/^BACKUP=//p' /tmp/m.8)
chk "rapid: last reported backup exists" "[ -f '$LASTB' ]"
chk "rapid: last reported backup is the newest name" "[ \"\$(ls -1 $D/.htaccess.ss-bak-* | sort -t- -k3,3n | tail -1)\" = '$LASTB' ]"
chk "rapid: still 5 kept" "[ \$(ls $D/.htaccess.ss-bak-* | wc -l) -eq 5 ]"
cp $D/.htaccess /tmp/ht.rapid
awk 'NR==1{print; next} /^RewriteCond %\{REQUEST_URI\} !\^\/\(releases/ && !done {done=1; next} {print}' /tmp/website/htaccess.site > /tmp/broken/htaccess.site
SG_SITE_SRC=/tmp/broken bash "$DEP" > /tmp/r20.log 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/r20.log | grep -E 'Restored|No backup' | head -2
chk "rapid: broken deploy right after rolls back to the pre-deploy file" "[ $rc -ne 0 ] && cmp -s $D/.htaccess /tmp/ht.rapid"
cp /tmp/ht.pre $D/.htaccess

sec "CRLF .htaccess (edited on Windows)"
printf '%s' "$CPANEL" | sed 's/$/\r/' > $D/.htaccess; cp $D/.htaccess /tmp/crlf.orig
sleep 1; SG_SITE_SRC=/tmp/website bash "$DEP" > /dev/null 2>&1; rc=$?
cp $D/.htaccess /tmp/crlf.1
sleep 1; SG_SITE_SRC=/tmp/website bash "$DEP" > /dev/null 2>&1
chk "CRLF: exit 0 and idempotent" "[ $rc -eq 0 ] && cmp -s $D/.htaccess /tmp/crlf.1"
END=$(grep -n '^# END ServerScrub site$' $D/.htaccess | cut -d: -f1)
tail -n +$((END+2)) $D/.htaccess > /tmp/crlf.after
chk "CRLF: cPanel section byte-identical" "cmp -s /tmp/crlf.after /tmp/crlf.orig"
# CRLF markers already present (whole file round-tripped through a Windows editor)
sed -i 's/$/\r/' $D/.htaccess; cp $D/.htaccess /tmp/crlf.2
sleep 1; SG_SITE_SRC=/tmp/website bash "$DEP" > /tmp/run11.log 2>&1; rc=$?
chk "CRLF markers: recognised (one BEGIN after merge)" "[ $rc -eq 0 ] && [ \$(grep -c 'BEGIN ServerScrub site' $D/.htaccess) -eq 1 ]"

sec "IfModule guards: no 500 without mod_headers / mod_rewrite"
cp /tmp/ht.run1 $D/.htaccess
sed -i 's/^LoadModule headers_module/#&/' /etc/httpd/conf.modules.d/*.conf; httpd -k restart; sleep 1
chk "no mod_headers: www 200, releases 200, no HSTS" "[ \"\$(code https://www.serverscrub.com/)\" = 200 ] && [ \"\$(code https://serverscrub.com/releases/latest.json)\" = 200 ] && ! hdr Strict-Transport-Security https://www.serverscrub.com/ | grep -q ."
sed -i 's/^#\(LoadModule headers_module\)/\1/; s/^LoadModule rewrite_module/#&/' /etc/httpd/conf.modules.d/*.conf; httpd -k restart; sleep 1
chk "no mod_rewrite: http apex 200 (no redirect, no 500)" "[ \"\$(code http://serverscrub.com/)\" = 200 ]"
sed -i 's/^#\(LoadModule rewrite_module\)/\1/' /etc/httpd/conf.modules.d/*.conf; httpd -k restart; sleep 1

sec "error log"
grep -iE 'error|alert|crit' /var/log/httpd/error_log | grep -v 'AH00558' | tail -5

echo; echo "TOTAL: $PASS passed, $FAILS failed"
[ $FAILS -eq 0 ]
