#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — seed logs the ingesters actually parse
#
# Taken from real entries off the production server, with hostnames and the
# header suffix changed. Real shapes matter here more than volume: every log
# bug this product has had came from a layout that was assumed rather than
# read -- section A parsed positionally when mod_unique_id was absent, the
# action field invented as 'block' for 148,551 rows, the client address taken
# from the connection when a proxy sat in front of it.
#
# The three ModSecurity entries below are chosen to be the three cases that
# have to come out differently:
#
#   1. direct      — client connects to Apache, section A has the real address
#   2. proxied     — nginx in front, section A says 127.0.0.1, and the address
#                    is only in X-Forwarded-For. Before 4.35.1 this was filed
#                    against loopback.
#   3. spoofed     — the same, but the attacker sent their own X-Forwarded-For
#                    first. nginx appends what it saw, so the RIGHTMOST entry
#                    is the true one. Reading the leftmost hands the attacker
#                    the choice of who gets blamed and firewalled.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

AUDIT=/etc/apache2/logs/modsec_audit.log
mkdir -p "$(dirname "$AUDIT")"

ts() { date '+%d/%b/%Y:%H:%M:%S %z'; }

# ── 1. A direct connection ────────────────────────────────────────────────────
cat >> "$AUDIT" <<EOF
--aa000001-A--
[$(ts)] Xf8aQwAAQEAAAaa 20.46.43.126 41022 51.68.163.24 443
--aa000001-B--
GET /.env HTTP/1.1
Host: acct3.test
User-Agent: Mozilla/5.0 (compatible; Scanner/1.0)
Accept: */*

--aa000001-F--
HTTP/1.1 403 Forbidden

--aa000001-H--
Message: Access denied with code 403 (phase 2). Matched "Operator \`Rx' with parameter \`(?i)(?:\\\\.env)' against variable \`REQUEST_URI' [file "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/REQUEST-930-APPLICATION-ATTACK-LFI.conf"] [line "78"] [id "930120"] [msg "OS File Access Attempt"] [severity "CRITICAL"]
Action: Intercepted (phase 2)
Engine-Mode: "ENABLED"

--aa000001-Z--

EOF

# ── 2. Behind nginx: the address is ONLY in the header ────────────────────────
cat >> "$AUDIT" <<EOF
--aa000002-A--
[$(ts)] Xf8aQwAAQEAAAbb 127.0.0.1 52118 127.0.0.1 80
--aa000002-B--
GET /....//....//....//..../.env HTTP/1.0
Host: addons.test
X-Forwarded-For: 20.218.73.251
X-Forwarded-Host: addons.test
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: addons.test
User-Agent: python-requests/2.31.0

--aa000002-F--
HTTP/1.1 200 OK

--aa000002-H--
Message: Warning. Matched "Operator \`Rx' with parameter \`(?i)(?:\\\\.env)' against variable \`REQUEST_URI' [file "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/REQUEST-930-APPLICATION-ATTACK-LFI.conf"] [line "78"] [id "930120"] [msg "OS File Access Attempt"] [severity "CRITICAL"]
Engine-Mode: "DETECTION_ONLY"

--aa000002-Z--

EOF

# ── 3. The same, with a forged header in front of the real one ────────────────
cat >> "$AUDIT" <<EOF
--aa000003-A--
[$(ts)] Xf8aQwAAQEAAAcc 51.68.163.24 33440 51.68.163.24 80
--aa000003-B--
GET /wp-content/plugins/hellopress/wp_filemanager.php HTTP/1.0
Host: shopfront.test
X-Forwarded-For: 8.8.8.8, 52.242.194.83
X-Forwarded-Proto: https
User-Agent: Mozilla/5.0

--aa000003-F--
HTTP/1.1 404 Not Found

--aa000003-H--
Message: Warning. Matched "Operator \`Rx' with parameter \`(?i)(filemanager)' against variable \`REQUEST_URI' [file "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/REQUEST-932-APPLICATION-ATTACK-RCE.conf"] [line "512"] [id "932100"] [msg "Remote Command Execution"] [severity "CRITICAL"]
Engine-Mode: "DETECTION_ONLY"

--aa000003-Z--

EOF

# ── 4. A Cloudflare-fronted request ───────────────────────────────────────────
cat >> "$AUDIT" <<EOF
--aa000004-A--
[$(ts)] Xf8aQwAAQEAAAdd 127.0.0.1 52120 127.0.0.1 80
--aa000004-B--
GET /?s=%E5%8D%9A%E5%BD%A9 HTTP/1.0
Host: blogsite.test
X-Forwarded-For: 203.0.113.77, 162.158.1.1
CF-Connecting-IP: 203.0.113.77
User-Agent: Mozilla/5.0

--aa000004-F--
HTTP/1.1 200 OK

--aa000004-H--
Message: Warning. Matched "Operator \`Rx' against variable \`ARGS:s' [id "913402"] [msg "Suspicious Keyword"] [severity "WARNING"]
Engine-Mode: "DETECTION_ONLY"

--aa000004-Z--

EOF

# ── 5. A request a REAL VISITOR makes, which must never be blocked ────────────
#
# One site, one address, an ordinary path. This is the shape the triage has to
# classify as a false-positive risk: arming a rule that only ever fires on
# traffic like this is somebody's shop refusing orders.
for i in 1 2 3 4 5 6; do
cat >> "$AUDIT" <<EOF
--bb00000${i}-A--
[$(ts)] Xf8aQwAAQEAAAe${i} 198.51.100.42 4411${i} 51.68.163.24 443
--bb00000${i}-B--
POST /shop/checkout HTTP/1.1
Host: shopfront.test
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36

--bb00000${i}-F--
HTTP/1.1 200 OK

--bb00000${i}-H--
Message: Warning. Matched "Operator \`Rx' against variable \`REQUEST_HEADERS:User-Agent' [id "420047"] [msg "Bad user-agent Mozilla/5.0"] [severity "NOTICE"]
Engine-Mode: "DETECTION_ONLY"

--bb00000${i}-Z--

EOF
done

# ── Brute force sources ───────────────────────────────────────────────────────
SECURE=/var/log/secure
mkdir -p "$(dirname "$SECURE")"
for i in $(seq 1 9); do
    echo "$(date '+%b %e %H:%M:%S') host sshd[$((2000+i))]: Failed password for invalid user admin from 45.148.10.9 port 5$((1000+i)) ssh2" >> "$SECURE"
done
echo "$(date '+%b %e %H:%M:%S') host sshd[2100]: Accepted publickey for root from 24.150.90.129 port 50022 ssh2" >> "$SECURE"

LOGIN=/usr/local/cpanel/logs/login_log
mkdir -p "$(dirname "$LOGIN")"
for i in $(seq 1 7); do
    echo "$(date '+%m/%d/%Y:%H:%M:%S %z') [cpaneld] info [cpaneld] 185.220.101.7 - FAILED LOGIN cpaneld: user addons" >> "$LOGIN"
done

MAILLOG=/var/log/maillog
for i in $(seq 1 6); do
    echo "$(date '+%b %e %H:%M:%S') host dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<info@addons.test>, method=PLAIN, rip=91.240.118.4, lip=51.68.163.24" >> "$MAILLOG"
done

# ── An Exim queue with messages old enough to prune ───────────────────────────
#
# 4.34.0 deletes anything queued 72 hours or more. The fixture needs one each
# side of the line, or the test proves only that deletion happens and not that
# it stops at the right place.
QUEUE=/var/spool/exim/input
mkdir -p "$QUEUE"
cat > /usr/local/bin/exim <<'EOF'
#!/usr/bin/env bash
# Stub exim. -bp prints a queue with messages either side of the 72h cutoff.
case "${1:-}" in
  -bp)
    cat <<'Q'
120h  2.4K 1aBcDe-0001aa-11 <bounce@addons.test>
          victim@example.net
 96h  1.1K 1aBcDe-0002bb-22 <newsletter@acct3.test>
          nobody@example.org
 73h  3.0K 1aBcDe-0003cc-33 <noreply@shopfront.test>
          lost@example.com
 71h  0.9K 1aBcDe-0004dd-44 <orders@shopfront.test>
          customer@example.com
  2h  1.4K 1aBcDe-0005ee-55 <hello@blogsite.test>
          reader@example.com
Q
    ;;
  -Mrm) echo "Message ${2:-} has been removed"; ;;
  -bpc) echo 5 ;;
  *) exit 0 ;;
esac
EOF
chmod +x /usr/local/bin/exim

echo "[seed-logs] modsec entries: $(grep -c -- '-A--$' "$AUDIT" || true)"
echo "[seed-logs] done"
