#!/usr/bin/env bash
# Shakaal — adversarial probe of `serverscrub quarantine restore` (2e0e576).
# Runs INSIDE the test container, against a real install and a real database.
set -uo pipefail
D=/usr/local/serverscrub
DB=$D/database/serverscrub.db
CLI="php $D/backend/cli/serverscrub.php"
Q=$(php -r "define('SG_ROOT','$D'); define('SG_API',true); require '$D/backend/config/config.php'; echo QUARANTINE_DIR;")
echo "QUARANTINE_DIR=$Q"
mkdir -p "$Q/$(date +%Y-%m-%d)"

# Two "accounts": one holding a genuine detection, one a false positive.
mkdir -p /home/victim/public_html /home/fpuser/public_html/node_modules/pkg1
chown -R 1001:1001 /home/victim 2>/dev/null
chown -R 1002:1002 /home/fpuser 2>/dev/null

JOB=$(sqlite3 "$DB" "INSERT INTO scan_jobs (scan_type,status,started_at,files_scanned,threats_found,scan_path,requested_by) VALUES ('full','completed',$(date +%s),100,0,'/home','@schedule'); SELECT last_insert_rowid();")
echo "JOB=$JOB"

mkrow() { # path signature user hash size
  sqlite3 "$DB" "INSERT INTO threats (scan_job_id,file_path,threat_name,threat_type,severity,status,hash,size,detected_at,resolved_at,cpanel_user,action_taken) VALUES ($JOB,'$1','$2','malware','critical','quarantined','$3',$4,$(date +%s),$(date +%s),'$5','quarantine'); SELECT last_insert_rowid();"
}

# 1. attacker's real webshell, quarantined
A_PATH=/home/victim/public_html/evil.php
printf 'INERT-SHELL-STANDIN\n' > /tmp/a; AH=$(sha256sum /tmp/a | cut -d' ' -f1)
AID=$(mkrow "$A_PATH" '{HEX}php.cmdshell.gifheader.400.UNOFFICIAL' "$AH" 20 victim)
cp /tmp/a "$Q/$(date +%Y-%m-%d)/evil.php_${AID}.quarantine"
sqlite3 "$DB" "UPDATE threats SET quarantine_path='$Q/$(date +%Y-%m-%d)/evil.php_${AID}.quarantine' WHERE id=$AID;"

# 2. false-positive changelog
B_PATH=/home/fpuser/public_html/node_modules/pkg1/CHANGELOG.md
printf '# changelog deadbeefcafe\n' > /tmp/b; BH=$(sha256sum /tmp/b | cut -d' ' -f1)
BID=$(mkrow "$B_PATH" '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL' "$BH" 26 fpuser)
cp /tmp/b "$Q/$(date +%Y-%m-%d)/CHANGELOG.md_${BID}.quarantine"
sqlite3 "$DB" "UPDATE threats SET quarantine_path='$Q/$(date +%Y-%m-%d)/CHANGELOG.md_${BID}.quarantine' WHERE id=$BID;"

# 3. a row whose quarantined copy has been TAMPERED WITH since (hash mismatch)
C_PATH=/home/fpuser/public_html/node_modules/pkg1/README.md
CID=$(mkrow "$C_PATH" '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL' "$(printf 'original' | sha256sum | cut -d' ' -f1)" 8 fpuser)
printf 'TAMPERED\n' > "$Q/$(date +%Y-%m-%d)/README.md_${CID}.quarantine"
sqlite3 "$DB" "UPDATE threats SET quarantine_path='$Q/$(date +%Y-%m-%d)/README.md_${CID}.quarantine' WHERE id=$CID;"

# 4. a row whose original path EXISTS AGAIN (customer replaced it)
E_PATH=/home/fpuser/public_html/node_modules/pkg1/LICENSE.md
printf 'customer put this back\n' > "$E_PATH"
printf 'quarantined copy\n' > /tmp/e; EH=$(sha256sum /tmp/e | cut -d' ' -f1)
EID=$(mkrow "$E_PATH" '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL' "$EH" 17 fpuser)
cp /tmp/e "$Q/$(date +%Y-%m-%d)/LICENSE.md_${EID}.quarantine"
sqlite3 "$DB" "UPDATE threats SET quarantine_path='$Q/$(date +%Y-%m-%d)/LICENSE.md_${EID}.quarantine' WHERE id=$EID;"

# 5. LEGACY path row: no quarantine_path, copy under the legacy quarantine dir
L_PATH=/home/fpuser/public_html/node_modules/pkg1/OLD.md
printf 'legacy quarantined\n' > /tmp/l; LH=$(sha256sum /tmp/l | cut -d' ' -f1)
LID=$(mkrow "$L_PATH" '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL' "$LH" 19 fpuser)
mkdir -p "/home/.sentinel""-gate/quarantine/$(date +%Y-%m-%d)"
cp /tmp/l "/home/.sentinel""-gate/quarantine/$(date +%Y-%m-%d)/OLD.md_${LID}.quarantine"

echo "IDS: webshell=$AID fp=$BID tampered=$CID exists=$EID legacy=$LID"

hr() { echo; echo "──────── $* ────────"; }

hr "A. UNSCOPED restore (must be REFUSED)"
$CLI quarantine restore --apply; echo "exit=$?"

hr "B. SCOPE BYPASS: --signature='*' with --apply"
$CLI quarantine restore --signature='*' --apply; echo "exit=$?"
echo "webshell back on disk? $([ -f "$A_PATH" ] && echo YES-BAD || echo no)"
ls -l "$A_PATH" 2>/dev/null

hr "C. state of rows after B"
sqlite3 -header -column "$DB" "SELECT id,status,action_taken FROM threats WHERE scan_job_id=$JOB;"
