#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# ServerScrub — publish the marketing site and the download directory
#
# Run as ROOT on the server that hosts serverscrub.com.
#
#   bash deploy-site.sh                 # fetch from GitHub and publish
#   SG_SITE_SRC=/path/to/website bash deploy-site.sh    # publish a local copy
#   SG_FORCE_WWW=0|1 bash deploy-site.sh                # skip the www probe
#
# It does three separate things, because the domain serves separate things:
#
#   1. The marketing site        -> /home/serversc/public_html/
#   2. The download directory    -> /home/serversc/public_html/releases/
#   3. The canonical-host rules  -> a marked block in public_html/.htaccess
#
# The second is what every installed server fetches updates from, so this
# script never deletes anything underneath it. Wiping a docroot that other
# machines depend on, to publish a website, is not a trade worth making.
#
# The third sends every browser to https://www.serverscrub.com/ -- and must
# NEVER redirect /releases/. UpdateChecker.php takes the status from the first
# response line and accepts only 200, so a 301 in front of latest.json makes
# every installed panel report the manifest unreadable and stop seeing
# updates, silently. The rules exempt /releases/, and this script checks that
# exemption against the live host after writing them and restores the backup
# if it does not hold.
#
# Two helper modes exist so the .htaccess logic can be exercised on its own,
# without root and without a live docroot (tests, and a docker Apache):
#
#   bash deploy-site.sh render-block <www 0|1> <htaccess.site>   # print block
#   bash deploy-site.sh merge-htaccess <.htaccess> <blockfile>   # merge it in
#   bash deploy-site.sh verify-exempt <www 0|1> <have_manifest 0|1>
#        # only the exempt-path probes against SG_DOMAIN (network, no root)
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[x]${NC} $*" >&2; }
die()  { fail "$*"; exit 1; }

CP_USER="${SG_CP_USER:-serversc}"
DOMAIN="${SG_DOMAIN:-serverscrub.com}"
HOME_DIR="/home/${CP_USER}"
DOCROOT="${HOME_DIR}/public_html"
CODE_DIR="${DOCROOT}/releases"
REPO_RAW="https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/website"

HT_BEGIN='# BEGIN ServerScrub site'
HT_END='# END ServerScrub site'
HT_KEEP_BACKUPS=5

# ── The manifest ──────────────────────────────────────────────────────────────
# status.html is the release dashboard. It is listed here because this array
# IS the deploy manifest -- a page absent from it is simply never uploaded,
# and a status page that is not live is worse than none at all.
# website/check-site.py parses these two arrays and fails when a page
# references a local file that is not listed, so the two cannot drift.
PAGES=(index.html features.html pricing.html install.html status.html)
# One per line, and that formatting is load-bearing. This used to be a
# single line with an escaped newline sequence in the middle, which bash
# does NOT treat as a line break inside an array literal: it became a
# seventh element, the bare letter n. The fetch loop then asked GitHub
# for <repo>/website/n, got a 404 and die()d, so the default
# fetch-from-GitHub path aborted every time it ran. The local-source
# path failed the same way, on "missing from source: n".
#
# Paths are relative to the docroot, so favicon.ico, robots.txt and
# sitemap.xml publish at its top level. logo.png and hero.svg are no longer
# listed; nothing is deleted, so the old files stay on the server and any
# outside link to them keeps working.
ASSETS=(
  assets/css/site.css
  assets/img/logo.svg
  assets/img/mark.svg
  assets/img/favicon.svg
  assets/img/favicon.png
  assets/img/icon-180.png
  assets/img/mark-64.png
  favicon.ico
  robots.txt
  sitemap.xml
)
# Fetched and staged with everything else, but never installed as a file: it
# is the source of the marked .htaccess block, and a file called htaccess.site
# sitting in a docroot would just be served to anyone who asked for it.
STAGE_ONLY=(htaccess.site)

# ── .htaccess block: render and merge ─────────────────────────────────────────

# Print the block for www enabled (1) or disabled (0). Disabled drops the
# apex->www rule and points the http->https redirect at the apex instead, so a
# server without a www certificate still gets HTTPS and never a broken host.
render_block() {
  local www="$1" src="$2"
  [[ -f "$src" ]] || { fail "block source not found: ${src}"; return 1; }
  if [[ "$www" == "1" ]]; then
    cat "$src"
  else
    awk '/^# ss:www-begin/ { skip = 1; next }
         /^# ss:www-end/   { skip = 0; next }
         !skip             { print }' "$src" \
      | sed 's#https://www\.serverscrub\.com#https://serverscrub.com#g'
  fi
}

# Line numbers of lines that are exactly the marker (a trailing CR from a file
# edited on Windows still counts, so CRLF files are recognised, not doubled).
_marker_lines() {
  awk -v m="$1" '{ sub(/\r$/, "") } $0 == m { printf "%d ", NR }' "$2"
}

# Merge <blockfile> into <target>, touching only the text between the markers.
#
#   markers absent      -> block PREPENDED (redirects must run first), plus one
#                          blank line; every other byte left as it was
#   one BEGIN, one END  -> only the lines between them replaced
#   anything else       -> REFUSE, print why, change nothing
#   no target           -> created with the block alone, mode 644
#
# A backup (.htaccess.ss-bak-<epoch>, last 5 kept) is written BEFORE the file
# changes, and the new file goes in with an atomic mv from the same directory.
# Running it twice produces a byte-identical file, and an unchanged file is
# not rewritten or backed up at all.
#
# On success, prints the backup path ("none" if the file did not exist) on
# the last line of stdout as  BACKUP=<path>  so the caller can roll back.
merge_htaccess() {
  local target="$1" block="$2"
  local dir tmp b e nb ne bak=none
  dir="$(dirname "$target")"

  # Validate the block itself first: it must open and close with our markers,
  # or a later run could not find what this run wrote.
  [[ "$(head -n 1 "$block" | tr -d '\r')" == "$HT_BEGIN" ]] \
    || { fail "block does not start with '${HT_BEGIN}': ${block}"; return 2; }
  [[ "$(tail -n 1 "$block" | tr -d '\r')" == "$HT_END" ]] \
    || { fail "block does not end with '${HT_END}': ${block}"; return 2; }

  tmp="$(mktemp "${dir}/.htaccess.ss-tmp.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -f '$tmp'" RETURN

  if [[ ! -e "$target" ]]; then
    cat "$block" > "$tmp"
  else
    b="$(_marker_lines "$HT_BEGIN" "$target")"
    e="$(_marker_lines "$HT_END" "$target")"
    nb=$(wc -w <<<"$b"); ne=$(wc -w <<<"$e")

    if [[ $nb -eq 0 && $ne -eq 0 ]]; then
      { cat "$block"; printf '\n'; cat "$target"; } > "$tmp"
    elif [[ $nb -eq 1 && $ne -eq 1 && ${b// /} -lt ${e// /} ]]; then
      b=${b// /}; e=${e// /}
      { if [[ $b -gt 1 ]]; then head -n $((b - 1)) "$target"; fi
        cat "$block"
        tail -n +$((e + 1)) "$target"; } > "$tmp"
    else
      # Guessing here could delete cPanel's own rules or leave two
      # conflicting blocks. Neither is acceptable on a live docroot.
      fail "refusing to edit ${target}: malformed ServerScrub markers"
      fail "  '${HT_BEGIN}' on line(s): ${b:-none}"
      fail "  '${HT_END}' on line(s): ${e:-none}"
      fail "  Expected exactly one BEGIN followed by one END. Fix the file by hand"
      fail "  and re-run; the file has not been changed."
      return 3
    fi

    if cmp -s "$tmp" "$target"; then
      echo "unchanged: ${target}"
      echo "BACKUP=none"
      return 0
    fi

    # Backup BEFORE the change, and verify it, or do not change anything.
    # Names are plain integers and strictly increasing: max(now, newest + 1).
    # One-second names collided (two changing merges in the same second both
    # picked .ss-bak-<epoch> and the second cp overwrote the first). Stepping
    # to the first FREE name was not enough either: once pruning had deleted
    # the oldest name, a fast later merge reused it, sorted first, and was
    # pruned at once, so rollback found no backup. Above the newest, the
    # backup just written is always the last to go.
    local ts newest
    ts="$(date +%s)"
    newest="$(find "$dir" -maxdepth 1 -type f -name "$(basename "$target").ss-bak-*" -printf '%f\n' 2>/dev/null \
              | sed -n 's/.*\.ss-bak-\([0-9][0-9]*\)$/\1/p' | sort -n | tail -n 1)"
    if [[ -n "$newest" ]] && (( newest >= ts )); then ts=$(( newest + 1 )); fi
    bak="${target}.ss-bak-${ts}"
    cp -p "$target" "$bak" && cmp -s "$target" "$bak" \
      || { fail "could not back up ${target}; not changing it"; return 4; }
    # Keep the newest few; only ever our own backup files.
    find "$dir" -maxdepth 1 -type f -name "$(basename "$target").ss-bak-*" -printf '%f\n' 2>/dev/null \
      | sort -t- -k3,3n | head -n -"$HT_KEEP_BACKUPS" \
      | while IFS= read -r old; do
          [[ "$old" == "$(basename "$bak")" ]] && continue   # never the one just written
          rm -f -- "${dir}/${old}"
        done
  fi

  chmod 644 "$tmp" || { fail "could not chmod ${tmp}"; return 5; }
  if [[ $EUID -eq 0 ]]; then chown "${CP_USER}:${CP_USER}" "$tmp" 2>/dev/null || true; fi
  mv -f "$tmp" "$target" || { fail "could not move the new file into place; ${target} unchanged"; return 5; }
  echo "wrote: ${target}"
  echo "BACKUP=${bak}"
}

# ── Live-host probes ──────────────────────────────────────────────────────────
# --max-redirs 0 so we see the redirect itself rather than where it leads.
# Returns "<code> <location>" (code 000 when there was no response at all).
head_of() {
  local out code loc
  out="$(curl -sS -o /dev/null -D - --max-redirs 0 --max-time 15 "$1" 2>/dev/null || true)"
  code="$(printf '%s' "$out" | awk 'toupper($1) ~ /^HTTP\// { c = $2 } END { print c ? c : "000" }')"
  loc="$(printf '%s' "$out" | tr -d '\r' | awk 'tolower($1) == "location:" { print $2 }' | tail -n 1)"
  printf '%s %s\n' "$code" "${loc:--}"
}
has_header() {
  curl -sS -o /dev/null -D - --max-redirs 0 --max-time 15 "$1" 2>/dev/null \
    | tr -d '\r' | grep -qi "^$2:"
}

# The exempt paths must not be redirected on ANY scheme or host the rules
# touch. This used to probe only https://<apex>/releases/latest.json, so a
# block whose plain-HTTP rule lost the /releases exemption was verified "OK"
# and left live: http://serverscrub.com/releases/latest.json answered 301 to
# www and the deploy exited 0. Now both schemes are probed on the apex, and
# on www as well when the rules send traffic there.
#
#   /releases/latest.json    200 with no Location, or 404 with no Location
#                            while nothing is published yet; else broken
#   /.well-known/, /serverscrub/
#                            a probe file that does not exist; broken only if
#                            it is redirected to our own host (our rule did it)
#
# verify_exempt <www 0|1> <have_manifest 0|1>; returns 1 if anything is broken.
verify_exempt() {
  local www="$1" have_manifest="$2" broken=0 h scheme url code loc p re
  local hosts=("$DOMAIN")
  [[ "$www" == "1" ]] && hosts+=("www.${DOMAIN}")
  local dot='\.'
  re="^https?://(www${dot})?${DOMAIN//./$dot}(:[0-9]+)?/"
  for h in "${hosts[@]}"; do
    for scheme in https http; do
      url="${scheme}://${h}/releases/latest.json"
      read -r code loc <<<"$(head_of "$url")"
      if [[ "$code" == "200" && "$loc" == "-" ]]; then
        ok "  200  ${url} (not redirected)"
      elif [[ "$code" == "404" && "$have_manifest" == "0" && "$loc" == "-" ]]; then
        warn "  404  ${url} (not redirected; nothing published there yet)"
      elif [[ "$code" == "000" && "$h" != "$DOMAIN" ]]; then
        # www forced or flaky; the apex is the URL installed servers read.
        warn "  ---  ${url} (no response)"
      else
        fail "  ${code}  ${url}  Location: ${loc}"
        fail "  Installed servers read this URL and accept only a 200 with no redirect."
        broken=1
      fi
      for p in .well-known/ss-deploy-probe serverscrub/ss-deploy-probe; do
        url="${scheme}://${h}/${p}"
        read -r code loc <<<"$(head_of "$url")"
        if [[ "$code" == 3?? && "$loc" =~ ${re}${p//./$dot}$ ]]; then
          fail "  ${code}  ${url}  Location: ${loc} (this path must never be redirected)"
          broken=1
        else
          ok "  ${code}  ${url} (not redirected)"
        fi
      done
    done
  done
  return $broken
}

# ── Helper modes (no root, no network) ────────────────────────────────────────
case "${1:-}" in
  render-block)
    [[ $# -eq 3 ]] || die "usage: $0 render-block <www 0|1> <htaccess.site>"
    render_block "$2" "$3"; exit $? ;;
  merge-htaccess)
    [[ $# -eq 3 ]] || die "usage: $0 merge-htaccess <.htaccess> <blockfile>"
    merge_htaccess "$2" "$3"; exit $? ;;
  verify-exempt)
    # Network, but no root and no writes: only the exempt-path probes, against
    # SG_DOMAIN. Exits 1 if any exempt path is redirected.
    [[ $# -eq 3 ]] || die "usage: $0 verify-exempt <www 0|1> <have_manifest 0|1>"
    verify_exempt "$2" "$3"; exit $? ;;
  "") ;;
  *) die "unknown argument: $1" ;;
esac

[[ $EUID -eq 0 ]] || die "run as root"
[[ -d "$HOME_DIR" ]] || die "no such account: ${HOME_DIR} (is the cPanel account created?)"

# ── Where the site files come from ────────────────────────────────────────────
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

if [[ -n "${SG_SITE_SRC:-}" ]]; then
  [[ -d "$SG_SITE_SRC" ]] || die "SG_SITE_SRC is not a directory: $SG_SITE_SRC"
  info "Using local source: ${SG_SITE_SRC}"
  for f in "${PAGES[@]}" "${ASSETS[@]}" "${STAGE_ONLY[@]}"; do
    [[ -f "${SG_SITE_SRC}/${f}" ]] || die "missing from source: ${f}"
    mkdir -p "${STAGE}/$(dirname "$f")"
    cp -f "${SG_SITE_SRC}/${f}" "${STAGE}/${f}"
  done
else
  info "Fetching the site from GitHub…"
  for f in "${PAGES[@]}" "${ASSETS[@]}" "${STAGE_ONLY[@]}"; do
    mkdir -p "${STAGE}/$(dirname "$f")"
    curl -fsSL --max-time 30 "${REPO_RAW}/${f}" -o "${STAGE}/${f}" \
      || die "could not fetch ${f} — if the repository is private, re-run with SG_SITE_SRC=<local copy>"
    [[ -s "${STAGE}/${f}" ]] || die "fetched ${f} but it is empty"
  done
fi

# Every page must be whole. A truncated download that still exits 0 would
# otherwise publish a half-written page over a working one.
for f in "${PAGES[@]}"; do
  grep -q '</html>' "${STAGE}/${f}" || die "${f} looks truncated — not publishing"
done
grep -qxF "$HT_END" "${STAGE}/htaccess.site" || die "htaccess.site looks truncated — not publishing"
ok "Staged $(( ${#PAGES[@]} + ${#ASSETS[@]} + ${#STAGE_ONLY[@]} )) file(s), all complete"

# ── Publish ───────────────────────────────────────────────────────────────────
info "Publishing to ${DOCROOT}…"
mkdir -p "${DOCROOT}/assets/css" "${DOCROOT}/assets/img" "${CODE_DIR}"

for f in "${PAGES[@]}" "${ASSETS[@]}"; do
  install -m 644 -o "$CP_USER" -g "$CP_USER" "${STAGE}/${f}" "${DOCROOT}/${f}"
  echo "      ${f}"
done

# cPanel serves as the account user; files owned by root are a 403 waiting to
# happen the first time something needs to write one. Every published file is
# named here from the manifest itself: the old hand-written list left out
# status.html, which stayed root-owned after every deploy.
for f in "${PAGES[@]}" "${ASSETS[@]}"; do
  chown "${CP_USER}:${CP_USER}" "${DOCROOT}/${f}"
done
chown "${CP_USER}:${CP_USER}" "${DOCROOT}/assets" "${DOCROOT}/assets/css" "${DOCROOT}/assets/img"
find "${DOCROOT}/assets" -type d -exec chmod 755 {} + 2>/dev/null || true
ok "Site published"

# ── The download directory ────────────────────────────────────────────────────
# Created, never emptied. Servers in the field fetch updates from here.
chown "${CP_USER}:${CP_USER}" "${CODE_DIR}" 2>/dev/null || true
chmod 755 "${CODE_DIR}"
if [[ -d "${DOCROOT}/serverscrub" ]]; then
  chown "${CP_USER}:${CP_USER}" "${DOCROOT}/serverscrub" 2>/dev/null || true
  chmod 755 "${DOCROOT}/serverscrub"
fi
HAVE_MANIFEST=0
if [[ -f "${CODE_DIR}/latest.json" ]]; then
  HAVE_MANIFEST=1
  ok "Download directory present: ${CODE_DIR} (latest.json found, left untouched)"
else
  warn "Download directory is EMPTY: ${CODE_DIR}"
  warn "  Until latest.json and dist/ are there, https://${DOMAIN}/releases/"
  warn "  serves nothing and installs fall back to the GitHub mirror."
  warn "  Populate it with scripts/cdn-sync.sh (see its header)."
fi

# ── Canonical host: is www usable? ────────────────────────────────────────────
# Probed against the robots.txt just published (the docroot is shared by both
# hosts), with normal certificate verification. Redirecting everyone to a
# host with no DNS record or a certificate for the wrong name would take the
# site down; staying on the apex with HTTPS forced is fully functional.
WWW=0
if [[ -n "${SG_FORCE_WWW:-}" ]]; then
  [[ "$SG_FORCE_WWW" == "0" || "$SG_FORCE_WWW" == "1" ]] || die "SG_FORCE_WWW must be 0 or 1"
  WWW="$SG_FORCE_WWW"
  info "www redirect forced to ${WWW} by SG_FORCE_WWW"
else
  info "Probing https://www.${DOMAIN}/ …"
  if probe_err="$(curl -fsS --max-time 15 -o /dev/null "https://www.${DOMAIN}/robots.txt" 2>&1)"; then
    WWW=1
    ok "www.${DOMAIN} answers over HTTPS with a valid certificate"
  else
    warn "www.${DOMAIN} is not usable yet: ${probe_err:-no response}"
    warn "  Writing the rules WITHOUT the apex->www redirect: the site stays on"
    warn "  https://${DOMAIN}/ with HTTPS forced. To finish the move to www:"
    warn "    1. add a DNS record for www.${DOMAIN} pointing at this server"
    warn "    2. /usr/local/cpanel/bin/autossl_check --user=${CP_USER}"
    warn "    3. re-run this script"
  fi
fi

# ── Write the .htaccess block ─────────────────────────────────────────────────
# Pages and rules are independent: the pages above are already live, so a
# refusal here exits non-zero without undoing them.
HT="${DOCROOT}/.htaccess"
BLOCK="${STAGE}/htaccess.block"
render_block "$WWW" "${STAGE}/htaccess.site" > "$BLOCK"
info "Merging the canonical-host block into ${HT}…"
set +e
merge_out="$(merge_htaccess "$HT" "$BLOCK" 2>&1)"; merge_rc=$?
set -e
printf '%s\n' "$merge_out" | grep -v '^BACKUP=' | sed 's/^/      /'
[[ $merge_rc -eq 0 ]] || die ".htaccess not changed (see above). The pages are published; the redirect rules are not."
HT_BACKUP="$(printf '%s\n' "$merge_out" | sed -n 's/^BACKUP=//p' | tail -n 1)"
HT_CREATED=0
[[ "$HT_BACKUP" == "none" ]] && grep -q '^wrote:' <<<"$merge_out" && HT_CREATED=1

rollback() {
  if [[ "$HT_BACKUP" != "none" && -f "$HT_BACKUP" ]]; then
    local t; t="$(mktemp "${DOCROOT}/.htaccess.ss-tmp.XXXXXX")"
    cp -p "$HT_BACKUP" "$t" && mv -f "$t" "$HT"
    fail "Restored ${HT} from ${HT_BACKUP}"
  elif [[ $HT_CREATED -eq 1 ]]; then
    rm -f "$HT"
    fail "Removed ${HT} (it did not exist before this run)"
  else
    fail "No backup to restore: ${HT} was unchanged by this run"
  fi
}

# ── Verify against the live host, roll back if /releases/ is affected ────────
# head_of, has_header and verify_exempt are defined above the helper modes.
info "Verifying the rules against the live host…"
BROKEN=0
CANON="https://www.${DOMAIN}"; [[ $WWW -eq 1 ]] || CANON="https://${DOMAIN}"

verify_exempt "$WWW" "$HAVE_MANIFEST" || BROKEN=1

read -r code loc <<<"$(head_of "http://${DOMAIN}/")"
case "$code" in
  301) [[ "$loc" == "${CANON}/" ]] && ok "  301  http://${DOMAIN}/ -> ${loc}" \
         || warn "  301  http://${DOMAIN}/ -> ${loc} (expected ${CANON}/)" ;;
  5??) fail "  ${code}  http://${DOMAIN}/"; BROKEN=1 ;;
  *)   warn "  ${code}  http://${DOMAIN}/ (expected 301 to ${CANON}/)" ;;
esac

if [[ $WWW -eq 1 ]]; then
  read -r code loc <<<"$(head_of "https://${DOMAIN}/")"
  case "$code" in
    301) [[ "$loc" == "${CANON}/" ]] && ok "  301  https://${DOMAIN}/ -> ${loc}" \
           || warn "  301  https://${DOMAIN}/ -> ${loc} (expected ${CANON}/)" ;;
    5??) fail "  ${code}  https://${DOMAIN}/"; BROKEN=1 ;;
    *)   warn "  ${code}  https://${DOMAIN}/ (expected 301 to ${CANON}/)" ;;
  esac

  read -r code loc <<<"$(head_of "https://www.${DOMAIN}/")"
  case "$code" in
    200) if has_header "https://www.${DOMAIN}/" 'Strict-Transport-Security'; then
           ok "  200  https://www.${DOMAIN}/ with Strict-Transport-Security"
         else
           warn "  200  https://www.${DOMAIN}/ but no Strict-Transport-Security (mod_headers missing?)"
         fi ;;
    5??) fail "  ${code}  https://www.${DOMAIN}/"; BROKEN=1 ;;
    3??) fail "  ${code}  https://www.${DOMAIN}/ -> ${loc} (the canonical host must not redirect)"; BROKEN=1 ;;
    *)   warn "  ${code}  https://www.${DOMAIN}/" ;;
  esac
fi

# A redirect loop shows up here: curl gives up after --max-redirs.
fr="$(curl -sS -o /dev/null -L --max-redirs 5 --max-time 15 \
        -w '%{http_code} %{num_redirects} %{url_effective}' "http://${DOMAIN}/features.html" 2>/dev/null)" \
  || fr="000 ${fr:-loop-or-no-response}"
read -r code hops final <<<"$fr"
if [[ "$code" == "200" && ${hops:-9} -le 2 ]]; then
  ok "  200  http://${DOMAIN}/features.html ends at ${final} in ${hops} hop(s)"
elif [[ "$code" =~ ^5 || ${hops:-0} -gt 2 || "$code" == "000" ]]; then
  fail "  ${code}  http://${DOMAIN}/features.html after ${hops} hop(s) (5xx, a loop, or no answer)"
  BROKEN=1
else
  warn "  ${code}  http://${DOMAIN}/features.html after ${hops} hop(s)"
fi

if [[ $BROKEN -ne 0 ]]; then
  rollback
  die "The canonical-host rules failed verification and were rolled back. The pages are published."
fi
ok "Canonical-host rules verified"

# ── Check it actually serves ──────────────────────────────────────────────────
info "Checking the site responds…"
for p in "" features.html pricing.html install.html status.html assets/css/site.css; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
          "${CANON}/${p}" 2>/dev/null)" || code=000
  case "$code" in
    200) ok   "  200  /${p}" ;;
    000) warn "  ---  /${p}  (no response — DNS or TLS not ready yet)" ;;
    *)   warn "  ${code}  /${p}" ;;
  esac
done

echo
ok "Done."
echo "   Site:      ${CANON}/"
echo "   Downloads: https://${DOMAIN}/releases/   (always the apex, never redirected)"
echo
echo "   If TLS is not valid yet, issue it with:"
echo "     /usr/local/cpanel/bin/autossl_check --user=${CP_USER}"
