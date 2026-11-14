#!/usr/bin/env python3
"""A channel that answers with a STALE manifest must not decide the version.

Reported symptom (2026-11-13, during the v4.36.0 release): the release was
published, cdn-sync.sh ran successfully, and every installed copy still
believed 4.35.1 was current.

    GET https://serverscrub.com/releases/latest.json          -> 4.35.1
      Server: nginx
      Last-Modified: Sat, 07 Nov 2026 02:40:12 GMT  (the 4.35.1 publish)
    GET .../latest.json -H 'Cache-Control: no-cache'
                        -H 'Pragma: no-cache'                 -> 4.35.1
    GET .../latest.json?cb=<timestamp>                        -> 4.36.0

The origin files were correct: v4.36.0/latest.json and latest/VERSION both
read 4.36.0. cPanel's nginx reverse-proxy cache was holding the old object and
ignoring client revalidation, so ONLY a url it had never seen missed it.

Two consequences, both tested here:

  1. `update.sh --yes` compared the cached 4.35.1 against the installed
     4.35.1 and reported "Already up to date". The cross-check of
     latest/VERSION read 4.36.0 at the time and threw it away as
     informational.
  2. Nothing in the updater's fetches could miss that cache, because polite
     revalidation headers are what it sent.

These tests run the REAL blocks out of update.sh -- the version comparison,
the channel loop and the latest/VERSION override -- in bash, against a stubbed
curl serving fixtures. They are not text assertions about the script; they
execute it, so a revert fails them.

Run by tests/run.php alongside the PHP suite.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
UPDATE_SH = os.path.join(REPO, 'update.sh')

_passed = 0
_failed = 0


def ok(cond, what):
    global _passed, _failed
    if cond:
        _passed += 1
        print('PASS ' + what)
    else:
        _failed += 1
        print('FAIL ' + what)


def eq(expected, actual, what):
    ok(expected == actual, what + ('' if expected == actual
                                   else '  (expected %r, got %r)' % (expected, actual)))


# ── Pull the real code out of update.sh ──────────────────────────────────────
#
# By marker rather than by line number, so the test follows the script when it
# moves rather than quietly testing the wrong lines.

def _block(src, first_line, last_line):
    lines = src.splitlines()
    try:
        i = next(n for n, l in enumerate(lines) if l.startswith(first_line))
    except StopIteration:
        raise AssertionError('update.sh no longer contains: ' + first_line)
    try:
        j = next(n for n, l in enumerate(lines[i + 1:], i + 1) if l == last_line)
    except StopIteration:
        raise AssertionError('no closing %r after %r' % (last_line, first_line))
    return '\n'.join(lines[i:j + 1])


with open(UPDATE_SH, encoding='utf-8') as fh:
    SRC = fh.read()

VER_GT   = _block(SRC, '    _ver_gt() {', '    }')
LOOP     = _block(SRC, '    for BASE in "${CHANNELS[@]}"; do', '    done')
OVERRIDE = _block(SRC, '    if [[ -n "$BEST_LIVE" ]] && _ver_gt "$BEST_LIVE" "$LATEST_VERSION"; then',
                  '    fi')

BASH = shutil.which('bash') or shutil.which('bash.exe')
if BASH is None:
    print('SKIP bash not available; cannot execute the updater blocks')
    sys.exit(0)


def run_bash(script, env=None):
    d = tempfile.mkdtemp(prefix='sg-upd-')
    path = os.path.join(d, 'harness.sh')
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(script)
    e = dict(os.environ)
    e['SG_FIXDIR'] = d.replace('\\', '/')
    if env:
        e.update(env)
    r = subprocess.run([BASH, path], capture_output=True, text=True, env=e, cwd=d)
    return r, d


# ── 1. The version comparison itself ─────────────────────────────────────────
#
# A string compare puts 4.35.1 above 4.36.0 and 4.28.9 above 4.28.10 -- the
# exact pairs these two incidents turned on. Nothing here may be a string
# compare.
CASES = [
    ('4.36.0',  '4.35.1',  True,  'a new minor beats the previous patch'),
    ('4.35.1',  '4.36.0',  False, 'and not the other way round'),
    ('4.28.10', '4.28.9',  True,  'double-digit patch beats single-digit'),
    ('4.28.9',  '4.28.10', False, 'and not the other way round'),
    ('4.36.0',  '4.36.0',  False, 'equal is not newer'),
    ('5.0.0',   '4.99.99', True,  'a major bump wins'),
    ('4.36.1',  '4.36.0',  True,  'a patch bump wins'),
    ('4.36.0',  '4.36.0-rc1', False, 'a suffix does not make it newer'),
    ('4.37.0-rc1', '4.36.0', True, 'a prerelease of a newer version is newer'),
    ('4.9.0',   '4.10.0',  False, '4.9.0 is OLDER than 4.10.0'),
    ('4.10.0',  '4.9.0',   True,  '4.10.0 is newer than 4.9.0'),
]

script = VER_GT + '\n' + 'rc=0\n'
for a, b, want, _ in CASES:
    script += 'if _ver_gt "%s" "%s"; then echo "%s %s YES"; else echo "%s %s NO"; fi\n' % (a, b, a, b, a, b)
r, _ = run_bash("set -uo pipefail\n" + script)
got = dict()
for line in r.stdout.splitlines():
    parts = line.split()
    if len(parts) == 3:
        got[(parts[0], parts[1])] = (parts[2] == 'YES')
for a, b, want, what in CASES:
    eq(want, got.get((a, b)), 'version compare: %s > %s - %s' % (a, b, what))


# ── 2. Channel selection: a stale answer does not win ────────────────────────
#
# The harness runs the script's own loop with curl replaced by a function that
# serves fixture files and logs every url it was asked for.

HARNESS_HEAD = r'''
set -uo pipefail
info() { echo "INFO $*" >&2; }
warn() { echo "WARN $*" >&2; }
ok()   { echo "OK   $*" >&2; }
err()  { echo "ERR  $*" >&2; }
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
CACHE_BUST="TESTBUST"
NOCACHE_HDRS=(-H 'Cache-Control: no-cache, no-store, max-age=0' -H 'Pragma: no-cache')
_nocache() {
    local u="$1" sep='?'
    case "$u" in *\?*) sep='&' ;; esac
    printf '%s%scb=%s' "$u" "$sep" "$CACHE_BUST"
}
URLLOG="${SG_FIXDIR}/urls.log"
: > "$URLLOG"
# Stub curl. Fixtures live in $SG_FIXDIR under a sanitised copy of the url
# with the query string stripped; a missing fixture is a 404 (exit 22), which
# is what a channel serving only dist/ does.
curl() {
    local url=""
    for a in "$@"; do case "$a" in http*) url="$a" ;; esac; done
    printf '%s\n' "$url" >> "$URLLOG"
    local bare="${url%%\?*}"
    local key
    key="$(printf '%s' "$bare" | sed -e 's#^https\?://##' -e 's#[^A-Za-z0-9]#_#g')"
    if [ -f "${SG_FIXDIR}/fix_${key}" ]; then
        cat "${SG_FIXDIR}/fix_${key}"
        return 0
    fi
    return 22
}
sleep() { :; }
API_RETRIES=2
API_WAIT=0
MANIFEST_JSON=""
ACTIVE_BASE=""
BEST_VER=""
BEST_LIVE=""
BEST_LIVE_BASE=""
LIVE_VER=""
DIST_BASE=""
CHANNEL_REPORT=()
'''

HARNESS_TAIL = r'''
echo "RESULT best_ver=${BEST_VER}"
echo "RESULT best_live=${BEST_LIVE}"
echo "RESULT best_live_base=${BEST_LIVE_BASE}"
echo "RESULT active_base=${ACTIVE_BASE}"
echo "RESULT live_ver=${LIVE_VER}"
echo "RESULT dist_base=${DIST_BASE}"
echo "RESULT latest_version=${LATEST_VERSION:-}"
echo "RESULT download_url=${DOWNLOAD_URL:-}"
echo "RESULT sha=${EXPECTED_SHA256:-}"
echo "RESULT manifest=${MANIFEST_JSON}"
'''

CDN = 'https://cdn.example/releases'
LEGACY = 'https://legacy.example/releases'
GH = 'https://raw.example/repo/main'


def fixkey(url):
    bare = url.split('?')[0]
    bare = re.sub(r'^https?://', '', bare)
    return 'fix_' + re.sub(r'[^A-Za-z0-9]', '_', bare)


def manifest(ver, sha='a' * 64, base=CDN):
    return ('{"version":"%s","url":"%s/dist/serverscrub-%s.zip",'
            '"sha256":"%s","notes":"https://notes/%s"}' % (ver, base, ver, sha, ver))


def scenario(fixtures, channels, extra='', body=LOOP):
    """Run `body` with these url->content fixtures and this channel list."""
    script = (HARNESS_HEAD
              + 'CHANNELS=(' + ' '.join('"%s"' % c for c in channels) + ')\n'
              + VER_GT + '\n'
              + extra
              + body + '\n'
              + HARNESS_TAIL)
    d = tempfile.mkdtemp(prefix='sg-upd-')
    for url, content in fixtures.items():
        with open(os.path.join(d, fixkey(url)), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(content)
    path = os.path.join(d, 'harness.sh')
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(script)
    e = dict(os.environ)
    e['SG_FIXDIR'] = d.replace('\\', '/')
    r = subprocess.run([BASH, path], capture_output=True, text=True, env=e, cwd=d)
    out = {}
    for line in r.stdout.splitlines():
        if line.startswith('RESULT '):
            k, _, v = line[7:].partition('=')
            out[k] = v
    urls = []
    log = os.path.join(d, 'urls.log')
    if os.path.exists(log):
        with open(log, encoding='utf-8') as fh:
            urls = [l.strip() for l in fh if l.strip()]
    return out, urls, r


# THE 4.36.0 FAILURE, exactly as it was on the wire: the CDN's cached manifest
# says 4.35.1, its own extracted tree says 4.36.0, and GitHub raw is also
# behind a cache serving 4.35.1 (raw.githubusercontent.com has its own).
res, urls, r = scenario({
    CDN + '/latest.json':      manifest('4.35.1'),
    CDN + '/latest/VERSION':   '4.36.0\n',
    CDN + '/v4.36.0/latest.json': manifest('4.36.0', sha='b' * 64),
    GH + '/latest.json':       manifest('4.35.1', base=GH),
}, [CDN, LEGACY, GH], extra='LATEST_VERSION=""\nDOWNLOAD_URL=""\nEXPECTED_SHA256=""\n',
   body=LOOP + '\nLATEST_VERSION="$BEST_VER"\n' + OVERRIDE)

eq('4.36.0', res.get('latest_version'),
   'THE 4.36.0 FAILURE: a cached 4.35.1 manifest beside a 4.36.0 tree '
   'resolves to 4.36.0, not to "already up to date"')
eq('4.36.0', res.get('best_live'),
   'latest/VERSION is kept from the channel that reported it')
eq(CDN + '/dist/serverscrub-4.36.0.zip', res.get('download_url'),
   'and the download url comes from the per-version manifest, so it points '
   'at the build that actually exists')
eq('b' * 64, res.get('sha'),
   'with the checksum for THAT build - the stale manifest carried the 4.35.1 '
   'checksum, which would have failed verification')
ok(any('/v4.36.0/latest.json' in u for u in urls),
   'the per-version manifest is fetched: that url is requested about once '
   'ever, so no proxy cache holds it')


# Every version-bearing fetch must be cache-busted. Revalidation headers were
# measured NOT to miss cPanel's nginx cache; a unique query string was the
# only thing that did.
version_urls = [u for u in urls if '/latest.json' in u or '/latest/VERSION' in u]
ok(len(version_urls) > 0, 'the loop fetches version-bearing urls at all')
ok(all('cb=' in u for u in version_urls),
   'CACHE KEY: every manifest and VERSION fetch carries a cache-buster '
   '(%d urls checked)' % len(version_urls))
ok(not any('cb=' in u for u in urls if u.endswith('.zip')),
   'but the zips are not cache-busted - their names already contain the '
   'version, so a cached copy is the right bytes')


# A tree BEHIND the manifest is a sync still extracting. Nothing to take there.
res, _, _ = scenario({
    CDN + '/latest.json':    manifest('4.36.0'),
    CDN + '/latest/VERSION': '4.35.1\n',
}, [CDN], extra='LATEST_VERSION=""\nDOWNLOAD_URL=""\nEXPECTED_SHA256=""\n',
   body=LOOP + '\nLATEST_VERSION="$BEST_VER"\n' + OVERRIDE)
eq('4.36.0', res.get('latest_version'),
   'MID-SYNC: a manifest AHEAD of latest/ is left alone - the override is '
   'one-directional, and there is no 4.35.1 to go back to')


# The original first-answer bug, in its own right: the first channel answers
# with a valid older manifest and a later one has the newer release.
res, _, _ = scenario({
    CDN + '/latest.json': manifest('4.28.9'),
    GH + '/latest.json':  manifest('4.28.10', base=GH),
}, [CDN, LEGACY, GH])
eq('4.28.10', res.get('best_ver'),
   'FIRST-ANSWER RULE: the newest manifest across channels wins, not the '
   'first channel that replied')
eq(GH, res.get('active_base'),
   'and the winning channel becomes the active one')
eq(GH + '/dist', res.get('dist_base'),
   'so the download base follows it - fetching 4.28.10 from a mirror still '
   'serving 4.28.9 would 404')


# A dead first channel still falls through, which is the behaviour the
# first-answer rule got right and must not be lost.
res, _, _ = scenario({
    GH + '/latest.json': manifest('4.36.0', base=GH),
}, [CDN, LEGACY, GH])
eq('4.36.0', res.get('best_ver'),
   'an unreachable channel is skipped and a later one still answers')
eq(GH, res.get('active_base'), 'and that later channel is used')


# latest/VERSION is tracked across ALL channels, not only the winning one.
# This is the half of the fix that is easy to miss: if the CDN's manifest loses
# the comparison, its tree reading must not be discarded with it.
res, _, _ = scenario({
    CDN + '/latest.json':    manifest('4.30.0'),
    CDN + '/latest/VERSION': '4.36.0\n',
    GH + '/latest.json':     manifest('4.35.1', base=GH),
}, [CDN, LEGACY, GH], extra='LATEST_VERSION=""\nDOWNLOAD_URL=""\nEXPECTED_SHA256=""\n',
   body=LOOP + '\nLATEST_VERSION="$BEST_VER"\n' + OVERRIDE)
eq('4.36.0', res.get('latest_version'),
   'A LOSING CHANNEL STILL REPORTS ITS TREE: the CDN manifest (4.30.0) lost '
   'to GitHub (4.35.1), and the CDN tree (4.36.0) still decided the answer')
eq(CDN, res.get('best_live_base'),
   'and the override goes back to the channel that holds that tree')


# No per-version manifest: take the version anyway, but carry no checksum
# rather than pretending the stale one verifies this build.
res, _, _ = scenario({
    CDN + '/latest.json':    manifest('4.35.1'),
    CDN + '/latest/VERSION': '4.36.0\n',
}, [CDN], extra='LATEST_VERSION=""\nDOWNLOAD_URL=""\nEXPECTED_SHA256=""\n',
   body=LOOP + '\nLATEST_VERSION="$BEST_VER"\n' + OVERRIDE)
eq('4.36.0', res.get('latest_version'),
   'NO PINNED MANIFEST: the version from the tree is still taken - telling '
   'an operator they are up to date when they are not is the worse failure')
eq(CDN + '/dist/serverscrub-4.36.0.zip', res.get('download_url'),
   'with the conventional dist path')
eq('', res.get('sha'),
   'and NO checksum, so the stale manifest\'s 4.35.1 hash cannot be '
   'presented as verification of a 4.36.0 zip')


# A channel with no latest/ tree at all (dist/ only) must be unaffected.
res, _, _ = scenario({
    CDN + '/latest.json': manifest('4.36.0'),
}, [CDN], extra='LATEST_VERSION=""\nDOWNLOAD_URL=""\nEXPECTED_SHA256=""\n',
   body=LOOP + '\nLATEST_VERSION="$BEST_VER"\n' + OVERRIDE)
eq('4.36.0', res.get('latest_version'),
   'NO latest/ TREE: a channel serving only dist/ is normal and the '
   'manifest stands')


print('')
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
