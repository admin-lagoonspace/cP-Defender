#!/usr/bin/env python3
"""A release is not published until the mirror has been observed serving it.

The standing rule is that a release is done when the build is in git AND in a
v<version>/ folder on the CDN. On 2026-11-23 nine releases (4.37.1 ... 4.37.9)
were in git and NONE were on the CDN, which had been frozen at 4.37.0 since
September. Measured that day:

    https://serverscrub.com/releases/latest.json          -> 4.37.0
    https://serverscrub.com/releases/latest/VERSION       -> 4.37.0  (HTTP 200)
    https://serverscrub.com/releases/v4.37.8/latest.json  -> HTTP 404

Nobody found out for a month, because both halves of the release process
reported success:

  * publish.sh asked the CDN exactly once, immediately after the push -- the
    one moment it is guaranteed to still be serving the PREVIOUS version --
    and treated the answer as information:

        info "CDN is live, serving 4.37.0 - it pulls 4.37.9 within ~10 min"
        ok   "Published v4.37.9. CDN will pick it up within ~10 min."

    then exited 0. Nothing ever looked again. Its git-side check, by contrast,
    is strict and fails the release; that asymmetry was the whole defect.

  * cdn-sync.sh already read the public url back, already reached the right
    diagnosis and already logged WARNING -- and then logged
    "published v${NEW_VER}" anyway and exited 0.

These tests execute the real blocks out of both scripts against a stubbed CDN,
so they fail on a revert rather than on a reworded comment.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

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


def _block(src, first_line, last_line):
    lines = src.splitlines()
    try:
        i = next(n for n, l in enumerate(lines) if l.startswith(first_line))
    except StopIteration:
        raise AssertionError('no longer contains: ' + first_line)
    try:
        j = next(n for n, l in enumerate(lines[i + 1:], i + 1) if l == last_line)
    except StopIteration:
        raise AssertionError('no closing %r after %r' % (last_line, first_line))
    return '\n'.join(lines[i:j + 1])


def _between(src, first_line, stop_line):
    lines = src.splitlines()
    try:
        i = next(n for n, l in enumerate(lines) if l.startswith(first_line))
    except StopIteration:
        raise AssertionError('no longer contains: ' + first_line)
    try:
        j = next(n for n, l in enumerate(lines[i + 1:], i + 1) if l.startswith(stop_line))
    except StopIteration:
        raise AssertionError('no %r after %r' % (stop_line, first_line))
    return '\n'.join(lines[i:j])


with open(os.path.join(REPO, 'scripts', 'publish.sh'), encoding='utf-8') as fh:
    PUB = fh.read()
with open(os.path.join(REPO, 'scripts', 'cdn-sync.sh'), encoding='utf-8') as fh:
    SYNC = fh.read()

GH_VERIFY = _between(PUB, 'info "Verifying the GitHub channel through the tag',
                     '# ── 7b.')
CDN_WAIT  = _between(PUB, 'CDN_BASE="${SG_CDN_BASE:-', '# UPGRADE FIRST, install second.')

JSON_GET  = _block(SYNC, 'json_get() {', '}')
VERIFY_FN = _block(SYNC, '_verify_public_manifest() {', '}')
SYNC_PUB  = _between(SYNC, '# A FAILED READ-BACK IS A FAILED PUBLISH.',
                     '# ── Optional retention')

BASH = shutil.which('bash') or shutil.which('bash.exe')
if BASH is None:
    print('SKIP bash not available; cannot execute the release blocks')
    sys.exit(0)

CDN = 'https://cdn.example/releases'
VER = '4.37.9'
SLUG = 'example/repo'

# The stub curl answers from fixtures and, when asked for a status code the way
# the real script asks (-o /dev/null -w '%{http_code}'), prints a code and
# nothing else. SG_SWITCH rounds of polling are answered with the OLD state, so
# a test can make the mirror appear on the Nth poll.
HARNESS = r'''
set -euo pipefail
BOLD=''; NC=''
info() { echo "INFO $*"; }
ok()   { echo "OK   $*"; }
warn() { echo "WARN $*"; }
err()  { echo "ERR  $*"; }
die()  { echo "DIE  $*"; exit 1; }
log()  { echo "LOG $*"; }
ROUNDS="${SG_FIXDIR}/rounds"
: > "$ROUNDS"
curl() {
    local url="" code=false
    for a in "$@"; do
        case "$a" in
            http*) url="$a" ;;
            -w)    code=true ;;
        esac
    done
    local bare="${url%%\?*}"
    printf '%s\n' "$bare" >> "${SG_FIXDIR}/urls.log"
    # One "round" of polling is one status probe of the top-level manifest.
    if [ "$bare" = "${SG_POLL_URL:-}" ] && [ "$code" = true ]; then
        printf 'x' >> "$ROUNDS"
    fi
    local n
    n="$(wc -c < "$ROUNDS" | tr -d ' ')"
    local state=new
    [ "$n" -le "${SG_SWITCH:-0}" ] && state=old
    local key
    key="$(printf '%s' "$bare" | sed -e 's#^https\?://##' -e 's#[^A-Za-z0-9]#_#g')"
    local f="${SG_FIXDIR}/${state}_${key}"
    if [ -f "$f" ]; then
        if [ "$code" = true ]; then printf '200'; else cat "$f"; fi
        return 0
    fi
    if [ "$code" = true ]; then printf '404'; return 0; fi
    return 22
}
sleep() { :; }
'''


def manifest(ver):
    return ('{"version":"%s","url":"%s/dist/serverscrub-%s.zip",'
            '"sha256":"%s","notes":"n"}' % (ver, CDN, ver, 'a' * 64))


def fixname(state, url):
    bare = re.sub(r'^https?://', '', url.split('?')[0])
    return state + '_' + re.sub(r'[^A-Za-z0-9]', '_', bare)


def run(script, old_fixtures, new_fixtures, env=None):
    d = tempfile.mkdtemp(prefix='sg-mirror-')
    for state, fx in (('old', old_fixtures), ('new', new_fixtures)):
        for url, content in fx.items():
            with open(os.path.join(d, fixname(state, url)), 'w',
                      encoding='utf-8', newline='\n') as fh:
                fh.write(content)
    path = os.path.join(d, 'harness.sh')
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(script)
    e = dict(os.environ)
    e['SG_FIXDIR'] = d.replace(chr(92), '/')
    e['SG_POLL_URL'] = CDN + '/latest.json'
    if env:
        e.update(env)
    r = subprocess.run([BASH, path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True, env=e, cwd=d)
    return r


# ═════════════════════════════════════════════════════════════════════════════
# 1. publish.sh waits for the mirror, then requires BOTH halves of done
# ═════════════════════════════════════════════════════════════════════════════

def publish_cdn(old, new, switch=0, tries=4):
    script = (HARNESS
              + 'VER="%s"\nTAG="v%s"\nSLUG="%s"\n' % (VER, VER, SLUG)
              + 'SG_CDN_BASE="%s"\n' % CDN
              + 'export SG_CDN_POLL_TRIES=%d\nexport SG_CDN_POLL_SECS=0\n' % tries
              + CDN_WAIT + '\n'
              + 'echo "RESULT reached_end=1"\n')
    return run(script, old, new, env={'SG_SWITCH': str(switch)})


FROZEN = {CDN + '/latest.json': manifest('4.37.0'),
          CDN + '/v4.37.0/latest.json': manifest('4.37.0')}
MIRRORED = {CDN + '/latest.json': manifest(VER),
            CDN + '/v4.37.9/latest.json': manifest(VER)}

# ── The mirror never appears ──────────────────────────────────────────────────
r = publish_cdn(FROZEN, FROZEN, switch=99, tries=3)
eq(1, r.returncode,
   'THE FROZEN MIRROR FAILS THE RELEASE: a CDN that never serves the new '
   'version exits non-zero. Nine releases exited 0 in exactly this state')
ok('RELEASE IS IN GIT BUT NOT MIRRORED' in r.stdout,
   'and says which half happened: the release IS in git, and is NOT mirrored')
ok('/home/serversc/bin/cdn-sync.sh' in r.stdout,
   'printing the force-sync command, which is the one thing that fixes it')
ok('cdn-sync.log' in r.stdout and 'documentroot' in r.stdout,
   'and the read-only diagnosis commands, because a sync that has stopped '
   'needs a cause before a re-run means anything')
ok('will pick it up' not in r.stdout,
   'NO PROMISE: nothing in the run says the CDN will pick it up later. That '
   'sentence was printed for every one of the nine releases that never '
   'reached the mirror')
ok('Published' not in r.stdout,
   'and nothing says Published, because it was not')
ok('4.37.0' in r.stdout and '4.37.9' in r.stdout,
   'the failure names what was served and what was expected')

# ── The mirror appears on the third poll ─────────────────────────────────────
r = publish_cdn(FROZEN, MIRRORED, switch=2, tries=6)
eq(0, r.returncode,
   'IT WAITS: a mirror that appears on the third poll passes - the sync cron '
   'is */10, so the first answer after a push is always the old version')
ok('CDN mirror verified' in r.stdout, 'and reports the mirror as verified')
ok('Published v4.37.9: in git, readable at the tag, and mirrored on the CDN.'
   in r.stdout,
   'the one "Published" sentence left is in the branch where both halves were '
   'observed')

# ── Partial mirror: the manifest moved, the v<version>/ folder did not ───────
r = publish_cdn(FROZEN, {CDN + '/latest.json': manifest(VER)}, switch=0, tries=2)
eq(1, r.returncode,
   'PARTIAL MIRROR FAILS: latest.json serves 4.37.9 but v4.37.9/latest.json '
   '404s. The per-version folder is half the definition of done, and it is '
   'the path that carries this build\'s own checksum')
ok('HTTP 404' in r.stdout, 'and the failure says which path is missing')

# ── A CDN that is not answering at all is a different diagnosis ──────────────
r = publish_cdn({}, {}, switch=99, tries=2)
eq(1, r.returncode, 'A DEAD CDN also fails the release')
ok('CDN IS NOT SERVING ANYTHING' in r.stdout,
   'but it is diagnosed differently: not answering is a vhost or DNS problem, '
   'a wrong version is a stalled sync, and the fix is not the same')
ok('cdn-setup.sh' in r.stdout,
   'so the fix offered is the one-time setup, which reads the docroot out of '
   'cPanel rather than assuming /home/<acct>/public_html')
ok('they fall back to the GitHub mirror' in r.stdout,
   'while still explaining why installs keep working, which is exactly why '
   'this went unnoticed release after release')


# ═════════════════════════════════════════════════════════════════════════════
# 2. publish.sh verifies the GitHub side THROUGH THE TAG
# ═════════════════════════════════════════════════════════════════════════════

GHTAG = 'https://raw.githubusercontent.com/example/repo/v4.37.9'
GHBRANCH = 'https://raw.githubusercontent.com/example/repo/main'


def publish_gh(fixtures, tries=2):
    script = (HARNESS
              + 'VER="%s"\nTAG="v%s"\nSLUG="%s"\n' % (VER, VER, SLUG)
              + 'export SG_GH_POLL_TRIES=%d\nexport SG_GH_POLL_SECS=0\n' % tries
              + GH_VERIFY + '\n'
              + 'echo "RESULT reached_end=1"\n')
    return run(script, fixtures, fixtures)


r = publish_gh({GHTAG + '/latest.json': manifest(VER)})
eq(0, r.returncode, 'THE TAG PATH: a release readable at its tag passes')
ok(GHTAG in r.stdout, 'and the url it checked is named in the output')

# The branch path is served with max-age=300 and ?cb= does not miss Fastly's
# cache (measured 2026-11-23, same ETag, X-Cache: HIT), so a check against it
# can be satisfied by a cached copy of the PREVIOUS release -- it can pass
# without the release having happened.
r = publish_gh({GHBRANCH + '/latest.json': manifest(VER)})
eq(1, r.returncode,
   'AND ONLY THE TAG PATH: a branch path still serving the new version is not '
   'accepted as evidence, because a cached object can satisfy it without the '
   'release having happened at all')
ok('NOT READABLE ON THE GITHUB CHANNEL' in r.stdout, 'and the release fails')
ok('nothing here rolls that back' in r.stdout,
   'saying plainly that the commit and tag are pushed and are not being '
   'rolled back - the git side is correct and must be left alone')


# ═════════════════════════════════════════════════════════════════════════════
# 3. cdn-sync.sh does not log "published" over a failed read-back
# ═════════════════════════════════════════════════════════════════════════════

def sync_publish(served):
    fx = {}
    if served is not None:
        fx[CDN + '/latest.json'] = manifest(served)
    script = (HARNESS
              + 'NEW_VER="%s"\nDOCROOT="/home/serversc/public_html/releases"\n' % VER
              + 'PUBLIC_BASE="%s"\n' % CDN
              + JSON_GET + '\n' + VERIFY_FN + '\n'
              + SYNC_PUB + '\n'
              + '$PUBLISH_OK || exit 1\n'
              + 'echo "RESULT reached_end=1"\n')
    return run(script, fx, fx)


r = sync_publish(VER)
ok('published v4.37.9' in r.stdout,
   'A VERIFIED PUBLISH: unchanged behaviour when the public url serves the '
   'new version')
eq(0, r.returncode, 'and exit 0')

r = sync_publish('4.37.0')
ok('published v4.37.9' not in r.stdout,
   'THE DISHONEST LOG LINE: with a read-back that disagrees, the run does NOT '
   'log "published v4.37.9". It already logged WARNING here and then said '
   'published anyway, nine times')
ok('NOT published' in r.stdout, 'it says it did not publish')
eq(1, r.returncode,
   'and exits non-zero, so a cron log and a caller can tell a published '
   'release from one that only reached the disk')
ok('/home/serversc/public_html/releases' in r.stdout,
   'naming the docroot it wrote to, which is the hard-coded default and the '
   'standing hypothesis for why the mirror froze')

r = sync_publish(None)
ok('published v4.37.9' not in r.stdout,
   'A PUBLIC URL THAT CANNOT BE READ AT ALL is also not a publish')
eq(1, r.returncode, 'and also exits non-zero')


print('')
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
