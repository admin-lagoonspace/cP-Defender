#!/usr/bin/env python3
"""publish.sh must accept a git worktree, and still refuse a non-repo.

Reported symptom (2026-11-24, releasing 4.37.10): the release was prepared in a
separate `git worktree` at ../cP-Defender-release, because the main checkout
held three concurrent workstreams and publish.sh's `git add -A -- <dir>` would
have swept them into a customer release. The run died on its fourth line:

    [x] Not a git repo: /c/Users/rohan/OneDrive/code/cP-Defender-release
    EXIT=1

The check was `[[ -d .git ]]`. In a worktree `.git` is a FILE containing
`gitdir: /path/to/repo/.git/worktrees/<name>`, so a directory test fails on a
directory that is a perfectly good checkout. Nothing was built, pushed or
tagged -- the one good thing about failing on line 49.

The replacement cannot simply be "am I inside a repo", because this script
stages and commits: a copy of it dropped into a SUBDIRECTORY of some other
repository would pass that, and then commit that repository. The toplevel git
reports has to be the script's own root.

This runs the real check out of publish.sh against four real repositories built
by `git` in a temp directory -- a normal clone, a worktree of it, a plain
directory, and a subdirectory of a repo -- so it fails if the check is reverted
or loosened.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PUBLISH = os.path.join(REPO, 'scripts', 'publish.sh')

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


def _between(src, first_line, stop_line):
    """Everything from the line starting with `first_line` up to, but not
    including, the line starting with `stop_line`. By marker, not by line
    number, so this follows the check when it moves."""
    lines = src.splitlines()
    try:
        i = next(n for n, l in enumerate(lines) if l.startswith(first_line))
    except StopIteration:
        raise AssertionError('publish.sh no longer contains: ' + first_line)
    try:
        j = next(n for n, l in enumerate(lines[i + 1:], i + 1) if l.startswith(stop_line))
    except StopIteration:
        raise AssertionError('no %r after %r' % (stop_line, first_line))
    return '\n'.join(lines[i:j])


with open(PUBLISH, encoding='utf-8') as fh:
    SRC = fh.read()

CHECK = _between(SRC, 'git rev-parse --is-inside-work-tree', 'TOKEN="${GH_TOKEN')

BASH = shutil.which('bash') or shutil.which('bash.exe')
GIT = shutil.which('git') or shutil.which('git.exe')
if BASH is None or GIT is None:
    print('SKIP bash and git are both required to build the fixtures')
    sys.exit(0)

HARNESS = '''
set -euo pipefail
die() { echo "DIE $*"; exit 1; }
REPO_ROOT="$(cd "$SG_ROOT_UNDER_TEST" && pwd)"
cd "$REPO_ROOT"
''' + CHECK + '''
echo "RESULT accepted=1"
'''


def run_check(where):
    d = tempfile.mkdtemp(prefix='sg-wt-h-')
    path = os.path.join(d, 'harness.sh')
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(HARNESS)
    e = dict(os.environ)
    e['SG_ROOT_UNDER_TEST'] = where.replace(chr(92), '/')
    r = subprocess.run([BASH, path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True, env=e, cwd=where)
    accepted = 'RESULT accepted=1' in r.stdout
    return accepted, r


def git(args, cwd):
    return subprocess.run([GIT] + args, cwd=cwd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, universal_newlines=True)


# ── Build the fixtures with real git ────────────────────────────────────────
base = tempfile.mkdtemp(prefix='sg-worktree-')
main = os.path.join(base, 'main')
os.makedirs(main)
git(['init', '-q'], main)
git(['config', 'user.email', 't@example.invalid'], main)
git(['config', 'user.name', 'test'], main)
with open(os.path.join(main, 'VERSION'), 'w') as fh:
    fh.write('1.0.0\n')
git(['add', 'VERSION'], main)
git(['commit', '-q', '-m', 'seed'], main)

wt = os.path.join(base, 'release-worktree')
r = git(['worktree', 'add', '-q', wt, 'HEAD'], main)
have_worktree = os.path.exists(wt)

plain = os.path.join(base, 'not-a-repo')
os.makedirs(plain)

subdir = os.path.join(main, 'scripts-copy')
os.makedirs(subdir)


# ── 1. A worktree is a repo ─────────────────────────────────────────────────
if not have_worktree:
    print('SKIP this git cannot create a worktree: ' + r.stdout.strip())
else:
    dotgit = os.path.join(wt, '.git')
    ok(os.path.isfile(dotgit) and not os.path.isdir(dotgit),
       "THE PREMISE: a worktree's .git is a FILE, not a directory, so the "
       "`[[ -d .git ]]` this replaced could never have accepted one")
    accepted, res = run_check(wt)
    eq(True, accepted,
       'A WORKTREE IS ACCEPTED: this is what refused the 4.37.10 release, on '
       'the fourth line of the script, having built nothing. A worktree is '
       'how a release gets cut while the main checkout holds unrelated work '
       'that `git add -A -- <dir>` would otherwise sweep into it')
    eq(0, res.returncode, 'and the check exits 0')


# ── 2. A normal checkout still works ────────────────────────────────────────
accepted, res = run_check(main)
eq(True, accepted,
   'A NORMAL CHECKOUT IS STILL ACCEPTED: the fix must not trade one shape '
   'of repo for the other')


# ── 3. A directory that is not a repo at all is still refused ───────────────
accepted, res = run_check(plain)
eq(False, accepted,
   'A NON-REPO IS STILL REFUSED. The looser check `[[ -e .git ]]` would pass '
   'here the moment anything named .git existed, and this script commits and '
   'pushes -- it has no business running outside a repository')
eq(1, res.returncode, 'with a non-zero status')
ok('Not a git repo' in res.stdout, 'saying so')


# ── 4. A SUBDIRECTORY of a repo is refused ──────────────────────────────────
#
# This is why `--is-inside-work-tree` alone is not enough: it is true here,
# and the staging step would then commit the enclosing repository.
accepted, res = run_check(subdir)
eq(False, accepted,
   'A SUBDIRECTORY OF ANOTHER REPO IS REFUSED: --is-inside-work-tree is TRUE '
   'there, so without the toplevel comparison a copy of this script in some '
   "other project's subdirectory would stage and commit that project")
eq(1, res.returncode, 'with a non-zero status')
ok('not the root of one' in res.stdout,
   'and the message says which repo it found and that it is not its root, '
   'rather than claiming there is no repo')


# ── 5. No other .git-is-a-directory assumption on the release path ──────────
#
# publish.sh had never been run from a worktree, so line 49 was not
# necessarily the only place that would break. These are the scripts a release
# actually executes.
def code_only(path):
    """The script with whole-line comments dropped. Without this the scan
    below matches the comment that explains the fix, which is how a structural
    assertion comes to assert the opposite of what it means."""
    out = []
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            if line.lstrip().startswith('#'):
                continue
            out.append(line)
    return ''.join(out)


BAD = ('-d .git', '-d "$REPO_ROOT/.git"', '-d "${REPO_ROOT}/.git"',
       '-d "$REPO_DIR/.git"', "-d '.git'")
for name in ('publish.sh', 'make-release.sh', 'check-version-bump.sh',
             'extract-notes.sh', 'cdn-sync.sh'):
    f = os.path.join(REPO, 'scripts', name)
    if not os.path.exists(f):
        continue
    body = code_only(f)
    hits = [bad for bad in BAD if bad in body]
    eq([], hits,
       'NO DIRECTORY TEST ON .git in %s: in a worktree .git is a file, and a '
       'release — cut from a worktree precisely so unrelated work cannot '
       'reach a customer — is exactly when that matters' % name)

print('')
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
