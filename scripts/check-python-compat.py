#!/usr/bin/env python3
"""Will the daemon run on the OLDEST Python we support?

The real-time monitor died on every start with

    ValueError: Unrecognised argument(s): force

because logging.basicConfig(force=True) needs Python 3.8 and the server runs
3.6. systemd reported the unit as started -- the process did launch -- so the UI
said "Monitor started" over a daemon that had already crashed, and restarted it
in a loop.

The tests missed it because they run on the DEVELOPMENT machine's Python, which
is far newer than what a RHEL-family server ships. A test that only proves the
code works on the author's interpreter proves very little about the customer's.

Two checks:
  1. Parse with ast feature_version, which rejects syntax newer than the target.
  2. Scan for stdlib APIs and keyword arguments added after the target, which
     parse fine everywhere and fail only at runtime -- the class of bug that
     actually shipped.

Usage:  python scripts/check-python-compat.py [3.6]
"""
import ast
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = tuple(int(x) for x in (sys.argv[1] if len(sys.argv) > 1 else '3.6').split('.'))

# Keyword arguments added after a given version. These parse on every Python
# and fail only at runtime, which is the class of bug that actually shipped.
#
# Matched through the AST, not a regex: the first version of this check used
# `basicConfig\([^)]*force=` scanned line by line, and logging.basicConfig() in
# monitor.py spans five lines -- so the check reported "compatible" about the
# very call that was crashing the daemon on every start. A check that cannot
# catch the bug it was written for is worse than none, because it is believed.
CALL_KWARGS = {
    ('logging.basicConfig', 'force'):        ((3, 8), 'remove force=; clear root handlers manually'),
    ('subprocess.run', 'capture_output'):    ((3, 7), 'use stdout=PIPE, stderr=PIPE'),
    ('subprocess.run', 'text'):              ((3, 7), 'use universal_newlines='),
    ('subprocess.call', 'text'):             ((3, 7), 'use universal_newlines='),
}

# Attributes/functions that simply do not exist before a version.
ATTRS = {
    'removeprefix':      ((3, 9), 'use slicing'),
    'removesuffix':      ((3, 9), 'use slicing'),
    'fromisoformat':     ((3, 7), 'parse with strptime'),
    'perf_counter_ns':   ((3, 7), 'use perf_counter()'),
    'cached_property':   ((3, 8), 'use a plain property'),
    'prod':              ((3, 8), 'use functools.reduce'),
    'shlex_join':        ((3, 8), 'use " ".join(shlex.quote(...))'),
}


def dotted(node):
    """Best-effort dotted name for a call target."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return '.'.join(reversed(parts))


files = []
for sub in ('backend/daemon', 'backend/cron'):
    d = os.path.join(REPO, sub)
    if not os.path.isdir(d):
        continue
    for root, _dirs, names in os.walk(d):
        for n in names:
            if n.endswith('.py'):
                files.append(os.path.join(root, n))
files.sort()

problems = []

for path in files:
    rel = os.path.relpath(path, REPO)
    src = open(path, encoding='utf-8', errors='replace').read()

    # 1. syntax
    try:
        ast.parse(src, filename=path, feature_version=TARGET)
    except SyntaxError as e:
        problems.append('%s:%s  syntax not valid on Python %s: %s'
                        % (rel, e.lineno, '.'.join(map(str, TARGET)), e.msg))
    except TypeError:
        # feature_version unsupported on very old hosts; parse without it.
        try:
            ast.parse(src, filename=path)
        except SyntaxError as e:
            problems.append('%s:%s  syntax error: %s' % (rel, e.lineno, e.msg))

    # 2. runtime APIs, via the AST so multi-line calls are seen whole
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError:
        continue                      # already reported above

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                key = (name, kw.arg)
                # Match on the tail too, so `basicConfig(force=)` is caught
                # whether it was reached as logging.basicConfig or imported.
                for (fname, argname), (since, hint) in CALL_KWARGS.items():
                    if kw.arg != argname:
                        continue
                    if name != fname and not name.endswith('.' + fname.split('.')[-1]) \
                       and name != fname.split('.')[-1]:
                        continue
                    if since <= TARGET:
                        continue
                    problems.append('%s:%d  %s(%s=) needs Python %s (target %s) -- %s'
                                    % (rel, node.lineno, fname, argname,
                                       '.'.join(map(str, since)),
                                       '.'.join(map(str, TARGET)), hint))

        if isinstance(node, ast.Attribute) and node.attr in ATTRS:
            since, hint = ATTRS[node.attr]
            if since > TARGET:
                problems.append('%s:%d  .%s needs Python %s (target %s) -- %s'
                                % (rel, node.lineno, node.attr,
                                   '.'.join(map(str, since)),
                                   '.'.join(map(str, TARGET)), hint))

print('Checked %d file(s) against Python %s' % (len(files), '.'.join(map(str, TARGET))))
if problems:
    print('\n'.join(problems))
    print('\n%d incompatibility/ies.' % len(problems))
    sys.exit(1)
print('All daemon and cron scripts are compatible.')
sys.exit(0)
