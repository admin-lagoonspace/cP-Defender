#!/usr/bin/env python3
"""
Catch the silent-death pattern in shell scripts that use `set -e` + `pipefail`.

THE BUG THIS EXISTS FOR
-----------------------
Under `set -e`, a plain assignment takes the exit status of its command
substitution. Under `pipefail`, a pipeline fails if ANY stage fails. Together:

    VAR="$(curl -fsSL "$URL" 2>/dev/null | tr -d '[:space:]')"

does NOT leave VAR empty when the URL 404s. It terminates the script, and
because stderr went to /dev/null it does so with no message whatsoever.

On 2026-10-20 a production server on v4.4.2 ran update.sh twice. Both times it
printed "Checking releases channel for latest version..." and returned to the
prompt, having changed nothing and said nothing. The cause was one
informational line cross-checking <channel>/latest/VERSION, which 404s on a
channel that serves only dist/. It died on the first channel and never tried
the GitHub mirror that was working perfectly.

Every such assignment in that script was already followed by an `[[ -z ... ]]`
check or a fallback -- the code was written expecting an empty value on
failure. The shell options silently defeated that intent in eleven places.

WHAT IS FLAGGED
---------------
An assignment whose value is a command substitution containing a pipe, in a
file that enables both options, without `|| true` (or `|| :`) inside the
substitution.

Pass a file to check just that file; with no arguments every tracked .sh is
checked.

Exit 0 clean, 1 on findings.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

# NAME="$( ... | ... )"  -- an assignment, a command substitution, a pipe.
ASSIGN = re.compile(r"""^\s*(?:local\s+|declare\s+\S*\s+|export\s+)?
                         ([A-Za-z_][A-Za-z0-9_]*)=
                         "?\$\((.*)\)"?\s*$""", re.X)

# Any `|| fallback` at the end of the substitution is a guard. `|| true` and
# `|| :` are the common ones, but `|| echo unknown` is equally deliberate and
# flagging it would train people to ignore this check.
GUARDED = re.compile(r"\|\|\s*\S")


def enables_both(src):
    """Does this script turn on BOTH set -e and pipefail?"""
    has_e = re.search(r"^\s*set\s+-[a-z]*e[a-z]*\b", src, re.M) is not None
    has_pf = re.search(r"^\s*set\s+-o\s+pipefail|^\s*set\s+-[a-z]*\s+-o\s+pipefail"
                       r"|^\s*set\s+-euo\s+pipefail", src, re.M) is not None
    return has_e and has_pf


def check(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        return [(0, "", "cannot read: %s" % exc)]

    if not enables_both(src):
        return []

    out = []
    for n, line in enumerate(src.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        m = ASSIGN.match(line)
        if not m:
            continue

        name, body = m.group(1), m.group(2)

        # Only a pipeline can be defeated by pipefail. A bare `$(cmd)` that
        # fails is a different conversation -- often the author does want the
        # script to stop -- so this check stays narrowly on the pipe case it
        # can be confident about.
        if "|" not in body:
            continue
        # `||` is not a pipe.
        if re.sub(r"\|\|", "", body).count("|") == 0:
            continue

        if GUARDED.search(line):
            continue

        out.append((n, name, stripped))
    return out


def main(argv):
    # Scripts that run on a customer's server. A silent abort in one of these
    # is a failed update nobody is told about; the same bug in a dev script
    # fails on a maintainer's laptop with someone watching. Only these gate
    # the build.
    SHIPPED = ["install.sh", "uninstall.sh", "update.sh", "upgrade.sh",
               "get.sh", "test.sh"]

    if argv:
        files = [a if os.path.isabs(a) else os.path.join(REPO, a) for a in argv]
        gate = files
    else:
        files = []
        for root, dirs, names in os.walk(REPO):
            dirs[:] = [d for d in dirs
                       if d not in {".git", "node_modules", "php", "python",
                                    "dist", "__pycache__"}]
            for nm in names:
                if nm.endswith(".sh"):
                    files.append(os.path.join(root, nm))
        gate = [os.path.join(REPO, n) for n in SHIPPED]

    gate_set = {os.path.normcase(os.path.abspath(g)) for g in gate}

    total = 0
    advisory = 0
    checked = 0
    for path in sorted(files):
        if not os.path.isfile(path):
            continue
        checked += 1
        hits = check(path)
        if not hits:
            continue
        rel = os.path.relpath(path, REPO).replace("\\", "/")
        shipped = os.path.normcase(os.path.abspath(path)) in gate_set
        for n, name, text in hits:
            if shipped:
                total += 1
            else:
                advisory += 1
            print("%s[%s]%s %s:%d  %s is assigned from a pipeline with no "
                  "`|| true`" % (RED if shipped else YELLOW,
                                 "!" if shipped else "-", NC,
                                 rel, n, name or "?"))
            print("      %s" % text)

    if advisory and not total:
        print()
        print("%s[+]%s no shipped script can silently abort; %d advisory "
              "finding(s) in dev-only scripts (%d checked)"
              % (GREEN, NC, advisory, checked))
        return 0

    if total:
        print()
        print("%s[-]%s %d assignment(s) can kill the script silently under "
              "set -e + pipefail." % (RED, NC, total))
        print("      A failing stage terminates the script instead of leaving the")
        print("      variable empty. Append `|| true` inside the substitution if the")
        print("      caller checks for an empty value, which is almost always the case.")
        return 1

    print("%s[+]%s no pipeline assignment can silently abort a shell script "
          "(%d checked)" % (GREEN, NC, checked))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
