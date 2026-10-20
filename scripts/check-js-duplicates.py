#!/usr/bin/env python3
"""
Catch two top-level JavaScript functions with the same name in one file.

WHY THIS EXISTS
---------------
JavaScript allows it. The later declaration silently replaces the earlier one
for EVERY caller in the file, including callers written months before and
tested against the original behaviour. Nothing warns.

While adding the outbound-mail page, a helper called fmtNum() was written
without noticing that app.js already had one 4,600 lines earlier. The two were
not identical -- the new one returned an em dash for a non-finite value where
the original returned "NaN" -- so every number on every other page in the
product would have quietly changed behaviour. Not a crash, not a visible error:
just different output in places nobody was looking.

The fix in that case was to delete the new one and use the original, because a
shared helper's behaviour is not a thing one page gets to redefine.

Pass files to check, or run with no arguments to check frontend/js/*.js.
Exit 0 clean, 1 on findings.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GREEN = "\033[0;32m"
RED = "\033[0;31m"
NC = "\033[0m"

# Top level only: no leading whitespace. A nested function of the same name is
# a different scope and legitimate.
DECL = re.compile(r"^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", re.M)

# `const x = ...` / `let x = ...` at top level would be a SyntaxError on
# redeclaration, so the engine already catches those. Only `function` and `var`
# are silent.
VAR_FN = re.compile(r"^var\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b", re.M)


def strip_noise(src):
    """Blank out comments and strings, preserving newlines so lines still map.

    Line-destroying substitutions would report the wrong line number, which on
    a 5,000-line file makes the finding useless.
    """
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif c in "\"'`":
            quote = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == quote:
                    j += 1
                    break
                j += 1
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        return [("", 0, 0, "cannot read: %s" % exc)]

    clean = strip_noise(src)
    seen = {}
    dupes = []

    for rx in (DECL, VAR_FN):
        for m in rx.finditer(clean):
            name = m.group(1)
            line = clean.count("\n", 0, m.start()) + 1
            if name in seen:
                dupes.append((name, seen[name], line, ""))
            else:
                seen[name] = line
    return dupes


def main(argv):
    if argv:
        files = [a if os.path.isabs(a) else os.path.join(REPO, a) for a in argv]
    else:
        d = os.path.join(REPO, "frontend", "js")
        files = [os.path.join(d, f) for f in sorted(os.listdir(d))
                 if f.endswith(".js")] if os.path.isdir(d) else []

    total = 0
    checked = 0
    for path in files:
        if not os.path.isfile(path):
            continue
        checked += 1
        rel = os.path.relpath(path, REPO).replace("\\", "/")
        for name, first, second, err in check(path):
            if err:
                print("%s[-]%s %s: %s" % (RED, NC, rel, err))
                total += 1
                continue
            total += 1
            print("%s[-]%s %s: %s() is declared twice, at line %d and line %d"
                  % (RED, NC, rel, name, first, second))
            print("      The second silently replaces the first for every caller")
            print("      in the file. Rename it, or use the existing one.")

    if total:
        print()
        print("%s[-]%s %d duplicate top-level function(s)." % (RED, NC, total))
        return 1

    print("%s[+]%s no JS function is declared twice at top level (%d file(s))"
          % (GREEN, NC, checked))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
