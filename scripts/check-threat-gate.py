#!/usr/bin/env python3
"""
Every detection must go through the verdict gate.

WHY THIS EXISTS
---------------
"Respect the operator's not-malware verdict" is a rule that has to hold for
EVERY finding, or it holds for none of them: one writer that inserts straight
into `threats` re-creates a row the operator already cleared, and from the
panel that is indistinguishable from the feature being broken.

When the gate was added there were six writers -- five `Database::insert(
'threats', ...)` calls in Scanner.php and one INSERT in the Python daemon.
Nothing stopped a seventh being added next to them.

This is not hypothetical in this codebase:

  - update.sh carried three divergent lists of files to copy. The one nobody
    remembered shipped customers an empty cPanel menu for two releases.
  - updateBulkBar() enabled buttons from a hardcoded list of two ids, so a
    third bulk button was dead the day it shipped.

Both were a rule duplicated across call sites instead of enforced in one.

WHAT IS CHECKED
---------------
A. No raw insert into `threats` in PHP outside ThreatStore::record().
B. The daemon's INSERT INTO threats is preceded by its verdict check, so the
   Python side cannot quietly lose it either.

Exit 0 clean, 1 on findings.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIBS = os.path.join(REPO, "backend")
GATE = os.path.join(REPO, "backend", "lib", "ThreatStore.php")
DAEMON = os.path.join(REPO, "backend", "daemon", "monitor.py")

GREEN = "\033[0;32m"
RED = "\033[0;31m"
NC = "\033[0m"


def read(p):
    with open(p, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def check_php():
    """Raw inserts into `threats` anywhere but the gate itself."""
    out = []
    pat = re.compile(r"""insert\(\s*['"]threats['"]""", re.I)
    for root, _dirs, files in os.walk(LIBS):
        for fn in files:
            if not fn.endswith(".php"):
                continue
            full = os.path.join(root, fn)
            if os.path.abspath(full) == os.path.abspath(GATE):
                continue  # the gate is allowed to do the insert
            body = read(full)
            for m in pat.finditer(body):
                line = body[:m.start()].count("\n") + 1
                rel = os.path.relpath(full, REPO).replace("\\", "/")
                out.append((
                    "%s:%d" % (rel, line),
                    "inserts into `threats` directly instead of calling "
                    "ThreatStore::record(), so a file the operator has marked "
                    "not malware is reported again"))
    return out


def check_daemon():
    """The daemon's insert must still be guarded by its verdict check."""
    out = []
    if not os.path.exists(DAEMON):
        return out
    body = read(DAEMON)

    if "INSERT INTO threats" not in body.upper().replace("\n", " ") \
            and "insert into threats" not in body.lower():
        return out  # no writer, nothing to guard

    # The guard and the insert both live in db_threat(). Pull that function out
    # and require the check inside it -- a check elsewhere in the file would
    # pass a naive substring search while doing nothing.
    m = re.search(r"^def db_threat\(.*?(?=^def |\Z)", body, re.S | re.M)
    if not m:
        out.append(("backend/daemon/monitor.py",
                    "has an INSERT INTO threats but no db_threat() to hold the "
                    "verdict check"))
        return out

    fn = m.group(0)
    if "is_cleared(" not in fn:
        out.append(("backend/daemon/monitor.py:db_threat",
                    "inserts a threat without calling is_cleared() first, so "
                    "the realtime monitor re-reports files the operator has "
                    "already cleared"))
    if "sha256_of(" not in fn:
        out.append(("backend/daemon/monitor.py:db_threat",
                    "does not record a sha256, so there is nothing for a "
                    "not-malware verdict to be keyed on"))
    return out


def main():
    findings = check_php() + check_daemon()

    for where, why in findings:
        print("%s[-]%s %s %s" % (RED, NC, where, why))

    if findings:
        print()
        print("%s[-]%s %d detection writer(s) bypass the verdict gate."
              % (RED, NC, len(findings)))
        print("      Route PHP writers through ThreatStore::record().")
        return 1

    print("%s[+]%s every detection writer goes through the verdict gate"
          % (GREEN, NC))
    return 0


if __name__ == "__main__":
    sys.exit(main())
