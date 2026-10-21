#!/usr/bin/env python3
"""
Catch values interpolated into HTML event attributes inside template literals.

THE BUG THIS EXISTS FOR
-----------------------
A threat row rendered its "exclude" button like this:

    onclick="excludeThreatPath(${JSON.stringify(t.file_path || '')})"

JSON.stringify emits DOUBLE quotes. Inside a double-quoted HTML attribute the
first one terminates the attribute, so the browser saw

    onclick="excludeThreatPath("

and never bound a handler. The button did nothing at all when clicked.

Nothing caught it. check-ui-handlers.php confirms the function exists, which it
did. check-js-syntax.py balances brackets, which balanced. The test asserted
excludeThreatPath was present in app.js, which it was. Every check passed and
the feature was completely dead.

THE RULE
--------
Inside an on* attribute, only a NUMBER may be interpolated. Not a path, not a
name, not a quoted string -- a file path can contain quotes, spaces,
backslashes and newlines, and there is no escaping that survives both the HTML
attribute parser and the JavaScript string parser reliably. Pass an id and look
the value up.

Exit 0 clean, 1 on findings.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GREEN = "\033[0;32m"
RED = "\033[0;31m"
NC = "\033[0m"

# on<event>="...."  -- the attribute value, non-greedy to the closing quote.
ATTR = re.compile(r'\bon[a-z]+\s*=\s*"([^"]*)"', re.I)

# Expressions safe to interpolate: a number, or something that is obviously
# one. Anything else is a string and must not be inlined.
NUMERIC_OK = re.compile(
    r"""^\s*(?:
          \d+                                   # literal
        | Number\([^)]*\)                       # Number(x)
        | parseInt\([^)]*\)
        | [A-Za-z_$][\w$]*\.(?:id|ID|length|count|index|idx)\b
        | (?:id|tid|rid|jobId|n|i|idx|index|count|num|row)\b
        )
        (?:\s*\|\|\s*\d+)?                 # ... || 0 fallback
        \s*$""",
    re.X,
)


# Names that hold a filesystem path. These are the values that genuinely break
# an attribute, because a path may contain an apostrophe or a backslash.
PATHISH = re.compile(r"(?:file_path|filepath|filePath|path|dir|directory|"
                     r"install_path|script|fullpath)")


def strip_noise(src):
    """Blank comments and plain strings, keeping template literals and newlines."""
    out = []
    i, n = 0, len(src)
    while i < n:
        two = src[i:i + 2]
        c = src[i]
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
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except OSError as exc:
        return [(0, "cannot read: %s" % exc, "")]

    clean = strip_noise(src)
    out = []

    for m in ATTR.finditer(clean):
        value = m.group(1)
        if "${" not in value:
            continue
        line = clean.count("\n", 0, m.start()) + 1

        # Pull each interpolation out, honouring nesting one level deep.
        for em in re.finditer(r"\$\{", value):
            start = em.end()
            depth = 1
            j = start
            while j < len(value) and depth:
                if value[j] == "{":
                    depth += 1
                elif value[j] == "}":
                    depth -= 1
                j += 1
            expr = value[start:j - 1]

            # Is the interpolation wrapped in single quotes inside the
            # attribute? `onclick="f('${ip}')"` is how the rest of this file
            # passes strings, and it is safe for values that cannot contain a
            # quote -- an IP, a country code, a numeric id.
            before = value[em.start() - 1] if em.start() > 0 else ""
            after = value[j] if j < len(value) else ""
            quoted = before == "'" and after == "'"

            if "JSON.stringify" in expr:
                # Unconditionally wrong: it emits DOUBLE quotes, which end the
                # attribute wherever it appears.
                out.append((line, expr.strip()[:70],
                            "JSON.stringify emits double quotes, which end the "
                            "attribute and leave the handler unbound"))
                continue

            if not quoted and not NUMERIC_OK.match(expr):
                out.append((line, expr.strip()[:70],
                            "an unquoted, non-numeric value in an event "
                            "attribute; quote it or pass an id"))
                continue

            # Quoted, but a PATH can contain an apostrophe, a space, a
            # backslash or a newline -- single quotes do not save it. IPs and
            # country codes cannot, which is why those call sites are fine.
            if quoted and PATHISH.search(expr):
                out.append((line, expr.strip()[:70],
                            "a file path must never be inlined into an "
                            "attribute -- it can contain quotes; pass an id "
                            "and look it up"))
    return out


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
        for line, expr, why in check(path):
            total += 1
            print("%s[-]%s %s:%d  %s" % (RED, NC, rel, line, why))
            print("      ${%s}" % expr)

    if total:
        print()
        print("%s[-]%s %d unsafe interpolation(s) in event attributes."
              % (RED, NC, total))
        print("      The attribute breaks and the handler is never bound, so the")
        print("      control silently does nothing. Pass an id instead.")
        return 1

    print("%s[+]%s only numbers are interpolated into event attributes "
          "(%d file(s))" % (GREEN, NC, checked))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
