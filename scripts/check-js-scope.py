#!/usr/bin/env python3
"""
Catch helpers that are called at module scope but only defined inside a
function.

This shipped three times. `g()` -- the element lookup nearly every handler uses
-- was declared as `const g = ...` INSIDE two functions and nowhere else. Any
module-scope code calling it threw ReferenceError the instant it ran, silently,
because the throw happened inside an event handler with nothing watching. Three
features did nothing at all as a result: the custom-scan account picker, the
adoption of an already-running scan, and the brute-force ladder preview. Every
other gate passed: the brackets balanced, the handlers resolved to defined
functions, and the syntax was valid.

The check is deliberately narrow, so it does not become a linter nobody trusts.
It only reports a name that is:

  * called as NAME(...) from a top-level function body,
  * declared somewhere in the file as a const/let INSIDE a function,
  * and NOT declared at module scope, nor locally in the calling function.

That is exactly the shape of the bug and almost nothing else.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DECL_RE = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=')
FUNC_RE = re.compile(r'^(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(', re.M)
# A bare call, not a method call. Without the lookbehind this matches the
# `map` in `rows.map(...)`, and the check drowns in names that never had to
# resolve in this scope -- a gate nobody trusts is a gate nobody keeps.
CALL_RE = re.compile(r'(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(')

# Called like functions but not ours.
IGNORE = {
    'if', 'for', 'while', 'switch', 'catch', 'return', 'typeof', 'function',
    'await', 'new', 'do', 'else', 'try', 'throw', 'case', 'in', 'of',
}


def strip_noise(src: str) -> str:
    """Remove comments and string/template bodies so they cannot create matches."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            while i < n and src[i] != '\n':
                i += 1
        elif c == '/' and i + 1 < n and src[i + 1] == '*':
            i += 2
            while i + 1 < n and not (src[i] == '*' and src[i + 1] == '/'):
                # Same reason as strings: a block comment spans lines, and
                # dropping its newlines pulls later code onto an earlier line,
                # which breaks the column-0 module-scope test.
                if src[i] == chr(10):
                    out.append(chr(10))
                i += 1
            i += 2
        elif c in '"\'`':
            quote = c
            i += 1
            out.append(' ')
            while i < n:
                if src[i] == '\\':
                    i += 2
                    continue
                if src[i] == quote:
                    i += 1
                    break
                # Newlines are kept. Collapsing a multi-line template literal
                # would pull the code after it onto an earlier line, and the
                # module-scope test is "declared at column 0" -- so losing the
                # line structure quietly broke that test.
                if src[i] == chr(10):
                    out.append(chr(10))
                # Keep template-literal interpolations: they hold real calls.
                if quote == '`' and src[i] == '$' and i + 1 < n and src[i + 1] == '{':
                    depth = 1
                    i += 2
                    out.append(' ')
                    while i < n and depth:
                        if src[i] == '{':
                            depth += 1
                        elif src[i] == '}':
                            depth -= 1
                            if not depth:
                                i += 1
                                break
                        out.append(src[i])
                        i += 1
                    continue
                i += 1
            out.append(' ')
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def top_level_functions(src: str):
    """Yield (name, body, params) for each module-scope function declaration."""
    for m in FUNC_RE.finditer(src):
        # Only module scope: the declaration must start at column 0.
        start = src.rfind('\n', 0, m.start()) + 1
        # Column 0 exactly. Testing .strip() instead treats indentation as
        # module scope, which makes every nested declaration look global and
        # silently disables this whole check.
        if src[start:m.start()] != '':
            continue
        brace = src.find('{', m.end())
        if brace < 0:
            continue
        # The parameter list, which is as local as any declaration. Leaving it
        # out reported fallbackCopy(text, done) as calling an undeclared
        # done() -- a false positive, and false positives are how a gate gets
        # switched off.
        params = {
            p.strip().split('=')[0].strip()
            for p in src[m.end():brace].rstrip().rstrip(')').split(',')
            if p.strip() and re.fullmatch(r'[A-Za-z_$][\w$]*\s*(=.*)?', p.strip(), re.S)
        }
        depth, i, n = 0, brace, len(src)
        while i < n:
            if src[i] == '{':
                depth += 1
            elif src[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield m.group(1), src[brace:i], params


def check(path: Path):
    raw = path.read_text(encoding='utf-8', errors='replace')
    src = strip_noise(raw)

    module_names = set(FUNC_RE.findall(src))
    for m in DECL_RE.finditer(src):
        line_start = src.rfind('\n', 0, m.start()) + 1
        if src[line_start:m.start()] == '':        # column 0 == module scope
            module_names.add(m.group(1))

    # Names declared only inside some function.
    nested = {m.group(1) for m in DECL_RE.finditer(src)} - module_names
    if not nested:
        return []

    problems = []
    for fname, body, params in top_level_functions(src):
        local = {m.group(1) for m in DECL_RE.finditer(body)} | params
        for called in {c for c in CALL_RE.findall(body) if c not in IGNORE}:
            if called in nested and called not in local and called not in module_names:
                problems.append((fname, called))
    return problems


def main():
    bad = []
    for f in sorted((ROOT / 'frontend' / 'js').glob('*.js')):
        for fname, called in check(f):
            bad.append(f"{f.name}: {fname}() calls {called}(), which is only "
                       f"declared inside another function")

    if bad:
        print("\033[0;31m[x]\033[0m JavaScript scope problems:")
        for b in sorted(set(bad)):
            print("      " + b)
        print("      A call like this throws ReferenceError at runtime, silently, "
              "inside an event handler.")
        return 1

    print("\033[0;32m[+]\033[0m no helper is called outside the function that declares it")
    return 0


if __name__ == '__main__':
    sys.exit(main())
