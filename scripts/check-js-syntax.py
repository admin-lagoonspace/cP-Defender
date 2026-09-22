#!/usr/bin/env python3
"""A real balance check for the front-end JavaScript.

There is no Node on the build machine, so for this whole project the only JS
validation was a regex brace-counter that mis-handled template literals and
regex literals -- it reported a different imbalance for correct code and could
not tell a real error from its own confusion. Every front-end change shipped
unparsed.

This is a proper lexer for the parts that matter: it walks the source once,
tracking whether it is inside a line comment, block comment, single- or
double-quoted string, a regex literal, or a template literal (including nested
${ ... } substitutions, which can themselves contain more template literals).
Only brackets in actual code are counted.

It is not a parser and cannot find every error -- an unbalanced bracket is what
it catches, and that is the failure mode a hand-edited template literal actually
produces.

Usage:  python scripts/check-js-syntax.py [file ...]
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A regex literal can only start where a value is expected. After one of these
# tokens a '/' is division, not the start of a pattern.
VALUE_END = set(') ] }'.split()) | {'_ident_', '_num_'}


def check(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    n = len(src)
    i = 0
    line = 1

    stack = []          # (char, line) for ( [ {
    tmpl = []           # depth of ${ } nesting per open template literal
    prev_significant = None

    pairs = {')': '(', ']': '[', '}': '{'}
    errors = []

    while i < n:
        c = src[i]

        if c == '\n':
            line += 1
            i += 1
            continue

        # comments
        if c == '/' and i + 1 < n:
            nxt = src[i + 1]
            if nxt == '/':
                while i < n and src[i] != '\n':
                    i += 1
                continue
            if nxt == '*':
                i += 2
                while i + 1 < n and not (src[i] == '*' and src[i + 1] == '/'):
                    if src[i] == '\n':
                        line += 1
                    i += 1
                i += 2
                continue

            # regex literal, only where a value may begin
            if prev_significant not in VALUE_END:
                j = i + 1
                in_class = False
                closed = False
                while j < n:
                    d = src[j]
                    if d == '\\':
                        j += 2
                        continue
                    if d == '\n':
                        break
                    if d == '[':
                        in_class = True
                    elif d == ']':
                        in_class = False
                    elif d == '/' and not in_class:
                        closed = True
                        break
                    j += 1
                if closed:
                    i = j + 1
                    prev_significant = '_ident_'
                    continue
            # otherwise it is division
            prev_significant = '/'
            i += 1
            continue

        # plain strings
        if c in ('"', "'"):
            quote = c
            i += 1
            while i < n:
                if src[i] == '\\':
                    i += 2
                    continue
                if src[i] == '\n':
                    errors.append('%s:%d unterminated string' % (path, line))
                    break
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            prev_significant = '_ident_'
            continue

        # template literal
        if c == '`':
            tmpl.append(0)
            i += 1
            while i < n and tmpl:
                d = src[i]
                if d == '\\':
                    i += 2
                    continue
                if d == '\n':
                    line += 1
                    i += 1
                    continue
                if d == '$' and i + 1 < n and src[i + 1] == '{':
                    tmpl[-1] += 1
                    i += 2
                    # Inside ${ } normal rules apply again; recurse by scanning
                    # forward with a nested depth counter.
                    depth = 1
                    while i < n and depth:
                        e = src[i]
                        if e == '\n':
                            line += 1
                        elif e == '`':
                            # nested template literal
                            i += 1
                            inner = 1
                            while i < n and inner:
                                f = src[i]
                                if f == '\\':
                                    i += 2
                                    continue
                                if f == '\n':
                                    line += 1
                                elif f == '`':
                                    inner -= 1
                                i += 1
                            continue
                        elif e in ('"', "'"):
                            q = e
                            i += 1
                            while i < n and src[i] != q:
                                if src[i] == '\\':
                                    i += 1
                                i += 1
                        elif e == '{':
                            depth += 1
                        elif e == '}':
                            depth -= 1
                        i += 1
                    tmpl[-1] -= 1
                    continue
                if d == '`':
                    tmpl.pop()
                    i += 1
                    break
                i += 1
            prev_significant = '_ident_'
            continue

        # brackets
        if c in '([{':
            stack.append((c, line))
            prev_significant = c
            i += 1
            continue
        if c in ')]}':
            if not stack:
                errors.append('%s:%d unexpected %s' % (path, line, c))
            else:
                opened, oline = stack.pop()
                if opened != pairs[c]:
                    errors.append('%s:%d %s closes %s opened on line %d'
                                  % (path, line, c, opened, oline))
            prev_significant = c
            i += 1
            continue

        if not c.isspace():
            prev_significant = '_ident_' if (c.isalnum() or c in '_$') else c
        i += 1

    for opened, oline in stack:
        errors.append('%s:%d unclosed %s' % (path, oline, opened))

    return errors


def main():
    targets = sys.argv[1:]
    if not targets:
        d = os.path.join(REPO, 'frontend', 'js')
        targets = [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith('.js')]

    all_errors = []
    for t in targets:
        all_errors.extend(check(t))

    print('Checked %d JavaScript file(s)' % len(targets))
    if all_errors:
        for e in all_errors:
            print('  ' + e.replace(REPO + os.sep, ''))
        print('\n%d problem(s).' % len(all_errors))
        return 1
    print('All brackets balanced.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
