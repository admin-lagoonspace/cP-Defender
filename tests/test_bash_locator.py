r"""The Python tests that execute shell blocks must find a bash that works.

Reported (Shakaal, 2026-11-26/27; Wasooli, 2026-11-23): four update/CDN
tests "crashed in 2 of 3 preflight runs" and passed alone. They were not
flaky. Each picked `shutil.which('bash')`, which from PowerShell is
C:\Windows\System32\bash.exe -- WSL's launcher, with no distro installed --
so every run launched from PowerShell failed them and every run launched
from Git Bash passed them. tests/_bash.py now owns the choice.
"""
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _bash  # noqa: E402

_p = _f = 0


def ok(cond, what):
    global _p, _f
    if cond:
        _p += 1
        print('PASS ' + what)
    else:
        _f += 1
        print('FAIL ' + what)


if os.name == 'nt':
    stub = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'bash.exe')
    ok(_bash._is_wsl_stub(stub), "WSL's System32 bash.exe is recognised as the stub")
    ok(all(not _bash._is_wsl_stub(c) for c in _bash.candidates()),
       'and is never a candidate, whatever PATH puts first')
    ok(not _bash._is_wsl_stub(r'C:\Program Files\Git\bin\bash.exe'), 'Git Bash is not mistaken for it')

path, why = _bash.find_bash()
ok(path is not None, 'a working bash is found on this machine (%s)' % (path or why))

# Every Python test that runs a shell must take bash from the helper; one
# that goes back to shutil.which reintroduces the shell-dependent failure.
for f in sorted(glob.glob(os.path.join(HERE, 'test_*.py'))):
    src = open(f, encoding='utf-8').read()
    if os.path.basename(f) == 'test_bash_locator.py':
        continue
    if 'BASH' in src:
        ok("shutil.which('bash')" not in src and 'from _bash import find_bash' in src,
           '%s takes bash from tests/_bash.py, not shutil.which' % os.path.basename(f))

print()
print('%d passed, %d failed' % (_p, _f))
sys.exit(1 if _f else 0)
