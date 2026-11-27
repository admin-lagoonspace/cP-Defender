"""Find a bash that can actually run this project's shell scripts.

Not a test (tests/run.php only collects test_*.py); imported by the Python
tests that execute real blocks of the shell scripts.

Why this exists: the tests used `shutil.which('bash')`. From PowerShell or
cmd that resolves to C:\\Windows\\System32\\bash.exe, WSL's launcher, which
with no distro installed prints `execvpe(/bin/bash) failed` and runs nothing.
So test_update_corroboration, test_cdn_manifest_cache,
test_release_mirror_verified and test_update_stale_channel failed every time
preflight was started from PowerShell and passed every time it was started
from Git Bash. That read as a flake that "crashes in 2 of 3 runs" (Shakaal,
2026-11-26/27, and Wasooli on 2026-11-23); it depended only on which shell
launched it.

The WSL stub is skipped, Git for Windows is looked for explicitly, and a
candidate is only returned after it has run a trivial command.
"""
import os
import shutil
import subprocess


def _is_wsl_stub(path):
    if os.name != 'nt':
        return False
    d = os.path.normcase(os.path.dirname(os.path.abspath(path)))
    return d.endswith(os.path.normcase(os.path.join('windows', 'system32'))) \
        or d.endswith(os.path.normcase(os.path.join('windows', 'sysnative'))) \
        or 'windowsapps' in d


def candidates():
    out = []
    w = shutil.which('bash') or shutil.which('bash.exe')
    if w and not _is_wsl_stub(w):
        out.append(w)
    if os.name == 'nt':
        git = shutil.which('git')
        if git:   # ...\Git\cmd\git.exe -> ...\Git\bin\bash.exe
            out.append(os.path.join(os.path.dirname(os.path.dirname(git)), 'bin', 'bash.exe'))
        for root in (os.environ.get('ProgramFiles', r'C:\Program Files'),
                     os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
                     os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs')):
            out.append(os.path.join(root, 'Git', 'bin', 'bash.exe'))
    else:
        out += ['/bin/bash', '/usr/bin/bash']
    seen, uniq = set(), []
    for c in out:
        k = os.path.normcase(c)
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    return uniq


def find_bash():
    """Return (path, None) for a working bash, or (None, reason)."""
    tried = candidates()
    for c in tried:
        if not os.path.isfile(c):
            continue
        try:
            pr = subprocess.run([c, '-c', 'echo ss-ok'], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if pr.returncode == 0 and b'ss-ok' in pr.stdout:
            return c, None
    return None, ("no working bash found (tried: %s). If only WSL's stub is on PATH, "
                  "install Git for Windows or run under Git Bash." % (', '.join(tried) or 'nothing'))
