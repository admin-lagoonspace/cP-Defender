# Sentinel Gate 3.27.4

[3.27.4] - 2026-09-23

### Fixed
- **The release package carried build leftovers.** v3.27.3 shipped
  `backend/daemon/__pycache__/monitor.cpython-310.pyc` and `-312.pyc` --
  bytecode compiled on the maintainer's machine for interpreters no target
  server runs, since cPanel hosts are on Python 3.6. Nothing broke, because
  Python only loads a `.pyc` matching its own version, but the staging step
  should copy the source tree rather than whatever happens to be sitting in it.
  `__pycache__`, `*.pyc`, `*.pyo` and `.DS_Store` are now pruned, and
  `tests/test_packaging.php` fails the build if any reappear.
- **The release could not be built on the maintainer's machine at all.**
  `make-release.sh` called `zip`, which Git Bash on Windows does not ship, so
  publishing stopped at `zip: command not found`. It now falls back to Python's
  `zipfile`, setting the mode bits explicitly so the packaged shell scripts stay
  executable (zipfile would otherwise write them 0600).

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
