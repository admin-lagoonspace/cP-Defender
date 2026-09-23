# Sentinel Gate 3.27.3

[3.27.3] - 2026-09-23

### Fixed
- **A routine update aborted and rolled itself back**, printing
  `Unsuccessful stat on filename containing newline at
  /var/cpanel/ea4/ea_php_cli.pm line 87`.

  On cPanel the `php` on PATH is not PHP. It is a Perl wrapper that selects an
  EasyApache interpreter, and when the argument it is given contains a newline
  it tries to stat that argument as a filename and dies -- before any PHP runs
  at all. The scripts passed several multi-line `php -r "..."` payloads, so the
  wrapper exited non-zero, `set -euo pipefail` turned that into an abort, and
  the error trap restored the previous version. A working update was discarded
  over how the script that applied it was formatted.

  All ten payloads across `install.sh`, `update.sh`, `test.sh` and
  `uninstall.sh` are now single-line, which the wrapper accepts. Two `//`
  comments inside one of them became `/* ... */` so they could share a line.
  Nothing else about them changed.
- **Database migrations no longer run from a `-r` payload at all**, and can no
  longer fail the update. They run from a temporary file using a verified CLI
  interpreter, and a failure is now a warning: `Database::get()` applies
  migrations on first use anyway, so throwing away a good code update over a
  hiccup here was the worse outcome.
- **The update printed a wall of 404s before succeeding.** The download chain
  tried `builds/` and `v<version>/` ahead of `dist/`, which is the path that
  actually exists, and asked every channel for all three. It now tries `dist/`
  first and gives up on a host after two failures -- a host that is down does
  not come back for the next URL.

### Added
- `tests/test_shell_php.php`: asserts no shipped script contains a multi-line
  `php -r`, and parses every payload with `php -l` so a collapsed line cannot
  hide a `//` comment that swallows the rest of it. The shell scripts are the
  one part of the product nothing else exercises -- they run as root on the
  customer's server, where a mistake is found by the customer.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
