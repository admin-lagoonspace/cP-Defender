# Sentinel Gate 3.25.2

[3.25.2] - 2026-08-28

### Fixed
- **The real-time monitor daemon never started.** It died on its first line with
  `ValueError: Unrecognised argument(s): force` - `logging.basicConfig(force=)`
  requires Python 3.8, and cPanel's RHEL-family hosts ship 3.6. systemd
  relaunched it in a loop, `systemctl start` returned 0 because the process HAD
  launched, and the dashboard reported "Monitor started" over a daemon that had
  already crashed. The logging setup is 3.6-compatible now.
- **A crash loop was indistinguishable from a running daemon.** `is-active`
  answers "active" while systemd is restarting a process on a loop. Status now
  reads `ActiveState` *and* `SubState`: `running` means up, `auto-restart` means
  it is being resurrected. `start()` waits for the unit to settle and returns
  failure - with the restart count and the daemon's last log lines - instead of
  reporting success over something that is crashing.

### Added
- `scripts/check-python-compat.py`, in preflight: the daemon and cron scripts
  are checked against **Python 3.6**, the oldest version the target servers ship.
  The test suite runs on the development machine's interpreter, which is far
  newer, so it proved nothing about the customer's - which is exactly how a
  3.8-only keyword argument shipped.

  Its own first version used a line-by-line regex and reported "compatible"
  about the very call that was crashing the daemon, because `basicConfig(`
  spanned five lines. It uses the AST now.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
