# Sentinel Gate 3.25.1

[3.25.1] - 2026-08-28

### Fixed
- **"Threat Breakdown - Loading..." never resolved on a clean server.** Every
  chart returned early on empty data, leaving the static placeholder in place.
  So the *good* outcome - a scan finding nothing - rendered as a panel stuck
  loading. Charts now draw an explicit empty state.
- **Monitor start/stop felt laggy and unreliable.** `systemctl` takes seconds and
  the daemon needs longer still to write its PID file, but the button returned
  immediately: a second click could race the first, and the state it flipped to
  was assumed rather than observed.

  It now disables both buttons while working, shows "Startingâ€¦"/"Stoppingâ€¦",
  polls the server until the reported state matches what was asked for, and says
  so plainly when a command was accepted but did not take effect - instead of a
  success toast over a monitor that is not running.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
