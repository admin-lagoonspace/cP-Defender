# Sentinel Gate 3.31.0

[3.31.0] - 2026-09-28

### Fixed
- **The monitor could not be turned on at all once a backup had finished.**
  `stop()` gained `systemctl reset-failed` in 3.30.1; `start()` did not. A unit
  sitting in `failed` will not start, and once systemd's start rate limit is
  reached it refuses outright with "start request repeated too quickly" -- so
  pressing Start achieved nothing, however many times it was pressed. Starting
  now clears a failed unit first, and recognises the rate-limit refusal and
  retries after resetting it.

### Added
- **Monitoring comes back on its own once the backups are done.** A `rtguard`
  task runs on every scheduler tick -- cron already fires the scheduler every
  15 minutes -- probes for JetBackup and rsync directly in `/proc`, and starts
  the monitor once they have gone.

  This is a different problem from the pause added in 3.30.0. That one lives
  inside the daemon and suspends its scanning; it works only while the daemon
  is running. A daemon that has been *stopped* can do nothing for itself, so
  something outside it has to notice the backup has ended. Without that, a
  monitor that went down during a backup window stays down until a person
  notices and presses Start.

- **It will not overrule a deliberate decision.** Stopping the monitor while no
  backup is running records that somebody wanted it off, and auto-resume leaves
  it off. Stopping it *during* a backup does not record that: it reads as "off
  for the backup", which is the case this exists to undo. Starting it by hand
  clears the flag either way.

- `rt_autostart_after_backup` (on by default) and a toggle in the Real-Time
  Monitor settings card. Auto-starts are recorded as security events, so the
  monitor coming back is visible rather than silent.

- An `every` schedule cadence, meaning every scheduler tick. Previously a
  schedule string the scheduler did not recognise fell through to "not due",
  which is indistinguishable from being switched off.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
