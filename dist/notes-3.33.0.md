# Sentinel Gate 3.33.0

[3.33.0] - 2026-10-01

### Fixed
- **The WAF recorded nothing, on every install.** `ingestModSecLog()` existed
  and worked, but its only caller was an API route nothing ever invoked — no
  scheduled run, no call on page load. `waf_events` therefore stayed empty for
  ever, and the WAF page showed no attacks on servers that were certainly
  receiving some. Without events there is nothing to judge a ruleset by, which
  is the point of having them.

  It now runs on every scheduler tick (every 15 minutes).

- **It was also reading the wrong file.** `MODSEC_AUDIT` is
  `/var/log/modsec_audit.log` — the Debian default, and the path our own
  installer writes into its config. cPanel's EasyApache 4 logs to
  `/var/log/apache2/modsec_audit.log`, so on a server using cPanel's own
  ModSecurity there was never a file at our path. The ingester checked
  `file_exists()` and returned 0 silently, which is indistinguishable from a
  quiet server. The path is now resolved against the places ModSecurity is
  actually known to write, remembered once found, and re-resolved if it
  disappears. `waf_audit_log_override` covers anything unusual.

- **Reading is now incremental.** The old version opened the file and read from
  the top on every call. Put on a schedule, that would re-parse the entire
  audit log every 15 minutes — gigabytes of I/O on a busy server — and
  duplicate every entry older than the 60-second dedup window. It now resumes
  from the recorded offset and restarts only when the file shrinks, which means
  rotation.

- **An empty WAF table now explains itself.** "No attacks were blocked" and
  "nothing is reading a log" rendered identically. The page now says which,
  names the paths it looked in, and offers a button to read the log
  immediately.

### Added
- **A blocking busy overlay for actions.** Every request that changes something
  raises it, so the page cannot be clicked into a queue of overlapping work.

  Deliberately not shown for plain reads: the monitor page polls itself every
  15 seconds and an overlay flashing on each poll would be worse than none.
  Showing it is delayed by 180ms so a fast request does not produce a flash
  that reads as a glitch; the count is released in a `finally`, so a thrown
  fetch or an early return cannot strand it and lock the user out of the error
  it is reporting. `API.withBusy()` is available for slow reads.

- `scripts/check-cron-requires.php`, wired into preflight: every class a cron
  script names must be required by it. A scheduled task referencing an unloaded
  class fatals the moment it becomes due, and cron output goes to a log nobody
  reads — so the symptom is a feature that silently never runs. This had
  happened three times: `UserReport`, `RealTimeMonitor` and now `WAF`.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
