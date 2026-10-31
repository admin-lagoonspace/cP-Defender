# ServerScrub 4.25.1

[4.25.1] - 2026-10-31

### Changed

- **A scan a customer asks for no longer waits for JetBackup or rsync.** The
  backup gate was written for the scheduled server-wide sweep, where standing
  down is obviously right: nothing is waiting on it, and walking all of `/home`
  competes with rsync for exactly the same disks. A cPanel customer pressing
  "Scan my account" is the opposite case on both counts — someone is sitting in
  front of the page, and the work is one home directory.

  Two gates had to give way, not one. `Scanner::startScan()` refused outright
  while a backup was running, and the worker called `waitOutBackup()` between
  every batch — so a backup starting *after* the scan began parked it for up to
  four hours (`scan_backup_max_wait`) and then abandoned the rest of it.
  Waiving only the first would have been the worse bug of the two: the scan
  starts, the page says "running", and then it silently stalls.

  The waiver is recorded on the job row (`scan_jobs.ignore_backup`) rather than
  decided by the caller, because the worker is a separate process and by the
  time it re-checks, that row is all it knows about the scan. The lookup sits
  behind the "is a backup even running" test, so an idle server pays nothing
  per batch. The decision is logged — "did this scan run during the backup
  window" is exactly what gets asked after a slow night.

  Unchanged: the scheduled sweep, the operator UI and the CLI all still stand
  down for a backup, and `scan_max_concurrent` still bounds everything, so
  removing this wait did not uncap ClamAV.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
