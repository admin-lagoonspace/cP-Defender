# ServerScrub 4.31.2

[4.31.2] - 2026-11-05

### Changed

- **Scans no longer stand down for JetBackup or rsync.** The gate was never a
  pause: `waitOutBackup()` sleeps up to `scan_backup_max_wait` (four hours) and
  then gives up, abandoning the rest of the sweep until the next scheduled run
  a day later. On a server whose backup windows overlap the scan window that
  bought whole nights with no malware scan, traded against I/O contention --
  which makes both jobs slower but loses neither. `scan_pause_on_backup` is now
  seeded off, and an existing install is switched off once by migration, since
  `INSERT OR IGNORE` never revisits a row that already exists. The refusal and
  the wait cap are both still in the code: set `scan_pause_on_backup` to `1` to
  put the gate back.

### Fixed

- **`scan_pause_on_backup` did not govern the scheduled sweep.** `startScan()`
  and `waitOutBackup()` both honoured it; the scheduler called
  `Scanner::backupRunning()` directly and deferred whatever the setting said.
  So the setting controlled the two callers that barely matter and not the
  nightly scan, the only one coverage depends on -- turning the gate off left
  the sweep exactly as blocked as before, while reporting a state it did not
  have.
- **The two readers of `scan_pause_on_backup` fell back to `'1'` while the seed
  said `'0'`.** An install missing the row behaved the opposite way to one that
  had it.
- **`scan_paused_for_backup` could be left set.** A scan parked by the old gate
  left the flag at `1`, so the dashboard showed a pause that could no longer
  end. The migration clears it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
