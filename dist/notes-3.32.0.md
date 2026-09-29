# Sentinel Gate 3.32.0

[3.32.0] - 2026-09-29

### Added
- **Malware scans now stand down during a backup, as the real-time monitor
  already did.**

  Reported with a `top` capture taken during a JetBackup run: the monitor was
  sitting at 1% CPU, correctly suspended, while `clamscan` ran at 58% in
  uninterruptible I/O wait against the same disks rsync was using. The pause
  added in 3.30.0 lives inside the monitor daemon, and a malware scan is a
  separate process that knew nothing about it. The quiet half of the product
  stood down and the loud half did not — and the loud half is the one that
  reads every file on the server.

  A running scan now checks between batches and waits while a backup is in
  progress, rather than abandoning the scan: it resumes and finishes, and a
  sleeping worker costs one idle process. It keeps its lock slot while waiting,
  since a second scan starting because this one is politely asleep would defeat
  the purpose. A stop request still takes effect while it waits, and after
  `scan_backup_max_wait` (4 hours) it gives up and leaves the work to the next
  scheduled run rather than sleeping indefinitely.

  A scan will not *start* into a backup either — `startScan()` refuses, and the
  scheduler defers with a log line instead of trying.

  `scan_pause_on_backup`, on by default. Both halves use the same probe, so
  they cannot disagree about what counts as a backup.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
