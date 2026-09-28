# Sentinel Gate 3.30.4

[3.30.4] - 2026-09-28

### Fixed
- **Upgrading did not stop the scans that were already running.** 3.30.3 added
  the guard that prevents new scans from stacking, but nothing dealt with the
  ones already on the server. Those workers are detached, so nothing else stops
  them: they keep running the *old* code against a database the installer has
  just migrated, and they keep their `clamscan` processes. Installing now stops
  every running scan as its own step, before the new scheduler can start any,
  and clears stale slot locks.
- **`Scanner::reapOrphanClamscans()` was never going to help here.** It
  deliberately skips any process group whose worker is still alive, because it
  is an *orphan* reaper -- so on a server with several live scans it correctly
  reported them and killed nothing. That is right for a reaper and wrong as a
  cleanup tool, which is what was missing.
- **`stopScan()` stops one job.** With several scans stacked up, stopping them
  meant finding every job id first. Added `Scanner::stopAllScans()`, the
  `scanner/stop-all` route, and `sentinel scan-stop-all`.

### Changed
- **The concurrency limit is now 2 by default, and configurable, rather than
  a hard 1.** 3.30.3 enforced a single scan; that was a choice made without
  being asked for. `scan_max_concurrent` defaults to 2 and is clamped to 1-4 --
  clamped because each `clamscan` loads the entire ClamAV signature database
  into its own memory (650MB-1.3GB observed), so raising it multiplies memory
  and disk contention rather than dividing the work.
- The worker's lock is now one file per permitted slot rather than a single
  exclusive lock, so the cap is enforced at the filesystem no matter what
  started the scan.
- `scanner/running` reports the live scans and the cap, not just the newest job.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
