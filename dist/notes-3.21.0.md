# Sentinel Gate 3.21.0

[3.21.0] - 2026-08-27

### Added
- **Resource profiles for the real-time monitor.** Reported as putting excessive
  load on a live server. Settings now offers Light / Balanced / Thorough /
  Custom, controlling files examined per second, maximum file size, process
  priority, poll interval, inotify watch ceiling, repeat-event window and
  directory exclusions. Custom values are clamped: a rate of 0 would mean an
  unthrottled monitor, so the floor is 1.
- Limits are **re-read roughly every minute**, so calming a loaded server down no
  longer needs a daemon restart.
- Status reports the profile the daemon actually applied and the live watch
  count, rather than only what was configured.

### Fixed
- **Polling mode was the real cost.** It walked every watched path and stat()ed
  EVERY file each interval, holding a path-to-mtime map for the whole tree.
  Against /home on a shared host that is millions of syscalls per pass, for ever.
  It now filters by extension *before* stat() (a string compare instead of a
  syscall), tracks only files it would ever scan, bounds the tracked set, and
  yields between directories.
- **inotify had no watch ceiling**, and an exhausted kernel watch limit was
  swallowed with every other error - leaving the monitor covering a fraction of
  the tree while reporting itself healthy. The cap is a setting, ENOSPC is
  reported explicitly, and the capped state is visible in status.
- **Repeated events for one file were each scanned in full.** An editor save or
  a deploy produces several events per path; they are coalesced now.
- The monitor asks for **idle I/O priority**. The load here is mostly disk, and
  `nice` only covers CPU.

### Notes
- The existing CPU slider only ever set process priority and the pause between
  scans. It could not stop the monitor walking the filesystem, which is what
  actually loaded the server; it remains, and applies to scans as before.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
