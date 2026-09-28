# Sentinel Gate 3.30.5

[3.30.5] - 2026-09-28

### Changed
- **One scanner process. `scan_max_concurrent` now defaults to 1**, reverting
  the 2 that shipped in 3.30.4.

  The reasoning that makes 1 the right number rather than a cautious one: each
  `clamscan` loads the entire ClamAV signature database into its own memory --
  650MB to 1.3GB per process on the reporting server. A second concurrent scan
  therefore buys a second copy of that database and two processes queued on the
  same disks. It does not halve the runtime, and it is the mechanism by which a
  server ends up with six of them and no CPU left.

  The value remains a setting, still clamped to 1-4, so an operator who wants
  more can have it deliberately.

### Fixed
- **An upgrade from 3.30.4 would silently have kept the old limit of 2.** The
  settings seed is `INSERT OR IGNORE`, which by design cannot change a row that
  already exists -- so changing the shipped default alone would have left every
  3.30.4 install running two scanners. There is now an explicit migration that
  resets the stored value.

  It is marked so it runs exactly once: an operator who later sets this to 2 on
  purpose keeps that choice rather than having every subsequent upgrade quietly
  overrule them.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
