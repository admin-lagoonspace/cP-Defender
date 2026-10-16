# ServerScrub 4.5.0

[4.5.0] - 2026-10-16

### Added
- **A running scan now says what it is covering.** The job row has always
  carried the scan path and the progress card always ignored it, so a custom
  scan of three accounts looked identical to a full scan of the whole server.
  Paths map back to account names -- "alice", not `/home/alice/public_html` --
  with many web roots counted rather than listed, and a long selection
  abbreviated with the full list kept on hover. It appears the moment the scan
  starts rather than at the first poll two seconds later.

### Fixed
- **The stall warning never cleared.** It was set once and left, so a scan that
  paused briefly -- loading the ClamAV signature database, or working through
  one large file -- displayed "the scan process may not be running" for the
  rest of its life while the counter beside it climbed past 5,600 files. A
  warning that contradicts the number next to it teaches an operator to ignore
  both.
- That warning told operators to check `logs/scanner.log`, which has never
  existed anywhere in the product. Each worker writes to
  `logs/scan_<job>.log`, and the scan status payload now carries the real name.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
