# Sentinel Gate 3.19.2

[3.19.2] — 2026-08-27

### Fixed
- **`backend/config/config.php` was truncated mid-file and had been for at least
  eight releases.** It ended part-way through a string literal in the `RBL_FEEDS`
  array — `'spamco` — so the file was a parse error, and since every other PHP
  file requires it, *nothing* server-side could run. It never surfaced because
  the API returned 501 before PHP was ever asked to parse it; the moment 3.19.1
  got PHP actually executing, this was the first thing it hit. The array is
  closed and the missing entries restored.

### Changed
- The build's syntax gate now uses a repository-local PHP interpreter and
  **fails the build when no interpreter is available**, instead of warning and
  continuing. The gate added in 3.19.0 looked for `php` on PATH; releases are
  built on Windows, where there is none, so it skipped itself every time while
  printing a reassuring line. That is precisely how a file truncated mid-string
  shipped eight times. Set `SG_ALLOW_UNVERIFIED=1` to build without it
  deliberately.
- All 27 PHP files now parse. This is the first release where that has ever been
  verified rather than assumed.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
