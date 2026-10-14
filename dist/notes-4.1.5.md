# ServerScrub 4.1.5

[4.1.5] - 2026-10-14

### Fixed
- **The scanner was re-scanning its own quarantine.** Quarantined files *are*
  malware, and nothing stopped the walk entering the quarantine directory. With
  quarantine moved to `/home/.serverscrub/quarantine` — sensible, since that is
  where the disk space is — it sat directly inside the default scan path. Every
  scan then re-detected every file it had already caught, wrote a fresh threat
  record for each, and quarantined the quarantined file.

  That is where a log full of 200 identical entries came from, all pointing at
  quarantine paths, with the account column showing the install directory
  rather than a customer. The quarantine directory is now excluded by resolved
  path (it is configurable, so matching on its name would not do), and any
  stray `.quarantine` file is skipped wherever it sits.

- **The log kept saying "Quarantined" for files that had been deleted.**
  `pruneQuarantine()` removed files by age and never touched the database, so a
  status outlived the thing it described by days. Rows whose quarantined file
  has gone are now reconciled to `deleted`.

- **Records written before per-threat deadlines existed were never swept.**
  Nothing before 3.37.0 has a `quarantine_expires_at`, and the policy pass only
  looks at rows that have one — so they sat at "Quarantined" indefinitely while
  their files were quietly removed underneath. They are now given a deadline
  derived from when they were detected, and the normal rules apply.

- **Threat records were never pruned at all.** Resolved records are now retired
  after `threat_retention_days` (7). Anything still **active** is kept
  regardless of age — an unresolved threat is exactly what the log is for.

### Notes
- The threat list is ordered `detected_at DESC` — newest first. That is now
  pinned by a test, since a log that silently reversed would be read upside
  down without anyone noticing.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
