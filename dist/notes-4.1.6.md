# ServerScrub 4.1.6

[4.1.6] - 2026-10-14

### Fixed
- **Our own working directories are now skipped by name**, not only by
  resolved path. The path check added in 4.1.5 is the precise one, but it
  trusts `quarantine_dir` to still point where the files actually are — and on
  a server renamed from the old product, with quarantine left at
  `/home/.sentinel-gate/quarantine`, a stale setting is exactly when that check
  stops protecting anything. `.serverscrub` and `.sentinel-gate` are skipped
  wherever they appear. A customer's own dot-directory is still scanned; this
  is not a blanket rule.

- **The quarantine sweep can be run on demand.** It only ever ran from the
  nightly scheduler, so a backlog could not be cleared without waiting until
  04:30. `serverscrub quarantine sweep` now applies the retention immediately:
  expiries, reconciliation of records whose file has gone, and retirement of
  resolved records.

  `quarantine prune` deletes files by age and does not touch the log, which is
  why running it left the entries in place.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
