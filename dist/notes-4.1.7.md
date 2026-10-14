# ServerScrub 4.1.7

[4.1.7] - 2026-10-14

### Fixed
- **Quarantine directories the product used to use are now swept.** The
  default quarantine path is derived from the product name, so the rename to
  ServerScrub changed where the product *looks* without moving a single file.
  A server holding two hundred quarantined files in
  `/home/.sentinel-gate/quarantine` had `quarantine status` report `files: 0`
  against the new, empty `/home/.serverscrub/quarantine`. The sweep follows
  each threat row's recorded path and so still expires those files, but
  anything whose record had been retired had nothing left to find it, and
  `pruneQuarantine()` walked only the configured directory — so the old
  location leaked for ever. It is now swept too, and the same applies whenever
  an operator relocates quarantine.
- In a directory that is merely inferred, only files we can name as ours
  (`*.quarantine`) are removed. An operator's own file sitting there is left
  alone however old it is.
- `quarantine status` now lists previous locations and what they hold, so
  `files: 0` can no longer describe the wrong directory without saying so.
- `serverscrub quarantine` usage now lists `sweep`, which it had omitted since
  the subcommand was added in 4.1.6 — running it on an older build printed the
  usage line instead, which read as though the command did not exist.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
