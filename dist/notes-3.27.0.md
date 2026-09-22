# Sentinel Gate 3.27.0

[3.27.0] - 2026-09-22

Quarantine filled a live server's root partition. Three separate faults, any one
of which was enough on its own.

### Fixed
- **Quarantine defaulted to a directory on the root filesystem.**
  `QUARANTINE_DIR` was `SG_ROOT . '/quarantine'`, i.e.
  `/usr/local/sentinel-gate/quarantine`. Quarantine *moves* infected files
  there, so on a hosting server - where customer data is a separate and far
  larger volume - a busy scan fills `/` and takes the machine down. A security
  tool must not be the cause of the outage.

  It now defaults to `/home/.sentinel-gate/quarantine`, which is where the files
  being quarantined already live: there is space for them, and the move stays on
  one filesystem, which is also faster. `quarantine_dir` still overrides it.
- **Nothing ever removed anything.** Quarantine grew without limit, so a server
  scanning nightly keeps every infected file it has ever seen until the disk is
  gone. Files older than `quarantine_retention_days` (30 by default, 0 to keep
  everything) are pruned daily, along with per-scan logs, which were also one
  file per scan and never cleaned up.
- **Nothing checked free space before writing.** Quarantining now refuses if the
  move would take the target volume below 5% free, and says so. Leaving the file
  in place is recoverable; a full disk is not.

### Added
- Existing installs are **migrated on update**: if quarantine sits on a
  different filesystem to `/home`, its contents are *moved* there and the
  setting updated. Files are never deleted - they are evidence, and one may be a
  customer's only copy of something. Anything that cannot be moved is left where
  it is and reported.
- `sentinel quarantine status | prune [days] | move <dir>` - see where it lives
  and how much it holds, prune it, or relocate it to another volume without
  editing the database by hand.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
