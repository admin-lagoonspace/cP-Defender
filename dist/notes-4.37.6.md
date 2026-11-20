# ServerScrub 4.37.6

[4.37.6] - 2026-11-20

### Fixed

- **An admin's deliberate quarantine relocation was undone by every update.**
  install.sh moves quarantine off the root partition, because quarantine MOVES
  infected files into its directory and a busy scan filling `/` took a live
  server down. That part is right. What it also did was compute the first
  writable big volume and write it into `quarantine_dir` *unconditionally*, on
  every `--register-only` run -- which is every update.

  So an admin who relocated quarantine through the panel, because the volume it
  was on had filled up, had the setting silently moved back on the next update,
  and every new detection began landing on the full volume again. Filling a
  volume with quarantined files is the exact production incident this block
  exists to prevent, and it was reintroducing it once a release. The empty
  directory on the abandoned volume was recreated each time too.

  Already-quarantined files were never lost: every `threats` row stores its own
  absolute `quarantine_path`, so a restore still resolves. But the recovery
  path that reconstructs a location from the setting looks in the wrong
  directory after a clobber, and new quarantines go to the wrong volume.

  The installer now reads the setting before writing it, and writes only when
  there is nothing deliberate to respect: when it is unset, when it still
  points inside the install directory -- on the root partition, the case this
  block exists for -- or when it holds a value that is not a quarantine
  directory at all. A path that is safe and off the root partition was chosen
  on purpose, so it is kept, announced, and used as the destination for any
  files still waiting in the install directory.

  `_sg_quarantine_path_ok()` is byte-identical in install.sh and update.sh, and
  a test asserts that: update.sh refuses to *walk* such a path, install.sh
  refuses to *keep* one, and `Scanner::moveQuarantine()` refuses to *write*
  one. Three scripts, one rule — if they disagree, the one that is wrong is the
  one nobody notices.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
