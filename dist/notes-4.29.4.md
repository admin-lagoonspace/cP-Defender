# ServerScrub 4.29.4

[4.29.4] - 2026-11-03

### Fixed

- **The repository had drifted from what shipped.**
  `cpanel/serverscrub/index.live.php` had not been committed since v4.27.0
  while six releases changed it -- the scan log, the Started-by column, the
  threat dialog -- and `test.sh` had not been committed since the rename.

  The published zips were correct, because `make-release.sh` packages from
  the working tree, so every customer got the right files. The repository did
  not, so a fresh clone would have built a product missing the entire
  customer-facing plugin's recent work, and anyone reading the source saw
  code that had not shipped for weeks.

  The cause was `publish.sh` staging a hand-written list of directories.
  That list exists because of the same bug in v4.6.0, where two new library
  modules shipped uncommitted; the fix then was to enumerate the source
  trees, and the enumeration omitted `cpanel/`. Enumerating is the bug, not
  the particular list.

  So the release now asks the artifact: every path inside the built zip is
  checked against the repository, and a release is **refused** if any file
  that is about to ship is dirty or untracked. It tests the working-tree
  column specifically -- a staged file is about to be committed and must not
  trip it, since a guard that refuses every release is a guard somebody turns
  off. When `unzip` is unavailable it says the check did not run rather than
  passing quietly.

- Five assignments in `publish.sh` read from pipelines without `|| true`.
  Under `set -e` plus pipefail one failing stage ends the release silently
  and part-way, which is the failure this project already hit in `update.sh`.
  `scripts/check-shell-pipefail.py` only covers shipped scripts, so the
  release script itself was never checked.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
