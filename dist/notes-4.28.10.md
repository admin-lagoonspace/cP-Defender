# ServerScrub 4.28.10

[4.28.10] - 2026-11-03

### Fixed

- **A successful CDN publish printed what looked like a fault.** `cdn-setup.sh`
  starts the sync with `su -c`, which changes the user but not the working
  directory, so it ran from root's home. `find(1)` saves its cwd and restores
  it afterwards, and an unprivileged user cannot stat `/root`, so every run
  put two of these between "archived" and "published":

      find: Failed to restore initial working directory: /root: Permission denied

  Nothing was wrong, in the one output an operator reads to decide whether
  the setup worked. The sync now moves to its own work directory first, with
  `/` as a fallback and never aborting on it -- being in an awkward directory
  is cosmetic, not a reason to publish nothing.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
