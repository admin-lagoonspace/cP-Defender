# ServerScrub 4.7.2

[4.7.2] - 2026-10-20

Three bugs found by one real upgrade on a production server. The rollback did
its job — the server came back on 4.4.2 with nothing lost — but it should never
have been triggered.

### Fixed

- **A completed update was rolled back by a `chmod` on an optional directory.**
  v4.7.1 applied in full on a live server: files copied, user data restored,
  migrations run, plugin re-registered. Then:

      chmod: cannot access '/usr/local/serverscrub/quarantine': No such file or directory
      Update failed — rolling back to v4.4.2…

  Quarantine is **configurable** and routinely sits outside the install
  directory — that server had it at `/home/.serverscrub/quarantine`, because
  `/home` is the big volume. So the assumed path did not exist, `chmod` exited
  non-zero, `set -e` called that a failed update, and a successful upgrade was
  undone by a permissions tweak on a directory that was never there.

  `database`, `quarantine` and `logs` are now tightened only when present, and
  the real quarantine path is read from settings instead of assumed.

- **Updates never delivered `cpanel/`, `test.sh` or `upgrade.sh`.** `update.sh`
  carried its own list — `UPDATE_DIRS=( backend frontend whm )` — which was a
  **third** description of what this product consists of, alongside
  `build.py`'s `ITEMS` and `make-release.sh`'s allowlist. All three disagreed.

  The release zip was correct the whole time, which makes this the hardest
  version of the bug to see: nothing is missing from the package and a fresh
  install is perfect. Only servers that *updated* were affected, and the
  consequences were:

  - `cpanel/` holds the page every **customer** opens from their own cPanel.
    Any server updated after that directory was introduced showed an **empty
    menu entry to every user on it**. The only symptom was two lines in an
    installer log: `cPanel user page missing from the package`.
  - `test.sh` missing meant every update ended `test.sh not found — skipping
    verification`. Post-install verification had silently not run in months.
  - `upgrade.sh` missing meant the one script whose purpose is to fetch a newer
    updater could never arrive by update.

  `tests/test_packaging.php` now asserts all three lists are identical, and
  names these three individually.

### Notes

- After updating to 4.7.2, cPanel users get their menu entry back. It arrives
  with the first update that carries the corrected copy list.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
