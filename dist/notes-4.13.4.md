# ServerScrub 4.13.4

[4.13.4] - 2026-10-21

**This is the root cause behind five consecutive failed updates.** 4.13.2 and
4.13.3 fixed real bugs that were not it.

### Fixed

- **`rsync` was skipping files that had changed.**

  `rsync`'s default quick check is **size + mtime**. `make-release.sh` pinned
  every entry in the release archive to the ZIP epoch:

  ```python
  zi = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
  ```

  So after extraction every file carried an identical timestamp, and any file
  whose **size** had not changed looked identical to the one already installed
  and **was never transferred**.

  `backend/config/config.php` sat at **4.10.0 through five consecutive
  updates**, because `'4.10.0'` and `'4.13.3'` are both six characters and the
  size never moved. `frontend/index.html` was stuck the same way, for the same
  reason.

  The rsync reported success every time — it *had* finished, having decided
  there was nothing to do. So the updater printed "Update complete" while the
  panel correctly reported 4.10.0, and every feature shipped since 4.10.0 was
  simply absent.

  Both rsyncs now pass **`--checksum`**, comparing content rather than a
  timestamp we do not control. The rollback path needed it too: silently
  keeping a same-size file from the failed version leaves a half-reverted
  install, which is worse than either version on its own.

- **The archive carries real modification times.** `--checksum` means the
  updater no longer depends on them, but a timestamp that is a lie breaks
  every other tool that compares files.

### Notes

- Three symptoms, one cause: the stale sidebar version, the stale
  `SG_VERSION` the API reports, and the missing features. I chased all three
  separately. The `install.sh` double-space `sed` fixed in 4.13.3 was a genuine
  bug found on the way, but it was never going to help — the file it was meant
  to repair was not being delivered at all.

- The 4.13.2 partial-update check is what made this findable: it refused to
  report success, which is the only reason the mismatch stayed visible long
  enough to trace.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
