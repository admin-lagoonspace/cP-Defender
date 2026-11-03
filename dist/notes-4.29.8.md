# ServerScrub 4.29.8

[4.29.8] - 2026-11-03

### Fixed

- **A /home scan walked every account's files once per account.** cPanel
  jailshell bind-mounts a copy of the filesystem under `/home/virtfs` for
  EVERY account. `Scanner` had two walks with two different ideas of what to
  skip: `getPhpFiles()` pruned virtfs, and `walkFiles()` did not -- and
  `walkFiles()` is the one that feeds ClamAV.

  Straight out of the live database:

      account  job    status   n
      virtfs   12439  deleted  1

  The single finding on that server had the path `/home/virtfs/...`, so it
  was attributed to an "account" called virtfs. That account does not exist,
  so the finding appeared on nobody's page and no customer could act on it --
  which is why the threats dialog had nothing to show even once reports were
  writing again. The same `/home` scans reported 104-121 threats and ran for
  nine to seventeen hours, on a server with 132 accounts.

  `virtfs`, `.snapshot`, `.zfs`, `.trash` and `.cagefs` are in
  `SCAN_SKIP_DIRS` now, and the other walk builds its pattern FROM that list
  instead of keeping a second hand-written copy. Two lists disagreeing was
  the bug; one list is the fix.

  Expect scan times and threat counts on `/home` scans to drop sharply. That
  is the duplicate work going away, not detection being lost -- the test
  asserts the real file is still scanned exactly once while the bind-mounted
  copy is skipped.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
