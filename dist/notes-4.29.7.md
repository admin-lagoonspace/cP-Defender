# ServerScrub 4.29.7

[4.29.7] - 2026-11-03

### Fixed

- **A skipped account now says why it was skipped.** `writeAll()` returned
  two integers, and the CLI announced that skipped accounts "have no usable
  home directory, or one that is a symlink or owned by another user" -- a
  cause it had no way to know.

  When `build()` threw `Class "UserScanRequest" not found` on all 132
  accounts, that invented sentence is what the operator was told. The real
  error went to a log nobody was pointed at, and three rounds of debugging
  went looking at home directories. A caught exception reported as a
  confident guess about the filesystem is worse than no message at all.

  The reason is carried back per account and printed, grouped by distinct
  cause -- 132 copies of one error is not more informative than one, and
  would bury anything else. A thrown error appears as itself, with class,
  message, file and line. A write refused despite a good home is
  distinguished from a bad home, because those have nothing in common. What
  it would have printed on the first run:

      Per-user reports: 0 written, 132 skipped

      Why they were skipped:
        132 account(s): Error: Class "UserScanRequest" not found at UserReport.php:478
          e.g. aaksh, aavvarjunlogisti, aditihospitality

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
