# ServerScrub 4.29.6

[4.29.6] - 2026-11-03

### Fixed

- **`serverscrub user-reports` wrote nothing, on every account, because of a
  missing `require`.** The real error was

      Error: Class "UserScanRequest" not found
      at /usr/local/serverscrub/backend/lib/UserReport.php:478

  `UserReport::build()` calls `UserScanRequest::statusFor()`, and
  `UserReport.php` required nothing at all -- it relied on each caller having
  loaded its dependencies. `scheduler.php` and `user-scans.php` load
  `UserScanRequest`; the CLI does not. `writeAll()` catches `Throwable` per
  account and counts it as a skip, so 132 code errors were reported as "no
  usable home directory" -- a cause it invented, which sent everyone looking
  at home directories.

  Every customer's `report.json` has therefore been frozen since 4.29.0. The
  cPanel page reads that file for everything, so no amount of fixing the page
  could make the threats link appear: the page was right, the data was three
  releases old.

- **Every lib now requires what it calls.** 27 of 36 did not. A class whose
  correctness depends on the caller's include list breaks the moment a new
  caller appears, and breaks silently wherever that caller catches
  `Throwable`. `require_once` is idempotent and safe across the cycles these
  classes form (Scanner <-> UserReport <-> UserScanRequest), which is
  verified rather than assumed.

- **`scripts/check-lib-standalone.php`** loads each lib in a fresh process
  and fails the build if it cannot stand alone. Its first version only
  checked that a file declared its own class -- and passed with the
  `UserScanRequest` require removed again, because `UserReport.php` still
  declares `UserReport` perfectly well. The class that goes missing is one
  the file CALLS, so it now requires every referenced sibling to be loadable
  too. That is what found the remaining 26.

  It also caught two self-inflicted breakages while being written: requires
  inserted above `declare(strict_types=1)`, which must stay the first
  statement, and a require inserted inside a method body where a lazy one
  already sat.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
