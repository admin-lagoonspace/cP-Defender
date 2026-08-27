# Sentinel Gate 3.19.8

[3.19.8] â€” 2026-08-27

A regression suite, and a guarantee that none of it ships.

### Added
- `tests/` â€” 93 assertions across six files, run in preflight so no release can
  be packaged while any of them fails. Every test is pinned to a fault that
  actually reached a production server, and names it: the truncated and then
  zero-byte `config.php`; `getallheaders()` under the CGI SAPI; the WHM login
  form that should never have appeared; `Database::getSetting()`, which does not
  exist; `Logger::write()`, which is private; routing that searched for a
  literal `api` path segment; `error_reporting(0)` hiding *and* discarding
  errors.
- `tests/test_packaging.php` asserts against the **finished zip**, not the build
  script's intentions â€” the two have diverged before. It checks that `tests/`,
  `scripts/`, and the 36MB bundled PHP interpreter are absent, that every file
  the product needs is present, that no packaged PHP file is empty, and that the
  package declares the version its filename claims. `build.py` runs it after
  zipping and deletes the archive if it fails.

### Fixed
- **The trial marker path was machine-global and unmockable.** `installedAt()`
  read `/var/lib/sentinel-gate/installed-at` directly, so tests both depended on
  and corrupted real state â€” a marker left by an earlier run reported an expired
  trial on a fresh install. `License::markerPath()` honours `SG_INSTALL_MARKER`,
  which the test bootstrap points into its sandbox. The default is unchanged.

### Changed
- The test runner treats a crashed test file as a failure. Its first version
  reported "71 assertions passed" while two files had died with fatals â€” a
  harness that cannot fail is not a harness, and that is the same false-pass
  shape as `php -l` accepting an empty file and the call checker skipping an
  unreadable one.
- `build.py` names `tests/`, `scripts/` and `php/` as never-packaged and fails
  the build if any appears in the archive, rather than relying on them merely
  being absent from the include list.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
