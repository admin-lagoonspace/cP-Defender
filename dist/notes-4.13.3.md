# ServerScrub 4.13.3

[4.13.3] - 2026-10-21

### Fixed

- **The version-sync in `install.sh` never worked.** It keeps `SG_VERSION` in
  `config.php` in step with the `VERSION` file, and the pattern had **two**
  spaces after the comma:

  ```
  s/define('SG_VERSION',  '[0-9.]*')/.../
  ```

  while the file has one:

  ```php
  define('SG_VERSION', '4.13.3');
  ```

  It matched nothing, and `|| true` swallowed the result. **The one mechanism
  meant to rescue a `config.php` out of step with `VERSION` was a no-op for its
  entire life** — which is how a server came to run 4.10.0 code while its
  `VERSION` file, the updater and the upgrade script all reported 4.13.x.

  The 4.13.2 partial-update check caught the symptom; this is the cause.

  It is now whitespace-tolerant, and it **verifies the result** rather than
  assuming — a `sed` that silently matches nothing is precisely what caused
  this. It prints the version it confirmed, or warns that `config.php` still
  reports the wrong one and that the panel reads that value.

### Notes

- `tests/test_version.php` now applies `install.sh`'s own pattern to the real
  line in `config.php`. This is a **cross-file assumption** — a regex in a shell
  script about the exact text of a PHP file — and nothing links the two, so the
  test has to. Verified both directions before shipping: the new pattern
  repairs a deliberately-staled `config.php` from 4.10.0 to 4.13.2, and the old
  two-space pattern leaves it at 4.10.0.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
