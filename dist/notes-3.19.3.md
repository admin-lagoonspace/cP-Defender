# Sentinel Gate 3.19.3

[3.19.3] â€” 2026-08-27

### Fixed
- **3.19.2 shipped a zero-byte `config.php`.** A bump script wrote it with
  `open(path,'w').write(open(path).read())` â€” opening for writing truncates the
  file *before* the read runs, so it read back empty and wrote nothing. Since
  every PHP file requires config.php, and the runtime guards test constants it
  defines, the API answered "Direct access denied" to everything. This is almost
  certainly what truncated the same file originally. Restored from the last good
  commit, repaired, and re-stamped.
- **The WHM plugin still showed a login form.** SSO was attempted only when
  `detectMode()` had already succeeded, so one failed request left the user at a
  password prompt on a server where WHM had authenticated them. SSO is now
  attempted unless the install is positively known to be standalone; the
  endpoint refuses in standalone mode anyway, so asking is always safe.

### Changed
- The dashboard **opens in its own tab** instead of inside the WHM content
  frame. When framed it moves to a new tab, falling back to a single prominent
  link when the popup is blocked (a blocked popup is expected, not an error).

### Added
- `scripts/preflight.py` and `scripts/build.py`. The release was being built by a
  throwaway script in a temp directory, so every gate lived in `make-release.sh`
  â€” which cannot run on the machine releases are cut on, because there is no
  `zip` and no system `php`. Both now live in the repository and run everywhere.
- Preflight rejects **empty** PHP files. `php -l` reports success on a zero-byte
  file, so the parse gate passed 3.19.2's empty config.php cleanly. It also
  asserts config.php defines the constants the runtime guards require, and that
  its `SG_VERSION` matches `./VERSION`.
- The packaged zip is re-checked after zipping, so a payload cannot ship with an
  empty or absent config.php even if the source tree looked fine.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
