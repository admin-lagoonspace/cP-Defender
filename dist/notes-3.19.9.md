# Sentinel Gate 3.19.9

[3.19.9] - 2026-08-27

### Fixed
- **The scan progress percentage was `Math.random()`.** A scan that had examined
  zero files displayed "51 per cent". The value was
  `Math.min(99, Math.floor(Math.random() * 5) + 50)` - a number between 50 and
  54, refreshed every two seconds, with no relationship to anything. In a
  security product this is not cosmetic: it makes a dead scan indistinguishable
  from a working one, and once one number on screen is known to be invented,
  none of them can be trusted.

  There is no honest percentage available - a scan walks the filesystem without
  counting it first, so the total is genuinely unknown until it finishes. The
  bar is now indeterminate while running, and the panel shows the real file
  count from the job row, which was always available and always truthful.
- **A stalled scan looked identical to a running one.** The scan runs detached,
  so the UI cannot observe it dying. A job whose file count has not moved for
  about 30 seconds now says so and points at `logs/scanner.log`.
- **Log Analyzer had no client code at all.** The `logs` module has existed
  server-side throughout; `api.js` simply had no method that called it, so the
  page could never load anything.

### Added
- `tests/test_ui_honesty.php` - fails the build if `Math.random()` or a demo
  fixture value reaches a rendered element outside clearly-named demo code, and
  asserts that every server module has at least one client method. That second
  check is what catches a page like Log Analyzer shipping as navigation with no
  backing calls.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
