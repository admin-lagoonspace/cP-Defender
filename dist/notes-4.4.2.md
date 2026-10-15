# ServerScrub 4.4.2

[4.4.2] - 2026-10-15

### Fixed
- **The custom-scan account picker never appeared, and two other features were
  dead on arrival.** `g()` -- the element lookup nearly every handler uses --
  was declared as a `const g` *inside* two functions and nowhere else, so every
  module-scope caller threw `ReferenceError` the instant it ran: silently,
  inside an event handler, with nothing logged. Three shipped features did
  nothing at all as a result -- the account picker and the adoption of an
  already-running scan (both 4.3.0), and the brute-force ladder preview
  (4.2.0). `g()` is now defined once at module scope.
- The picker is a dialog rather than an inline panel: checkboxes, a filter that
  preserves what is already ticked, select all and clear, and a button that
  stays disabled until at least one account is chosen. Pressing Start Scan with
  Custom selected and nothing ticked reopens it rather than failing.

### Added
- `scripts/check-js-scope.py`, wired into preflight: it fails the build when a
  helper is called from module scope but only declared inside some other
  function. Bracket balance and handler resolution both passed while these
  three features were broken, so neither gate could have caught it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
