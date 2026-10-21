# ServerScrub 4.13.5

[4.13.5] - 2026-10-21

### Fixed

- **The bulk "Not malware — exclude" button did nothing.** `updateBulkBar()`
  enabled buttons from a **hardcoded list of two ids**:

  ```js
  [document.getElementById('threat-bulk-quarantine'),
   document.getElementById('threat-bulk-delete')].forEach(...)
  ```

  The new button was given the `threat-bulk-btn` class on the assumption that
  was what drove it. It was never enabled, stayed `disabled` from the markup,
  and could not be clicked. Selection is now applied **by class**, so a bulk
  button added tomorrow works without anyone editing that line.

- **The Scan exclusions card never loaded.** `loadExclusions()` was not in the
  Scanner page's loader, so "Already excluded automatically" was blank and the
  textarea showed only its placeholder — which reads as *"you have no
  exclusions"* rather than *"this was never loaded"*.

- **Two more sections on the Real-Time Monitor page were never populated.**
  `loadMonitorDetections()` and `loadMonitorLog()` were called by nothing, so
  "Recent detections" and the log panel sat on *Loading…* permanently. **Found
  by the new check, not by inspection.**

### Added

- `scripts/check-js-wiring.py`, in preflight. It fails the build on:
  - a control that ships `disabled` and is never enabled by anything
  - a no-argument `load*` function that fills a page but is absent from that
    page's loader entry

  Verified by re-injecting both real bugs into a copy and confirming it fires,
  then confirming it is clean on the fixed tree.

### Notes

- **On the tests.** The assertion covering the bulk button checked that it
  *carried* the `threat-bulk-btn` class — which it did, while nothing acted on
  that class. It now asserts the bar enables **by class** and that enabling is
  driven by the selection rather than set to a fixed value.

- Writing this check took three attempts, and the first two **failed their own
  proof**:
  1. A different selector set `.disabled = true` during an operation; the check
     saw the class in use and called it wired.
  2. A `finally` block set `.disabled = false` after that operation; the check
     accepted any non-`true` value.

  The working rule is that enabling must be **conditional** — a literal
  `true`/`false` brackets an operation, it is not a control responding to a
  selection. Both earlier versions would have passed the dead button.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
