# ServerScrub 4.13.1

[4.13.1] - 2026-10-21

### Fixed

- **The per-row "Not malware" button did nothing when clicked.** It rendered:

  ```
  onclick="excludeThreatPath(${JSON.stringify(t.file_path || '')})"
  ```

  `JSON.stringify` emits **double** quotes. Inside a double-quoted HTML
  attribute the first one terminates the attribute, so the browser saw
  `onclick="excludeThreatPath("` and **never bound a handler**. The control was
  completely dead, and it shipped that way.

  It now passes the numeric id like every other button in the row, and the path
  is resolved from a map rebuilt when the table renders. **No event attribute
  anywhere carries a file path** — a path can contain an apostrophe, a space or
  a backslash, and single quotes do not save it either.

### Added

- **Bulk exclusion.** Five findings from one vendor tree is the normal case —
  it is exactly what ai-bolit produced — so excluding them one prompt at a time
  was the wrong shape of work. Tick the rows, press **Not malware — exclude**.

  Selected files collapse to their **parent folders** and de-duplicate, so five
  files in one directory become one rule rather than five. Otherwise the
  exclusion list becomes its own unreadable mess within a week. Capped at 200
  per call for the same reason.

### Notes

- **Why nothing caught the dead button, and what does now.** Every existing
  check passed: `check-ui-handlers.php` confirmed the function existed, which
  it did; `check-js-syntax.py` balanced brackets, which balanced; and the test
  asserted `excludeThreatPath` appeared in `app.js`, which it did. None of that
  is evidence a control *works*.

  `scripts/check-js-attrs.py` now fails the build on any non-numeric value
  interpolated into an HTML event attribute, and unconditionally on
  `JSON.stringify` in one. Verified both ways: clean against the current tree,
  and it flags the original bug when re-injected.

  The tests were rewritten to assert the **shape of what is rendered**
  (`onclick="excludeThreatPath(${id})"`) rather than that an identifier exists
  somewhere in the file.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
