# Sentinel Gate 3.27.2

[3.27.2] - 2026-09-23

### Fixed
- **The bulk Quarantine/Delete buttons were missing from the malware scanner.**
  They shipped in 3.26.0, but into the wrong table: the patch anchored on the
  first `<thead>` in the file, which belongs to the dashboard's events table.
  They were also a `<div>` placed directly inside `<table>`, which browsers
  hoist out of the table or discard. The buttons existed in the source and were
  absent from the page they were asked for.

  They now sit above the threats table, outside the table element.
- **The bar was hidden until something was selected**, so anyone looking for a
  way to act on several files saw nothing and reasonably concluded it had not
  been built. The bar is always visible and the buttons enable once rows are
  ticked.
- The empty-state row still spanned 8 columns after the checkbox and View
  columns were added, so "no threats detected" rendered short of the table.

### Notes
- The test that should have caught this asserted only that `threat-bulk-bar`
  existed *somewhere* in the markup - true of a bar in the wrong table, in
  invalid HTML. It now asserts where it sits, that it is not nested inside a
  table, that the buttons are present and enabled by selection, and that the
  empty-state colspan matches the real column count.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
