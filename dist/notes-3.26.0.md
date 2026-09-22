# Sentinel Gate 3.26.0

[3.26.0] - 2026-09-22

### Fixed
- **Quarantine and delete failed with no explanation.** `quarantine()` used
  `rename()`, which cannot cross a filesystem boundary - and on a hosting server
  `/home` is routinely a separate volume from `/usr/local`, so it failed with
  EXDEV on exactly the files it exists to handle. It now falls back to
  copy-then-unlink, verifying the copy before removing the original: losing a
  customer's file while trying to protect it is worse than leaving the malware
  in place.

  Both routes also returned `['success' => bool]` and nothing else, so the
  reason never reached the user. They return the reason now - cross-device move,
  unwritable directory, or a file marked immutable with `chattr +i`, which looks
  like a permissions problem and is not.
- **Delete marked a threat removed even when the file was still there.**
  `@unlink()` failing was ignored and the row was updated regardless, so the
  dashboard could report malware deleted while it sat untouched on disk. The row
  is only updated after the unlink is checked.
- **The threats table rendered file paths unescaped.** A file name is
  attacker-controlled; interpolating it into `innerHTML` made the table an XSS
  sink in the dashboard of a security product. Every value in the row is escaped.
- **Refresh buttons appeared dead.** They always refetched - which is why the
  handler check passed - but nothing on screen changed, so on an idle server a
  working refresh and a dead button looked identical. They now disable, show
  progress and stamp the time data last arrived.

### Added
- **Select-all and bulk actions** in the malware scanner: tick individual rows
  or the header box, then quarantine or delete the selection. Destructive
  actions are confirmed first, each file is attempted independently, and
  failures are reported per file with their reason rather than one pass/fail
  for the batch.
- **A read-only file viewer.** Inspect what is inside an infected file without
  running it: the server reads the bytes with `file_get_contents` - never
  including or evaluating them - and the dialog inserts them with `textContent`,
  so a payload made of markup is displayed as characters. Binary files are
  described rather than dumped, and the read is capped at 256 KB.
- `scripts/check-js-syntax.py`, in preflight. There is no Node on the build
  machine, so the only JavaScript validation this project ever had was a regex
  brace counter that mis-handled template literals - it reported a different
  imbalance for correct code and could not distinguish a real error from its own
  confusion. Every front-end change until now shipped unparsed.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
