# ServerScrub 4.29.0

[4.29.0] - 2026-11-03

### Added

- **The Threats count in the scan log leads somewhere.** Both logs showed a
  number and nothing behind it, so a customer could be told a scan found
  three things in their account and had no way to learn which files, or what
  had become of them. The threats table is server-wide and ordered by time,
  so answering "which three" meant reading past every other finding from that
  night.

  A non-zero count is now a link, and it opens a dialog **inside the app**
  listing each finding: the full path, what it was detected as, severity,
  when it was found, and what happened to it -- quarantined, deleted,
  cleaned, judged safe, or still on disk with no action taken. Where the
  quarantined copy went is shown too, because otherwise "quarantined" is a
  claim the reader cannot check. Zero stays plain text: a link that opens an
  empty dialog costs a click and returns nothing.

  On the root side this is a new `scanner/threats?job_id=` filter, which
  deliberately drops the status filter -- "what happened to it" is half the
  question, and a scan that found two and cleaned both would otherwise read
  as a scan that found none.

  On the customer side it needs no JavaScript at all. The page is
  server-rendered on purpose, so the dialog opens on `:target` and the data
  is already in the report the page was built from -- nothing to fetch and
  nothing that can fail. The back button closes it.

### Fixed

- **A customer's scan log was showing a number about somebody else.**
  `scan_jobs.threats_found` is server-wide, so a nightly `/home` sweep that
  found three webshells in three OTHER accounts displayed "3" on this
  customer's own page. The count is recomputed from their own findings, and
  the dialog's list is scoped the same way the threats table already is --
  a `/home` scan covers every account, and listing it unfiltered would hand
  one customer the paths and filenames inside another customer's site.

- The customer-side list does **not** hide deleted findings the way the
  Detected-threats card does. A scan that found two and removed both would
  otherwise read as a scan that found nothing.

- **Modal styling is a class now, not a sixth entry in five id lists.** Every
  dialog's CSS named each modal by id across five separate rules; a new one
  missing from all five rendered as unstyled inline markup -- present in the
  DOM, correctly populated, and simply not on screen. Which is exactly what
  happened the first time this dialog was built. Existing dialogs are left
  alone; new ones use `.wem-modal` and need nothing else.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
