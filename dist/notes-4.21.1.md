# ServerScrub 4.21.1

[4.21.1] - 2026-10-27

### Added

- **Pagination on Blocked Bots and Recent Bot Events.** 50 per page by default,
  with a per-page selector offering **50 / 100 / 200 / 500** that is remembered
  for the browser session.

  Each page carries its own total, so the tables now say *"Showing 51â€“100 of
  137"* instead of filling with rows and leaving you to guess. Changing the
  page size resets both tables to the first page â€” page 3 of 50 is not page 3
  of 500, and landing past the end would show an empty table.

  The size lives in `sessionStorage`: a reading preference, not server
  configuration. Every read and write is wrapped, because `sessionStorage`
  throws in a private window and returns nothing with site data blocked â€”
  neither of which should break a table.

### Fixed

- **Recent Bot Events silently showed 50 of however many there were.** The
  route returned up to 100 rows and the renderer then did `events.slice(0, 50)`
  on top. A server with thousands of events displayed fifty and said nothing.
  A table that shows part of the data without saying so invites exactly the
  wrong conclusion â€” that there is nothing more to see.

- **The blocked-address total counts addresses, not events.** That query groups
  by IP, so counting rows would have reported 137 where there were 7 addresses
  and offered pages that do not exist.

- **Log-derived text is now escaped.** Both tables interpolated `user_agent`,
  `uri` and `ip_address` straight into HTML and into a `title` attribute. Those
  come from web logs, so the user-agent is whatever a stranger chose to send â€”
  a request with `<img src=x onerror=â€¦>` as its UA would have put that into the
  page. Verified with exactly that payload: it renders as text.

- The Unblock button no longer interpolates an address into its `onclick`; it
  passes the row index, like every other action in the product.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
