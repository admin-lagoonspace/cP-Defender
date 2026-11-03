# ServerScrub 4.29.3

[4.29.3] - 2026-11-03

### Fixed

- **The customer-side threats link did nothing.** It set the URL fragment and
  no dialog appeared.

  The link was rendered from the scan row's `threats_found`; the dialog was
  rendered from the report's `scan_threats` map. Those are two different
  sources, and on a `report.json` written before 4.29.0 the map is absent
  while the count is not -- so the page offered a link to a `#fragment` with
  no element behind it. Clicking it matched no `:target` and did precisely
  nothing, which is what it looked like.

  A dead anchor is worse than a plain number: it looks clickable, consumes
  the click, and leaves the reader thinking the page is broken.

  The map is read once, before the table, and the link is offered only when
  the dialog will actually be rendered -- so the two cannot disagree. Where
  the map exists the COUNT comes from it too, making the number and the list
  the same fact rather than two that can drift apart. A count with no stored
  detail stays plain text and explains itself on hover.

  An older report self-heals on the next rebuild; `serverscrub.php
  user-reports` forces it immediately.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
