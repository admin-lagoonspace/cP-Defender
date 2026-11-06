# ServerScrub 4.33.0

[4.33.0] - 2026-11-06

### Added

- **An Action column on the WAF event log**, saying what ModSecurity actually
  did: Blocked, Dropped, Redirected, or Logged (matched and served anyway).
  Rendered through one function shared by the table and the detail dialog, so
  the two cannot disagree about whether a request was stopped.
- **Pagination on the WAF event log**, the same control as Bot Shield's --
  Previous/Next, a "showing x of y" note and a 50/100/200/500 page size kept
  in `sessionStorage` for the session. `getEvents()` now returns
  items/total/limit/offset, and the total is counted under the same filter as
  the rows: counting the whole table while listing a filtered page would claim
  120 matching events under ten.

### Fixed

- **The WAF recorded an action it never observed.** `saveWafEvent()` wrote the
  literal string `'block'` on every row it ever inserted, and the detail
  dialog displayed it as fact. It was never parsed from the audit log, so on
  an engine running in `DetectionOnly` -- a mode this product offers and sets
  itself -- every row claimed a request had been blocked when it had been
  served. 148,551 rows on the server that prompted this. The action is now
  read from the Message preamble (`Access denied`, `Warning.`), from section
  H's `Action: Intercepted`, and from `Engine-Mode: DETECTION_ONLY`, which is
  decisive against any individual rule's claim. Where a transaction matched
  several rules the most consequential outcome wins: four warnings and one
  denial is a blocked request.
- **Existing WAF events are reset to `unknown`** by a one-time migration and
  shown as a dash that explains itself. The value was never observed, so there
  is nothing to recover, and a confident wrong answer is worse than an
  admitted gap.
- **The WAF event log showed only the newest 100 events** of however many
  existed, with nothing to say more existed. An attack from last week was in
  the database and unreachable from the product.
- **Changing the severity filter kept the page offset**, so filtering while on
  a later page landed past the end of the filtered set and showed an empty
  table -- which reads as "no critical events" when there are plenty.
- **A test asserted on a fixed 2,200-character window of `loadWAFEvents()`.**
  When the function grew past that, five assertions about escaping failed
  while the escaping was exactly where it should be. It reads the whole
  function now: a test that depends on the length of the code it reads reports
  on its own window, not on the product.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
