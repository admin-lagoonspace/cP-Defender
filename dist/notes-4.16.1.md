# ServerScrub 4.16.1

[4.16.1] - 2026-10-23

### Fixed

- **The Brute Force settings form could save two fields but never read them
  back, so opening the page and pressing Save silently discarded them.**

  `bf-set-whitelist` and `bf-set-retention` were posted by Save and were never
  populated from the server, because `BruteForce::stats()` did not return them.
  The allow-list box therefore always rendered empty and the retention box
  always rendered the markup's hard-coded `7`. Change the threshold, press
  Save, and the allow list was emptied and retention reset â€” with no warning.

  Clearing an allow list makes the product block **more**, including
  potentially the address you administer the server from.

- **An empty allow list looked like a configured one.** Its placeholder was
  `203.0.113.5, 198.51.100.0` â€” RFC 5737 documentation addresses â€” which reads
  as a live setting in a greyed-out box. Same mistake as the Settings page
  naming `/usr/local/serverscrub/quarantine`. Placeholders on configuration
  fields now read as examples (`e.g. â€¦`, `blank = none`), and the allow list
  states its effective contents beneath the box: either *"Never blocked: â€¦"* or
  a warning that **nothing** is allow-listed.

  The escalation-ladder placeholder got the same treatment.

### Changed

- Offender status labels quote **your** threshold and window â€” *"Watching Â·
  blocks at 4 in 5m"* â€” read from settings rather than from constants in the
  UI, and a test now fails if either is hard-coded into the label.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
