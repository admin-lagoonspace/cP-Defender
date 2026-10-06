# ServerScrub 4.0.1

[4.0.1] - 2026-10-06

### Fixed
- **The installer banner still spelled SENTINEL.** It is ASCII art — the name
  drawn in block characters, not written as text — so no search for the old
  name could find it, and it was the first thing an operator saw when
  installing ServerScrub. It now reads SERVER over SCRUB, in the silver and
  green of the logo. Two lines because eleven letters in that font is 99
  columns, which wraps on an 80-column terminal and turns the banner into
  noise.

  There is now a test that asserts the drawn letters, so a brand name hidden in
  art cannot survive the next rename either.

- **Two more references the sweep could not match**, both because the product
  name wrapped across two comment lines: one in `install.sh` about exempting
  the daemons from LFD, one in `FirewallEngine.php` about licensing. A
  line-by-line replacement cannot see a name split over a newline.

- `backend/signatures/custom.sig` still carried the old name in its header;
  `.sig` was not in the swept extension list.

### Note on what you saw
The install in that session downloaded **3.37.2**, not 4.0.0 — the CDN still
serves the old layout at `/sentinel-gate/code/`, so `get.sh` resolved an old
`latest.json` and fetched an old release. That install was genuinely Sentinel
Gate; it was not 4.0.0 showing old names. The CDN needs the new
`/serverscrub/code/` path before the primary channel will serve 4.x.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
