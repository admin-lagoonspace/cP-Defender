# ServerScrub 4.24.1

[4.24.1] - 2026-10-31

### Fixed

- **The cPanel user page used invented branding.** Its header carried a
  hand-drawn SVG shield that resembled the product's logo without being it,
  and a palette (`#1976b6`, `#1d7a46`) chosen rather than taken from the
  artwork.

  The palette is now the logo's, measured rather than picked. Counting pixels
  by hue family in `frontend/images/logo.png` gives:

  | | |
  |---|---|
  | green — the word "Scrub" and the swoosh | `#00b03c`, 10,948 px |
  | navy — the shield body | `#001a3d`, 21,096 px |
  | blue — the shield highlight | `#0090f0` |

  A brand colour is not a judgement call when the logo is sitting there to be
  measured. The header now uses the real shield icon the installer already
  places beside the page, with "Server" in navy and "Scrub" in green, matching
  the logo's own treatment.

  The marketing site is repalleted to match: navy footer and code blocks, the
  logo's green on primary actions, and the real artwork shipped in place of
  the drawn one.

  One thing worth recording about the site header: the full lockup is 480x304
  with its wordmark filling the lower half, so at a 38px header height it
  rendered "ServerScrub" about six pixels tall and read as a smudge. The
  header uses the **shield mark** with the words set in type; the full lockup
  is kept for the footer, where it has the width to be legible.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
