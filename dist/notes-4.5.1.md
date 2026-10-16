# ServerScrub 4.5.1

[4.5.1] - 2026-10-16

### Changed
- The running-scan label shows **paths** rather than account names:
  `/home/alice/public_html` instead of `alice`. The path says which account
  and which part of it is being walked, and since quick and full scans cover
  different trees that second half is the half worth knowing. Many web roots
  are listed as paths too, abbreviated past three rather than collapsed into a
  bare count, with the full list still on hover.
- The label shown the instant a scan starts now uses the same paths the server
  reports on the first poll, so it no longer changes from `alice` to
  `/home/alice` two seconds later.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
