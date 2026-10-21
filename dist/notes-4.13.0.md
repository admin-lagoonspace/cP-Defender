# ServerScrub 4.13.0

[4.13.0] - 2026-10-21

### Added

- **Scan exclusions, with a UI.** On a live server this product reported five
  **HIGH** threats against `ai-bolit` — Imunify360's own malware scanner,
  shipped by CloudLinux. Every one was `SG.RT.eval_base64`, and every one was
  correct in the narrow sense: those files genuinely contain
  `eval(base64_decode(...))`, because **a malware scanner carries the patterns
  it hunts for**.

  A scanner that flags other scanners is not merely noisy. It teaches the
  operator that HIGH findings are usually wrong, and the next one that matters
  gets the same shrug. The signature was right and the product was still wrong.

  Excluded by default now: ai-bolit, Imunify360, `/opt/alt` (CloudLinux),
  maldet, cPGuard, ClamAV and rkhunter databases, and cPanel's own bundled
  third-party code. All vendor trees owned by root, outside any customer home —
  if one is compromised the machine is lost in ways this module cannot help
  with. **No customer path is ever excluded by default.**

  Operators can add their own from **Scanner → Scan exclusions**: plain paths
  and `*`/`**` globs, one per line. Deliberately *not* regular expressions — a
  path should not be able to switch scanning off through a stray character. `/`
  and `*` alone are refused outright for the same reason.

  There is also a **"Not malware" button on every threat row**, because the
  moment an operator is looking at a finding is the only moment they have the
  context to judge it wrong, and a "would this path be scanned?" test so a rule
  can be checked before it is trusted.

  **Both engines honour them.** These detections came from the real-time
  daemon, not the scanner; if only one side excluded them a file would be
  quarantined in real time and then declared clean by the next scheduled scan.

### Fixed

- **A finished scan was polled for ever and never showed complete.**
  `followScan()` cleared its timer only on `done` or `error`. The backend also
  writes `cancelled`, `skipped` and **`interrupted`** — the last whenever a
  worker dies and `reapStaleJobs()` closes the row out. None of those stopped
  the poll.

  It now lists the **active** states and treats everything else as finished, so
  a status added later ends the poll rather than looping silently. Having that
  the wrong way round is what caused this.

- **The Scanner page had no Refresh button** — the only module page without
  one, which is why a completed scan could not simply be re-read.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
