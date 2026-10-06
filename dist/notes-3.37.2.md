# Sentinel Gate 3.37.2

[3.37.2] - 2026-10-06

### Fixed
- **The firewall page is fast now, and cannot go slow again.** This was
  reported three times. The first fix removed a pointless `csf -l`; the second
  bounded the commands and cached them for 60 seconds. Both missed the real
  problem: **the work was still on the request path.**

  A 60-second cache still means one request a minute pays for an `iptables -L`
  that can sit waiting on the xtables lock — and because cpsrvd serialises
  requests, that one request stalls every other page behind it. Caching made
  the slowness intermittent, which is why it kept being reported after being
  "fixed".

  Nothing on a page load spawns a process any more. `iptables` and CSF are
  measured by the scheduler, once at install, and the page only reads what they
  left behind. Measured with 3,000 blocked addresses: `getStats()` returns in
  **0.4ms**, and the test fails if any shell call reappears on that path.

- **"Not measured yet" is now distinguishable from "zero rules".** Reporting an
  unmeasured server as `0 iptables rules` reads as "no firewall", which is a
  very different claim. There are three states: measured, measured-and-failed,
  and not yet measured.

### Added
- **Every API response carries how long it took** (`ms`), and anything over a
  second is logged as a slow request. Two attempts at this page were spent
  reasoning about which call was slow without ever timing one.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
