# ServerScrub 4.17.0

[4.17.0] - 2026-10-23

### Added

- **Brute Force now reconciles with the defences already on the server.** A
  cPanel box runs CSF's lfd, and usually cPHulk, before this product is
  installed. Reporting *"Not blocked"* while lfd dropped the address minutes
  ago was true of ServerScrub and false of the server — and it invited an
  operator to go and fix a problem that did not exist.

  | what is true | what the row says |
  |---|---|
  | lfd already denied it | **Blocked by lfd** *(green — the server is protected)* |
  | it is in `csf.allow` | **In csf.allow** · CSF will not deny it |
  | genuinely nothing blocking it | **Not blocked** |

  Read from CSF's own files — `csf.deny`, `csf.allow`, `lfd.log` — parsed once
  per page rather than forking `csf -g` per row.

- **When CSF refuses a block, CSF explains why.** The generic *"the firewall
  refused the block"* is replaced by the actual cause, which is almost always
  one of three knowable things: the address is in `csf.allow`, it is already in
  `csf.deny`, or CSF is in TESTING mode.

- **`TESTING = "1"` is now called out.** It is the single most common reason
  blocks do not hold: CSF writes every rule it is given and a cron flushes them
  minutes later, so *no* block holds — ours or lfd's. The banner says so and
  gives the fix (`TESTING = "0"`, then `csf -r`), and it overrides every other
  message, because nothing else is worth reading while that is true.

- **A line naming the other engines**: *"Also defending this server: CSF/lfd ·
  1,842 denied · cPHulk"*, or plainly that none was detected. The page used to
  imply ServerScrub was the only thing between the server and the internet.

`ExternalDefence` is strictly read-only and bounded — capped file reads, a
tailed `lfd.log`, no writes and no shell-outs — and a test enforces that.

### Changed

- `t_fn_body()` moved into `tests/assert.php`. Fixed-size `substr()` windows in
  three tests silently truncated when the functions grew and then reported bugs
  that were not there.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
