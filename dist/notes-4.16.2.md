# ServerScrub 4.16.2

[4.16.2] - 2026-10-23

### Fixed

- **CSF was never detected, so nothing was ever blocked.** Backend detection
  ran `command -v csf`. A CGI does not inherit a login shell's PATH â€” under
  cPanel it is typically `/usr/local/bin:/bin:/usr/bin`, with **no
  `/usr/sbin`** â€” so `csf` was not found on a server with CSF plainly
  installed, detection fell through to `none`, and every block was refused.

  The engine now carries its own PATH for firewall tools, locates CSF **on
  disk** (`/usr/sbin`, `/usr/local/sbin`, `/usr/bin`, `/usr/local/csf/bin`,
  confirmed by `/etc/csf`), and invokes `csf` by absolute path. Which backend
  answered is reported alongside every result.

- **The real reason was discarded twice.** `FirewallEngine::block()` returned
  `No firewall backend available`; `Firewall::blockIP()` passed back only
  `success` and `output`, never `error`; and the brute-force escalation reads
  `error`, so it substituted a generic *"the firewall refused the block"*. The
  tool's own message now survives to the panel.

- **A refused block was still recorded as a block.** `blockIP()` wrote the
  `blocked_ips` row *before* checking whether the firewall accepted anything,
  so the Firewall page listed addresses as blocked while packets from them
  arrived normally. The row is now written only on success â€” the most
  expensive kind of wrong a security tool can be is the kind that makes the
  operator stop looking.

### Changed

- **One banner instead of twenty red badges.** When blocking is broken it is
  broken for every address; repeating the same sentence on each row buried the
  one fact that mattered. The offenders table now carries a single alert
  naming the reason, the usual cause, and the consequence â€” *"detection is
  still running but nothing is being blocked"* â€” and each row reads simply
  **Not blocked**.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
