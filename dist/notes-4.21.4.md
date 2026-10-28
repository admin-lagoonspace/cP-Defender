# ServerScrub 4.21.4

[4.21.4] - 2026-10-28

### Fixed

- **Blocked Bots said "bot" on every row.** The Type column was useless: it
  showed the same word for a SQL injection tool, an SEO crawler and a
  WordPress exploit attempt, which warrant completely different reactions.

  The cause was not a missing feature. `threat_type` has been recorded since
  the first version, and the panel already fell back to it — the grouped query
  simply never selected the column, so the fallback fired on every row. It is
  selected now, and each row carries a one-line description saying what the
  bot was doing and which tool it was, with the full user agent on hover:

  - `Scanning for known vulnerabilities (sqlmap)`
  - `Crawling the site for its own index (AhrefsBot)`
  - `Attacking WordPress login or XML-RPC (a Python script)`

  Rows from before the type was recorded read `Automated client`, and an empty
  user agent is called out as such — an ordinary browser always sends one, so
  its absence is itself the finding.

- **Recent Bot Events labelled anything unclassified as a scanner.** The badge
  defaulted to the literal string `scanner` when no type was stored, so an
  unrecognised client was reported as an attack. Both tables now say
  `unclassified` and mean it.

- **Bot Shield blocked around the firewall gate.** It shelled out to `csf -d`
  itself, so it bypassed every check `Firewall::blockIP()` performs —
  including the proxy guard added yesterday, which meant Bot Shield could
  still put a Cloudflare edge into `csf.deny` after that guard shipped. It now
  goes through the gate, and asks the firewall *before* writing the event
  rather than after, so a refused block is never recorded as a block.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
