# ServerScrub 4.21.3

[4.21.3] - 2026-10-28

### Fixed

- **Cloudflare edge addresses were being blocked.** Two of them were sitting in
  `/etc/csf/csf.deny` on a live server with our name on them. A site behind a
  CDN logs the *edge* as its client, because the visitor's address only ever
  arrives in a header — so a few hundred failed logins arriving through one
  edge looked like one attacker, crossed the threshold, and got the proxy
  blocked.

  That is wrong twice over. The attacker returns through another of thousands
  of edges, so the block achieves nothing; and every genuine visitor routed
  through that edge is dropped, invisibly, because those requests never reach
  the server to be logged.

  Blocking now goes through a guard in `Firewall::blockIP()` — the one gate
  every block in the product passes through, rather than a check each detector
  has to remember. A proxy address is refused with the provider named and the
  remedy stated, and HTTP log parsing now reads the originating client out of
  the line when the proxy recorded one, so the attacker is counted instead of
  the edge. An explicit `force` still allows an operator who means it.

  The forwarded address is matched on *shape* — a quoted field that is entirely
  a list of IP addresses — rather than on field position, so it works across
  log formats and can never hand back the user agent.

- **The scheduler had no lock, and was running twice.** 49 of 141 addresses in
  that same `csf.deny` had been written **twice**, the pairs 0–1 seconds apart,
  always on a quarter hour — one cron tick overlapping the next. A run that
  takes longer than fifteen minutes is still going when the following one
  starts, and then both parse the auth logs, both read the mail queue and both
  block the same offenders.

  The duplicate deny lines were only the visible part: on a busy server — which
  is exactly when a run overruns — the product was doing all of its work twice,
  and the overlap grew the busier the box got. `scan.php` has guarded itself
  since 3.x; the entry point that runs everything else never did. It now takes
  a non-blocking exclusive lock and stands aside, while `--status` and
  `--dry-run` deliberately take no lock.

- **A refusal from the proxy guard is no longer overwritten by CSF.** Those two
  Cloudflare addresses were already in `csf.deny`, so the brute-force panel
  would have reported "already in csf.deny" and buried the only reason an
  operator can act on.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
