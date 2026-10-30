# ServerScrub 4.21.5

[4.21.5] - 2026-10-30

### Fixed

- **Googlebot was blocked.** On a live server this product put
  `66.249.73.8` into `csf.deny`. Nothing stopped it: Bot Shield has a good-bot
  check, but it matches on the **user agent** and exists only in Bot Shield —
  HttpFlood and BruteForce had no concept of a good bot at all, so a crawler
  working through a site with dead links tripped the not-found threshold and
  was blocked outright.

  The cost is asymmetric, which is why this now sits ahead of the attacker
  case: a blocked crawler drops a customer's pages out of the search index,
  which they discover weeks later as unexplained lost traffic. A crawler we
  decline to block costs a few requests.

  Verification is by **address**, never by user agent — anyone can send
  `Googlebot`, and scrapers do precisely because so many products allow-list
  on that string. Published crawler ranges are checked first, then
  forward-confirmed reverse DNS, the method Google and Bing both document: the
  rDNS name must end in the operator's domain *on a dot boundary*, and a
  forward lookup of that name must return the same address. Whoever owns an
  address owns its PTR, so the forward check is what makes it the operator's
  claim about its own name rather than an attacker's claim about someone
  else's.

  Like the proxy guard, the check lives in `Firewall::blockIP()` — the one
  gate every block passes through — rather than in each detector. A check only
  Bot Shield performed is exactly what let this through.

  Google Cloud addresses are deliberately **not** covered: a rented VM is not
  a crawler, and treating Google's whole address space as untouchable would
  hand an allow list to anyone who can start an instance for an hour.

  Every DNS lookup on this path is bounded (`+time=2 +tries=1`) and there is
  no fallback to PHP's resolver, which cannot be given a timeout. On a loaded
  server DNS is the first thing to go slow, so an unbounded call would stall
  the response to an attack exactly when the attack is what made it slow.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
