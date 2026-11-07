# ServerScrub 4.35.1

[4.35.1] - 2026-11-06

### Fixed

- **WAF events named the proxy, not the attacker.** On a live server the
  attacker list opened with the machine's own address, `51.68.163.24`, at
  1,780 hits, and loopback fourth at 848. Neither was an attack from the box:
  both are cPanel's nginx, which proxies to Apache for accounts with caching
  enabled, and ModSecurity writes its audit-log section A from the
  *connection*. The report's top line invited the operator to firewall their
  own web server.

  Those events were not noise. The loopback ones were asking for
  `/....//....//....//..../.env`, `/.aws/credentials`, `/.git/config` and
  `proc/self/environ` -- real credential theft, with no recorded source.

  `mod_remoteip` was **not** at fault, which is where this was first wrongly
  pinned. cPanel points it at a secret-suffixed header name, nginx sends the
  plain `X-Forwarded-For`, and it rightly declines to trust an unsigned one.
  Section A comes from the connection regardless. The address was in the
  request headers the whole time, and the parser was reading `Host` and
  `User-Agent` out of the same section while walking past it.

  The ingest now resolves the client from `X-Forwarded-For`, taking the
  **rightmost** hop rather than the leftmost: nginx builds that header with
  `$proxy_add_x_forwarded_for`, which appends what it saw to whatever the
  client sent, so the left of the chain is attacker-controlled text. Reading
  the leftmost entry -- the conventional "original client" reading -- would
  let any scanner choose who gets reported and firewalled by sending
  `X-Forwarded-For: 8.8.8.8`. Headers are consulted only when section A gave
  a proxy address; a request that reached Apache directly already has a
  trustworthy source.

  `CF-Connecting-IP` is preferred for sites behind Cloudflare, where the
  nearest hop is an edge rather than the visitor -- but only when the nearest
  hop is in fact Cloudflare, which corroborates it. Without that check a
  forged header on any non-Cloudflare site would be believed.

- **The triage told the operator to fix working configuration.** Its note
  asserted that `mod_remoteip` was not reading `X-Forwarded-For`. Wrong, and
  actionable, which is the bad combination. It now separates rows that predate
  this release -- unrepairable, because the header is in the audit log and not
  in the table -- from rows that arrived with no usable header at all.

- **The attacker list filtered private ranges, so a public address that
  happened to be this server led the report.** It now also excludes the
  `RemoteIPInternalProxy` entries cPanel writes into `httpd.conf` and the
  hostname's own resolution. CIDR blocks in that list are skipped -- those are
  Cloudflare's edge, a real intermediary rather than this machine.

### Added

- `waf_events.ip_source` and `waf_events.forwarded_for`, so attribution can be
  audited rather than trusted. An operator about to block an address can see
  whether it came from the connection, from a header, or not at all. Existing
  rows are left labelled empty: not backfilled, because they genuinely cannot
  be -- the header lives in the audit log, not in the table.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
