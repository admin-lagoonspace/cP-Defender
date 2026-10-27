# ServerScrub 4.21.0

[4.21.0] - 2026-10-27

### Added

- **HTTP flood and scanner detection**, on the Bot Shield page, running every
  scheduler tick.

  Built after a live incident: one address took all eight cores of a server to
  **load 22 with 1.2% idle**, and this product reported nothing.
  `185.177.72.49` sent 1,963 of 2,000 requests on a single vhost, brute-forcing
  filenames across *every* site on the box â€” `/.env`, `/.git/config`,
  `/settings.py`, `~/.aws/credentials`.

  Every request was a **404**. No failed logins, no malware on disk, no error
  spike â€” nothing any existing check watches. But WordPress serves 404s in PHP,
  so each miss was a full framework boot plus database queries.

  **Why Bot Shield missed it**, both reasons now fixed here:
  1. it reads `/var/log/nginx/access.log`, which on a cPanel box carries almost
     nothing â€” per-vhost traffic goes to `/var/log/nginx/domains/*`
  2. it classifies by **user-agent**, and the attack had no distinctive one

  So this keys on shape instead:

  | shape | catches |
  |---|---|
  | **404 storm** â€” one address, many misses, several sites | secret-hunting scanners |
  | **Endpoint flood** â€” many addresses, one costly path | `/xmlrpc.php`, `/wp-login.php` |
  | **Rate** â€” one address far above the rest | brute hammering |

  The endpoint detector exists because in the same incident ten addresses sent
  509 requests to `/xmlrpc.php` while **no single one** was busy enough to trip
  a per-address rate rule.

### Safety

An automatic blocker that locks the administrator out of the server it is
defending has done more damage than the attack. Three rails, all tested:

- the **Brute Force allow list** governs both modules, so there is one list
- **this server's own addresses**, read from the interfaces
- **any address that has reached the panel** in the last 24 hours, recorded on
  every authenticated request. On the day this was built the operator's own
  address appeared in the logs with 261 requests â€” inside some thresholds.

Loopback and private ranges are never candidates. Thresholds are clamped, and
the panel re-reads them from the server after saving so it cannot display a
value the detector is not using. **Monitor-only** is available and reports what
it *would* block.

Bounded throughout â€” at most 25 logs, 4,000 lines and 4 MB each, tailed never
read whole. `/var/log/nginx/domains` was 5.4 GB on the server this was written
for. Logs are chosen by **last write, not size**: during the incident, sorting
by size picked files eleven days stale while the live attack sat in a smaller
one.

A refused block records the firewall's own reason, is logged at error level,
and is surfaced in the UI.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
