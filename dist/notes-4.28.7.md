# ServerScrub 4.28.7

[4.28.7] - 2026-11-03

### Fixed

- **`--diagnose` was interrogating the wrong vhost and drawing confident
  conclusions from the answers.** Apache selects a vhost by IP:port FIRST and
  ServerName second, and cPanel binds each account's vhost to that account's
  own IP. A request sent to `127.0.0.1` can therefore match no vhost on that
  address and fall through to the DEFAULT one -- which answers 200 for `/`
  (the server's own page) and 404 for every other path.

  By status code alone that is indistinguishable from "Apache cannot see this
  directory", and on a live server it produced precisely that reading: 200 for
  `/`, 404 for a brand-new file written beside the working homepage, and a
  verdict about stale bind mounts derived entirely from a vhost that was not
  the site.

  The probe now sends to the vhost's IP from cPanel as well as the loopback,
  **fingerprints the real site's `/` first** and compares every answer against
  it, and reports which site replied. When nothing reaches the right vhost it
  says so, disclaims the numbers above it, and prints the `httpd -S` lines
  naming the default server and the namevhosts -- which is the question at
  that point. The two-file test then uses the address proven to reach the
  site, not the assumption that produced the wrong reading.

- The "Apache is not reading that directory" verdict states the precondition
  that makes it meaningful, and when it is not VirtFS the script **runs**
  `findmnt -T` on the docroot instead of printing it for the operator to run
  -- with `/proc/mounts` as a fallback. Suggesting a command the script could
  have executed is another round trip for nothing.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
