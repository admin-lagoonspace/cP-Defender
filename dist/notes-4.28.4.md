# ServerScrub 4.28.4

[4.28.4] - 2026-11-02

### Fixed

- **`--diagnose` read cPanel's source of truth and called it the state.** It
  printed `/var/cpanel/userdata` as "what cPanel thinks" and stopped. On a live
  server that directory read perfectly -- correct account, correct
  `documentroot` -- while Apache 404d the site root. userdata is what cPanel
  will GENERATE `httpd.conf` from; it is not what Apache is running, and the
  two diverge whenever the config has not been rebuilt since the domain was
  created or moved. Every source of truth then agrees except the one actually
  serving requests.

  It now reads the generated `httpd.conf`, pulls the `DocumentRoot` out of the
  vhost block for that `ServerName`, and says plainly whether there is no
  vhost at all or a stale one -- with `/scripts/rebuildhttpdconf &&
  /scripts/restartsrv_httpd` in both cases. Reading the source and calling it
  the state is the same mistake as writing a cron and not reading it back,
  which this script already refuses to make twenty lines earlier.

- **One 404 could not tell two failures apart.** The probe asked Apache only
  about the published file. A 404 there means the path is missing from a vhost
  that otherwise works; a 404 for the site root as well means there is no
  working vhost for that Host at all and the request is landing on the default
  one. Same status code, unrelated fixes. It now asks for both and names the
  combination.

- **A healthy account looked like a finding.** The domain-collision check
  counted vhost FILES, and every domain has a plain one and an `_SSL` one, so
  a perfectly normal account printed "vhost files naming serverscrub.com: 2".
  A number that reads as a problem and is not sends the reader after the wrong
  thing. It counts accounts now, and only flags more than one.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
