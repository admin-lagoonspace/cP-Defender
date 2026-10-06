# ServerScrub 4.0.0

[4.0.0] - 2026-10-06

### Changed — the product is now ServerScrub

Everything that answered to "Sentinel Gate" now answers to ServerScrub: the
install directory, the systemd units, the WHM and cPanel registrations, the
command-line tool, the database file, the WAF include and the logo.

| Was | Is |
|---|---|
| `/usr/local/sentinel-gate` | `/usr/local/serverscrub` |
| `sentinel-gate-monitor.service` | `serverscrub-monitor.service` |
| `sentinel-gate-web.service` | `serverscrub-web.service` |
| `/usr/bin/sentinel` | `/usr/bin/serverscrub` |
| `database/sentinel.db` | `database/serverscrub.db` |
| `sentinel-waf.conf` | `serverscrub-waf.conf` |
| WHM plugin `sentinel_gate` | `serverscrub` |

**Upgrading migrates in place; it does not install alongside.** An existing
server has its database, its quarantined files and its settings under the old
path, so the installer stops the old services, kills the detached scan workers
that outlive them, removes the old cron entries, deregisters the old WHM plugin
and Driver module, and then **moves** the directory — a move, not a copy, so
several hundred quarantined files cannot be left half-written. The database is
renamed along with its write-ahead log, so an uncheckpointed transaction is not
stranded. If something already exists under the new name, the old install is
set aside rather than either being overwritten.

The WAF include is renamed rather than deleted: Apache references it by name,
and removing it would silently drop every rule.

### Added
- The new logo throughout: the login screen, the header mark, the activation
  card, the browser tab icon, and the WHM and cPanel plugin icons. The two
  hand-drawn shield marks are gone — two different shields in one interface is
  one too many.

### Notes
- **You will be signed out once.** The session secret is derived from the
  product name, so existing tokens stop validating. Signing in again is all
  that is needed.
- The release history below is left as it was written. It records what the
  product was called at the time; rewriting it would be a false record rather
  than a rename.
- The internal `SG_` constant prefix is unchanged. It appears in roughly 400
  places, is never shown to a user, and renaming it would multiply the chance
  of one missed reference becoming a runtime fatal for no visible benefit. Say
  the word and it can follow as its own change.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
