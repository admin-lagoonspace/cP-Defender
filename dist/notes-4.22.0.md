# ServerScrub 4.22.0

[4.22.0] - 2026-10-30

### Added

- **cPanel users can scan their own account.** The per-account plugin already
  appeared in cPanel's Security section for every user and showed the findings
  from the last server scan, but it was read-only — it ended by telling the
  customer to email their host. It now has a **Scan my account** button, which
  is what cPGuard offered and what customers actually want.

  The page runs as the customer and must never reach the database (0700 root)
  or the API (admin role). `UserReport` already solved the outbound direction
  by having root write a report into the customer's own home; this is the same
  boundary in reverse. The button writes a small request file into that same
  directory, and the privileged side picks it up on its next tick.

  **Nothing in that file is trusted.** The path to scan is derived from the
  account's passwd entry, as root — never read from the request. A request
  naming `/root` would otherwise be a request to scan `/root`. The file is
  refused if it is a symlink, if it is not owned by the account it claims to
  come from, if it exceeds 4 KB, or if its timestamp is in the future or more
  than a day old. It is written aside and renamed into place, so the
  privileged side never reads a half-written file and discards the request as
  malformed.

  **Both limits are enforced as root, not in the page.** One scan per account
  per cooldown window (default 6 hours, `user_scan_cooldown_hours`) and at most
  a fixed number started per tick server-wide (default 1,
  `user_scan_max_per_run`, hard-capped at 10). A button every customer can
  press that starts a ClamAV run is a denial-of-service feature unless it is
  bounded — this product runs on an 8-core server whose recurring problem is
  load. A customer who edits their own request file gains nothing, because
  this side decides.

  Pending requests are served **oldest first**: directory order would let an
  account early in the alphabet starve one late in it every time the cap bites.
  A request that is declined for cooldown is **kept**, not discarded, so the
  customer's click does not vanish silently and leave them clicking again. The
  existing refusal to scan while a backup is running applies here too, so a
  customer cannot start a scan that competes with JetBackup for the same disks.

  The whole integration remains cPanel-only, gated on `/usr/local/cpanel`
  existing, and the page still reaches nothing but the one file in its own
  home. Operators can switch the feature off entirely with
  `user_scan_enabled=0`.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
