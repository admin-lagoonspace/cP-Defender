# Sentinel Gate 3.29.0

[3.29.0] - 2026-09-23

### Added
- **Sentinel Gate now appears in the Security section of cPanel for every
  user**, not only in WHM, and the page behind it is a real one.

  Two things stood in the way. The menu entry was gated on a cPanel feature
  that was only ever enabled in `/var/cpanel/features/default`, so every account
  on a reseller's own feature list -- which is most accounts on a reseller box
  -- had the entry hidden. And the page behind it was a redirect to the WHM
  dashboard, which authenticates against WHM, so any user who did reach it
  landed on a login they could never pass. The entry is no longer feature-gated,
  and the flag is written to every feature list rather than only `default` for
  operators who want to add the gate back.

- **A per-user security page.** It shows that account's detected threats, its
  WordPress/Joomla/Drupal installations with versions and whether an update is
  available, and any changed files -- with paths relative to the account's home.

  It reads exactly one file: `~/.sentinel-gate/report.json`, written by the
  privileged side after each scan. It does not talk to the API or the database,
  and it must not: the database directory is `0700 root` and the data is
  server-wide, so reaching it from a page every hosting customer can load would
  require either a setuid helper or loosening those permissions, and both would
  hand every customer on the box a route to the whole server's security data.
  Reading a file in the caller's own home makes cross-account disclosure
  impossible by construction rather than by a filter someone has to maintain.

- **`UserReport`**, which generates those files as root. Every write here is
  root writing into a directory a hostile user can rearrange, so it refuses to
  follow a symlinked home or report directory, verifies the home is owned by
  the account it names, creates the directory without creating parents, and
  renames the report into place rather than opening whatever is already there.
  It is scheduled hourly, generated during install so the plugin is not empty on
  day one, and rebuildable with `sentinel user-reports`.

### Fixed
- A table a module has not created yet -- `cms_installs` before CMS Guard has
  ever run -- raised a PDOException that aborted report generation. As the
  hourly task, for every account on the server. A module that has not run yet
  means nothing to report, not that reporting is broken.
- `scripts/preflight.py` walked only `backend/` and `scripts/`, so the new
  `cpanel/` page -- the file with the widest audience in the product -- had
  neither the empty-file nor the parse gate applied to it. That is the same
  blind spot that shipped a zero-byte `config.php` in 3.19.2.
- The release archive now carries `cpanel/`, and `tests/test_packaging.php`
  fails the build if the user page is missing: without it the installer has
  nothing to copy and the menu entry opens a blank page for every customer.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
