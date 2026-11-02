# ServerScrub 4.28.5

[4.28.5] - 2026-11-02

### Added

- **`--diagnose` now separates "this path" from "this disk".** It writes two
  brand-new files -- one at the document root beside the homepage that is
  known to work, one in the published directory -- requests both from Apache,
  and removes them. Three outcomes, three unrelated problems:

  - both served: the published files themselves are what Apache will not serve
  - only the root served: something path-specific (an Alias, a Location or a
    rewrite in the vhost include), and it prints where to grep
  - neither served: Apache is not reading that directory at all. On cPanel
    that is jailed Apache, where a vhost is served out of a per-account bind
    mount under `/home/virtfs` which can be stale or predate the directory.
    It checks whether that mount exists before saying so, and gives
    `/scripts/clear_orphaned_virtfs_mounts` when it does and `findmnt` when it
    does not.

  Everything before this could report five facts that were each correct --
  vhost works, DocumentRoot right, permissions right, one account, file on
  disk 644 -- and still not say which of two unrelated things was wrong.

### Fixed

- **A named `.htaccess` with nothing printed under it read as a clean bill of
  health.** The walk grepped for `Rewrite`, `Deny` and friends, matched
  nothing in a `.htaccess` that was sitting right there, and printed only the
  path. These files are a few lines; they are printed whole now.

- The probe files are written into a live customer's document root, so the
  removal is registered as a trap **before** the first write rather than
  trusted to be reached -- a `^C` in between would otherwise leave litter in
  somebody's `public_html`.

- The probe uses the port Apache actually answered on. On the server this was
  written for that is `:81`, which is not where a list of likely ports starts.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
