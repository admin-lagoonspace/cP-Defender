# ServerScrub 4.28.9

[4.28.9] - 2026-11-03

### Fixed

- **Our Apache alias claimed `/serverscrub` on every website this server
  hosts, not just ours.** `install.sh` writes
  `/etc/apache2/conf.d/serverscrub.conf`, and `conf.d` applies to every vhost
  on the machine, so `Alias /serverscrub <dir>` captured that URL path on all
  of them. Any account with a directory of that name in its docroot had those
  URLs silently served out of our directory instead of theirs, with nothing
  on their side to explain it.

  That is the other half of the 4.28.8 bug: it is how
  `serverscrub.com/serverscrub/code/latest.json` returned 404 for six
  releases while the file sat on disk with correct ownership under a vhost
  with the correct DocumentRoot.

  **On cPanel the alias is now an exact match.** `/serverscrub/` there serves
  one static signpost that redirects to the WHM plugin -- it makes no API
  calls, and the dashboard's API candidates are all page-relative, so from
  `/cgi/serverscrub/` they resolve under cpsrvd and never touched this alias
  anyway. `AliasMatch "^/serverscrub/?$"` answers the signpost and lets
  `/serverscrub/<anything>` fall through to whatever site was asked for. The
  API alias and its `<Directory>` block are not emitted in that mode at all,
  since nothing routes to them.

  **Standalone is unchanged**, because it is the opposite case: there is no
  cpsrvd, Apache is the application server, the dashboard is served from this
  alias, and the subtree genuinely belongs to us.

  Existing servers get it on upgrade -- `update.sh` re-runs
  `install.sh --register-only`, which rewrites this config. A fix that landed
  only on fresh installs would leave every current server shadowing its
  customers' URLs indefinitely.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
