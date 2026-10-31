# ServerScrub 4.23.0

[4.23.0] - 2026-10-31

### Changed

- **Downloads moved to serverscrub.com.** The product has its own domain and
  cPanel account, so the release channel moved from
  `https://defender.lws-s1.com/serverscrub/code` to
  `https://serverscrub.com/serverscrub/code`. The path is unchanged — only the
  host — so published URLs keep the same shape.

  Updated across the installer (`get.sh`), the updater (`update.sh`,
  `upgrade.sh`), the update checker, the build and publish scripts, the CDN
  sync script, the webhook, the install docs and the tests. The CDN-side paths
  moved with the account: `/home/lwss1/...` became `/home/serversc/...`, and
  the sync script's docroot is now `/home/serversc/public_html/serverscrub/code`
  — the new account serves the domain from `public_html` directly rather than
  from a per-domain folder.

  **The old host is kept as a channel, tried after the new one.** The risk in
  a move like this is not the new URL, it is the servers already running: each
  has the old host baked into the `update.sh` on its disk and only learns the
  new one by taking an update. That direction is covered by the old host
  continuing to serve. The legacy channel covers the other direction — a
  server that *has* taken this update, on a day the new host is not yet
  reachable, still has somewhere to go. It can be removed once no installation
  predates the move.

  The changelog still records the old host in entries where releases genuinely
  used it. Rewriting those to match a later move would make the record lie.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
