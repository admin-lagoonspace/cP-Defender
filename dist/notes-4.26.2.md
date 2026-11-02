# ServerScrub 4.26.2

[4.26.2] - 2026-11-02

### Fixed

- **The installer announced cron entries it had not verified.** A live server
  was found running a current build with **no `user-scans` line at all** in
  `/etc/cron.d/serverscrub`. Every customer who pressed "Scan my account" saw
  *Queued* and nothing else — for eight hours — because nothing was scheduled
  to pick the request up, and every install and update had printed success on
  its way past. `install.sh` now greps the file it just wrote for both
  entries, says plainly when one is missing, and checks that the PHP those
  lines reference is executable before 03:00 proves otherwise.

- **`update.sh` now repairs a missing cron entry instead of only reporting
  it.** An update that can see the line is absent and leaves it absent has
  told the operator about a problem it could have fixed. It backs the file up
  first, since an administrator may have edited it too, and is idempotent.

- **Releases never checked whether the CDN was serving anything.**
  `publish.sh` printed "CDN mirrors automatically" and stopped. The CDN had in
  fact never been populated under the account the domain moved to, so every
  `serverscrub.com` download URL returned 404 — release after release.
  Installs kept working because they fall back to the GitHub mirror, which is
  precisely why nobody noticed. It now fetches `latest.json` from the CDN,
  reports which version is live, and prints the one-time setup when there is
  nothing there.

- `publish.sh` and `scripts/cdn-trigger-watch.sh` still named the old hosting
  account (`lwss1`) after the move to `serverscrub.com`, so the "force a sync"
  instruction pointed at a path that does not exist.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
