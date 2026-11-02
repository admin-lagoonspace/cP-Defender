# ServerScrub 4.28.2

[4.28.2] - 2026-11-02

### Fixed

- **The CDN sync could not take its own lock, and died before doing
  anything.** On the first live run:

      /home/serversc/bin/cdn-sync.sh: line 53: /tmp/sg-cdn-sync.lock: Permission denied

  A fixed name in `/tmp` belongs to whoever created it first. `cdn-sync.sh`
  runs as an unprivileged cPanel user on a machine full of other accounts, so
  if root -- or any of them -- got there first, this user cannot open it for
  writing, and the sync dies every ten minutes for ever having published
  nothing. The same name is also squattable as a symlink, and `curl -o`
  follows one that is already in place.

  The lock, the download staging directory and the `get.sh` comparison file
  all moved to `~/.serverscrub-cdn`, mode 700. Nothing of this script's is in
  `/tmp` any more.

- **`cdn-setup.sh` pins that directory in the cron line.** cron often runs
  with no `HOME`, so left to the fallback the cron run and the one-off run
  would lock different files -- and a lock two processes cannot both see is
  not a lock.

- **A failed setup said two contradictory things in one breath.** It printed
  "The sync did its job; something between that directory and the web has not"
  and then, four lines later, "latest.json is NOT in <docroot> -- the sync did
  not publish". It now checks which failure it is before suggesting a cause,
  and stops rather than sending anyone to `dig` and certificates when the sync
  never ran. Printing a diagnosis and its own contradiction underneath it is
  how the CDN 404 survived six releases; it does not get to happen in the
  script written to end that.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
