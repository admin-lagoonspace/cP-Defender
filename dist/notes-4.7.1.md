# ServerScrub 4.7.1

[4.7.1] - 2026-10-20

### Fixed

- **The updater could abort in total silence, and did, on a production server.**
  A v4.4.2 install ran `update.sh` twice; both times it printed
  `Checking releases channel for latest version…` and returned to the prompt,
  having changed nothing and reported nothing.

  The cause was one informational line cross-checking
  `<channel>/latest/VERSION` to print a nicer message. Under `set -e` a plain
  assignment takes the exit status of its command substitution, and under
  `pipefail` a pipeline fails if any stage fails — so

      LIVE_VER="$(curl -fsSL "$URL" 2>/dev/null | tr -d '[:space:]')"

  does not leave `LIVE_VER` empty on a 404. It terminates the script, and
  because stderr went to `/dev/null`, without a word. It failed on the *first*
  channel, so the GitHub mirror that was working perfectly was never tried.

  **Eleven assignments in `update.sh` had this shape**, and every one of them
  was already followed by an `[[ -z … ]]` check or a fallback: the code was
  written expecting an empty value and the shell options silently defeated it.
  Two others were live landmines of their own — a `df` that cannot stat the
  install directory killed the updater one step before it started, and
  `ls -1dt "$BACKUP_ROOT"/*/` killed it mid-prune on any server whose backup
  directory exists but holds nothing, which is the second update a server ever
  runs.

- `scripts/check-shell-pipefail.py`, wired into preflight, fails the build on
  any new pipeline assignment in a shipped script that is not guarded.
  Dev-only scripts are reported as advisory: the same bug there fails on a
  maintainer's laptop with someone watching, not at 04:30 on a customer's
  server.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
