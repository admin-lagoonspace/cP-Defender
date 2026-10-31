# ServerScrub 4.23.1

[4.23.1] - 2026-10-31

### Fixed

- **The updater corrupted itself mid-run.** Updating to 4.23.0 applied every
  file and then died:

  ```
  ✔  Updated: update.sh
  /usr/local/serverscrub/update.sh: line 642: ater: command not found
  ⚠  Update failed — rolling back to v4.22.5
  ```

  `ater` appears in no file in this repository. `update.sh` is in
  `UPDATE_FILES`, so the updater copies the new version over **itself** while
  bash is still reading it. Bash does not read a script in one go: it reads
  incrementally and remembers a byte **offset**. Replace the file underneath it
  and execution resumes at that offset in different content — landing mid-word
  and running the tail of one as a command.

  This has been in the updater for its whole life. It only fires when a release
  changes the length of `update.sh` enough to move the offset somewhere
  harmful, so every previous update survived on luck. 4.23.0 added ten lines
  for the legacy download channel and moved it.

  `update.sh` now re-execs from a private copy under `/tmp` before doing any
  work, so the file bash is reading is never the file being overwritten. The
  copy is unlinked immediately — the descriptor keeps it alive, so an
  interrupted run leaves nothing behind. Only the **installed** copy re-execs:
  `upgrade.sh` already runs a fetched updater out of `/tmp`, which is why it
  was never affected. A server that cannot stage a temp copy still updates
  rather than refusing outright.

  **If you are on 4.22.5 or earlier, update with `upgrade.sh`, not
  `update.sh`** — the copy of `update.sh` already on disk still has the bug,
  and it is the running script that matters. `upgrade.sh` fetches the current
  updater into `/tmp` and runs it from there:

  ```
  bash /usr/local/serverscrub/upgrade.sh --yes
  ```

  After that, every future update is safe either way.

- **Three copy errors during every update.** `install.sh --register-only` runs
  from the install directory, so `cp "${SCRIPT_DIR}/install.sh"
  "$INSTALL_DIR/"` and its two siblings were copying each file onto itself and
  printing `cp: ... are the same file` to stderr. Harmless — this script sets
  `pipefail` but not `errexit`, so it carried on — but printing three copy
  errors during every update is how an operator learns to ignore an updater's
  output. The copies are now skipped when the source and destination are the
  same directory, and it says so.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
