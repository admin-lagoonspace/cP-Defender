# ServerScrub 4.29.1

[4.29.1] - 2026-11-03

### Fixed

- **`--yes` silently rolled a server BACK a version.** On a live server:

      Updated from v4.28.10 -> v4.28.9

  Nobody asked for that. The guard warned that the offered version was not
  newer, skipped its confirmation prompt because `--yes` was given, and then
  fell straight through to the install. A mirror serving an older build plus
  `--yes` was enough to replace a newer install with an older one and report
  "Update complete".

  `--yes` means "do not ask me the routine question". It does not mean "do
  anything at all without asking". Installing an older build over a newer one
  is a different act from updating -- it is how a server quietly loses fixes
  -- and it now has to be asked for by name with `--allow-downgrade`.
  Otherwise the updater refuses and exits non-zero.

  The refusal explains the likely cause, which is a mirror that has fallen
  behind rather than a withdrawn release, and gives both commands: the one
  that takes the newest build from a named channel, and the one that performs
  a rollback that really is intended. An interactive rollback now names both
  versions and the word OLDER instead of asking to "force reinstall".

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
