# ServerScrub 4.16.0

[4.16.0] - 2026-10-23

### Fixed

- **Brute Force said "Watching" for four different things, one of them a
  fault.** Every offending address rendered the same amber badge â€” including
  one with 398 port-scan hits. That status is produced whenever `blocked=0`,
  and `blocked=0` has four very different causes:

  | cause | now reads |
  |---|---|
  | below the auto-block threshold | **Watching** Â· blocks at 5 in 10m |
  | auto-block switched off | **Would block** Â· auto-block is off |
  | the firewall refused the block | **Block FAILED** Â· *with the reason* |
  | address is on the allow list | **Allow-listed** |

  Three of those mean nothing is protecting the server and one is an outright
  bug, so showing them identically is how an address knocking 398 times sat
  there looking as though that were the plan.

- **A refused block vanished without trace.** Escalation only set `blocked=1`
  when `Firewall::blockIP()` reported success; a refusal fell through with no
  log line, no event and no record, leaving the row at `blocked=0`. The reason
  is now persisted on the offender, logged at error level, and raised as a
  `brute_force_block_failed` security event. Nothing about a failure to defend
  the server should be quiet.

- **Every row offered "Release", including rows that were never blocked.** On
  those, `release()` does not unblock anything â€” it **deletes the strike
  history**, close to the opposite of what the label implies. Unblocked rows
  now offer **Block** and **Forget**; blocked rows keep **Release**. An
  allow-listed row offers only Forget, since blocking it would contradict the
  allow list.

### Added

- **Block now**, straight from the offenders table, for an address that has
  earned it but has not been blocked. The answer to "why is this still only
  being watched" should not be "go to the Firewall page and retype it". Its
  failure reports the firewall's actual reason rather than "failed".

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
