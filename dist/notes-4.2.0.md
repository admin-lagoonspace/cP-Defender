# ServerScrub 4.2.0

[4.2.0] - 2026-10-15

### Added
- **Escalating blocks for repeat offenders.** More than four failed logins from
  one address inside the window now earns a three-hour block; coming back after
  serving it earns six hours, then twenty-four, then a permanent block. The
  strike count — not the attempt count — drives the ladder, so an address that
  returns patiently still climbs it. The ladder is editable per-server
  (`bf_ladder`, in the Brute Force settings panel); leaving off the final `0`
  means the last term repeats and nothing is ever blocked permanently, which is
  a deliberate choice an operator is allowed to make.
- The offenders table now says which term is being served and how long is left,
  and for an address merely being watched, what its next offence will cost.

### Fixed
- **Expired firewall blocks are now actually lifted.** `blockIP()` has written
  `expires_at` since the firewall module shipped, and nothing anywhere ever read
  it: every "temporary" block was permanent at the firewall while the database
  reported a deadline. An operator who believes a block is temporary does not go
  looking for the customer it is silently holding out. `Firewall::expireBlocks()`
  now sweeps them on the schedule. Permanent blocks are never touched.
- **Brute force now blocks at all.** The block path required the address to have
  never been blocked before, and since nothing ever cleared that flag, an address
  was blocked at most once ever — in practice, with nothing expiring anything,
  addresses accumulated hundreds of failures while the page showed "Watching"
  and did nothing. Reported from a live server with 234 and 266 failures listed
  as watched.
- The strike count is no longer pruned on the attempts clock. Attempts are
  evidence and expire in a week; strikes are history and are kept for 30 days
  (`bf_offence_memory_days`), or an attacker returning every eighth day would
  have been blocked for three hours for ever.
- Attempts recorded before a block are discarded when its term ends, so a
  released address is not instantly re-blocked on evidence it has already been
  punished for — which would have collapsed the whole ladder to "permanent"
  within minutes.

### Changed
- The failure threshold default drops from 10 to 5. Existing installs are
  migrated once; a threshold an operator sets afterwards is left alone.
- `bf_block_duration` is removed. It no longer drove anything once the ladder
  landed, and the settings panel offering it was a control that did nothing.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
