# ServerScrub 4.11.0

[4.11.0] - 2026-10-20

### Fixed

- **The Spam Monitor's loudest alarm was a false positive, on a live server.**
  It reported `mailnull` as the top sender at **3,114 messages an hour**,
  marked it **critical**, ranked it above a real customer account, and offered
  a "Cap rate" button beside it.

  `mailnull` is the user **exim itself runs as** on cPanel. That traffic is
  exim processing mail, overwhelmingly bounces — not an account sending spam.
  `magicspam` appeared for the same reason: it is MagicSpam's own system user.
  Capping either would have run `whmapi1 modifyacct` against something that is
  not a cPanel account at all.

  A detector whose loudest alarm is always the same false positive trains the
  operator to ignore it, which costs more than having no detector. Mail-system
  accounts are now excluded from send-burst findings.

  Their volume is **not** discarded: 3,114/hour through exim's own user is
  almost always bounces, and a flood of bounces means spam has already left and
  is being rejected elsewhere. It is reported as `system_mail_volume` at
  medium, with advice that says plainly not to cap it and to look at the
  per-account table for who actually sent it.

### Added

- **The Queue and Frozen cards are clickable** and list the messages behind
  them — age, size, sender, owning cPanel account, recipients and state — with
  a filter by sender or recipient.

- **Per-message deletion.** Select messages, confirm, delete. **There is still
  no "empty the queue" button and there will not be one:** during the incident
  this module was built after, 92,954 of 93,255 queued messages were the relay,
  which still left **301 that a real customer was waiting for**. A flush
  destroys those with no record of what they were.

  Deletion is capped at 500 per call so one click cannot clear a 93,000-message
  queue, every id is validated against exim's id format before it can reach a
  root command, and what is being destroyed is logged **before** it is
  destroyed — afterwards there is nothing left to log.

- **Message header inspection**, including cPanel's `X-Source` headers, which
  name the script that generated the mail. That is the same answer exim's
  `cwd=` gives in the log, from the other side — and on servers whose log does
  not carry `cwd=`, it is the only place the script name exists. **Headers
  only, never the body:** the body is a customer's private mail and nothing
  here needs it to tell a relay from a receipt.

- The list says when it is showing a page of a larger queue. A table showing
  200 of 93,000 with nothing saying so invites a "delete selected" that looks
  complete and is not.

### Notes

- Input validation in `deleteMessages()` now runs **before** the exim binary is
  located. Validation must not depend on a binary being present, or a server
  without exim would answer "exim not found" to a hostile id and never record
  that it was hostile.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
