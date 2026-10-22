# ServerScrub 4.15.0

[4.15.0] - 2026-10-22

### Added

- **Deliver queued mail from Spam Monitor**, selected or in bulk — the action
  cPanel's Mail Queue Manager calls *Deliver*. It runs `exim -M`, which attempts
  delivery immediately and ignores the retry schedule. That is usually the right
  tool: mail sits in this queue because a timer has not expired, not because
  anything is permanently wrong. A Gmail `421-4.7.0` rate limit or a full
  recipient mailbox parks a genuine customer message for hours.

  Three things this had to get right that deletion does not:

  - **It thaws.** The Exim specification is explicit: with `-M`, frozen messages
    "are automatically thawed before the delivery attempt". Frozen means Exim
    already gave up, so this is not a neutral retry. The dialog says how many of
    the selected messages are frozen and what delivering them will do.

  - **It blocks on the network.** Deletion is a local unlink; a delivery attempt
    is an SMTP conversation with a remote server that may be slow or
    black-holing. Each attempt is bounded by its own `timeout`, the batch has an
    overall wall-clock budget, and anything not reached is reported as
    *not attempted* rather than silently dropped. Capped at **100** per call
    against deletion's 500, because the cost per item is a round trip.

  - **Exit 0 does not mean delivered.** `exim -M` exits 0 for an attempt that
    deferred — the message is still queued and Exim is perfectly happy.
    Reporting that as success would be a lie an operator then acts on, so the
    queue is re-read afterwards and *delivered* means **left the queue**. The
    result separates delivered from still-queued and names what failed.

  Admin-only, and it refuses an unconfirmed request: this is the only route in
  the module that sends. There is still no "flush the whole queue" action.

### Fixed

- **`confirm()` and `alert()` replaced with in-app dialogs** in Spam Monitor.
  Once a page has shown a few dialogs, Chrome and Firefox offer *"prevent this
  page from creating additional dialogs"*; after that `confirm()` returns false
  and `alert()` does nothing, silently. Every handler shaped like
  `if (!confirm(...)) return;` becomes a button that does nothing when clicked —
  which is exactly how the two "Not malware" controls shipped dead. **Delete
  selected** and **Headers** were both exposed to this.

  Correcting the record: 4.14.0 attributed that failure to cPanel's iframe
  suppressing modals. The plugin runs at a top-level URL, so dialog suppression
  in the browser is the likelier cause. The fix was right either way; the
  explanation was not.

  Eight other `confirm()`/`prompt()` calls remain elsewhere in the product with
  the same exposure — listed in the commit, not yet converted.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
