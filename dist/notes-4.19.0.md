# ServerScrub 4.19.0

[4.19.0] - 2026-10-26

### Added

- **Subjects in the queue listing.** `exim -bp` does not report one, so the
  listing was a wall of message ids and addresses with no way to tell a receipt
  from a relay at a glance — which is most of why ConfigServer Mail Manage was
  pleasant to use.

  Read from the spool header file **directly**, never by forking `exim -Mvh`
  per message: on a 93,000-message queue that is the difference between 200
  file reads and 200 forks. Bounded three ways — at most 250 header files per
  listing, each read capped at 64 KB, and only for messages already selected
  for display. `split_spool_directory` is handled (the subdirectory is the
  sixth character of the message id), and RFC 2047 encoded subjects are
  decoded.

### Fixed

- **Mail view had no mail in it.** The queue card hid itself until somebody
  clicked the QUEUE stat card, so the tab looked empty — and because the card
  declared no hidden state, a tab switch revealed it with nothing loaded,
  leaving a permanent *"Loading…"*. The queue is now simply what the Mail view
  tab **is**, and the page loader fetches it.

  Cards that genuinely do hide themselves (findings, delivery problems) now
  declare `data-mg-hidden="1"` in the markup, so an unset flag can never again
  be read as "show it".

- **"Senders, last 24 hours" moved to Logs.** It is history, not live mail.

- **The queue's "Close" button emptied the tab.** With the queue as the tab's
  only content, hiding it left a blank page. Replaced with **Show all**, which
  clears the filter — what an operator actually wants from a button beside a
  search box.

### Note

The queue filter matches sender and recipient, not subject: filtering happens
before the spool headers are read, and reading every header in a large queue to
support it would cost far more than the feature is worth. The search box says
so rather than implying otherwise.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
