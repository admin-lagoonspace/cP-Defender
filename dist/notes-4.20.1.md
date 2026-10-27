# ServerScrub 4.20.1

[4.20.1] - 2026-10-27

### Fixed

- **The Mail Queue filter did nothing.** Type `inditdel`, press Search, get
  *"57 of 57 matching"*.

  Text was only honoured when a **Field** had also been chosen, and the default
  Field was *"— no text search —"*. So the obvious action — type a word, press
  Search — matched everything and reported a number that looked like a result.
  A filter that ignores what you typed is worse than no filter: it answers a
  question you did not ask and looks like it worked.

  The default is now **Sender, recipient or ID**, all of which are already in
  the snapshot and cost nothing extra. Text with no field selected searches
  those rather than being discarded. Subject stays an explicit choice and is
  labelled *"slower — reads each message"*, because it is a file read per
  message.

### Removed

- **The queue inside Spam Monitor, and its filter.** It duplicated the Mail
  Queue section with fewer capabilities, and the weaker of the two was the one
  an operator met first. Finding a message among thousands is now one job in
  one place.

  The QUEUE and FROZEN cards still work — they cross to Mail Queue, carrying
  the frozen filter with them. `reloadMailQueue()`, `openMailQueue()`,
  `showAllQueue()`, `toggleAllQueue()`, `deliverSelectedQueue()` and
  `deleteSelectedQueue()` are deleted rather than left orphaned.

### Changed

- Spam Monitor's tabs are now **Findings · Settings · Logs**. With the queue
  gone, "Mail view" held only the findings card, so the tab is named after what
  is actually on it.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
