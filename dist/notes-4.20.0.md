# ServerScrub 4.20.0

[4.20.0] - 2026-10-27

### Added

- **Mail Queue, as its own section.** Spam Monitor answers *"who is sending too
  much, from which script"*. This answers *"find me that one message among nine
  thousand and tell me whether it goes out"*. Two different jobs; bolting one
  onto the other gave a tab where neither was answered properly.

  - **Inbound / outbound split**, decided by whether the recipient domain is in
    `/etc/localdomains`. On a cPanel box that one distinction separates *"my
    customers' mail is stuck"* from *"we are relaying spam"*. When
    `/etc/localdomains` cannot be read the page says so rather than guessing.
  - **Search** on sender, recipient, subject or message id, with
    *contains / begins with / ends with / equals* and a **NOT** toggle, plus
    filters for direction, state (normal, frozen, bounces) and age.
  - **Cached snapshot.** `exim -bp` on a large queue is expensive, and a UI
    that re-runs it for every search and page is unusable exactly when the
    queue is big enough to need searching. Refining a filter or paging reads
    the snapshot; **Rebuild snapshot** forces a fresh one.
  - **Delivery log per message** via `exigrep`, under a timeout — it scans the
    whole of `exim_mainlog`, which on a busy server is hundreds of megabytes.
    An empty result after a timeout is reported as *"may have been missed
    rather than absent"*, because those are not the same thing.
  - Deliver and Delete reuse Spam Monitor's existing implementations rather
    than duplicating the id validation, the caps, and the *did it actually
    leave the queue* check. Two copies of a destructive path is one too many.

- **Already-delivered recipients are marked.** `exim -bp` prefixes them with
  `D`, meaning the message is still queued only for the *others*. Listing them
  as pending told the operator the opposite of the truth. This also corrects
  the Spam Monitor queue listing.

### Note on prior art

Modelled on **ConfigServer Mail Queue**, now discontinued. cmq is **GPL-3.0**
(Copyright 2006–2025 Jonathan Michaelson) and ServerScrub is not GPL, so **no
code from it is used**. What is reused is knowledge that is not anyone's to
own: which `exim` command does what, and which questions an operator actually
needs to ask of a queue.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
