# ServerScrub 4.18.0

[4.18.0] - 2026-10-26

### Added

- **Message view.** A **View** button on every queued message opens sender,
  recipients, subject, date, the sending script, every attachment, and the
  **first 1,000 characters** of the body.

  This module read headers and never bodies on purpose â€” *"the body is a
  customer's private mail and nothing here needs it to tell a relay from a
  receipt"*. That still holds for **everything automatic**: the log collector
  is unchanged and never reads a body. What changed is that an operator can
  open one specific message, and the safeguards are that it is capped at 1,000
  characters, admin only, **written to the security timeline**, and bounded at
  the pipe (`head -c`) so a 50 MB message costs 2 MB of I/O rather than being
  read whole to show a preview.

- **Flag an attachment as malicious**, with its sha256 recorded so the malware
  scanner recognises the same bytes if they ever land on disk. Flagging
  **records, it does not alter the message** â€” exim has no clean way to strip
  one part from a queued mail, and a half-rewritten message is worse than a
  flagged one. Delete the whole message if that is what you want.

  Attachments whose extension or type is commonly used to deliver malware
  (including double extensions like `shipment.pdf.exe`) carry a **risky type**
  hint. A hint, never a verdict â€” the flag is the operator's to set.

  An attachment that ran past the 2 MB read cap is reported as *"not hashed â€”
  message too large"* rather than given a hash of part of a file. A hash of a
  fragment is not that file's hash, and acting on it later would be acting on
  a fiction.

- **Tabs: Mail view Â· Settings Â· Logs.** The page was five stacked cards mixing
  live mail, policy and history, so the thing an operator came for was never on
  screen. The KPI row stays visible on every tab â€” those four numbers are the
  reason to open the page. Cards that hide themselves (the queue, findings,
  delivery problems) keep their own state across a tab switch, so an empty card
  never gets forced open to look broken.

- **A Logs tab listing everything flagged**, with hash, message, who flagged it
  and when, and a one-click withdrawal.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
