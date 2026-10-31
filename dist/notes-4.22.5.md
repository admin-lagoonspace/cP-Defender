# ServerScrub 4.22.5

[4.22.5] - 2026-10-30

### Fixed

- **A queued scan looked like nothing had happened.** The page said "Your scan
  is waiting to run. Scans are started a few at a time." — which tells a
  customer nothing they can act on and nothing that distinguishes a working
  queue from a broken one. A feature that was behaving correctly produced "is
  this thing on?"

  Every reason for a wait lives on the privileged side: the per-tick cap, the
  cooldown, the backup that refused the scan. The page had none of it, so the
  privileged side now records the reason and the page explains it:

  - `There are 2 accounts ahead of you in the queue. The server starts 1 scan
    each time it checks, so that other customers' sites stay fast while scans
    run.`
  - `The server could not start it yet: A backup is running (jetbackup5d).
    It will start automatically once that clears — you do not need to ask
    again.`
  - `This account has been scanned recently, so this request is held until the
    next one is allowed.`

  Each now also carries **when the request was made** and **when the server
  last checked**, so a wait has a shape rather than being open-ended, and a
  plain "Nothing is wrong — the server picks up requests on a schedule"
  fallback for when there is no recorded reason, because silence reads as
  failure.

  The request time is read from the customer's **own request file** rather
  than the report. The report is rewritten only when the scheduler runs, so
  somebody who clicked and reloaded was told nothing had been requested. A
  recorded reason older than the current request is ignored, or a customer
  would be shown why their *previous* scan waited.

---

Full history: https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
