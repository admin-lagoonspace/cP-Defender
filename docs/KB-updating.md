# Updating ServerScrub

**Applies to:** ServerScrub 4.7.1 and later
**Last reviewed:** 20 October 2026

---

## In most cases you don't need to do anything

From version 4.7.0, ServerScrub keeps itself up to date. It checks for a new
version once a day at **04:30** server time and installs it.

Your settings, scan history, quarantined files, logs, TLS certificates and
custom signatures are all kept. Nothing you have configured is lost.

You can see what it is doing — and turn it off — under
**WHM → Plugins → ServerScrub → Settings → Updates**.

### What it will not do on its own

ServerScrub deliberately holds back and tells you why, rather than updating
regardless. It waits when:

| Situation | What happens |
|---|---|
| A **major** version is available (for example 4.x → 5.x) | Never installed automatically. Major versions can change how things behave, so this one waits for you. |
| A **scan** is running | Waits for the next check. Replacing files under a running scan would interrupt it. |
| A **backup** is running | Waits for the next check. |
| An update is **already in progress** | Only one at a time. |
| The last attempt **failed** | Tries again after 1 hour, then 2, then 4. After three failures it stops and shows a message asking you to look at the log. |

The Updates panel always shows a **Next action** line explaining exactly which
of these applies. If automatic updates are on but something is holding them
back, that line tells you what.

---

## Updating now, from WHM

1. Open **WHM → Plugins → ServerScrub**.
2. Go to **Settings → Updates**.
3. Check **Installed** and **Available** at the top of the panel.
4. Click **Update now** and confirm.

The dashboard and the API restart while this runs, so the page will be briefly
unavailable and will reload itself when it finishes. Scans and the real-time
monitor are stopped and started again for you.

> If the button reports that your server's PHP cannot start background
> processes, use the SSH method below. Some hardened servers block this, and
> ServerScrub's own PHP hardening can be one cause.

---

## Updating now, over SSH

Run these as **root**.

**Step 1 — see what is available.** This changes nothing:

```
curl -fsSL https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/upgrade.sh -o /home/upgrade.sh
bash /home/upgrade.sh --check
```

You will see something like:

```
  Installed: v4.4.2 at /usr/local/serverscrub
  Available: v4.7.1

  v4.4.2  →  v4.7.1
```

**Step 2 — update.**

```
bash /home/upgrade.sh
```

It shows what is about to happen and asks you to confirm. Type `y`.

To skip the question — in a maintenance window, or from a script — add `--yes`:

```
bash /home/upgrade.sh --yes
```

### Why `upgrade.sh` and not `update.sh`?

Both work, and `upgrade.sh` simply calls `update.sh` for you. The difference is
that `upgrade.sh` first downloads the **current** updater from our release
channel.

The copy of `update.sh` on your server is the one that shipped with the version
you already have. If we fix something in the updater itself, your server cannot
benefit from that fix, because the old updater is the thing doing the updating.
`upgrade.sh` closes that gap. It is the recommended route for a manual update.

---

## What an update does

In order:

1. Reads the release channel to find the newest version.
2. Downloads it and **verifies its SHA-256 checksum**. A file that does not
   match is rejected.
3. Backs up your current installation to `/var/backups/serverscrub`, keeping
   the three most recent.
4. Replaces the program files, keeping your database, settings, quarantine,
   logs, certificates and custom signatures.
5. Restarts the web service and the real-time monitor.
6. Checks that the new version answers. **If it does not, it puts the previous
   version back automatically.**

Step 6 is the important one: a failed update leaves you on the version you
started from, not on a half-installed one.

---

## If something goes wrong

**The update failed or rolled back.** You are still on your previous version
and nothing has been lost. The log has the detail:

```
tail -50 /usr/local/serverscrub/logs/update.log
```

**Restore a backup by hand.** Backups are in `/var/backups/serverscrub`, newest
last:

```
ls -1t /var/backups/serverscrub
```

**"Cannot reach any releases channel."** The server could not reach either
download location. Check outbound HTTPS and DNS from the server itself. The
updater prints both addresses it tried and runs a DNS check for you.

**Automatic updates say they are paused.** Three attempts in a row failed. Read
`logs/update.log` to see why, fix it, then click **Resume** in
Settings → Updates.

**Nothing in the Updates panel ever changes.** Automatic updating runs from
ServerScrub's scheduler, which needs its cron entry in place:

```
grep scheduler /etc/cron.d/serverscrub
```

If that returns nothing, the scheduler is not running — and neither are the
nightly scan or the database sweep. Reinstalling or updating puts it back.

---

## Turning automatic updates off

**Settings → Updates → Install updates automatically.**

Switching it off does **not** stop the daily check, so the panel still tells
you when a new version is available. You just apply it yourself.

We recommend leaving it on. ServerScrub is the software watching everything
else on the server; an out-of-date copy is the one component nobody notices is
behind.

---

## What's new

**4.7.1** — current

- Automatic updates: ServerScrub now installs new versions itself, daily.
- A new WordPress database scanner, finding rogue administrator accounts, fake
  roles, login backdoors and contact forms being used to relay spam — problems
  that leave no trace in any file.
- Much better malware detection, including backdoors made entirely of ordinary
  WordPress code that no signature can match.
- Fixed: the updater could stop without printing an error on servers that could
  not reach the primary download location.

**Full changelog for every version:**
https://github.com/admin-lagoonspace/cP-Defender/blob/main/CHANGELOG.md
