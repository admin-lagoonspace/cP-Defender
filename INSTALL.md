# Installing Sentinel Gate

Security suite for cPanel/WHM servers and standalone Linux servers.
Malware scanning, firewall management, WAF, rootkit detection and real-time
file monitoring.

---

## Requirements

| | |
|---|---|
| Access | **root** (SSH). The WHM plugin registers system-wide. |
| OS | Any Linux. cPanel hosts are RHEL-family (AlmaLinux, CloudLinux, CentOS, RHEL). |
| PHP | 7.4 or newer, with `sqlite3` and `pdo` |
| Tools | `curl` or `wget`, and `unzip` — the installer fetches these if missing |
| Disk | ~50 MB, plus room for quarantine and logs |

You do **not** need to install ClamAV first. If it is present the scanner uses
it; if not, pattern-based scanning is used until you install it.

---

## Install

SSH in **as root** and run one line:

```bash
bash <(curl -fsSL https://defender.lws-s1.com/sentinel-gate/code/get.sh)
```

If the box has `wget` but not `curl`:

```bash
bash <(wget -qO- https://defender.lws-s1.com/sentinel-gate/code/get.sh)
```

That is the whole install. It detects whether this is a cPanel server or a
plain Linux server and configures itself accordingly.

### What it does

1. Fetches the release manifest and verifies the download's SHA-256
2. Installs to `/usr/local/sentinel-gate/`
3. **cPanel host** — registers the WHM plugin, adds the Apache alias, installs
   the per-account plugin for both themes
   **Plain Linux** — starts a self-contained dashboard on port `31150`
4. Installs cron jobs (hourly quick scan, nightly full scan, weekly signature
   update) and the real-time monitor service
5. Runs a self-test and reports the result

Takes 1–3 minutes.

---

## After installing

**cPanel / WHM**

> WHM → Plugins → **Sentinel Gate Security**

or directly: `https://your-server-hostname/sentinel-gate/`
Sign in with your existing WHM credentials — no separate account.

**Standalone Linux**

> `http://your-server-ip:31150`

The installer prints the admin username and password when it finishes. If you
did not choose a password it generates one and shows it in a box at the end —
**save it before closing the terminal**, it is not stored in plain text
anywhere.

---

## Unattended / scripted installs

Piping to `bash` makes the installer fully non-interactive — it detects the
mode and never prompts:

```bash
curl -fsSL https://defender.lws-s1.com/sentinel-gate/code/get.sh | bash
```

Force a mode instead of auto-detecting:

```bash
curl -fsSL .../get.sh | bash -s -- --mode cpanel
curl -fsSL .../get.sh | bash -s -- --mode standalone
```

Set the standalone admin password yourself. Use the environment variable, not
the flag — command-line arguments are visible to any user via `ps`:

```bash
curl -fsSL .../get.sh | SG_ADMIN_PASS='your-password' bash -s -- --mode standalone
```

Other options, passed straight through to the installer:

| Option | Effect |
|---|---|
| `--mode cpanel\|standalone` | Skip auto-detection |
| `--admin-user NAME` | Standalone admin username (default `admin`) |
| `--no-deps` | Do not install OS packages |
| `SG_VERSION=3.7.1` | Install a specific version instead of latest |

---

## Verify the install

```bash
sentinel status
sentinel version
```

Or re-run the self-test:

```bash
bash /usr/local/sentinel-gate/test.sh
```

---

## Updating

```bash
bash /usr/local/sentinel-gate/update.sh
```

Your database, settings, quarantine and logs are preserved, and a backup is
written to `/var/backups/sentinel-gate/` before anything changes.

Non-interactive, or pinned to a version:

```bash
bash /usr/local/sentinel-gate/update.sh --yes
bash /usr/local/sentinel-gate/update.sh --version 3.7.1
```

---

## Uninstalling

```bash
bash /usr/local/sentinel-gate/uninstall.sh
```

Removes everything — services, cron jobs, Apache config, WHM registration and
all data. It does not ask for confirmation, so take a backup first if you want
to keep the quarantine or scan history.

---

## If something goes wrong

**"Run as root"** — you are not root. Use `sudo -i` first.

**Install command returns 404 or cannot connect** — the installer falls back to
GitHub automatically, so try it explicitly:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/get.sh)
```

**Plugin missing from the WHM menu** — cPanel caches its navigation. Log out of
WHM and back in. If it is still absent:

```bash
/usr/local/cpanel/scripts/restartsrv_cpsrvd
```

**Checksum mismatch** — the download was corrupted or tampered with. The
installer aborts rather than proceeding. Re-run it; if it persists, report it.

**Logs**

```
/usr/local/sentinel-gate/logs/
```

---

## Where things are installed

| Path | |
|---|---|
| `/usr/local/sentinel-gate/` | Application, database, quarantine, logs |
| `/etc/cron.d/sentinel-gate` | Scheduled scans |
| `/etc/systemd/system/sentinel-gate-monitor.service` | Real-time monitor |
| `/usr/bin/sentinel` | Command-line interface |
| `/var/backups/sentinel-gate/` | Pre-update backups |

On cPanel hosts the plugin also registers under `/var/cpanel/apps/` and
`/usr/local/cpanel/`. Nothing but registration stubs live there, so a cPanel
update cannot remove the application. The uninstaller reads
`/usr/local/sentinel-gate/install-manifest.env`, which records every path
touched, so it removes exactly what was added.
