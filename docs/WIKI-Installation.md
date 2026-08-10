# Installation & Uninstallation

Sentinel Gate installs on cPanel/WHM servers and on standalone Linux servers
with a single command. The installer detects which kind of server it is on and
configures itself accordingly.

---

## Before you begin

| | |
|---|---|
| **Access** | root, via SSH |
| **Operating system** | Any Linux. cPanel hosts are RHEL-family — AlmaLinux, CloudLinux, CentOS, RHEL |
| **PHP** | 7.4 or newer, with the `sqlite3` and `pdo` extensions |
| **Disk space** | ~50 MB, plus room for quarantine and logs |
| **Network** | Outbound HTTPS to `defender.lws-s1.com` |

You do not need to install ClamAV beforehand. If it is already present the
scanner will use it; if not, Sentinel Gate uses its own pattern-based engine
until you install it.

---

## Installing

Log in over SSH as **root** and run:

```bash
bash <(curl -fsSL https://defender.lws-s1.com/sentinel-gate/code/get.sh)
```

If the server has `wget` but not `curl`:

```bash
bash <(wget -qO- https://defender.lws-s1.com/sentinel-gate/code/get.sh)
```

Installation takes one to three minutes.

### What the installer does

1. Checks prerequisites and installs any missing packages
2. Downloads the current release and verifies its SHA-256 checksum
3. Creates `/usr/local/sentinel-gate/` and its data directories
4. Detects the server type and configures it:
   - **cPanel/WHM** — registers the WHM plugin, adds the Apache alias, installs
     the per-account plugin for the Jupiter and Paper Lantern themes
   - **Standalone Linux** — starts a self-contained dashboard on port `31150`
5. Installs scheduled scans and the real-time file monitor service
6. Runs a self-test and reports the result

If the checksum does not match, the installer stops rather than continuing.

---

## After installation

### cPanel / WHM

> **WHM → Plugins → Sentinel Gate Security**

You can also open it directly at `https://your-server-hostname/sentinel-gate/`.
Sign in with your existing WHM credentials — there is no separate account.

If the plugin does not appear in the menu, log out of WHM and back in. cPanel
caches its navigation. If it is still missing:

```bash
/usr/local/cpanel/scripts/restartsrv_cpsrvd
```

### Standalone Linux

> `http://your-server-ip:31150`

The installer prints the admin username and password when it finishes. If you
did not choose a password, one is generated and displayed in a box at the end of
the install — **save it before closing the terminal**. It is stored only as a
hash and cannot be recovered.

---

## Activating your license

Sentinel Gate requires a license key. Enter it at:

> **Settings → License → Enter license key**

Or from the command line:

```bash
sentinel license activate YOUR-LICENSE-KEY
sentinel license status
```

The license is verified against our licensing server and then cached locally, so
routine use does not depend on network access. The server is contacted again
roughly every 15 days.

**If the licensing server is temporarily unreachable, protection continues.**
Scanning, the firewall, the real-time monitor and quarantine keep running
regardless of license state — a licensing problem is never allowed to leave a
server unprotected. Only the management interface is gated, and only after an
extended grace period or an explicit rejection.

---

## Unattended installation

Piping the installer to `bash` makes it fully non-interactive. It detects the
server type and never prompts:

```bash
curl -fsSL https://defender.lws-s1.com/sentinel-gate/code/get.sh | bash
```

Force a particular mode instead of auto-detecting:

```bash
curl -fsSL .../get.sh | bash -s -- --mode cpanel
curl -fsSL .../get.sh | bash -s -- --mode standalone
```

Set the standalone admin password yourself. Use the environment variable rather
than the flag — command-line arguments are visible to other users via `ps`:

```bash
curl -fsSL .../get.sh | SG_ADMIN_PASS='your-password' bash -s -- --mode standalone
```

### Options

| Option | Effect |
|---|---|
| `--mode cpanel` / `--mode standalone` | Skip auto-detection |
| `--admin-user NAME` | Standalone admin username (default: `admin`) |
| `--admin-pass PASS` | Standalone admin password (prefer `SG_ADMIN_PASS`) |
| `--no-deps` | Do not install operating-system packages |
| `SG_VERSION=3.7.1` | Install a specific version rather than the latest |

---

## Verifying the installation

```bash
sentinel status
sentinel version
```

To re-run the full self-test:

```bash
bash /usr/local/sentinel-gate/test.sh
```

---

## Updating

```bash
bash /usr/local/sentinel-gate/update.sh
```

Your database, settings, quarantine and logs are preserved. A backup is written
to `/var/backups/sentinel-gate/` before anything is changed.

Non-interactive, or pinned to a specific version:

```bash
bash /usr/local/sentinel-gate/update.sh --yes
bash /usr/local/sentinel-gate/update.sh --version 3.7.1
```

Sentinel Gate also checks for updates daily and shows a notice in the dashboard
when a new version is available.

---

## Uninstalling

```bash
bash /usr/local/sentinel-gate/uninstall.sh
```

> **This does not ask for confirmation and removes everything**, including your
> scan history and anything held in quarantine. Take a copy of
> `/usr/local/sentinel-gate/database/` first if you want to keep that data.

### What is removed

- The `sentinel-gate-monitor` and `sentinel-gate-web` services
- Scheduled scan cron jobs
- The Apache configuration and alias
- WHM plugin registration and the per-account plugin from both themes
- Feature flags and the WHM menu entry
- `/usr/local/sentinel-gate/` and all data within it
- The `sentinel` command-line tool

The uninstaller reads `/usr/local/sentinel-gate/install-manifest.env`, which
records every path the installer touched, so it removes exactly what was added
and nothing else.

### After uninstalling on cPanel

The uninstaller restarts `cpsrvd` to clear the WHM navigation cache. If the menu
entry is still visible, log out of WHM and back in.

### Reinstalling later

Run the install command again. Nothing from a previous installation is left
behind, so it is a clean install. Your license key can be re-entered and will
re-activate on the same server.

---

## Troubleshooting

**`Run as root`**
You are not root. Use `sudo -i` first, then re-run the command.

**The install command returns 404 or cannot connect**
The installer falls back to GitHub automatically. To use it explicitly:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/get.sh)
```

**`Checksum mismatch`**
The download was corrupted or altered in transit. The installer stops rather
than installing it. Run the command again; if it keeps happening, contact
support — do not bypass the check.

**Installation finished but reported failed tests**
The plugin is installed. Review the failed items in the output, then re-run:

```bash
bash /usr/local/sentinel-gate/test.sh
```

**The dashboard will not load on a standalone server**
Confirm the service is running and port `31150` is open:

```bash
systemctl status sentinel-gate-web
```

**Logs**

```
/usr/local/sentinel-gate/logs/
```

---

## Where files are installed

| Path | Contents |
|---|---|
| `/usr/local/sentinel-gate/` | Application, database, quarantine, logs |
| `/etc/cron.d/sentinel-gate` | Scheduled scans |
| `/etc/systemd/system/sentinel-gate-monitor.service` | Real-time file monitor |
| `/usr/bin/sentinel` | Command-line interface |
| `/var/backups/sentinel-gate/` | Backups taken before each update |

On cPanel servers the plugin additionally registers under `/var/cpanel/apps/`
and `/usr/local/cpanel/`. Only registration stubs are placed there — the
application itself lives entirely under `/usr/local/sentinel-gate/`, so a cPanel
update cannot remove or damage it.
