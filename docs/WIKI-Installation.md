# Installation & Uninstallation

Sentinel Gate is a complete server security suite for cPanel/WHM and standalone
Linux servers. It installs with a single command and brings its own firewall,
malware scanner, rootkit detection and web application firewall — there is
nothing to download or configure beforehand.

**Every installation includes a 3-day trial with full protection active.**

---

## Before you begin

| | |
|---|---|
| **Access** | root, via SSH |
| **Operating system** | Any Linux. cPanel hosts are RHEL-family — AlmaLinux, CloudLinux, CentOS, RHEL |
| **PHP** | 7.4 or newer, with the `sqlite3` and `pdo` extensions |
| **Disk space** | ~50 MB, plus room for quarantine and logs |
| **Network** | Outbound HTTPS to `defender.lws-s1.com` |

You do **not** need to install ClamAV, CSF, ModSecurity or rkhunter first.
Sentinel Gate installs what it needs and includes its own engines where no
third-party tool is present.

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
5. Sets up the firewall engine, installing `nftables` if no packet filter exists
6. Installs ClamAV and downloads malware signatures
7. Installs scheduled scans and the real-time file monitor
8. Runs a self-test and reports the result

If the checksum does not match, the installer stops rather than continuing.

---

## Your 3-day trial

Full protection is active immediately after installation for **three days**. The
dashboard shows the days remaining.

To keep protection running after the trial, activate a licence:

> **Settings → Licence → Enter licence key**

Or from the command line:

```bash
sentinel license activate YOUR-LICENCE-KEY
sentinel license status
```

The licence is verified once and then cached locally, so day-to-day use does not
depend on network access. The licensing server is contacted again roughly every
15 days.

If the licensing server is temporarily unreachable, an already-verified licence
keeps working for 10 days so a network problem never interrupts protection.

**When the trial ends without a licence**, the dashboard shows an activation
screen and protection pauses until a key is entered. Your settings, scan history
and quarantined files are all retained.

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

## What is included

| Feature | Notes |
|---|---|
| **Malware scanning** | ClamAV plus a built-in pattern engine that needs no signature database |
| **Firewall** | Built in. Uses CSF or firewalld if already present, otherwise manages nftables or iptables directly |
| **Web application firewall** | Installs and configures ModSecurity with the OWASP Core Rule Set |
| **Rootkit detection** | Built-in engine; also uses rkhunter when installed |
| **IP reputation** | Checks your server against 25 public blocklists |
| **Real-time monitoring** | Watches for file changes as they happen |
| **Scheduled scans** | Configurable in Settings |

Nothing here requires a separate purchase or install.

### Enabling the web application firewall

The WAF is not switched on automatically, because a misconfigured rule can block
legitimate visitors. To enable it:

> **WAF → Install ModSecurity + OWASP CRS**

It starts in **Detection only** — attacks are logged but not blocked. Review the
audit log, then switch to **Blocking** when you are satisfied the rules are not
matching normal traffic.

The Sentinel Gate dashboard is always exempt from the rules, so a false positive
cannot lock you out of the page you would need to turn the WAF off.

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
| `SG_VERSION=3.18.0` | Install a specific version rather than the latest |

---

## Verifying the installation

```bash
sentinel status
sentinel version
sentinel license status
```

To re-run the full self-test:

```bash
bash /usr/local/sentinel-gate/test.sh
```

---

## Updating

Sentinel Gate checks for updates daily. When one is available a button appears
in the top right of the dashboard — click it and the update runs with a progress
display, then reloads.

If the update fails at any point it is **rolled back automatically** to the
previous version. Your settings, database and quarantine are preserved either
way.

To update from the command line instead:

```bash
bash /usr/local/sentinel-gate/update.sh
```

Non-interactive, or pinned to a specific version:

```bash
bash /usr/local/sentinel-gate/update.sh --yes
bash /usr/local/sentinel-gate/update.sh --version 3.18.0
```

A backup is written to `/var/backups/sentinel-gate/` before anything is changed.

---

## Uninstalling

```bash
bash /usr/local/sentinel-gate/uninstall.sh
```

> **This does not ask for confirmation and removes everything**, including your
> scan history and anything held in quarantine. Take a copy of
> `/usr/local/sentinel-gate/database/` first if you want to keep that data.

### What is removed

- The monitor, web and firewall services
- Scheduled scan cron jobs
- The Apache configuration, alias, and the WAF include
- The Sentinel Gate firewall rules — only ours; anything belonging to CSF,
  firewalld or you is left untouched
- WHM plugin registration and the per-account plugin from both themes
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
behind, so it is a clean install. Your licence key can be re-entered and will
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

**The dashboard shows an activation screen**
The trial has ended, or the licence could not be verified. Enter your key, or use
`sentinel license refresh` to re-check. `sentinel license identity` shows the
domain and IP this server reports, which is what a licence is bound to.

**Malware scanning reports no signatures**
The ClamAV signature download did not finish. It retries on the weekly schedule,
and scanning continues on the built-in pattern engine meanwhile. To retry now:

```bash
sentinel update-sigs
```

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
| `/etc/cron.d/sentinel-gate` | Scheduled tasks |
| `/etc/systemd/system/sentinel-gate-monitor.service` | Real-time file monitor |
| `/etc/systemd/system/sentinel-gate-firewall.service` | Restores firewall rules at boot |
| `/etc/sentinel-gate/` | Firewall and WAF configuration |
| `/usr/bin/sentinel` | Command-line interface |
| `/var/backups/sentinel-gate/` | Backups taken before each update |

On cPanel servers the plugin additionally registers under `/var/cpanel/apps/`
and `/usr/local/cpanel/`. Only registration stubs are placed there — the
application itself lives entirely under `/usr/local/sentinel-gate/`, so a cPanel
update cannot remove or damage it.
