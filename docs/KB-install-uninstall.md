# ServerScrub — Installation & Uninstallation

ServerScrub is a complete server security suite for cPanel/WHM and standalone
Linux servers. It installs with a single command and brings its own firewall,
malware scanner, rootkit detection and web application firewall — there is
nothing to download or configure beforehand.

Every installation includes a 3-day trial with full protection active.

> **Previously known as Sentinel Gate.** If you have an older install under
> `/usr/local/sentinel-gate`, the installer migrates it in place — your
> database, settings and quarantined files are carried over. Do not install
> alongside it.

---

## Before you begin

| | |
|---|---|
| **Access** | root, via SSH |
| **Operating system** | Any Linux. cPanel hosts are RHEL-family — AlmaLinux, CloudLinux, CentOS, RHEL |
| **PHP** | 7.4 or newer, with the `sqlite3` and `pdo` extensions |
| **Disk space** | ~50 MB for the application. Quarantine and logs are separate — see below |
| **Network** | Outbound HTTPS to `serverscrub.com`, or to `raw.githubusercontent.com` as a fallback |

You do not need to install ClamAV, CSF, ModSecurity or rkhunter first.
ServerScrub installs what it needs and includes its own engines where no
third-party tool is present.

**On quarantine space:** quarantined files are copies of real infected files
and can grow large, so ServerScrub does **not** keep them under
`/usr/local/serverscrub`. It picks the first writable of `/home` or `/var` and
uses `/home/.serverscrub/quarantine`, which on a cPanel server is the large
volume. You can move it later from **Settings**, or with
`serverscrub quarantine move <dir>`.

---

## Installing

Log in over SSH as root and run:

```
bash <(curl -fsSL https://serverscrub.com/serverscrub/code/get.sh)
```

If the server has `wget` but not `curl`:

```
bash <(wget -qO- https://serverscrub.com/serverscrub/code/get.sh)
```

Installation takes one to three minutes.

### What the installer does

1. Checks prerequisites and installs any missing packages
2. Downloads the current release and verifies its SHA-256 checksum
3. Creates `/usr/local/serverscrub/` and its data directories
4. Detects the server type and configures it:
   - **cPanel/WHM** — registers the WHM plugin, adds the Apache alias, installs
     the per-account plugin for the Jupiter and Paper Lantern themes
   - **Standalone Linux** — starts a self-contained dashboard on port 31150
5. Sets up the firewall engine, installing nftables if no packet filter exists
6. Installs ClamAV and downloads malware signatures
7. Installs scheduled scans and the real-time file monitor
8. Runs a self-test and reports the result

If the checksum does not match, the installer stops rather than continuing.

---

## Your 3-day trial

Full protection is active immediately after installation for three days. The
dashboard shows the days remaining.

To keep protection running after the trial, activate a licence:

**Settings → Licence → Enter licence key**

Or from the command line:

```
serverscrub license activate YOUR-LICENCE-KEY
serverscrub license status
```

The licence is verified once and then cached locally, so day-to-day use does not
depend on network access. The licensing server is contacted again roughly every
15 days.

If the licensing server is temporarily unreachable, an already-verified licence
keeps working for a further 10 days, so a network problem never interrupts
protection.

When the trial ends without a licence, the dashboard shows an activation screen
and protection pauses until a key is entered. Your settings, scan history and
quarantined files are all retained.

---

## After installation

### cPanel / WHM

**WHM → Plugins → ServerScrub Security**

You can also open it directly at `https://your-server-hostname/serverscrub/`.
Sign in with your existing WHM credentials — there is no separate account.

If the plugin does not appear in the menu, log out of WHM and back in. cPanel
caches its navigation. If it is still missing:

```
/usr/local/cpanel/scripts/restartsrv_cpsrvd
```

### Standalone Linux

`http://your-server-ip:31150`

The installer prints the admin username and password when it finishes. If you
did not choose a password, one is generated and displayed in a box at the end of
the install — **save it before closing the terminal.** It is stored only as a
hash and cannot be recovered.

---

## What is included

| Feature | Notes |
|---|---|
| Malware scanning | ClamAV plus a built-in pattern and heuristic engine that needs no signature database |
| WordPress database scanning | Finds rogue administrators, fabricated roles, login backdoors and mail relays — compromises that leave no trace in any file |
| Firewall | Built in. Uses CSF or firewalld if already present, otherwise manages nftables or iptables directly |
| Web application firewall | Installs and configures ModSecurity with the OWASP Core Rule Set |
| Rootkit detection | Built-in engine; also uses rkhunter when installed |
| Brute-force protection | Escalating blocks: 3 hours, 6 hours, 24 hours, then permanent |
| IP reputation | Checks your server against 26 public blocklists |
| Real-time monitoring | Watches for file changes as they happen |
| Scheduled scans | Configurable in Settings |

Nothing here requires a separate purchase or install.

---

## Enabling the web application firewall

The WAF is not switched on automatically, because a misconfigured rule can block
legitimate visitors. To enable it:

**WAF → Install ModSecurity + OWASP CRS**

It starts in **Detection only** — attacks are logged but not blocked. Review the
audit log, then switch to **Blocking** when you are satisfied the rules are not
matching normal traffic.

The ServerScrub dashboard is always exempt from the rules, so a false positive
cannot lock you out of the page you would need to turn the WAF off.

---

## Unattended installation

Piping the installer to bash makes it fully non-interactive. It detects the
server type and never prompts:

```
curl -fsSL https://serverscrub.com/serverscrub/code/get.sh | bash
```

Force a particular mode instead of auto-detecting:

```
curl -fsSL .../get.sh | bash -s -- --mode cpanel
curl -fsSL .../get.sh | bash -s -- --mode standalone
```

Set the standalone admin password yourself. Use the environment variable rather
than the flag — command-line arguments are visible to other users via `ps`:

```
curl -fsSL .../get.sh | SG_ADMIN_PASS='your-password' bash -s -- --mode standalone
```

### Options

| Option | Effect |
|---|---|
| `--mode cpanel` / `--mode standalone` | Skip auto-detection |
| `--admin-user NAME` | Standalone admin username (default: `admin`) |
| `--admin-pass PASS` | Standalone admin password (prefer `SG_ADMIN_PASS`) |
| `--no-deps` | Do not install operating-system packages |
| `SG_VERSION=4.7.2` | Install a specific version rather than the latest |
| `SG_BASE_URL=<url>` | Pin to one download channel instead of trying both |

---

## Verifying the installation

```
serverscrub status
serverscrub version
serverscrub license status
```

To re-run the full self-test:

```
bash /usr/local/serverscrub/test.sh
```

---

## Updating

**From version 4.7.0, ServerScrub keeps itself up to date.** It checks once a
day at 04:30 server time and installs what it finds. Your settings, database,
quarantine, logs, certificates and custom signatures are preserved.

See and change this under **Settings → Updates**.

### What it will not install on its own

ServerScrub holds back and tells you why, rather than updating regardless:

| Situation | What happens |
|---|---|
| A **major** version (for example 4.x → 5.x) | Never automatic. Major versions can change behaviour, so this one waits for you |
| A **scan** or a **backup** is running | Waits for the next check |
| An update is already in progress | Only one at a time |
| The last attempt failed | Retries after 1 hour, then 2, then 4. After three failures it stops and asks you to check the log |

The Updates panel always shows a **Next action** line saying which of these
applies, so "automatic updates: on" can never quietly mean "blocked".

### Updating now

From the dashboard: **Settings → Updates → Update now**.

From the command line, the recommended route:

```
curl -fsSL https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/upgrade.sh -o /home/upgrade.sh
bash /home/upgrade.sh --check     # report versions, change nothing
bash /home/upgrade.sh             # upgrade, with a confirmation prompt
bash /home/upgrade.sh --yes       # no prompt
```

`upgrade.sh` downloads the **current** updater before handing over. The copy of
`update.sh` on your server is the one that shipped with the version you already
have, so a fix to the updater itself cannot otherwise reach you.

You can still call the installed updater directly:

```
bash /usr/local/serverscrub/update.sh --yes
bash /usr/local/serverscrub/update.sh --version 4.7.2
```

**If an update fails at any point it is rolled back automatically** to the
previous version, and your data is preserved either way. A backup is written to
`/var/backups/serverscrub/` before anything is changed, and the three most
recent are kept.

### Turning automatic updates off

**Settings → Updates → Install updates automatically.**

Switching it off does not stop the daily check, so the panel still tells you
when a new version is available. We recommend leaving it on: ServerScrub is the
software watching everything else, and an out-of-date copy is the one component
nobody notices is behind.

---

## Uninstalling

```
bash /usr/local/serverscrub/uninstall.sh
```

This does not ask for confirmation and removes everything, including your scan
history and anything held in quarantine.

If you want to keep that data, copy it first — note that quarantine is **not**
inside the install directory:

```
cp -a /usr/local/serverscrub/database /root/serverscrub-database-backup
cp -a /home/.serverscrub/quarantine   /root/serverscrub-quarantine-backup
```

Check where your quarantine actually is before relying on that second path:

```
serverscrub quarantine status
```

### What is removed

- The monitor, web and firewall services
- Scheduled scan cron jobs
- The Apache configuration, alias, and the WAF include
- The ServerScrub firewall rules — only ours; anything belonging to CSF,
  firewalld or you is left untouched
- WHM plugin registration and the per-account plugin from both themes
- `/usr/local/serverscrub/` and all data within it, and the quarantine directory
  wherever it lives
- The `serverscrub` command-line tool

The uninstaller reads `/usr/local/serverscrub/install-manifest.env`, which
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

**"Run as root"**
You are not root. Use `sudo -i` first, then re-run the command.

**The install command returns 404 or cannot connect**
The installer falls back to GitHub automatically. To use it explicitly:

```
bash <(curl -fsSL https://raw.githubusercontent.com/admin-lagoonspace/cP-Defender/main/get.sh)
```

**Checksum mismatch**
The download was corrupted or altered in transit. The installer stops rather
than installing it. Run the command again; if it keeps happening, contact
support — do not bypass the check.

**The dashboard shows an activation screen**
The trial has ended, or the licence could not be verified. Enter your key, or
run `serverscrub license refresh` to re-check.
`serverscrub license identity` shows the domain and IP this server reports,
which is what a licence is bound to.

**Malware scanning reports no signatures**
The ClamAV signature download did not finish. It retries on the weekly
schedule, and scanning continues on the built-in pattern engine meanwhile. To
retry now:

```
serverscrub update-sigs
```

**Installation finished but reported failed tests**
The plugin is installed. Review the failed items in the output, then re-run:

```
bash /usr/local/serverscrub/test.sh
```

**The dashboard will not load on a standalone server**
Confirm the service is running and port 31150 is open:

```
systemctl status serverscrub-web
```

**Nothing scheduled ever runs** — no nightly scan, no automatic update
Everything scheduled runs from one cron entry. Check it is there:

```
grep scheduler /etc/cron.d/serverscrub
```

If that returns nothing, re-running the installer or an update puts it back.

**Logs**

```
/usr/local/serverscrub/logs/
```

---

## Where files are installed

| Path | Contents |
|---|---|
| `/usr/local/serverscrub/` | Application, database, logs |
| `/home/.serverscrub/quarantine/` | Quarantined files — on the large volume, not under the install directory. Overridable in Settings |
| `/etc/cron.d/serverscrub` | Scheduled tasks |
| `/etc/systemd/system/serverscrub-monitor.service` | Real-time file monitor |
| `/etc/systemd/system/serverscrub-firewall.service` | Restores firewall rules at boot |
| `/etc/systemd/system/serverscrub-web.service` | Dashboard, standalone mode only |
| `/etc/serverscrub/` | CSF allow and ignore include files |
| `/usr/bin/serverscrub` | Command-line interface |
| `/var/backups/serverscrub/` | Backups taken before each update |

On cPanel servers the plugin additionally registers under `/var/cpanel/apps/`
and `/usr/local/cpanel/`. Only registration stubs are placed there — the
application itself lives entirely under `/usr/local/serverscrub/`, so a cPanel
update cannot remove or damage it.
