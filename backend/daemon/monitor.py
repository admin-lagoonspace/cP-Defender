#!/usr/bin/env python3
"""
Sentinel Gate — Real-Time File Monitor Daemon
Uses Linux inotify to watch for new/modified files and scans them immediately.
Mirrors the PHP Scanner's pattern library so no PHP subprocess needed per-file.

Requirements: pip3 install inotify_simple
Runs as: systemd service (sentinel-gate-monitor.service)
"""

import os, sys, re, sqlite3, json, time, hashlib, signal, logging, subprocess
from pathlib import Path
from datetime import datetime

# ── Try inotify_simple, fallback to polling ───────────────────────────────────
try:
    import inotify_simple
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

# ── Configuration (read from sentinel.db on startup) ─────────────────────────
INSTALL_DIR   = os.environ.get('SG_ROOT', '/usr/local/sentinel-gate')
DB_PATH       = os.path.join(INSTALL_DIR, 'database', 'sentinel.db')
LOG_PATH      = os.path.join(INSTALL_DIR, 'logs', 'monitor.log')
PID_FILE      = '/var/run/sentinel-gate-monitor.pid'

WATCH_EXTENSIONS = {'.php', '.php3', '.php4', '.php5', '.php7', '.phtml',
                    '.phps', '.phar', '.js', '.py', '.pl', '.sh', '.rb',
                    '.asp', '.aspx', '.jsp', '.cgi'}

MAX_FILE_SIZE   = 52_428_800   # 50 MB — skip larger files
SCAN_COOLDOWN   = 5            # seconds before re-scanning the same path

# ── CPU throttle defaults (overridden at runtime from DB setting) ─────────────
DEFAULT_CPU_LIMIT = 50         # percent

def cpu_to_nice(cpu_pct: int) -> int:
    """Map CPU % (10–100) to nice value (19–0). Lower % = higher nice = lower priority."""
    cpu_pct = max(10, min(100, cpu_pct))
    return round(19 * (1.0 - cpu_pct / 100.0))

def cpu_to_scan_sleep(cpu_pct: int) -> float:
    """Seconds to sleep between each file scan in inotify mode.
       10% → 0.5 s,  50% → 0.1 s,  100% → 0 s."""
    cpu_pct = max(10, min(100, cpu_pct))
    return max(0.0, (1.0 - cpu_pct / 100.0) * 0.55)

def cpu_to_poll_interval(cpu_pct: int) -> float:
    """Poll interval for polling mode.
       10% → 30 s,  50% → 5 s,  100% → 1 s."""
    cpu_pct = max(10, min(100, cpu_pct))
    return max(1.0, 30.0 * (1.0 - cpu_pct / 100.0) + 1.0)

# ── PHP Malware Patterns (mirrors Scanner.php) ────────────────────────────────
PATTERNS = [
    ('eval_base64',          re.compile(rb'eval\s*\(\s*base64_decode\s*\(', re.I)),
    ('eval_gzinflate',       re.compile(rb'eval\s*\(\s*gzinflate\s*\(',     re.I)),
    ('eval_str_rot13',       re.compile(rb'eval\s*\(\s*str_rot13\s*\(',      re.I)),
    ('preg_replace_eval',    re.compile(rb'preg_replace\s*\(\s*[\'"].*/e[\'"]\s*,', re.I)),
    ('assert_base64',        re.compile(rb'assert\s*\(\s*base64_decode\s*\(', re.I)),
    ('c99_shell',            re.compile(rb'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[.{0,30}\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', re.I)),
    ('system_shell',         re.compile(rb'\$_(?:GET|POST|REQUEST)\s*\[.{0,30}\]\s*;\s*(?:system|exec|passthru|shell_exec)', re.I)),
    ('backdoor_connect',     re.compile(rb'fsockopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', re.I)),
    ('reverse_shell',        re.compile(rb'(?:bash|sh)\s*-i\s*>&?\s*/dev/tcp', re.I)),
    ('xmrig_pattern',        re.compile(rb'stratum\+tcp://|xmrig|moneropool|minergate\.com', re.I)),
    ('coin_hive',            re.compile(rb'CoinHive\.Anonymous|coinhive\.min\.js', re.I)),
    ('long_base64',          re.compile(rb'[\'"][A-Za-z0-9+/]{500,}={0,2}[\'"']')),
    ('hex_string_long',      re.compile(rb'[\'"][0-9a-f]{200,}[\'"]', re.I)),
    ('gzuncompress_eval',    re.compile(rb'eval\s*\(\s*gzuncompress\s*\(', re.I)),
    ('stdin_exec',           re.compile(rb'proc_open.*STDIN.*STDOUT.*STDERR', re.I | re.S)),
    ('spam_mailer',          re.compile(rb'\$(?:to|from|subject)\s*=.*(?:@gmail|@yahoo|@hotmail).*;\s*mail\s*\(', re.I | re.S)),
]

SEVERITY_MAP = {
    'eval_base64': 'high',    'eval_gzinflate': 'high',
    'c99_shell': 'critical',  'backdoor_connect': 'critical',
    'reverse_shell': 'critical', 'system_shell': 'critical',
    'stdin_exec': 'critical', 'xmrig_pattern': 'high',
    'spam_mailer': 'medium',  'long_base64': 'medium',
}

# ── Logger ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('sentinel-monitor')

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def get_setting(key, default=''):
    try:
        db = get_db()
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        db.close()
        return row['value'] if row else default
    except Exception:
        return default

def get_cpu_limit() -> int:
    """Read cpu_limit_percent from DB; returns int 10–100."""
    try:
        val = int(get_setting('cpu_limit_percent', str(DEFAULT_CPU_LIMIT)))
        return max(10, min(100, val))
    except (ValueError, TypeError):
        return DEFAULT_CPU_LIMIT

def apply_cpu_priority(cpu_pct: int):
    """Set the process nice value according to the CPU limit."""
    nice_val = cpu_to_nice(cpu_pct)
    try:
        os.nice(nice_val - os.nice(0))   # delta from current nice
    except Exception:
        try:
            os.nice(nice_val)
        except Exception:
            pass
    log.info(f"CPU limit: {cpu_pct}% → nice {nice_val}, "
             f"scan_sleep {cpu_to_scan_sleep(cpu_pct):.3f}s, "
             f"poll_interval {cpu_to_poll_interval(cpu_pct):.1f}s")

def record_threat(file_path: str, sig_name: str, file_hash: str, file_size: int):
    severity = SEVERITY_MAP.get(sig_name, 'medium')
    try:
        db = get_db()
        job = db.execute(
            "SELECT id FROM scan_jobs WHERE scan_type='realtime' AND status='running' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not job:
            db.execute(
                "INSERT INTO scan_jobs (scan_type, status, started_at, scan_path) VALUES ('realtime','running',?,?)",
                (int(time.time()), get_setting('scan_paths', '/home'))
            )
            job_id = db.lastrowid
        else:
            job_id = job['id']

        existing = db.execute(
            "SELECT id FROM threats WHERE file_path=? AND status='active'", (file_path,)
        ).fetchone()
        if existing:
            db.close()
            return

        db.execute(
            """INSERT INTO threats
               (scan_job_id, file_path, threat_name, threat_type, severity, hash, size, status, detected_at)
               VALUES (?,?,?,?,?,?,?,'active',?)""",
            (job_id, file_path, f'SG.RT.{sig_name}', 'realtime_detection',
             severity, file_hash, file_size, int(time.time()))
        )
        db.execute(
            """INSERT INTO security_events
               (type, severity, source_ip, target, description, timestamp)
               VALUES ('realtime_malware',?,NULL,?,?,?)""",
            (severity, file_path, f'Real-time detection: {sig_name}', int(time.time()))
        )
        db.commit()
        db.close()

        log.warning(f"THREAT DETECTED | {severity.upper()} | {sig_name} | {file_path}")
        send_alert(file_path, sig_name, severity)

        if get_setting('auto_quarantine') == '1':
            auto_quarantine(file_path, sig_name)

    except Exception as e:
        log.error(f"DB error recording threat: {e}")

def update_monitor_stats(files_checked: int, threats_found: int):
    try:
        db = get_db()
        for k, v in [
            ('rt_files_checked', str(files_checked)),
            ('rt_threats_found', str(threats_found)),
            ('rt_monitor_pid',   str(os.getpid())),
            ('rt_monitor_status', 'running'),
            ('rt_last_activity', str(int(time.time()))),
        ]:
            db.execute(
                "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?,?,strftime('%s','now'))",
                (k, v)
            )
        db.commit()
        db.close()
    except Exception:
        pass

# ── Scanner ───────────────────────────────────────────────────────────────────
def scan_file(path: str, cpu_pct: int = DEFAULT_CPU_LIMIT) -> bool:
    """Scan a single file. Returns True if threat found."""
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return False

    if stat.st_size == 0 or stat.st_size > MAX_FILE_SIZE:
        return False

    ext = Path(path).suffix.lower()
    if ext not in WATCH_EXTENSIONS:
        return False

    # ClamAV: run with nice/ionice based on CPU limit
    clamscan = '/usr/bin/clamscan'
    if os.path.exists(clamscan):
        nice_val = cpu_to_nice(cpu_pct)
        cmd = ['nice', f'-n{nice_val}', 'ionice', '-c3',
               clamscan, '--no-summary', '--infected', path]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
            if result.returncode == 1:
                for line in result.stdout.splitlines():
                    if 'FOUND' in line:
                        threat_name = line.split(': ')[1].replace(' FOUND', '').strip()
                        file_hash = hashlib.sha256(open(path, 'rb').read()).hexdigest()
                        record_threat(path, threat_name, file_hash, stat.st_size)
                        return True
        except (subprocess.TimeoutExpired, Exception) as e:
            log.debug(f"ClamAV scan failed for {path}: {e}")

    # Pattern scan fallback
    try:
        with open(path, 'rb') as f:
            content = f.read()
        for sig_name, pattern in PATTERNS:
            if pattern.search(content):
                file_hash = hashlib.sha256(content).hexdigest()
                record_threat(path, sig_name, file_hash, stat.st_size)
                return True
    except (IOError, PermissionError) as e:
        log.debug(f"Cannot read {path}: {e}")

    return False

def auto_quarantine(file_path: str, sig_name: str):
    q_dir = os.path.join(INSTALL_DIR, 'quarantine', datetime.now().strftime('%Y-%m-%d'))
    os.makedirs(q_dir, mode=0o700, exist_ok=True)
    basename = os.path.basename(file_path)
    dest = os.path.join(q_dir, f"{basename}_{int(time.time())}.quarantine")
    try:
        os.rename(file_path, dest)
        with open(file_path + '.sentinel_removed', 'w') as f:
            f.write(
                f"File quarantined by Sentinel Gate (real-time monitor)\n"
                f"Time: {datetime.now()}\n"
                f"Signature: {sig_name}\n"
                f"Quarantined to: {dest}\n"
            )
        log.info(f"Auto-quarantined: {file_path} → {dest}")
    except Exception as e:
        log.error(f"Quarantine failed for {file_path}: {e}")

def send_alert(file_path: str, sig_name: str, severity: str):
    alert_email = get_setting('alert_email')
    if not alert_email or get_setting('email_alerts') != '1':
        return
    hostname = os.uname().nodename
    subject = f"[Sentinel Gate] Real-time threat detected on {hostname}"
    body = (
        f"Sentinel Gate Real-Time Monitor detected a threat:\n\n"
        f"  File:      {file_path}\n"
        f"  Signature: {sig_name}\n"
        f"  Severity:  {severity.upper()}\n"
        f"  Time:      {datetime.now()}\n\n"
        f"Action: {'Quarantined automatically' if get_setting('auto_quarantine') == '1' else 'Manual action required'}\n"
        f"\nDashboard: https://{hostname}:2087\n"
    )
    try:
        subprocess.run(['mail', '-s', subject, alert_email], input=body.encode(), timeout=10)
    except Exception:
        pass

# ── inotify Watcher ───────────────────────────────────────────────────────────
class InotifyMonitor:

    def __init__(self, watch_paths: list, cpu_pct: int):
        self.watch_paths   = watch_paths
        self.cpu_pct       = cpu_pct
        self.inotify       = inotify_simple.INotify()
        self.wd_to_path    = {}
        self.cooldowns     = {}
        self.files_checked = 0
        self.threats_found = 0

        self.flags = (
            inotify_simple.flags.CREATE      |
            inotify_simple.flags.CLOSE_WRITE |
            inotify_simple.flags.MOVED_TO
        )

    def add_watch_recursive(self, path: str):
        if not os.path.isdir(path):
            log.warning(f"Watch path not found, skipping: {path}")
            return
        try:
            wd = self.inotify.add_watch(path, self.flags)
            self.wd_to_path[wd] = path
            log.info(f"Watching: {path}")
        except PermissionError:
            log.warning(f"Permission denied watching: {path}")
            return
        try:
            for entry in os.scandir(path):
                if entry.is_dir(follow_symlinks=False) and not entry.name.startswith('.'):
                    depth = path.count(os.sep)
                    if depth < 10:
                        self.add_watch_recursive(entry.path)
        except PermissionError:
            pass

    def start(self):
        for path in self.watch_paths:
            self.add_watch_recursive(path)

        total = len(self.wd_to_path)
        log.info(f"inotify monitor active — watching {total} directories")
        update_monitor_stats(0, 0)

        stats_tick      = time.time()
        cpu_reload_tick = time.time()   # re-read CPU setting every 5 min

        while True:
            # Periodically reload CPU limit in case user changed it
            if time.time() - cpu_reload_tick > 300:
                new_cpu = get_cpu_limit()
                if new_cpu != self.cpu_pct:
                    self.cpu_pct = new_cpu
                    apply_cpu_priority(self.cpu_pct)
                cpu_reload_tick = time.time()

            try:
                events = self.inotify.read(timeout=5000)
            except Exception as e:
                log.error(f"inotify read error: {e}")
                time.sleep(1)
                continue

            for event in events:
                if not event.name:
                    continue
                parent    = self.wd_to_path.get(event.wd, '')
                full_path = os.path.join(parent, event.name)

                if (inotify_simple.flags.CREATE & event.mask) and \
                   (inotify_simple.flags.ISDIR & event.mask):
                    self.add_watch_recursive(full_path)
                    continue

                if not (inotify_simple.flags.ISDIR & event.mask):
                    self._handle_file_event(full_path)

            if time.time() - stats_tick > 30:
                update_monitor_stats(self.files_checked, self.threats_found)
                stats_tick = time.time()

    def _handle_file_event(self, path: str):
        ext = Path(path).suffix.lower()
        if ext not in WATCH_EXTENSIONS:
            return

        now  = time.time()
        last = self.cooldowns.get(path, 0)
        if now - last < SCAN_COOLDOWN:
            return
        self.cooldowns[path] = now

        if len(self.cooldowns) > 5000:
            cutoff = now - 300
            self.cooldowns = {k: v for k, v in self.cooldowns.items() if v > cutoff}

        log.debug(f"Scanning: {path}")
        self.files_checked += 1

        # Throttle: sleep between scans to respect CPU limit
        sleep_s = cpu_to_scan_sleep(self.cpu_pct)
        if sleep_s > 0:
            time.sleep(sleep_s)

        if scan_file(path, self.cpu_pct):
            self.threats_found += 1
            log.warning(f"Threat in new/modified file: {path}")


# ── Polling Fallback ──────────────────────────────────────────────────────────
class PollingMonitor:

    def __init__(self, watch_paths: list, cpu_pct: int):
        self.watch_paths   = watch_paths
        self.cpu_pct       = cpu_pct
        self.seen_mtimes   = {}
        self.files_checked = 0
        self.threats_found = 0

    def start(self):
        log.info("Starting polling monitor (install inotify_simple for better performance: pip3 install inotify_simple)")
        log.info(f"Watch paths: {self.watch_paths}")

        stats_tick      = time.time()
        cpu_reload_tick = time.time()

        while True:
            # Reload CPU setting every 5 min
            if time.time() - cpu_reload_tick > 300:
                new_cpu = get_cpu_limit()
                if new_cpu != self.cpu_pct:
                    self.cpu_pct = new_cpu
                    apply_cpu_priority(self.cpu_pct)
                cpu_reload_tick = time.time()

            for watch_path in self.watch_paths:
                self._poll_directory(watch_path)

            if time.time() - stats_tick > 30:
                update_monitor_stats(self.files_checked, self.threats_found)
                stats_tick = time.time()

            time.sleep(cpu_to_poll_interval(self.cpu_pct))

    def _poll_directory(self, path: str):
        try:
            for root, _, files in os.walk(path, followlinks=False):
                for fname in files:
                    full = os.path.join(root, fname)
                    ext  = Path(full).suffix.lower()
                    if ext not in WATCH_EXTENSIONS:
                        continue
                    try:
                        mtime = os.path.getmtime(full)
                    except OSError:
                        continue
                    prev = self.seen_mtimes.get(full)
                    if prev != mtime:
                        self.seen_mtimes[full] = mtime
                        if prev is not None:
                            # Throttle per-file scan
                            sleep_s = cpu_to_scan_sleep(self.cpu_pct)
                            if sleep_s > 0:
                                time.sleep(sleep_s)
                            self.files_checked += 1
                            if scan_file(full, self.cpu_pct):
                                self.threats_found += 1
        except PermissionError:
            pass


# ── Signal handling ───────────────────────────────────────────────────────────
def handle_signal(signum, frame):
    log.info("Monitor daemon shutting down…")
    try:
        db = get_db()
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('rt_monitor_status','stopped')")
        db.commit()
        db.close()
    except Exception:
        pass
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
    sys.exit(0)

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT,  handle_signal)

    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

    # Read CPU limit and apply nice priority immediately
    cpu_pct = get_cpu_limit()
    apply_cpu_priority(cpu_pct)

    raw_paths   = get_setting('scan_paths', '/home')
    watch_paths = [p.strip() for p in raw_paths.split(',') if p.strip()]

    extra = ['/tmp', '/var/tmp', '/usr/local/apache/htdocs']
    for p in extra:
        if os.path.isdir(p) and p not in watch_paths:
            watch_paths.append(p)

    log.info(f"Sentinel Gate Real-Time Monitor starting (PID {os.getpid()})")
    log.info(f"Watch paths: {watch_paths}")
    log.info(f"Engine: {'inotify' if INOTIFY_AVAILABLE else 'polling (fallback)'}")
    log.info(f"CPU limit: {cpu_pct}% (nice={cpu_to_nice(cpu_pct)}, "
             f"scan_sleep={cpu_to_scan_sleep(cpu_pct):.3f}s, "
             f"poll_interval={cpu_to_poll_interval(cpu_pct):.1f}s)")

    if INOTIFY_AVAILABLE:
        InotifyMonitor(watch_paths, cpu_pct).start()
    else:
        PollingMonitor(watch_paths, cpu_pct).start()

if __name__ == '__main__':
    main()
