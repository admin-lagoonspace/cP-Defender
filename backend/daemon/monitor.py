#!/usr/bin/env python3
"""
Sentinel Gate - Real-Time File Monitor Daemon
Watches filesystem paths for new/modified PHP files and scans for malware.
Uses inotify_simple if available, falls back to polling.

Started by: RealTimeMonitor::start() (PHP) or systemd unit
Environment: SG_ROOT must be set (defaults to 2 dirs up from this script)
"""

import os, re, sys, time, signal, logging, sqlite3, shutil, datetime
from pathlib import Path
from typing import Optional, List, Dict

SG_ROOT  = os.environ.get('SG_ROOT', str(Path(__file__).resolve().parent.parent.parent))
SG_DB    = os.path.join(SG_ROOT, 'database', 'sentinel.db')
PID_FILE = '/var/run/sentinel-gate-monitor.pid'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [sg-monitor] %(levelname)s %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    stream=sys.stdout, force=True,
)
log = logging.getLogger('sg')

_running = True
def _on_sig(sig, frame):
    global _running
    log.info('Signal %s - shutting down', sig)
    _running = False
signal.signal(signal.SIGTERM, _on_sig)
signal.signal(signal.SIGINT,  _on_sig)

def write_pid():
    try:
        open(PID_FILE, 'w').write(str(os.getpid()))
        os.chmod(PID_FILE, 0o644)
    except Exception as e:
        log.warning('PID write failed: %s', e)

def remove_pid():
    try:
        os.path.exists(PID_FILE) and os.unlink(PID_FILE)
    except: pass

def db_connect():
    conn = sqlite3.connect(SG_DB, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn

def db_get(conn, key, default=''):
    try:
        r = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return str(r['value']) if (r and r['value'] is not None) else default
    except: return default

def db_set(conn, key, value):
    try:
        conn.execute(
            "INSERT INTO settings(key,value,updated_at) VALUES(?,?,strftime('%s','now')) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            (key, value))
        conn.commit()
    except Exception as e:
        log.debug('db_set %s: %s', key, e)

# -- CPU throttle ----------------------------------------------------------------
# Maps the user-facing cpu_limit_percent setting (Settings -> CPU usage limit)
# to process priority and inter-scan sleeps. Restored after the v3.3.7 rewrite
# dropped it while the UI/DB kept the setting.
DEFAULT_CPU_LIMIT = 50   # percent
_SCAN_SLEEP = 0.0        # set in main() from the CPU limit

def cpu_to_nice(cpu_pct):
    """Map CPU % (10-100) to a nice value (19-0). Lower % = lower priority."""
    cpu_pct = max(10, min(100, int(cpu_pct)))
    return round(19 * (1.0 - cpu_pct / 100.0))

def cpu_to_scan_sleep(cpu_pct):
    """Seconds to sleep between file scans in inotify mode.
       10% -> 0.50s, 50% -> 0.28s, 100% -> 0s."""
    cpu_pct = max(10, min(100, int(cpu_pct)))
    return max(0.0, (1.0 - cpu_pct / 100.0) * 0.55)

def get_cpu_limit(conn):
    """Read cpu_limit_percent from settings; clamp to 10-100."""
    try:
        return max(10, min(100, int(db_get(conn, 'cpu_limit_percent', str(DEFAULT_CPU_LIMIT)))))
    except (ValueError, TypeError):
        return DEFAULT_CPU_LIMIT

def get_poll_interval(conn):
    """Poll interval (seconds) for polling mode -- rt_poll_interval setting,
       default 300 (5 min), clamped to >= 10."""
    try:
        return max(10, int(db_get(conn, 'rt_poll_interval', '300') or '300'))
    except (ValueError, TypeError):
        return 300

# -- Resource profiles -----------------------------------------------------------
# Real-time monitoring was reported as putting excessive load on a live server.
# The throttle that existed only slowed the gap BETWEEN file scans; it did
# nothing about the three things that actually cost:
#
#   1. Polling mode walks every watched path and stats every file, every
#      interval, holding a path->mtime dict for the whole tree. On a shared host
#      with /home that is the dominant cost by a wide margin.
#   2. inotify adds one watch per directory with no ceiling. Tens of thousands
#      of watches is both kernel memory and a long startup walk, and exceeding
#      max_user_watches failed silently, leaving partial coverage nobody knew
#      about.
#   3. Every event reads the whole file and runs the pattern set over it, with
#      no ceiling on events per second and no coalescing of repeats.
#
# So the limits are explicit, named, and settable. A profile sets them all at
# once; 'custom' leaves whatever the user chose.

PROFILES = {
    # name        nice  files/s  max MB  poll s  watches  debounce s
    'light':     (19,     5,       4,     900,     5000,   10),
    'balanced':  (10,    25,      16,     300,    20000,    5),
    'thorough':  ( 5,   100,      50,     120,   100000,    2),
}
DEFAULT_PROFILE = 'balanced'

DEFAULT_EXCLUDES = {'node_modules', '.git', '__pycache__', '.svn', 'cache',
                    '.cache', 'vendor', 'backup', 'backups', '.trash'}


def load_profile(conn):
    """Effective resource limits, re-read from settings on every reload tick."""
    name = (db_get(conn, 'rt_profile', DEFAULT_PROFILE) or DEFAULT_PROFILE).strip().lower()
    base = PROFILES.get(name, PROFILES[DEFAULT_PROFILE])
    nice_v, fps, mb, poll, watches, debounce = base

    def num(key, fallback, lo, hi):
        try:
            return max(lo, min(hi, int(db_get(conn, key, str(fallback)) or fallback)))
        except (ValueError, TypeError):
            return fallback

    if name == 'custom':
        nice_v   = num('rt_nice',              10,  0, 19)
        fps      = num('rt_max_files_per_sec', 25,  1, 1000)
        mb       = num('rt_max_file_size_mb',  16,  1, 512)
        poll     = num('rt_poll_interval',    300, 10, 86400)
        watches  = num('rt_max_watches',    20000, 100, 500000)
        debounce = num('rt_debounce_seconds',   5,  0, 3600)

    extra = db_get(conn, 'rt_exclude_dirs', '') or ''
    excludes = set(DEFAULT_EXCLUDES)
    excludes.update(d.strip() for d in extra.split(',') if d.strip())

    return {
        'profile': name if name in PROFILES or name == 'custom' else DEFAULT_PROFILE,
        'nice': nice_v,
        'files_per_sec': fps,
        'max_file_size': mb * 1024 * 1024,
        'poll_interval': poll,
        'max_watches': watches,
        'debounce': debounce,
        'excludes': excludes,
    }


class RateLimiter:
    """Token bucket over files examined per second.

    A fixed sleep between scans cannot express "no more than N files a second":
    it makes every scan slower whether or not anything is happening, and it
    still lets a burst of ten thousand events through back to back. This caps
    the rate and costs nothing while idle.
    """

    def __init__(self, per_sec):
        self.rate = max(1, int(per_sec))
        self.allowance = float(self.rate)
        self.last = time.time()

    def update(self, per_sec):
        per_sec = max(1, int(per_sec))
        if per_sec != self.rate:
            self.rate = per_sec
            self.allowance = min(self.allowance, float(per_sec))

    def take(self):
        """Block just long enough to stay under the limit."""
        now = time.time()
        self.allowance += (now - self.last) * self.rate
        self.last = now
        if self.allowance > self.rate:
            self.allowance = float(self.rate)
        if self.allowance < 1.0:
            time.sleep((1.0 - self.allowance) / self.rate)
            self.allowance = 0.0
            self.last = time.time()
        else:
            self.allowance -= 1.0


class Debouncer:
    """Suppress repeat events for the same path within a window.

    An editor writing a file, a deploy, or a log rotation produces several
    CREATE/MODIFY events for one path in quick succession. Scanning it each time
    is pure waste: the content is read and pattern-matched again for no new
    information.
    """

    def __init__(self, seconds):
        self.window = max(0, int(seconds))
        self.seen = {}

    def update(self, seconds):
        self.window = max(0, int(seconds))

    def should_skip(self, path):
        if self.window <= 0:
            return False
        now = time.time()
        last = self.seen.get(path)
        if last is not None and (now - last) < self.window:
            return True
        self.seen[path] = now
        if len(self.seen) > 20000:      # bounded: this must not become a leak
            cutoff = now - self.window
            self.seen = {k: v for k, v in self.seen.items() if v > cutoff}
        return False


def apply_io_priority():
    """Best-effort idle I/O priority.

    Real-time monitoring is background work: it should yield to the web server
    and the database rather than compete with them. nice() only covers CPU, and
    the cost here is mostly disk.
    """
    try:
        os.system('ionice -c3 -p %d >/dev/null 2>&1' % os.getpid())
    except Exception as e:
        log.debug('ionice failed: %s', e)


def apply_cpu_priority_nice(target):
    """Set an absolute nice value (best effort).

    os.nice() is RELATIVE and a process cannot lower its own niceness without
    privilege, so re-applying on reload can only ever raise it. Called on every
    profile change so lowering the load takes effect immediately; raising it
    again needs a restart, which is the safe direction to fail in.
    """
    try:
        current = os.nice(0)
        if target > current:
            os.nice(target - current)
    except Exception as e:
        log.debug('nice failed: %s', e)


def apply_cpu_priority(cpu_pct):
    """Lower process priority according to the CPU limit (best-effort)."""
    target = cpu_to_nice(cpu_pct)
    try:
        current = os.nice(0)
        if target > current:
            os.nice(target - current)
    except Exception as e:
        log.debug('nice failed: %s', e)
    log.info('CPU limit %d%% -> nice %d, scan_sleep %.2fs',
             cpu_pct, target, cpu_to_scan_sleep(cpu_pct))

def db_threat(conn, path, name, sev='high'):
    try:
        cur = conn.execute(
            "INSERT INTO threats(file_path,threat_name,threat_type,severity,status,detected_at)"
            " VALUES(?,?,?,?,?,strftime('%s','now'))",
            (path, name, 'realtime_detection', sev, 'active'))
        conn.commit()
        return cur.lastrowid or 0
    except Exception as e:
        log.warning('db_threat: %s', e)
        return 0

def db_event(conn, etype, msg):
    try:
        conn.execute("INSERT INTO security_events(type,severity,description) VALUES(?,?,?)",
                     (etype,'medium',msg))
        conn.commit()
    except: pass

PATTERNS = [
    ('eval_base64',    re.compile(rb'eval\s*\(\s*base64_decode\s*\(',    re.I)),
    ('eval_gzinflate', re.compile(rb'eval\s*\(\s*gzinflate\s*\(',        re.I)),
    ('eval_rot13',     re.compile(rb'eval\s*\(\s*str_rot13\s*\(',        re.I)),
    ('assert_b64',     re.compile(rb'assert\s*\(\s*base64_decode\s*\(',  re.I)),
    ('preg_eval',      re.compile(rb'preg_replace\s*\([\'"][^\'"]*\/e[\'"]', re.I)),
    ('c99_shell',      re.compile(rb'\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[.{0,30}?\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', re.I|re.S)),
    ('sys_shell',      re.compile(rb'\$_(?:GET|POST|REQUEST)\[.{0,30}?\]\s*;\s*(?:system|exec|passthru|shell_exec)', re.I|re.S)),
    ('rev_shell',      re.compile(rb'(?:bash|sh)\s+-i\s+>&?\s*/dev/tcp', re.I)),
    ('fsock_bd',       re.compile(rb'fsockopen\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)', re.I)),
    ('xmrig',          re.compile(rb'stratum\+tcp://|xmrig|moneropool|minergate', re.I)),
    ('coinhive',       re.compile(rb'CoinHive\.Anonymous|coinhive\.min\.js', re.I)),
    ('long_b64',       re.compile(rb'[A-Za-z0-9+/]{500,}={0,2}')),
    ('hex_str',        re.compile(rb'[0-9a-fA-F]{200,}')),
]
SEV = {'c99_shell':'critical','rev_shell':'critical','fsock_bd':'critical',
       'eval_base64':'high','sys_shell':'high','assert_b64':'high'}
PHP_EXTS = {'.php','.php3','.php4','.php5','.php7','.phtml','.phps'}
MAX_SZ   = 52_428_800

def scan(path, max_size=None):
    try:
        sz = os.path.getsize(path)
        limit = MAX_SZ if max_size is None else max_size
        # Reading a 40MB file to regex it costs far more than the detection is
        # worth; the size ceiling is a user-visible resource control now.
        if sz == 0 or sz > limit: return None
        data = open(path,'rb').read()
        for n, p in PATTERNS:
            if p.search(data): return 'SG.RT.' + n
    except (PermissionError, OSError): pass
    return None

_chk = 0; _thr = 0

def handle(conn, path, limits=None, limiter=None, debouncer=None):
    global _chk, _thr

    if debouncer is not None and debouncer.should_skip(path):
        return
    if limiter is not None:
        limiter.take()

    _chk += 1
    t = scan(path, limits['max_file_size'] if limits else None)
    if not t: return
    _thr += 1
    sev = SEV.get(t.replace('SG.RT.',''),'medium')
    tid = db_threat(conn, path, t, sev)
    log.warning('THREAT %s -> %s (id=%d sev=%s)', path, t, tid, sev)
    db_event(conn, 'realtime_threat', f'{t} in {path}')
    if db_get(conn,'auto_quarantine') == '1' and tid:
        quarantine(conn, path, tid)

def quarantine(conn, path, tid):
    day  = datetime.date.today().strftime('%Y-%m-%d')
    base = db_get(conn,'quarantine_dir') or os.path.join(SG_ROOT,'quarantine')
    qd   = os.path.join(base, day)
    try:
        os.makedirs(qd, 0o700, exist_ok=True)
        dest = os.path.join(qd, os.path.basename(path) + f'_{tid}.quarantine')
        shutil.move(path, dest)
        open(path+'.sentinel_removed','w').write(
            f'Quarantined by Sentinel Gate at {datetime.datetime.now()}\nID:{tid}\nOrig:{path}\n')
        conn.execute("UPDATE threats SET status='quarantined',action_taken='quarantine',"
                     "resolved_at=strftime('%s','now') WHERE id=?", (tid,))
        conn.commit()
        log.info('Quarantined %s', path)
    except Exception as e:
        log.warning('Quarantine failed %s: %s', path, e)

def flush(conn):
    global _running
    db_set(conn,'rt_files_checked',str(_chk))
    db_set(conn,'rt_threats_found', str(_thr))
    db_set(conn,'rt_last_activity', str(int(time.time())))

    # Re-verify while running. Checking only at startup would let a licence that
    # lapses (or is revoked) keep the daemon alive indefinitely, since this
    # process can run for weeks.
    allowed, why = license_ok(conn)
    if not allowed:
        log.error('License no longer valid (%s) — stopping monitor', why)
        db_set(conn, 'rt_monitor_status', 'unlicensed')
        _running = False


# ── License gate ──────────────────────────────────────────────────────────────
# The daemon cannot validate a signed local key itself — that logic lives in
# PHP (License.php) and re-implementing the crypto here would mean two
# implementations to keep in sync and two chances to get it wrong. Instead PHP
# publishes its decision into the settings table and the daemon reads it.
#
# The staleness check matters: if PHP has not run for longer than FLAG_MAX_AGE
# the flag is treated as untrustworthy rather than as permission. Otherwise a
# customer could license once, delete the cron that refreshes the flag, and the
# daemon would keep running on a permission that is never re-verified.
FLAG_MAX_AGE = 3 * 86400          # 3 days — cron refreshes it hourly

def license_ok(conn):
    """(allowed, reason)"""
    ok    = db_get(conn, 'license_protection_ok', '')
    at    = db_get(conn, 'license_flag_at', '0')
    state = db_get(conn, 'license_status', 'Unknown')
    try:
        age = time.time() - int(at or 0)
    except ValueError:
        age = FLAG_MAX_AGE + 1

    if ok != '1':
        return False, f'license status: {state}'
    if age > FLAG_MAX_AGE:
        return False, (f'license flag is {int(age/86400)}d old — not re-verified. '
                       'Is the Sentinel Gate cron still installed?')
    return True, state

def watch_paths(conn):
    raw = db_get(conn,'scan_paths','/home')
    return [p.strip() for p in raw.split(',') if p.strip() and os.path.isdir(p.strip())]

SKIP = {'node_modules','.git','__pycache__','.svn'}

def run_inotify(conn, paths, limits):
    import inotify_simple
    fl = inotify_simple.flags.CREATE | inotify_simple.flags.MODIFY | inotify_simple.flags.MOVED_TO
    ino = inotify_simple.INotify()
    wds = {}
    capped = False

    for base in paths:
        for root, dirs, _ in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs
                       if d not in limits['excludes'] and not d.startswith('.')]
            if len(wds) >= limits['max_watches']:
                capped = True
                break
            try:
                wd = ino.add_watch(root, fl)
                wds[wd] = root
            except (PermissionError, FileNotFoundError):
                pass
            except OSError as e:
                # ENOSPC means the kernel's max_user_watches is exhausted. This
                # used to be swallowed with everything else, leaving the monitor
                # silently watching a fraction of the tree while reporting
                # itself healthy.
                log.error('inotify watch limit reached (%s). Watching %d dirs only. '
                          'Raise fs.inotify.max_user_watches or lower rt_max_watches.',
                          e, len(wds))
                capped = True
                break
        if capped:
            break

    log.info('inotify: %d dirs (cap %d)%s', len(wds), limits['max_watches'],
             ' - CAPPED' if capped else '')
    db_set(conn, 'rt_watch_count', str(len(wds)))
    db_set(conn, 'rt_watch_capped', '1' if capped else '0')

    limiter   = RateLimiter(limits['files_per_sec'])
    debouncer = Debouncer(limits['debounce'])

    tick = 0
    last_reload = time.time()

    while _running:
        try: evts = ino.read(timeout=2000)
        except Exception as e:
            if _running: log.warning('inotify err: %s', e)
            break

        # Settings must take effect without a restart: an administrator whose
        # server is under load should not have to restart the monitor to calm
        # it down.
        if time.time() - last_reload >= 60:
            fresh = load_profile(conn)
            if fresh != limits:
                limits = fresh
                limiter.update(limits['files_per_sec'])
                debouncer.update(limits['debounce'])
                apply_cpu_priority_nice(limits['nice'])
                log.info('resource profile reloaded: %s', limits['profile'])
            last_reload = time.time()

        for ev in evts:
            if not ev.name or Path(ev.name).suffix.lower() not in PHP_EXTS: continue
            dp = wds.get(ev.wd,'')
            if dp:
                handle(conn, os.path.join(dp, ev.name), limits, limiter, debouncer)
            tick += 1
            if tick >= 50: flush(conn); tick = 0
    ino.close()

def run_polling(conn, paths, limits):
    """Fallback when inotify is unavailable.

    This is where the load came from. The previous implementation walked every
    watched path and stat()ed every file on each pass, holding a path->mtime
    dict for the entire tree and a second copy while diffing. Against /home on a
    shared host that is millions of stat calls per interval, permanently.

    Three changes: only files we would ever scan are tracked (a PHP monitor has
    no use for the mtime of a JPEG), the tracked set is bounded and says so when
    it fills, and the walk yields between directories so it cannot monopolise a
    core.
    """
    interval = limits['poll_interval']
    log.info('polling: %s every %ds (tracking PHP files only)', paths, interval)

    max_tracked = 200000

    def snap(lim):
        out = {}
        truncated = False
        for b in paths:
            for r, ds, fs in os.walk(b, followlinks=False):
                ds[:] = [d for d in ds
                         if d not in lim['excludes'] and not d.startswith('.')]
                for f in fs:
                    # Filter BEFORE stat(): the extension check is a string
                    # comparison, the stat is a syscall. The old order paid the
                    # syscall for every file on the server.
                    if Path(f).suffix.lower() not in PHP_EXTS:
                        continue
                    if len(out) >= max_tracked:
                        truncated = True
                        break
                    fp = os.path.join(r, f)
                    try: out[fp] = os.path.getmtime(fp)
                    except OSError: pass
                if truncated:
                    break
                # Yield to the rest of the system between directories.
                time.sleep(0)
            if truncated:
                break
        if truncated:
            log.warning('polling: tracking capped at %d files. Narrow scan_paths '
                        'or install inotify_simple for event-driven monitoring.',
                        max_tracked)
        return out

    prev = snap(limits)
    last_fl = time.time()
    limiter   = RateLimiter(limits['files_per_sec'])
    debouncer = Debouncer(limits['debounce'])

    while _running:
        slept = 0
        while slept < interval and _running:
            time.sleep(min(5, interval - slept)); slept += 5
        if not _running: break

        fresh = load_profile(conn)
        if fresh != limits:
            limits = fresh
            interval = limits['poll_interval']
            limiter.update(limits['files_per_sec'])
            debouncer.update(limits['debounce'])
            apply_cpu_priority_nice(limits['nice'])
            log.info('resource profile reloaded: %s', limits['profile'])

        curr = snap(limits)
        for fp, mt in curr.items():
            if fp not in prev or prev[fp] < mt:
                handle(conn, fp, limits, limiter, debouncer)
        prev = curr
        if time.time() - last_fl >= 30: flush(conn); last_fl = time.time()

def main():
    global _SCAN_SLEEP
    write_pid()
    log.info('Sentinel Gate RT Monitor starting PID=%d SG_ROOT=%s', os.getpid(), SG_ROOT)
    conn = None
    try:
        conn = db_connect()

        allowed, why = license_ok(conn)
        if not allowed:
            log.error('Real-time monitoring requires a valid license (%s)', why)
            db_set(conn, 'rt_monitor_status', 'unlicensed')
            db_set(conn, 'rt_engine', 'disabled')
            return

        db_set(conn,'rt_monitor_status','running')

        limits = load_profile(conn)
        apply_cpu_priority_nice(limits['nice'])
        apply_io_priority()
        log.info('profile=%s nice=%d files/s=%d max_file=%dMB poll=%ds watches=%d debounce=%ds',
                 limits['profile'], limits['nice'], limits['files_per_sec'],
                 limits['max_file_size'] // (1024*1024), limits['poll_interval'],
                 limits['max_watches'], limits['debounce'])

        # Publish what is actually in effect so the UI shows the real limits
        # rather than what someone believes they configured.
        db_set(conn,'rt_effective_profile', limits['profile'])
        db_set(conn,'rt_effective_files_per_sec', str(limits['files_per_sec']))
        db_set(conn,'rt_effective_poll_interval', str(limits['poll_interval']))

        paths = watch_paths(conn)
        if not paths:
            paths = [p for p in ['/home','/var/www'] if os.path.isdir(p)] or ['/']
        log.info('Watch paths: %s', paths)
        try:
            import inotify_simple
            db_set(conn,'rt_engine','inotify')
            log.info('Engine: inotify_simple')
            run_inotify(conn, paths, limits)
        except ImportError:
            db_set(conn,'rt_engine','polling')
            log.info('Engine: polling interval=%ds', limits['poll_interval'])
            run_polling(conn, paths, limits)
    except Exception as e:
        log.error('Fatal: %s', e, exc_info=True)
    finally:
        if conn:
            try: flush(conn); db_set(conn,'rt_monitor_status','stopped'); conn.close()
            except: pass
        remove_pid()
        log.info('Monitor stopped')

if __name__ == '__main__':
    main()
