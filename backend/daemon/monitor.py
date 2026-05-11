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

def scan(path):
    try:
        sz = os.path.getsize(path)
        if sz == 0 or sz > MAX_SZ: return None
        data = open(path,'rb').read()
        for n, p in PATTERNS:
            if p.search(data): return 'SG.RT.' + n
    except (PermissionError, OSError): pass
    return None

_chk = 0; _thr = 0

def handle(conn, path):
    global _chk, _thr
    _chk += 1
    t = scan(path)
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
    db_set(conn,'rt_files_checked',str(_chk))
    db_set(conn,'rt_threats_found', str(_thr))
    db_set(conn,'rt_last_activity', str(int(time.time())))

def watch_paths(conn):
    raw = db_get(conn,'scan_paths','/home')
    return [p.strip() for p in raw.split(',') if p.strip() and os.path.isdir(p.strip())]

SKIP = {'node_modules','.git','__pycache__','.svn'}

def run_inotify(conn, paths):
    import inotify_simple
    fl = inotify_simple.flags.CREATE | inotify_simple.flags.MODIFY | inotify_simple.flags.MOVED_TO
    ino = inotify_simple.INotify()
    wds = {}
    for base in paths:
        for root, dirs, _ in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP and not d.startswith('.')]
            try:
                wd = ino.add_watch(root, fl)
                wds[wd] = root
            except (PermissionError, FileNotFoundError): pass
    log.info('inotify: %d dirs', len(wds))
    tick = 0
    while _running:
        try: evts = ino.read(timeout=2000)
        except Exception as e:
            if _running: log.warning('inotify err: %s', e)
            break
        for ev in evts:
            if not ev.name or Path(ev.name).suffix.lower() not in PHP_EXTS: continue
            dp = wds.get(ev.wd,'')
            if dp: handle(conn, os.path.join(dp, ev.name))
            tick += 1
            if tick >= 50: flush(conn); tick = 0
    ino.close()

def run_polling(conn, paths, interval):
    log.info('polling: %s every %ds', paths, interval)
    def snap():
        s = {}
        for b in paths:
            for r, ds, fs in os.walk(b, followlinks=False):
                ds[:] = [d for d in ds if d not in SKIP and not d.startswith('.')]
                for f in fs:
                    fp = os.path.join(r, f)
                    try: s[fp] = os.path.getmtime(fp)
                    except OSError: pass
        return s
    prev = snap(); last_fl = time.time()
    while _running:
        slept = 0
        while slept < interval and _running:
            time.sleep(min(5, interval-slept)); slept += 5
        if not _running: break
        curr = snap()
        for fp, mt in curr.items():
            if Path(fp).suffix.lower() not in PHP_EXTS: continue
            if fp not in prev or prev[fp] < mt: handle(conn, fp)
        prev = curr
        if time.time()-last_fl >= 30: flush(conn); last_fl = time.time()

def main():
    write_pid()
    log.info('Sentinel Gate RT Monitor starting PID=%d SG_ROOT=%s', os.getpid(), SG_ROOT)
    conn = None
    try:
        conn = db_connect()
        db_set(conn,'rt_monitor_status','running')
        paths = watch_paths(conn)
        if not paths:
            paths = [p for p in ['/home','/var/www'] if os.path.isdir(p)] or ['/']
        log.info('Watch paths: %s', paths)
        try:
            import inotify_simple
            db_set(conn,'rt_engine','inotify')
            log.info('Engine: inotify_simple')
            run_inotify(conn, paths)
        except ImportError:
            iv = int(db_get(conn,'rt_poll_interval','300') or '300')
            db_set(conn,'rt_engine','polling')
            log.info('Engine: polling interval=%ds', iv)
            run_polling(conn, paths, iv)
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
