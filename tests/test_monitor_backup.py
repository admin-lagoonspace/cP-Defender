#!/usr/bin/env python3
"""Suspending real-time monitoring while a backup or bulk transfer runs.

Requested: while JetBackup is running, or rsync is streaming data to a remote
server, the real-time monitor should stand down and resume once they finish.

Both walk or stream enormous numbers of files. A real-time scanner trying to
keep up is competing with the backup for the same disks at the moment the
server can least afford it -- the same class of problem as the excessive load
reported earlier, but triggered by something outside the product.

The state machine is what these exercise: detection is stubbed, because
starting a real JetBackup to test a test is not a reasonable thing to do, and
because what can actually be got wrong here is the suspend/resume logic -- the
settling period, the safety cap, and not adopting a backup window as the new
baseline.
"""
import os
import sys
import sqlite3
import tempfile
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DAEMON = os.path.join(REPO, 'backend', 'daemon', 'monitor.py')

_passed = 0
_failed = 0


def ok(cond, what):
    global _passed, _failed
    if cond:
        _passed += 1
        print('PASS ' + what)
    else:
        _failed += 1
        print('FAIL ' + what)


def eq(expected, actual, what):
    ok(expected == actual, what if expected == actual
       else '%s - expected %r, got %r' % (what, expected, actual))


os.environ.setdefault('SG_ROOT', tempfile.mkdtemp())
spec = importlib.util.spec_from_file_location('sg_monitor_backup', DAEMON)
mon = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mon)
except Exception as e:
    print('FAIL monitor.py could not be imported - %s' % e)
    sys.exit(1)


def make_conn(settings=None):
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    # updated_at matters: db_set() writes it, and a schema without it makes
    # every write fail into the daemon's swallowed-exception path -- so the
    # test would report the state machine as broken when only the fixture was.
    conn.execute('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER DEFAULT 0)')
    conn.execute('CREATE TABLE security_events ('
                 'id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, severity TEXT, '
                 'description TEXT, timestamp INTEGER DEFAULT 0)')
    for k, v in (settings or {}).items():
        conn.execute('INSERT INTO settings (key,value) VALUES (?,?)', (k, str(v)))
    conn.commit()
    return conn


def events(conn):
    return [r['type'] for r in conn.execute('SELECT type FROM security_events')]


def setting(conn, key):
    row = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else None


class Fake(mon.BackupActivityDetector):
    """Detection replaced; the state machine left exactly as it is."""
    running = []

    def find_running(self):
        return list(self.running)


# -- Defaults ---------------------------------------------------------------
d = Fake(make_conn())
ok(d.enabled, 'pausing during backups is on by default')
ok('jetbackup' in d.names, 'JetBackup is detected by default')
ok('rsync' in d.names, 'rsync is detected by default')

# -- Nothing running: the monitor keeps working -----------------------------
conn = make_conn({'rt_backup_check_secs': 0})
d = Fake(conn)
d.running = []
eq(False, d.poll(conn, now=1000), 'an idle server does not suspend the monitor')
eq(False, d.suspended, 'and the detector does not think it is suspended')

# -- JetBackup starts -------------------------------------------------------
conn = make_conn({'rt_backup_check_secs': 0, 'rt_backup_resume_secs': 60})
d = Fake(conn)
d.running = ['jetbackup']
eq(True, d.poll(conn, now=1000), 'the monitor suspends while JetBackup runs')
eq('1', setting(conn, 'rt_suspended'), 'the suspension is recorded for the UI')
eq('jetbackup', setting(conn, 'rt_suspend_reason'), 'with the reason')
ok('monitor_suspended' in events(conn), 'and raised as a security event')

# Still running: stays suspended, and does not re-announce itself.
eq(True, d.poll(conn, now=1100), 'it stays suspended while the backup continues')
eq(1, events(conn).count('monitor_suspended'),
   'suspension is announced once, not on every poll')

# -- The backup finishes: a settling period before resuming -----------------
d.running = []
eq(True, d.poll(conn, now=1200),
   'it does not resume the instant the process disappears')
eq(True, d.poll(conn, now=1230),
   'nor before the settling period has elapsed')
eq(False, d.poll(conn, now=1300), 'it resumes once the settling period passes')
eq('0', setting(conn, 'rt_suspended'), 'the suspension flag is cleared')
ok('monitor_resumed' in events(conn), 'the resume is recorded')
ok(int(setting(conn, 'rt_last_gap_seconds')) >= 200,
   'the length of the blind spot is recorded, not hidden')

# -- rsync flapping between invocations -------------------------------------
# rsync is typically a series of short runs. Resuming between each one costs
# more than staying down, and would also mean announcing a gap every time.
conn = make_conn({'rt_backup_check_secs': 0, 'rt_backup_resume_secs': 120})
d = Fake(conn)
d.running = ['rsync']
d.poll(conn, now=0)
d.running = []
eq(True, d.poll(conn, now=30), 'a gap between rsync runs does not resume yet')
d.running = ['rsync']
eq(True, d.poll(conn, now=40), 'the next rsync keeps it suspended')
d.running = []
eq(True, d.poll(conn, now=100), 'and the settling clock restarts from the last one')
eq(1, events(conn).count('monitor_suspended'),
   'the whole transfer is one suspension, not one per rsync invocation')

# -- The safety cap ---------------------------------------------------------
# A process merely NAMED rsync is enough to suspend monitoring, so anyone who
# can start a process can suppress it. The cap is what stops that being
# permanent.
conn = make_conn({'rt_backup_check_secs': 0, 'rt_backup_max_suspend_secs': 300})
d = Fake(conn)
d.running = ['rsync']
eq(True, d.poll(conn, now=0), 'suspends as usual')
eq(True, d.poll(conn, now=200), 'still suspended before the cap')
eq(False, d.poll(conn, now=400),
   'resumes at the cap even though the process is still running')
ok('monitor_suspend_capped' in events(conn),
   'and says so, because an over-long suspension is worth seeing')
eq('0', setting(conn, 'rt_suspended'), 'the flag is cleared when the cap fires')

# -- Turning the feature off ------------------------------------------------
conn = make_conn({'rt_pause_on_backup': '0', 'rt_backup_check_secs': 0})
d = Fake(conn)
d.running = ['jetbackup']
eq(False, d.poll(conn, now=0),
   'with the setting off, a running backup does not suspend anything')

# A suspended monitor must resume if the setting is turned off mid-backup.
conn = make_conn({'rt_backup_check_secs': 0})
d = Fake(conn)
d.running = ['jetbackup']
d.poll(conn, now=0)
eq(True, d.suspended, 'suspended first')
conn.execute("UPDATE settings SET value='0' WHERE key='rt_pause_on_backup'")
conn.execute("INSERT OR IGNORE INTO settings (key,value) VALUES ('rt_pause_on_backup','0')")
conn.commit()
d.reload(conn)
eq(False, d.poll(conn, now=10), 'turning the setting off resumes immediately')

# -- A process list that would suspend for ever -----------------------------
conn = make_conn({'rt_backup_procs': '*, ,'})
d = Fake(conn)
ok('*' not in d.names,
   'a wildcard process name is rejected rather than matching everything')
ok(len(d.names) > 0, 'and the defaults are used instead of an empty list')

conn = make_conn({'rt_backup_procs': 'jetbackup'})
d = Fake(conn)
eq(set(['jetbackup']), d.names, 'an explicit list replaces the defaults')

# -- Bounds on the numbers --------------------------------------------------
conn = make_conn({'rt_backup_check_secs': 'abc', 'rt_backup_resume_secs': '-5',
                  'rt_backup_max_suspend_secs': '99999999'})
d = Fake(conn)
ok(d.check_every >= 5, 'a non-numeric check interval falls back to a sane value')
ok(d.resume_after >= 0, 'a negative settling period is clamped')
ok(d.max_suspend <= 86400, 'the cap cannot be set beyond a day')

# -- The detector must never match the monitor itself -----------------------
real = mon.BackupActivityDetector(make_conn())
ok(os.getpid() in real._self_pids, 'the daemon excludes its own PID from detection')

print('')
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
