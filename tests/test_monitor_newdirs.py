#!/usr/bin/env python3
"""A directory created after the daemon started is watched too.

Asked for: "in real time monitor also check which new files were created and
scan them too not just changed files".

The event mask already carried CREATE and MOVED_TO, so a new FILE in a watched
directory was never the gap. The gap was a directory: inotify watches are
per-directory and do not recurse, and the watch list was built once by walking
the tree at startup. So a directory created afterwards had no watch, and every
file created inside it was invisible for the lifetime of the daemon -- which is
the ordinary shape of a web-shell drop, not an exotic case, and a restart was
the only thing that closed it.

Two halves, and the second is the one that is easy to leave out:

  - the new directory gets a watch, recursively, bounded by rt_max_watches;
  - the files ALREADY in it are swept once. Between the directory being created
    and the watch being added, files can land, and inotify never delivers those
    events to anybody. Watching without sweeping means the payload that arrived
    in that window is missed exactly as thoroughly as before.
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
spec = importlib.util.spec_from_file_location('sg_monitor_newdirs', DAEMON)
mon = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mon)
except Exception as e:
    print('FAIL monitor.py could not be imported - %s' % e)
    sys.exit(1)


def make_conn():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, '
                 'updated_at INTEGER DEFAULT 0)')
    conn.commit()
    return conn


class FakeINotify(object):
    """add_watch recorded rather than performed.

    The kernel is not the thing under test here; which directories we ASK it
    to watch is.
    """
    def __init__(self, fail_on=()):
        self.watched = []
        self.fail_on = set(fail_on)
        self._next = 1

    def add_watch(self, path, flags):
        if path in self.fail_on:
            raise PermissionError(path)
        self.watched.append(path)
        self._next += 1
        return self._next


# ── A tree that appears after startup ──────────────────────────────────────
base = tempfile.mkdtemp()
newdir = os.path.join(base, 'uploads')
nested = os.path.join(newdir, 'inner')
os.makedirs(nested)

# A payload already inside it before the watch exists. This is the file whose
# CREATE event nobody ever receives.
planted = os.path.join(nested, 'shell.php')
with open(planted, 'w') as fh:
    fh.write('<?php echo 1;')

# And something the monitor has no business opening, to confirm the sweep still
# goes through interesting() rather than handing over every file it finds.
with open(os.path.join(newdir, 'holiday.jpg'), 'w') as fh:
    fh.write('not php')

ok(hasattr(mon, 'add_watch_tree'),
   'the daemon has a path for directories that appear after startup')

limits = {'excludes': {'node_modules', '.git'}, 'max_watches': 100,
          'files_per_sec': 1000, 'debounce': 0, 'nice': 19,
          'poll_interval': 60, 'profile': 'test'}

handled = []


def fake_handle(conn, fp, lim, limiter, debouncer):
    handled.append(fp)


mon.handle = fake_handle

conn = make_conn()
ino = FakeINotify()
wds = {}

added = mon.add_watch_tree(conn, ino, wds, newdir, 0, limits, None, None)

eq(2, added, 'the new directory AND its subdirectory are watched - inotify '
             'does not recurse, so one watch on the parent would miss the rest')
ok(newdir in ino.watched, 'the directory itself is watched')
ok(nested in ino.watched, 'and so is the subdirectory created with it')
eq(2, len(wds), 'and both are recorded, so events on them can be resolved '
                'back to a path')

ok(planted in handled,
   'THE SWEEP: a file already inside the new directory is examined. Its '
   'CREATE event was delivered to nobody -- there was no watch yet -- so '
   'watching without sweeping would miss the payload that arrived in that '
   'window just as completely as before')
ok(not any(f.endswith('.jpg') for f in handled),
   'and the sweep still goes through interesting(), so it does not open '
   'every file in the tree')

# ── The watch cap is respected ─────────────────────────────────────────────
#
# Without this an attacker creating directories could exhaust
# fs.inotify.max_user_watches, and once that limit is hit the kernel refuses
# watches for the WHOLE tree. Declining a new subtree loses that subtree;
# running out of watches loses the server.
conn2 = make_conn()
ino2 = FakeINotify()
tight = dict(limits)
tight['max_watches'] = 1
wds2 = {}
mon.add_watch_tree(conn2, ino2, wds2, newdir, 0, tight, None, None)
ok(len(wds2) <= 1,
   'THE CAP HOLDS: watches stop at rt_max_watches rather than exhausting the '
   'kernel limit for every other watch on the server')
row = conn2.execute("SELECT value FROM settings WHERE key='rt_watch_capped'").fetchone()
eq('1', row['value'] if row else None,
   'and the capped state is recorded, so the monitor cannot report itself as '
   'fully covering a tree it is not')

# ── An excluded directory is still excluded ────────────────────────────────
excl = os.path.join(base, 'node_modules')
os.makedirs(excl)
conn3 = make_conn()
ino3 = FakeINotify()
wds3 = {}
eq(0, mon.add_watch_tree(conn3, ino3, wds3, excl, 0, limits, None, None),
   'an excluded directory created later is not watched either - the exclusion '
   'list has to mean the same thing before and after startup')

# ── A directory that vanishes between event and watch ──────────────────────
#
# Real, and common: a build tool creating and removing temporary directories.
# An unhandled exception here would kill the event loop and stop monitoring
# the entire server.
conn4 = make_conn()
ino4 = FakeINotify(fail_on=(newdir,))
wds4 = {}
try:
    mon.add_watch_tree(conn4, ino4, wds4, newdir, 0, limits, None, None)
    ok(True, 'a directory that cannot be watched is skipped, not fatal - an '
             'exception here would take down monitoring for the whole server')
except Exception as e:
    ok(False, 'a directory that cannot be watched raised %r' % (e,))

print()
if _failed:
    print('%d of %d assertions failed' % (_failed, _passed + _failed))
    sys.exit(1)
print('%d assertions passed' % _passed)
