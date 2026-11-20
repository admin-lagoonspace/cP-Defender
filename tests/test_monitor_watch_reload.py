#!/usr/bin/env python3
"""Changing a limit must take effect without restarting the monitor.

Reported with a screenshot: the Real-Time Monitor card showed

    WATCHES  20,000 / 100,000      [Watch limit reached]
    "The kernel refused more inotify watches, so some directories are NOT
     being watched."

after the operator had raised the watch ceiling to 100,000 and saved. A count
of 20,000 against a ceiling of 100,000 is not a state the kernel can be in, so
the panel was reporting something stale -- and the operator's conclusion, that
saving the setting had done nothing, was correct.

THREE DEFECTS, ALL FROM THE SAME ROOT
-------------------------------------
The watch list is built by walking the tree ONCE, at startup, and nothing
re-ran that walk.

  1. Raising rt_max_watches added no watches. The daemon kept exactly the
     watches it had until the process was restarted.
  2. rt_watch_capped was only ever set to '1' outside that initial walk --
     add_watch_tree() sets it, nothing clears it -- so once capped, always
     capped.
  3. The effective-limit settings (rt_effective_*) were published only at
     startup, so the row claiming to show "what is in force" showed what was
     in force when the process booted.

And the warning named our ceiling AND the host sysctl in one sentence for
every capped state, so whichever one an operator fixed, the text still told
them to fix the other.

These tests exercise the real functions out of monitor.py against a temporary
SQLite settings table and a fake inotify, so they fail if the re-walk, the
re-publish or the reason tracking is removed.
"""
import os
import sqlite3
import sys
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
    ok(expected == actual,
       what + ('' if expected == actual else '  (expected %r, got %r)' % (expected, actual)))


# ── Load the daemon without running it ──────────────────────────────────────
spec = importlib.util.spec_from_file_location('sg_monitor', DAEMON)
mon = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mon)
except Exception as e:                                    # pragma: no cover
    print('SKIP could not import monitor.py: %s' % e)
    sys.exit(0)

for fn in ('publish_effective', 'record_watch_state', 'rewatch_to_cap'):
    ok(hasattr(mon, fn), 'monitor.py defines %s()' % fn)
if not all(hasattr(mon, f) for f in ('publish_effective', 'record_watch_state', 'rewatch_to_cap')):
    print('\n%d passed, %d failed' % (_passed, _failed))
    sys.exit(1)


def settings_db():
    """A settings table shaped the way db_get/db_set expect."""
    path = os.path.join(tempfile.mkdtemp(prefix='sg-watch-'), 'sg.db')
    conn = sqlite3.connect(path)
    # updated_at is required: db_set() writes it, and without the column the
    # INSERT raises and db_set swallows it at debug level -- the write simply
    # does not happen and nothing says so.
    conn.execute('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, '
                 'updated_at INTEGER)')
    conn.commit()
    return conn


def get(conn, key, default=''):
    r = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return r[0] if r else default


class FakeINotify(object):
    """Stands in for inotify_simple.INotify.

    `refuse_after` is the HOST's limit: the point at which the kernel starts
    raising OSError no matter what our own ceiling says. That distinction is
    the thing under test.
    """

    def __init__(self, refuse_after=None):
        self.refuse_after = refuse_after
        self.n = 0

    def add_watch(self, path, flags):
        if self.refuse_after is not None and self.n >= self.refuse_after:
            raise OSError(28, 'No space left on device')
        self.n += 1
        return self.n


def tree(dirs):
    """A directory tree with `dirs` subdirectories to walk."""
    base = tempfile.mkdtemp(prefix='sg-tree-')
    for i in range(dirs):
        os.makedirs(os.path.join(base, 'd%03d' % i))
    return base


LIMITS = {
    'profile': 'custom', 'nice': 10, 'files_per_sec': 25,
    'max_file_size': 16 * 1024 * 1024, 'poll_interval': 300,
    'max_watches': 20000, 'debounce': 5, 'excludes': set(),
}


def limits(**over):
    d = dict(LIMITS)
    d.update(over)
    return d


# ── 1. Raising the ceiling takes up the refused watches ────────────────────
#
# The reported bug, directly: the count must move and the flag must clear,
# with no restart.
conn = settings_db()
base = tree(12)                      # 12 subdirs + the base itself = 13
ino = FakeINotify()
wds = {}

# A first walk under a low ceiling, capped by OUR setting.
mon.rewatch_to_cap(conn, ino, wds, [base], 0, limits(max_watches=5))
eq('5', get(conn, 'rt_watch_count'), 'a low ceiling stops the walk at the ceiling')
eq('1', get(conn, 'rt_watch_capped'), 'and records that it is capped')
eq('ceiling', get(conn, 'rt_watch_cap_reason'),
   'THE REASON IS RECORDED: our own setting was the binding limit, not the host')

# Now the operator raises it and saves. No restart.
added, capped, reason = mon.rewatch_to_cap(conn, ino, wds, [base], 0, limits(max_watches=20000))
ok(added > 0,
   'RAISING THE CEILING ADDS WATCHES: the re-walk takes up what the lower '
   'ceiling refused, which is what used to need a restart')
eq('0', get(conn, 'rt_watch_capped'),
   'THE FLAG CLEARS: this is the reported bug -- rt_watch_capped was only '
   'ever set to 1 outside the startup walk, so once capped it stayed capped '
   'for the life of the process')
eq('', get(conn, 'rt_watch_cap_reason'), 'and the reason is cleared with it')
eq('13', get(conn, 'rt_watch_count'),
   'and the count is the real number of watches now held, not the old one')

# The count must never exceed the ceiling it is displayed against -- that
# combination (20,000 / 100,000 and "limit reached") is what made the panel
# look stuck.
ok(int(get(conn, 'rt_watch_count')) <= 20000,
   'the published count never exceeds the ceiling it is shown against')


# ── 2. A kernel refusal is NOT the same as our ceiling ─────────────────────
#
# Raising rt_max_watches against a kernel limit changes nothing, and telling
# the operator to raise it is what made them think the setting was broken.
conn = settings_db()
base = tree(30)
ino = FakeINotify(refuse_after=7)        # the HOST gives up at 7
wds = {}
added, capped, reason = mon.rewatch_to_cap(conn, ino, wds, [base], 0, limits(max_watches=100000))

ok(capped, 'a kernel refusal still counts as capped')
eq('kernel', reason,
   'THE HOST IS NAMED, NOT OUR SETTING: the kernel refused below our ceiling, '
   'so raising the ceiling on the page would do nothing')
eq('kernel', get(conn, 'rt_watch_cap_reason'), 'and that reason is published for the panel')
ok(int(get(conn, 'rt_watch_count')) < 100000,
   'with a count below the ceiling -- exactly the screenshot that was '
   'reported, which is honest ONLY when the reason says the host refused')

# Raising our ceiling again must not pretend to fix it.
mon.rewatch_to_cap(conn, ino, wds, [base], 0, limits(max_watches=500000))
eq('1', get(conn, 'rt_watch_capped'),
   'raising OUR ceiling against a kernel limit leaves it capped, because it is')
eq('kernel', get(conn, 'rt_watch_cap_reason'), 'and still names the host')


# ── 3. Lowering the ceiling is reflected too ───────────────────────────────
conn = settings_db()
base = tree(10)
ino = FakeINotify()
wds = {}
mon.rewatch_to_cap(conn, ino, wds, [base], 0, limits(max_watches=20000))
eq('0', get(conn, 'rt_watch_capped'), 'an ample ceiling is not capped')

mon.rewatch_to_cap(conn, ino, wds, [base], 0, limits(max_watches=3))
eq('1', get(conn, 'rt_watch_capped'),
   'LOWERING the ceiling below the watches held reports capped, rather than '
   'leaving a stale "healthy" from the previous reading')
eq('ceiling', get(conn, 'rt_watch_cap_reason'), 'and names our setting, which is correct now')


# ── 4. Nothing is watched twice ────────────────────────────────────────────
conn = settings_db()
base = tree(8)
ino = FakeINotify()
wds = {}
mon.rewatch_to_cap(conn, ino, wds, [base], 0, limits(max_watches=20000))
first = len(wds)
added, _, _ = mon.rewatch_to_cap(conn, ino, wds, [base], 0, limits(max_watches=20000))
eq(0, added, 'a re-walk with nothing new adds nothing')
eq(first, len(wds),
   'IDEMPOTENT: the re-walk skips directories already watched, so it cannot '
   'inflate the count or burn kernel watches every reload tick')


# ── 5. The effective limits are publishable at any time ────────────────────
#
# They were written once, in main(), so every reported value was the one the
# process booted with.
conn = settings_db()
mon.publish_effective(conn, limits(max_watches=4242, nice=17, files_per_sec=9,
                                   poll_interval=600, debounce=11))
eq('4242', get(conn, 'rt_effective_max_watches'),
   'publish_effective() writes the watch ceiling')
eq('17', get(conn, 'rt_effective_nice'), 'and the nice value')
eq('9', get(conn, 'rt_effective_files_per_sec'), 'and the rate')
eq('600', get(conn, 'rt_effective_poll_interval'), 'and the poll interval')
eq('11', get(conn, 'rt_effective_debounce'), 'and the debounce window')

# Called again with different limits, it must overwrite -- that is the point.
mon.publish_effective(conn, limits(max_watches=99, nice=3))
eq('99', get(conn, 'rt_effective_max_watches'),
   'A SECOND CALL OVERWRITES: this is what makes a saved change visible '
   'without a restart')
eq('3', get(conn, 'rt_effective_nice'), 'for every field, not just one')


# ── 6. The reload tick actually calls them ─────────────────────────────────
#
# The functions existing is not the fix. Being wired into the reload path is.
with open(DAEMON, encoding='utf-8') as fh:
    src = fh.read()

reload_blocks = src.count('publish_effective(conn, limits)')
ok(reload_blocks >= 3,
   'publish_effective() is called from startup AND from both reload ticks '
   '(found %d call sites)' % reload_blocks)
ok('rewatch_to_cap(conn, ino, wds, paths, fl, limits)' in src,
   'THE RE-WALK IS WIRED IN: the inotify reload tick calls it, which is the '
   'difference between a fix and an unused function')
ok("if limits['max_watches'] != prev_max:" in src,
   'and only when the ceiling actually moved, so an unchanged reload does not '
   're-walk the whole tree every minute')
ok('record_watch_state(conn, len(wds), True' in src,
   'add_watch_tree records the cap reason rather than setting the bare flag')

print('')
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
