#!/usr/bin/env python3
"""Real-time monitor resource limits.

Reported symptom: real-time monitoring puts excessive load on a live server.

The throttle that existed only widened the gap between file scans. It did
nothing about the three things that actually cost:

  1. Polling walked every watched path and stat()ed EVERY file each interval,
     holding a path->mtime dict for the whole tree. Against /home on a shared
     host that is millions of syscalls per pass, for ever.
  2. inotify added one watch per directory with no ceiling, and an exhausted
     kernel watch limit was swallowed - leaving partial coverage while the
     monitor reported itself healthy.
  3. Every event read the whole file and ran the pattern set, with no cap on
     events per second and no coalescing of repeats.

These tests exercise the limiter, the debouncer and the profile resolution
directly. Run by tests/run.php alongside the PHP suite.
"""
import os
import sys
import time
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


# ── Import the daemon without running it ─────────────────────────────────────
os.environ.setdefault('SG_ROOT', tempfile.mkdtemp())
spec = importlib.util.spec_from_file_location('sg_monitor', DAEMON)
mon = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mon)
except Exception as e:                                    # pragma: no cover
    print('FAIL monitor.py could not be imported - %s' % e)
    sys.exit(1)
ok(True, 'monitor.py imports without side effects')


# ── A settings table the profile loader can read ─────────────────────────────
def make_conn(settings=None):
    conn = sqlite3.connect(':memory:')
    # db_get() reads r['value'], which requires the Row factory the daemon sets
    # in db_connect(). Without it every lookup raises and is swallowed by the
    # bare except, so every setting silently reads as its default -- which is
    # exactly what the first run of this test showed.
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)')
    for k, v in (settings or {}).items():
        conn.execute('INSERT INTO settings (key,value) VALUES (?,?)', (k, str(v)))
    conn.commit()
    return conn


# ── Profiles ─────────────────────────────────────────────────────────────────
light = mon.load_profile(make_conn({'rt_profile': 'light'}))
heavy = mon.load_profile(make_conn({'rt_profile': 'thorough'}))
default = mon.load_profile(make_conn({}))

eq('light', light['profile'], 'the light profile is selected by name')
eq('balanced', default['profile'], 'balanced is the default profile')

ok(light['files_per_sec'] < heavy['files_per_sec'],
   'light examines fewer files per second than thorough')
ok(light['nice'] > heavy['nice'],
   'light runs at a lower priority (higher nice) than thorough')
ok(light['poll_interval'] > heavy['poll_interval'],
   'light polls less often than thorough')
ok(light['max_watches'] < heavy['max_watches'],
   'light sets fewer inotify watches than thorough')
ok(light['max_file_size'] < heavy['max_file_size'],
   'light skips larger files sooner than thorough')

# An unknown profile name must not disable the limits.
weird = mon.load_profile(make_conn({'rt_profile': 'turbo'}))
eq('balanced', weird['profile'], 'an unrecognised profile falls back to balanced')

# ── Custom profile ───────────────────────────────────────────────────────────
custom = mon.load_profile(make_conn({
    'rt_profile': 'custom',
    'rt_nice': '15',
    'rt_max_files_per_sec': '7',
    'rt_max_file_size_mb': '2',
    'rt_poll_interval': '600',
    'rt_max_watches': '1234',
    'rt_debounce_seconds': '30',
}))
eq('custom', custom['profile'], 'custom is honoured')
eq(15, custom['nice'], 'a custom nice value is used')
eq(7, custom['files_per_sec'], 'a custom file rate is used')
eq(2 * 1024 * 1024, custom['max_file_size'], 'a custom size cap is used')
eq(600, custom['poll_interval'], 'a custom poll interval is used')
eq(1234, custom['max_watches'], 'a custom watch cap is used')
eq(30, custom['debounce'], 'a custom debounce window is used')

# Nonsense must be clamped, not obeyed. A user typing 0 or a negative number
# must not produce an unthrottled monitor.
clamped = mon.load_profile(make_conn({
    'rt_profile': 'custom',
    'rt_max_files_per_sec': '0',
    'rt_poll_interval': '1',
    'rt_max_watches': '99999999',
    'rt_nice': '-5',
}))
ok(clamped['files_per_sec'] >= 1, 'a file rate of 0 is clamped to at least 1')
ok(clamped['poll_interval'] >= 10, 'a 1-second poll interval is clamped upward')
ok(clamped['max_watches'] <= 500000, 'an absurd watch cap is clamped')
ok(0 <= clamped['nice'] <= 19, 'nice stays in range')

garbage = mon.load_profile(make_conn({'rt_profile': 'custom',
                                      'rt_max_files_per_sec': 'lots'}))
ok(garbage['files_per_sec'] >= 1, 'non-numeric settings fall back to a default')

# ── Exclusions ───────────────────────────────────────────────────────────────
ok('node_modules' in default['excludes'], 'node_modules is excluded by default')
withextra = mon.load_profile(make_conn({'rt_exclude_dirs': 'mybackups, tmpdir'}))
ok('mybackups' in withextra['excludes'], 'a user exclusion is honoured')
ok('tmpdir' in withextra['excludes'], 'whitespace around exclusions is trimmed')
ok('node_modules' in withextra['excludes'],
   'user exclusions add to the defaults rather than replacing them')

# ── Rate limiter ─────────────────────────────────────────────────────────────
lim = mon.RateLimiter(10)
start = time.time()
for _ in range(20):
    lim.take()
elapsed = time.time() - start
# 20 files at 10/s: the bucket starts full, so ~1s of enforced delay.
ok(elapsed >= 0.7, 'the limiter actually slows a burst (%.2fs for 20 at 10/s)' % elapsed)
ok(elapsed < 5.0, 'the limiter does not overshoot wildly (%.2fs)' % elapsed)

fast = mon.RateLimiter(1000)
start = time.time()
for _ in range(50):
    fast.take()
ok(time.time() - start < 0.5, 'a high limit costs almost nothing')

lim.update(50)
eq(50, lim.rate, 'the limiter rate can be changed without a restart')

# ── Debouncer ────────────────────────────────────────────────────────────────
deb = mon.Debouncer(5)
eq(False, deb.should_skip('/tmp/a.php'), 'the first event for a path is handled')
eq(True, deb.should_skip('/tmp/a.php'), 'an immediate repeat is suppressed')
eq(False, deb.should_skip('/tmp/b.php'), 'a different path is unaffected')

off = mon.Debouncer(0)
eq(False, off.should_skip('/tmp/c.php'), 'debounce 0 disables suppression')
eq(False, off.should_skip('/tmp/c.php'), 'debounce 0 lets repeats through')

# The suppression map must not grow without bound on a busy server.
big = mon.Debouncer(1)
for i in range(25000):
    big.should_skip('/tmp/f%d.php' % i)
ok(len(big.seen) <= 20000, 'the debounce map stays bounded (%d entries)' % len(big.seen))

# ── The size cap is enforced by scan() ───────────────────────────────────────
tmp = tempfile.mkdtemp()
big_file = os.path.join(tmp, 'big.php')
with open(big_file, 'wb') as fh:
    fh.write(b'<?php eval(base64_decode("aaa")); ?>' + b'x' * 200000)

eq(None, mon.scan(big_file, max_size=1024),
   'a file over the size cap is skipped entirely')
ok(mon.scan(big_file, max_size=10 * 1024 * 1024) is not None,
   'the same file is scanned when the cap allows it')

print('')
if _failed:
    sys.exit(1)
sys.exit(0)
