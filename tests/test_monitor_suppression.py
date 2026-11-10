#!/usr/bin/env python3
"""A signature switched off by name must be off for the REALTIME daemon too.

On 10 Nov one third-party ClamAV signature matched 154,323 customer files, and
the only lever the product offered was turning ClamAV off. Suppression by name
fixes that for the scan, through ThreatStore::record() -- the one place every
PHP detection passes through.

The daemon is not one of those places. monitor.py writes its own rows with its
own INSERT, and it honoured the verdict gate and nothing else. So an operator
could suppress a noisy signature, watch the scan go quiet, and then watch the
same finding arrive every time a file changed -- which is worse than having no
suppression at all, because it looks like the feature does not work.

What this file pins: a suppressed name produces no row, the match is still
counted so the hole stays visible, an unsuppressed name is recorded exactly as
before, a prefix suppression works the same way, and the list is re-read while
the daemon is running -- it runs for days, and a suppression added during an
incident has to take effect without a restart.
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
spec = importlib.util.spec_from_file_location('sg_monitor_suppression', DAEMON)
mon = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mon)
except Exception as e:
    print('FAIL monitor.py could not be imported - %s' % e)
    sys.exit(1)

SIG = '{HEX}linux.ransom.sessionscribe.qtox.toxid.171.UNOFFICIAL'
OTHER = '{HEX}php.cmdshell.gifheader.400.UNOFFICIAL'


def make_conn(suppressions=()):
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE threats (id INTEGER PRIMARY KEY AUTOINCREMENT, '
                 'file_path TEXT, threat_name TEXT, threat_type TEXT, severity TEXT, '
                 'status TEXT, hash TEXT, size INTEGER, detected_at INTEGER)')
    conn.execute('CREATE TABLE file_verdicts (id INTEGER PRIMARY KEY AUTOINCREMENT, '
                 'file_path TEXT, sha256 TEXT, verdict TEXT, revoked_at INTEGER)')
    conn.execute('CREATE TABLE signature_suppressions ('
                 'id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, is_prefix INTEGER '
                 'DEFAULT 0, reason TEXT DEFAULT \'\', created_by TEXT DEFAULT \'\', '
                 'created_at INTEGER DEFAULT 0, hits INTEGER NOT NULL DEFAULT 0, '
                 'last_hit_at INTEGER)')
    for name, prefix in suppressions:
        conn.execute('INSERT INTO signature_suppressions (name, is_prefix) VALUES (?,?)',
                     (name, 1 if prefix else 0))
    conn.commit()
    # The module caches the list; each connection is a fresh world.
    mon._SUPPRESSED = None
    mon._SUPPRESSED_AT = 0.0
    return conn


def a_file(body='inert fixture\n'):
    """A real file on disk, with inert content.

    Deliberately not malware: the developer's own antivirus reported two Severe
    backdoors against this suite's fixtures and held one open mid-test. What is
    being tested is whether a row is written, which has nothing to do with the
    bytes.
    """
    fd, path = tempfile.mkstemp(prefix='sg-sup-', suffix='.txt')
    with os.fdopen(fd, 'w') as fh:
        fh.write(body)
    return path


def rows(conn):
    return conn.execute('SELECT COUNT(*) FROM threats').fetchone()[0]


# -- Nothing suppressed: the daemon records as it always did ------------------

conn = make_conn()
path = a_file()
tid = mon.db_threat(conn, path, SIG)
ok(tid > 0, 'with nothing suppressed, a realtime detection is recorded')
eq(1, rows(conn), 'as one row')

# -- Suppressed by exact name ------------------------------------------------

conn = make_conn([(SIG, False)])
eq(0, mon.db_threat(conn, path, SIG),
   'A SUPPRESSED SIGNATURE PRODUCES NO ROW from the realtime daemon either. '
   'Without this, suppressing a noisy signature silenced the scan and left the '
   'daemon reporting the same finding on every file change')
eq(0, rows(conn), 'and the threats table stays empty')

hits = conn.execute('SELECT hits, last_hit_at FROM signature_suppressions').fetchone()
eq(1, hits[0],
   'AND THE MATCH IS COUNTED: a hole in the defence that nobody can see is '
   'indistinguishable from a scanner that has stopped working')
ok((hits[1] or 0) > 0, 'with when it last hid something')

# A different signature in the same world is unaffected.
ok(mon.db_threat(conn, path, OTHER) > 0,
   'another signature is still recorded - this suppresses one rule, not the '
   'monitor')

# -- Prefix suppression ------------------------------------------------------

conn = make_conn([('{HEX}linux.ransom.*', True)])
eq(0, mon.db_threat(conn, path, SIG),
   'a trailing * suppresses the family, the same as it does for the scan')
ok(mon.db_threat(conn, path, OTHER) > 0, 'and only that family')

# -- The list is re-read while the daemon runs -------------------------------

conn = make_conn()
ok(mon.db_threat(conn, path, SIG) > 0, 'recorded while nothing is suppressed')
conn.execute('INSERT INTO signature_suppressions (name, is_prefix) VALUES (?,0)', (SIG,))
conn.commit()
# The daemon runs for days; a suppression added during an incident must take
# effect without restarting it. The TTL is 60s, so the cache is aged by hand
# here rather than by sleeping through it.
mon._SUPPRESSED_AT = 0.0
eq(0, mon.db_threat(conn, path, SIG),
   'and a suppression added while the daemon is running takes effect without a '
   'restart - the cache has a TTL rather than being read once at startup')

# -- A missing table must not stop the daemon recording ----------------------

conn = sqlite3.connect(':memory:')
conn.row_factory = sqlite3.Row
conn.execute('CREATE TABLE threats (id INTEGER PRIMARY KEY AUTOINCREMENT, '
             'file_path TEXT, threat_name TEXT, threat_type TEXT, severity TEXT, '
             'status TEXT, hash TEXT, size INTEGER, detected_at INTEGER)')
conn.execute('CREATE TABLE file_verdicts (id INTEGER PRIMARY KEY AUTOINCREMENT, '
             'file_path TEXT, sha256 TEXT, verdict TEXT, revoked_at INTEGER)')
conn.commit()
mon._SUPPRESSED = None
mon._SUPPRESSED_AT = 0.0
ok(mon.db_threat(conn, path, SIG) > 0,
   'FAILING CLOSED HERE WOULD MEAN FAILING SILENT: with no suppressions table '
   'at all - an older database, mid-upgrade - the finding is still recorded')

os.unlink(path)

print('')
print('%d passed, %d failed' % (_passed, _failed))
sys.exit(1 if _failed else 0)
