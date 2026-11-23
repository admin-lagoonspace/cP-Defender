# Fixed-character windows in test_scan_concurrency.php become t_fn_body

**Asked for:** "fix everything and ship new one" (carried forward from the first-pass review finding 7: "three remaining fixed-character test windows, tightest `tests/test_scan_concurrency.php:388`, `waitOutBackup`/`sleep(30)`, 96 chars headroom; wants `t_fn_body()`")
**Status:** ready-for-wasooli
**Size:** Z (test-only; no product behaviour changes)

## What the user is actually trying to achieve

A test that fails for a reason unrelated to the behaviour it names costs more
than it earns — it gets investigated, found innocent, and teaches everyone to
distrust the suite. These windows will fail the next time a function above the
needle grows, on a commit that is correct.

## What exists today

`tests/assert.php:182` already provides the fix, with `'php'` support:

```php
function t_fn_body(string $src, string $name, string $lang = 'js'): string
```

It slices from a function's declaration to the next top-level declaration, and
the file's own comments explain why (`tests/test_scan_concurrency.php:158-166`
for `scanBatch`, `:320-329` for `reapStaleJobs` — the latter records a window
that reached its needles "with 193 characters to spare" and was pushed past the
end by a legitimate fix). `t_fn_body` is used 124 times across `tests/`, so this
is an established convention with stragglers, not a new idea.

Remaining fixed-character windows over a PHP **function body** in
`tests/test_scan_concurrency.php`:

- `:180` `reapOrphanClamscans`, 1600
- `:365` `stopAllScans`, 1600
- `:384` `backupRunning`, 700
- `:388` `waitOutBackup`, 1600 — the one reported at 96 characters of headroom
- `:404` `startScan`, 1800

That is five, not the three reported. I could not independently reproduce the
96-character figure and am not disputing it: `$sc2` comes from `t_code()`, which
blanks comments, so offsets measured against the raw file do not apply and raw
measurement is meaningless here. The count above is from reading the call sites.

Two windows in the same file are **not** function bodies and are out of scope:
`:145` (a `'scan' => [` array entry in the scheduler) and `:395` (a `foreach`
loop inside a function). `:149` slices from a `$paths = array_values` statement.
`t_fn_body` cannot express those.

## Requirements

1. Every assertion in `tests/test_scan_concurrency.php` that currently reads a
   fixed character count from the start of a PHP function declaration asserts
   against the whole function body instead, via `t_fn_body($src, '<name>',
   'php')`.
2. Each converted site asserts the same claims, in the same order, as it does
   today. No claim is dropped, weakened, or added.
3. Where a claim depended on a needle being *near the top* of a function (the
   700-character window at `:384` asserts the backup probe is cached rather than
   run per batch), that intent is preserved explicitly rather than lost to a
   wider window — assert the behaviour, not the proximity.
4. Each conversion carries a one-line reason in the same style as the two
   existing ones, so the next reader does not reintroduce a byte count.
5. Windows that do not slice a function body are left alone.

## Explicitly out of scope

- The other ~40 fixed-character `substr()` windows elsewhere in `tests/`
  (`test_chart_labels.php`, `test_dashboard_overview.php`, `test_autoupdate.php`
  and others). Converting them wholesale is a separate piece of work with its
  own risk of silently weakening assertions.
- Any change to `tests/assert.php`.
- Any change under `backend/`.

## Failure behaviour

- `t_fn_body` returns `''` when the function is not found. Each converted site
  must assert non-empty first (`t_ok($x !== '', '<name> is still where …')`), as
  `:168` already does — otherwise a renamed function turns every `t_contains`
  below it into a vacuous pass against an empty string. That is the one way this
  change could make the suite *less* honest, and it is the thing to watch for.

## Resource bounds

None. The suite reads five files it already reads; `t_fn_body` runs two
`preg_match` calls per site.

## Acceptance criteria

1. `tests/test_scan_concurrency.php` contains no `substr(` call whose second
   argument is a `strpos()` of a `function ` declaration.
2. The suite passes in docker, unchanged in pass count except for the
   non-empty-body assertions added by requirement 5 of the failure note.
3. Renaming one of the five functions in a scratch copy of
   `backend/lib/Scanner.php` makes the corresponding test **fail** with a
   message naming that function, rather than passing vacuously.
4. Inserting 400 characters of new code at the top of `waitOutBackup()` in a
   scratch copy leaves the test passing. On today's code that insertion breaks
   it, which is the defect.
5. No file under `backend/`, `frontend/` or `scripts/` is modified by this work.

## Open questions

1. The first-pass review said three windows; I found five function-body windows.
   If two of them were deliberately judged acceptable, converting them anyway is
   harmless, so this spec covers all five rather than guessing which three were
   meant.
