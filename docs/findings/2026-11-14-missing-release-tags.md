# Missing release tags — backfill decision list

**Date:** 2026-11-14
**Status:** DECIDED 2026-11-14 — baseline only. `v4.35.1` was tagged and
pushed (annotated, on `8552261`, tagger date set to that commit's own date,
2026-11-06). The other **37** tags were deliberately NOT created. The
historical gap `v4.25.1` .. `v4.35.0` stands as a matter of record.

The reasoning: the version gate needs a trustworthy *baseline*, not a complete
history. One tag repairs it; 37 more would be a cosmetic push to a published
repo. The table below is kept as the record of what is missing, so the
decision can be revisited in one pass without re-deriving it.

`scripts/publish.sh` never had a tag step. The tag existed only as a side
effect of the GitHub-Release step, and that step is skipped when neither `gh`
nor `GH_TOKEN` is present, which is the permanent state of the release
machine. The warning it printed named the Release *page*, so the missing tag
was never noticed. That is fixed (step 4b, plus a post-release assertion).

This file is about the tags already missing. **It is 38 releases, not ten,
and the run starts at `v4.25.1`, not `v4.26.0`.** `v4.25.0` is the last
correctly tagged release before the gap; `v4.36.0` was tagged by hand on
2026-11-13 and is fine.

Local and remote tag sets are identical (168 tags each), so there is no
local-only or remote-only discrepancy to reconcile — every one of these 38 is
missing in both places.

Each `Release vX.Y.Z` commit is present in `main`'s history, so every tag
below has an unambiguous target. Verified: no version has two release commits.

## The 38 tags, oldest first

| Tag | Commit | Date |
|---|---|---|
| `v4.25.1` | `1d092c3` | 2026-10-31 |
| `v4.26.0` | `1ac5677` | 2026-11-02 |
| `v4.26.1` | `85c125a` | 2026-11-02 |
| `v4.26.2` | `32b9e52` | 2026-11-02 |
| `v4.27.0` | `96f1d66` | 2026-11-02 |
| `v4.27.1` | `5c07e40` | 2026-11-02 |
| `v4.28.0` | `8158b6d` | 2026-11-02 |
| `v4.28.1` | `eaddad3` | 2026-11-02 |
| `v4.28.2` | `20e93d6` | 2026-11-02 |
| `v4.28.3` | `56145d2` | 2026-11-02 |
| `v4.28.4` | `9dcf085` | 2026-11-02 |
| `v4.28.5` | `704b0b1` | 2026-11-02 |
| `v4.28.6` | `a15134d` | 2026-11-02 |
| `v4.28.7` | `f1d498f` | 2026-11-03 |
| `v4.28.8` | `d951106` | 2026-11-03 |
| `v4.28.9` | `8749d09` | 2026-11-03 |
| `v4.28.10` | `68ba3e9` | 2026-11-03 |
| `v4.28.11` | `e34b7b9` | 2026-11-03 |
| `v4.29.0` | `5dcaad5` | 2026-11-03 |
| `v4.29.1` | `72735af` | 2026-11-03 |
| `v4.29.2` | `2cde732` | 2026-11-03 |
| `v4.29.3` | `ad5fc6a` | 2026-11-03 |
| `v4.29.4` | `9523e43` | 2026-11-03 |
| `v4.29.5` | `030bcab` | 2026-11-03 |
| `v4.29.6` | `fdba352` | 2026-11-03 |
| `v4.29.7` | `adb3158` | 2026-11-03 |
| `v4.29.8` | `4821e54` | 2026-11-03 |
| `v4.29.9` | `0749809` | 2026-11-03 |
| `v4.30.0` | `0c37b38` | 2026-11-05 |
| `v4.31.0` | `f1e5d50` | 2026-11-05 |
| `v4.31.1` | `763f75e` | 2026-11-05 |
| `v4.31.2` | `8105622` | 2026-11-05 |
| `v4.32.0` | `34a97d7` | 2026-11-06 |
| `v4.33.0` | `ffc55f6` | 2026-11-06 |
| `v4.33.1` | `cd4608b` | 2026-11-06 |
| `v4.34.0` | `2230e11` | 2026-11-06 |
| `v4.35.0` | `f62729e` | 2026-11-06 |
| `v4.35.1` | `8552261` | 2026-11-06 |

## What backfilling would mean

38 annotated tags pushed to a published repository. Points to weigh:

- **The dates would be wrong.** An annotated tag records the tagger date, not
  the commit date. Tagging today stamps all 38 with 2026-11-14 unless
  `GIT_COMMITTER_DATE` is set per tag to the release commit's date.
- **It is a push to a public repo**, visible to anyone watching the
  repository, and tags are awkward to retract once fetched.
- **No GitHub Releases would be created** — these would be bare tags. The
  in-app updater reads `latest.json`, not the Releases list, so that is a
  cosmetic difference, not a functional one.
- **What it buys:** `check-version-bump.sh` gets a real baseline, and
  `git describe` and release-to-release diffs become possible for a range
  that is currently opaque. Without a backfill, the next release's gate will
  refuse to run until `SG_SKIP_VERSION_CHECK=1` is set, or until at least
  `v4.35.1` is tagged.
- **The middle option:** tag only `v4.35.1` (`8552261`). That is one tag, it
  repairs the baseline for the version gate, and it leaves the historical gap
  alone. The gate's requirement is a trustworthy *baseline*, not a complete
  history.

## Commands — FOR THE USER TO RUN, NOT RUN HERE

The baseline repair below HAS BEEN RUN (2026-11-14) and is recorded here for
provenance. The full backfill has NOT been run and remains the open option.

Done — repair the baseline only:

    D="$(git log -1 --format=%aI 8552261)"
    GIT_COMMITTER_DATE="$D" git tag -a v4.35.1 -m "ServerScrub v4.35.1" 8552261
    git push origin refs/tags/v4.35.1

Verified afterwards: `refs/tags/v4.35.1` on origin dereferences to `8552261`;
local and remote both hold 169 tags, exactly one more than before; and no
untagged `Release vX.Y.Z` commit remains after the new baseline `v4.36.0`, so
the next release's version gate has a baseline it can trust.

NOT RUN — full backfill, with each tag dated to its own release commit:

    git log --format='%h %s' --grep='^Release v' --reverse | while read -r sha subj; do
        t="${subj#Release }"
        git rev-parse -q --verify "refs/tags/${t}" >/dev/null 2>&1 && continue
        d="$(git log -1 --format=%aI "$sha")"
        GIT_COMMITTER_DATE="$d" git tag -a "$t" -m "ServerScrub ${t}" "$sha"
    done
    # inspect what that created BEFORE pushing:
    git tag --sort=v:refname | tail -45
    # then, deliberately:
    git push origin --tags
