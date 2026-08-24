# Engineering decision record — M2c follow-up 2: the index digest was blind to flag bits

Date: 2026-08-24 · Branch: `m2c-index-flags` → `main` · Tier: **contained**
(one security control, no schema change) · Raised by: the Codex stop-time
review of `bc33722` — "`ls-files --stage` misses behavior-changing index flags,
leaving a silent tripwire bypass." Correct.

This is the THIRD finding against the verification tripwire (byte exclusion →
semantic digest → flag bits). The response therefore includes an enumeration
test so the control stops being fixed one hole at a time.

## The gap (measured, git 2.50.1)
`git ls-files --stage` prints mode, blob sha, stage, path — not the index flag
bits. Setting or clearing `--skip-worktree` or `--assume-unchanged` left the
digest byte-identical (`77e8ab5ecf` before and after both). Those bits change
what `git status` and `git diff` report about a file without changing staged
content, so later evidence goes misleading while the guard stays quiet.

## Selected approach
`GIT_INDEX_DIGEST_ARGS` becomes `--no-optional-locks ls-files -s -v`: one
spawn, status letter plus the stage line (`S` = skip-worktree, lowercase =
assume-unchanged). Measured: moves for each flag (`5162648e02`, `863840ac02`),
returns to baseline when cleared (`d90c4d69b7`), stable across a `touch` +
`diff HEAD` stat refresh and across an unstaged working-tree edit — so no
false positives. Intent-to-add entries remain visible.

**Enumeration test** (`real_subprocess`, parametrized, one line per
mechanism): `--skip-worktree`, `--no-skip-worktree`, `--assume-unchanged`,
`--no-assume-unchanged`, `--cacheinfo`, `--chmod=+x`, `-N`, `git add
<modified>`, `git rm --cached`. Each asserts `violated`, `reason ==
"git_index"`, a moved digest, and that later commands are refused.

## What is still NOT covered (each CHECKED, not assumed)
| feature | tree hash | index digest |
|---|---|---|
| untracked cache (`UNTR`) | no | no |
| fsmonitor (`FSMN`) | no | no |
| cache-tree (`TREE`) | only the new tree object under `.git/objects` | no |
| resolve-undo (`REUC`) | no | no |
| split index (`--split-index`) | **yes** (writes `.git/sharedindex.<sha>`) | no |

The four extensions live inside `.git/index`, which the byte hash excludes,
and `ls-files` prints no trace of them at any verbosity: **nothing in Eris
catches them**. Stated plainly in `docs/SECURITY.md` rather than implied away.
Their evidence impact is bounded — they change reporting about untracked or
merge state, and any file they could hide is still caught by the tree hash.

## Dissent and corrections (preserved)
- Codex stop-gate produced the finding; the coordinator's measurements were
  confirmed by the implementer with two additions now in the docs: `-s -v` is
  also stable across an unstaged working-tree edit, and the probe itself
  leaves `.git/index` byte-identical on a fresh copy.
- Implementer flagged that the split-index test mutates `env.guard.baseline`
  in place to continue past the first (expected) tree violation — test-local,
  but reaching into a dataclass; recorded rather than hidden.
- The earlier decision record (`2026-08-24-m2c-index-guard.md`) still says
  `--stage` and is deliberately left as the historical record.

## Commands actually run (synthesizer, worktree on `a8e8bf4`)
```
ruff check src tests eval            → All checks passed!
ruff format --check src tests eval   → 56 files already formatted
mypy                                 → Success: no issues found in 20 source files
mypy --ignore-missing-imports eval   → Success: no issues found in 4 source files
pytest --cov --cov-fail-under=90     → 813 passed; Total coverage: 95.14%
pytest tests/test_verify_real_git.py → 18 passed
pip-audit -r requirements.txt --strict → No known vulnerabilities found
git diff --stat bc33722..a8e8bf4 -- tests/fixtures → (empty); SCHEMA_VERSION still 0.1.5
```
Revert-check (implementer, old `--stage` restored): the four flag cases FAIL
with `violated=False` — i.e. the guard does not trip at all — plus the
split-index and allowlist-pinning tests. Fix restored, gate green.

## Unresolved risks
1. The four index extensions are uncovered by anything (above).
2. One `git` spawn per verification command remains unbudgeted.
3. The control has now been holed three times; the enumeration test converts
   future mechanisms into a one-line addition, but it enumerates what is
   KNOWN — it cannot prove completeness.

## Rollback
`git revert -m 1 <merge>`; no runtime state; goldens and `SCHEMA_VERSION`
untouched.

## Recommendation
SHIP.
