# Engineering decision record — M2c follow-up 3: the fsmonitor-valid entry bit

Date: 2026-08-24 · Branch: `m2c-fsmonitor` → `main` · Tier: **contained** ·
Raised by: the Codex stop-time review of `0f121d8` — "the 'enumeration' omits
Git's behavior-changing fsmonitor-valid entry bit."

Fourth consecutive finding against the verification tripwire. Each has been a
different KIND of hole (an excluded path → a missing semantic check → missing
flag bits → a bit no `-v` output reveals), which is itself the lesson: the
guard was built outward from observed symptoms rather than from git's index
format. That is recorded here as the standing risk, not solved by this change.

## The finding, and the correction to the coordinator's measurement
`git update-index --fsmonitor-valid <path>` sets a documented per-entry bit
that makes git treat the file as unchanged. `ls-files -v` does not show it;
only `ls-files -f` does.

The coordinator measured that the bit "did not stick" and was ready to record
the bypass as unreachable. The implementer disproved that: the missing
ingredient was the hook's output. With `core.fsmonitor` pointed at a hook
emitting a real v2 token (`printf 'eris-token\0'`):

```
no fsmonitor:                 -s -v = fddd9c362e62   -s -v -f = fddd9c362e62
hook emits a token, status:   -s -v = fddd9c362e62   -s -v -f = 01d054483cd1
--no-fsmonitor-valid calc.py: -s -v = fddd9c362e62   -s -v -f = 49273a2ab4d8
--fsmonitor-valid   calc.py:  -s -v = fddd9c362e62   -s -v -f = df9c5a9bab19
```
`-s -v` is flat throughout; `-s -v -f` moves every time. The bypass is real.

Two further facts the implementer found, both load-bearing:
* On a FRESH copy the first `git status` marks nothing (stat data mismatches);
  the second marks every entry. The enumeration setup primes twice.
* With `--no-optional-locks` on every invocation, git never writes the index —
  so Eris's own allowlisted git cannot set these bits. Repository code spawned
  by a trusted `pytest` can.

## Selected approach
1. `GIT_INDEX_DIGEST_ARGS` → `--no-optional-locks ls-files -s -v -f`; same
   single spawn, and `check_command` still refuses `-f` from a model.
2. `sanitize.neutralise_git_config()` unsets `core.fsmonitor` and
   `core.untrackedCache` in the COPY's `.git/config`, before the guard takes
   its baseline and before any verification command runs. This cuts both ways:
   an inherited monitor could mark entries valid mid-run — a FALSE violation
   that halts verification — as well as letting a command lean on stale
   validity. Removing `.git/hooks` does NOT cover this: `core.fsmonitor` may
   name any path (the test uses a tracked `tools/fsm`), which is why it is a
   separate control. The original is never opened for writing; two tests
   assert its config bytes and tree hash are unchanged.
3. Enumeration gains `--fsmonitor-valid` / `--no-fsmonitor-valid`, asserting
   REAL trips with `reason: "git_index"`.

## Dissent and corrections (preserved)
- The coordinator's measurement was wrong in a way that would have understated
  the risk; the implementer was asked to push on it and did.
- Implementer declined the spec's "record it in `SnapshotSanitization`-style
  manifest output": hook removal is not recorded there either, and adding a
  field would mutate a committed 0.1.5 golden, which the immutability rule
  forbids. Accepted — the neutralisation is covered by `copy_tree_sha256` and
  four named tests.
- Known parsing edge, documented in code: a variable on the same line as its
  section header (`[core] fsmonitor = x`) is not removed; the appended
  trailing `[core] fsmonitor = false` still wins by git's later-section rule.
- `neutralise_git_config` works in bytes so a CRLF config is not rewritten on
  Windows (portability rule).

## Commands actually run (synthesizer, worktree on `0802e28`)
```
ruff check src tests eval            → All checks passed!
ruff format --check src tests eval   → 56 files already formatted
mypy                                 → Success: no issues found in 20 source files
mypy --ignore-missing-imports eval   → Success: no issues found in 4 source files
pytest --cov --cov-fail-under=90     → 823 passed; Total coverage: 95.17%
pytest tests/test_verify_real_git.py tests/test_sanitize.py → 41 passed
pip-audit -r requirements.txt --strict → No known vulnerabilities found
git diff --stat 0f121d8..0802e28 -- tests/fixtures → (empty); SCHEMA_VERSION still 0.1.5
```

## Unresolved risks
1. **The standing one:** four different holes in this control in four reviews.
   The enumeration test makes a new mechanism one line, but it enumerates what
   is KNOWN. A format-derived audit of the index (extensions and per-entry
   flag bits, against git's documented on-disk format) is the durable fix and
   is NOT done.
2. The index extensions (`UNTR`, `FSMN`, `TREE`, `REUC`) remain invisible to
   every `ls-files` output; enabling them writes `.git/config`, which the tree
   hash catches, and the copy now unsets two of them.
3. One `git` spawn per verification command remains unbudgeted.

## Rollback
`git revert -m 1 <merge>`; no runtime state; goldens and `SCHEMA_VERSION`
untouched.

## Recommendation
SHIP, with risk 1 carried forward as the next piece of real work on this
control.
