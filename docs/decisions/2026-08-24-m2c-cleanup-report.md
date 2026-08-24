# Engineering decision record — M2c: a scratch cleanup failure is reported

Date: 2026-08-24 · Branch: `m2c-cleanup-report` → `main` · Tier: **contained** ·
Raised by: the Codex stop-time review of `be36ddb` — "cleanup errors can be
silently swallowed, leaving the verification copy behind."

Ninth finding in this arc, and the first BELOW the bar the coordinator had
just set (only arbitrary code execution blocks a merge). It was fixed anyway
because it is real, contradicts a contract the code documents, and is small —
not because it met the bar. That is recorded so the bar is not quietly moved.

## The defects
1. `eval/run.py` writer-open handler: `_remove_scratch(scratch)` was called
   with its **return value discarded**. That helper returns failure text and
   never raises, and on this path no ledger is open — so a failed removal was
   reported in no channel at all (no event, no stderr, no exit code) and the
   verification copy stayed on disk. `sanitize._remove_copy`'s docstring
   states the opposite contract ("never swallowed, because worker-visible
   files may remain").
2. Found alongside: `_scratch_root`'s `finally` called
   `shutil.rmtree(..., ignore_errors=False)`, which raises INSIDE a finally
   and therefore REPLACES any exception already propagating — the mirror-image
   failure, losing the reason instead of the cleanup error.

## Selected approach
1. Capture the return; report it on BOTH remaining channels — a structured
   stderr line (`{"status":"error","kind":"scratch_cleanup_failed",…}`, the
   same shape as the sweep and post-scan lines) and the returned
   `CellOutcome` (text appended to `error`, exit forced to `EXIT_RUN_ERROR`).
2. `except BaseException:` → attempt removal, report on stderr, re-raise the
   ORIGINAL; with no exception in flight the cleanup error still raises.
   Reconciled rule, now an INVARIANTS row: *a cleanup failure is never
   swallowed, and never at the cost of the reason.*

## Dissent and open items (preserved)
* Implementer's call, flagged not hidden: `status` still names the writer's
  reason, so `status: "exists"` can now pair with exit 4. The `finally` path
  at `~:1085` instead overwrites status with `run_error`. Inconsistent between
  the two paths; left as-is pending a preference.
* Audit result: `~:1000` and `~:1085` handle the return correctly (coordinator's
  reading confirmed). `~:1085` does not append the text to `outcome.error`, so
  the summary's `error` can read `None` while exit code, status, ledger and
  stderr all carry it. Not changed.
* Same shape found OUTSIDE this module and deliberately NOT fixed here
  (different subsystem): `evidence.py:945` (`verify_scratch`) and
  `sanitize.py:1313` (`sanitized_copy`) both raise from a `finally`. For
  `sanitized_copy` that is deliberate and documented (`SanitizeCleanupError`
  outranks); `verify_scratch`'s `EvidenceCleanupError` looks like the same
  trade made without examination. `launch.py:1365` drops `cleanup_error` if
  `_execute` raises — unreachable today except on `KeyboardInterrupt`.
* `_print_scratch_cleanup_failure` infers `run_id` from `scratch.name`; true by
  construction, but an inference rather than a passed value.
* The gate ran on Python 3.14.7 while the project pins `py312`; 3.12 was not
  exercised here.

## Commands actually run (synthesizer, worktree on `633f31b`)
```
ruff check src tests eval            → All checks passed!
ruff format --check src tests eval   → 57 files already formatted
mypy                                 → Success: no issues found in 20 source files
mypy --ignore-missing-imports eval   → Success: no issues found in 4 source files
pytest --cov --cov-fail-under=90     → 1033 passed; Total coverage: 95.47%
pip-audit -r requirements.txt --strict → No known vulnerabilities found
git diff --stat be36ddb..633f31b -- tests/fixtures src/eris/schemas.py → (empty)
```
Revert-checks (implementer): defect 1 → `assert 2 == 4` on the exit code and
no `scratch_cleanup_failed` line in stderr; defect 2 → the `OSError` replaced
the `RunExists` the body raised.

## Unresolved risks
1. The two out-of-module `finally`-raise sites above.
2. The `status`/`error` inconsistency between the two cleanup paths.
3. Everything carried forward from the containment record: the format-derived
   audit is still the durable fix, E1 still gates scored runs, and the live
   `indep_verify` run is still the untouched next step.

## Rollback
`git revert -m 1 <merge>`; no runtime state; goldens and `SCHEMA_VERSION`
untouched.

## Recommendation
SHIP.
