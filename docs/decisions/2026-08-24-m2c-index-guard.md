# Engineering decision record — M2c follow-up: the git-index gap in the verification tripwire

Date: 2026-08-24 · Branch: `m2c-index-guard` → `main` · Tier: **contained**
(security control, no schema change) · Raised by: the Codex stop-time review of
`920262d` — "the verification tripwire now ignores security-relevant Git index
mutations". The finding was correct; the synthesizer's earlier approval of a
plain byte-exclusion was the weaker choice.

## The gap
`SnapshotGuard` excluded `.git/index` and `.git/index.lock` from its tree hash.
The index is not inert: `git ls-files` reads it directly and `git diff` /
`git status` compare against it, so an index mutation changes what LATER
evidence reports. The allowlist cannot currently reach `git add` / `git rm`,
but the guard is defence in depth for exactly the case where an allowlist is
wrong or is later widened.

Proof of the gap (implementer's revert-check, with the semantic comparison
removed and the exclusion exactly as `920262d` shipped it):
* `git rm --cached README.md` → **the guard does not trip at all**
  (`violated=False`); nothing else in the tree moves.
* `git add <modified file>` → trips, but as `reason: "tree"` (the loose
  object) — the wrong story.

## Why the exclusion could not simply be removed
Measured on this machine (git 2.50.1). Under `--no-optional-locks`, every
allowlisted subcommand leaves `.git/index` byte-identical EXCEPT the first
command that reads the working tree against the index — which the implementer
showed is `diff HEAD`, an allowlisted subcommand (my spec had claimed only
bare `git diff`). Dropping the exclusion would therefore trip the guard on a
legitimate command in a normal run.

## Selected approach
Keep the byte exclusion; add a SEMANTIC index digest beside the tree hash:
`<pinned git> --no-optional-locks ls-files --stage` (mode, blob sha, stage,
path per entry). Measured invariant: blind to the stat refresh, sensitive to
real staging changes.

| after | index bytes | `ls-files --stage` |
|---|---|---|
| `diff HEAD` / bare `diff` (legitimate refresh) | churn | stable |
| `git add <modified file>` | churn | changes |
| `git rm --cached <file>` | churn | changes |

Either half moving trips `snapshot.violated`; the payload names which
(`reason: "tree" | "git_index"`) and records both digests. When both move,
`git_index` wins as the more specific cause (pinned by its own test). The
digest runs a policy-PINNED git with a fixed Eris-internal argv, re-checking
the pin at call time, and is deliberately NOT routed through the model-facing
allowlist (`git ls-files --stage` remains refused there). If the copy has a
`.git` but git is unusable, the guard FAILS CLOSED: it hashes `.git/index`
bytes instead and records `index_check: "bytes_fallback"`.

## Dissent and corrections (preserved)
- Codex stop-gate: the finding that produced this change.
- Implementer corrected the spec's measurement (`diff HEAD`, not only bare
  `diff`, pays the refresh) — which strengthens rather than weakens the case.
- Implementer's design call: `git_index` takes precedence when both halves
  move, otherwise the required test is unsatisfiable.
- Synthesizer rejected: dropping the exclusion entirely (breaks a legitimate
  allowlisted command every run); excluding `.git` wholesale (would hide ref,
  object, HEAD, config and hook rewrites).

## Commands actually run (synthesizer, worktree on `45bae7e`)
```
ruff check src tests eval            → All checks passed!
ruff format --check src tests eval   → 56 files already formatted
mypy                                 → Success: no issues found in 20 source files
mypy --ignore-missing-imports eval   → Success: no issues found in 4 source files
pytest --cov --cov-fail-under=90     → 799 passed; Total coverage: 95.14%
pytest tests/test_verify_real_git.py → 4 passed
pip-audit -r requirements.txt --strict → No known vulnerabilities found
git diff --stat 920262d..45bae7e -- tests/fixtures/records → (empty); SCHEMA_VERSION still 0.1.5
```

## Unresolved risks
1. One extra `git` spawn per verification command; no budget accounts for it.
2. A `bytes_fallback` guard never upgrades to semantic mid-run, so one
   transient git failure at construction time costs that run's tolerance for
   the legitimate `diff` churn.
3. The reachable-mutation set is bounded by the allowlist today; the digest is
   the control that keeps that true if the allowlist is widened.

## Rollback
`git revert -m 1 <merge>`; no runtime state; goldens and `SCHEMA_VERSION`
untouched.

## Recommendation
SHIP.
