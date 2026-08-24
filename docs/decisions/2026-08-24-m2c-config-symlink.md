# Engineering decision record — M2c follow-up 4: a symlinked `.git/config` failed open

Date: 2026-08-24 · Branch: `m2c-config-symlink` → `main` · Tier: **contained** ·
Raised by: the Codex stop-time review of `731ee2f` — "symlinked `.git/config`
bypasses the new neutralisation."

FIFTH consecutive finding against the verification tripwire and its copy.

## The finding
`neutralise_git_config` did `if cfg.is_symlink() or not cfg.is_file(): return
False`. Nothing was ever written through a link — that part was right — but the
control **failed OPEN**: a symlinked `.git/config` was silently skipped while
git follows the symlink and honours `core.fsmonitor` / `core.untrackedCache`.
Wrong direction of failure for a security control.

## Selected approach
1. **Fail closed.** A symlink whose target resolves INSIDE the copy is read,
   the link is `unlink`ed, and a regular file with the neutralised content is
   written in its place — never written through. Every other shape (escaping,
   dangling, fifo, device, directory) raises and the copy is refused.
   Race-guarded: realpath containment before any unlink, `O_NOFOLLOW |
   O_NONBLOCK` on the read, a re-`lstat` of dev+ino before the unlink, and
   `O_CREAT | O_EXCL | O_NOFOLLOW` on the write.
2. **A general layout assertion** (`assert_git_layout_sane` over
   `GIT_REQUIRED_KINDS`): every `.git` path Eris depends on must be the kind it
   expects or absent; anything else refuses the copy. A new path is one row.

## Dissent and corrections (preserved)
- The implementer found the SPEC self-contradictory: it asked for a dangling
  `.git/config` to refuse the copy while also (correctly) stating the copier
  drops dangling and escaping links alike. Through `sanitize_snapshot` a
  dangling config is dropped and the copy proceeds with no config; the raise
  lives in `neutralise_git_config`, where it is reachable, and both levels are
  tested. Accepted — the spec was wrong.
- The replaced link is recorded in the existing `dropped_symlinks` rather than
  a new `SnapshotSanitization` field, which would have mutated a committed
  0.1.5 golden.
- `O_NONBLOCK` on the target open is load-bearing: without it a link to a fifo
  HUNG the suite instead of failing the type check. On a platform lacking the
  flag the `getattr` yields 0 and the hang returns — untested, no such
  platform available.

## What the new assertion does NOT cover (implementer's own assessment, kept)
- It is a **type check on a fixed list, run once**: it says nothing about the
  CONTENT of `.git/config` or `.git/index`.
- `.git` paths deliberately off the list — `HEAD`, `refs/`, `objects/`,
  `info/`, `commondir`, `objects/info/alternates`, `modules/`, `worktrees/`.
  Git legitimately allows a symlinked `HEAD` (`core.prefersymlinkrefs`) and
  alternates are a real feature, so a broader list risks false-refusing a real
  repository — and a guard that false-refuses gets deleted. This is the
  weakest part of the change and it is a judgement call.
- Nothing re-runs it between verification commands.
- **It does not address the class the first four findings were about** — git
  honouring state that neither the tree hash nor the index digest observes.
  The implementer's prediction for a sixth finding: the index extensions
  (`UNTR`, `FSMN`, `TREE`, `REUC`), already documented as uncovered.

## Commands actually run (synthesizer, worktree on `595df45`)
```
ruff check src tests eval            → All checks passed!
ruff format --check src tests eval   → 56 files already formatted
mypy                                 → Success: no issues found in 20 source files
mypy --ignore-missing-imports eval   → Success: no issues found in 4 source files
pytest --cov --cov-fail-under=90     → 861 passed; Total coverage: 95.24%
pip-audit -r requirements.txt --strict → No known vulnerabilities found
git diff --stat 731ee2f..595df45 -- tests/fixtures → (empty); SCHEMA_VERSION still 0.1.5
```

## Unresolved risks
1. **The standing one, now five findings deep.** A format-derived audit of the
   git index and repository state — enumerated from git's documented on-disk
   format rather than from symptoms we happened to hit — is the durable fix
   and is still NOT done. The predicted next gap is named above.
2. `GIT_REQUIRED_KINDS` uses plain `str` kinds; a misspelled kind in a new row
   fails at runtime, not at type-check time.
3. The race guard is exercised by monkeypatching the swap, not by a real
   concurrent race.

## Proportionality note
Further hardening of this control has low marginal value right now: scored
defect/ABSTAIN runs are already blocked by the E1 containment decision, and
the threat it defends against is repository code spawned by a trusted
`pytest` during a corpus run that cannot yet be scored. The recommendation is
to stop here, carry risk 1 explicitly, and spend the next effort on the live
`indep_verify` run — the thing the project actually needs.

## Rollback
`git revert -m 1 <merge>`; no runtime state; goldens and `SCHEMA_VERSION`
untouched.

## Recommendation
SHIP.
