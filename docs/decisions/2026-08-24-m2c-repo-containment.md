# Engineering decision record — M2c: repo-level containment of the verification copy

Date: 2026-08-24 · Branch: `m2c-repo-containment` → `main` · Implementer: one
isolated worktree · Advisor: Codex (cross-family), two passes + the stop-time
gate that raised each finding.

This record closes an arc of EIGHT consecutive stop-time findings against one
control. It is written to be read as one story, because the individual patches
are less informative than the pattern.

## The arc
| # | Finding | Class |
|---|---|---|
| 1 | `.git/index` excluded from the tree hash | observation gap |
| 2 | `--stage` digest blind to a staging change | observation gap |
| 3 | digest blind to `skip-worktree` / `assume-unchanged` | observation gap |
| 4 | digest blind to the `fsmonitor-valid` bit | observation gap |
| 5 | symlinked `.git/config` skipped neutralisation (failed OPEN) | fail-open |
| 6 | `diff.external` / `textconv` / `alternates` | **code execution + corpus contamination** |
| 7 | nested gitdirs (gitlink → external repo) | **code execution** |
| 8 | `.GIT` case-fold evasion; `mypy` plugins; `bytes_fallback` gap; cleanup race | **code execution (non-git)** |

Findings 1–4 were the same kind and were patched one at a time. That was the
mistake: the control was being extended outward from symptoms. Findings 6–8
are what that costs — three separate arbitrary-execution paths that no amount
of index-digest work would ever have reached.

## Selected approach (the redesign)
* **Config by allowlist, not denylist.** The copy's `.git/config` is parsed
  (a port of git's grammar, measured against real `git config --list -z`) and
  RE-SERIALISED keeping only `core.{repositoryformatversion,filemode,bare,
  symlinks,ignorecase,precomposeunicode,logallrefupdates}` and
  `extensions.{objectformat,compatobjectformat}` with values in {sha1,sha256}.
  Any other `extensions` key REFUSES the copy (silently dropping would break a
  reftable/partialclone repo confusingly); `worktreeConfig` is dropped because
  git accepts it at format 0 and 1 and it only enables `.git/config.worktree`,
  which is deleted.
* **Repo-level escapes removed or refused**: `objects/info/alternates` and
  `http-alternates` deleted; `.git`-as-a-file (gitlink), `commondir`,
  `worktrees/`, `modules/` refuse; ANY nested `.git` at any depth refuses,
  matched case-insensitively after NFC (`sub/.GIT` otherwise evaded the walk
  while git still resolved it on a case-insensitive filesystem).
* **Gitlink scope**: a mode-160000 index entry refuses the verification run,
  read from the existing `ls-files -s -v -f` output — no new spawn. It catches
  the gitlink whose submodule is not checked out, which the filesystem walk
  cannot see.
* **Tool isolation beyond git**: Eris appends each verification tool's
  isolating flag the way it appends `--no-optional-locks` to git —
  `mypy --config-file /dev/null`, `ruff --isolated` — and model-supplied
  config flags stay denied. `pytest` remains `requires_trusted` because
  `conftest.py` is repository code no flag can isolate.

## Measurements that drove it (all on git 2.50.1 / macOS APFS, 2026-08-24)
* `[diff] external` and `[diff "x"] textconv` + `.gitattributes`: our
  allowlisted `git diff HEAD` EXECUTED the named program.
* `objects/info/alternates`: a truncated-away fix commit went from unreachable
  to reachable — the answer key becomes readable inside the snapshot.
* gitlink registered as mode 160000 → `status --porcelain`, `diff HEAD` and
  `status --porcelain=v2` all EXECUTED an external repo's config; unregistered,
  nothing executed.
* repo `mypy.ini` with `plugins = ./evil_plugin.py` → EXECUTED;
  `--config-file /dev/null` → not executed.
* `sub/.GIT`: `os.walk` reports the literal name, an exact `== ".git"` match
  misses it, `os.path.exists("sub/.git")` is True.

## Dissent and corrections (preserved)
* The implementer corrected the coordinator FOUR times: `diff HEAD` (not only
  bare `diff`) churns the index; the fsmonitor bit DOES persist given a real
  update token; a dangling `.git/config` cannot both be dropped by the copier
  and refuse the copy; and there is no NFD variant of `.git` to test, because
  `.git` is pure ASCII — it declined to fabricate that test and pinned the
  no-op instead. It also measured that a fullwidth `.gｉt` is a genuinely
  different file, so folding lookalikes would be a FALSE refusal.
* While fixing the case-fold hole it found a second one unprompted: the
  copier's `.git/hooks` skip also matched by exact name, so **`.GIT/HOOKS` was
  being copied into the verification copy**, where our own git would have run
  a repository hook.
* Its differential test disproved its own prediction about which grammar rows
  git rejects (it guessed 3; git rejects all but one).
* Ruff's config discovery is **evidence manipulation, not execution**
  (`[lint] select = []` makes `ruff check` report clean on a real violation) —
  described as such rather than lumped in with mypy.

## Accepted trade-offs (each a real scope reduction)
1. **Submodule, reftable and partial-clone repositories are now unverifiable**
   — refused loudly, naming the path. A non-recursive clone still leaves
   gitlinks in the index, so any submodule-bearing corpus task refuses.
2. **`bytes_fallback` was deleted**, not just bypassed: with no working pinned
   git there is now NO verification, where before there was a degraded mode.
   Coherent (every default-battery command is git) but stricter than before.
3. The extensions refusal is unconditional on `repositoryformatversion`, so a
   v0 repo carrying a stray extension is refused although git would open it.
4. mypy's isolation writes `<devnull>: No [mypy] section in config file` to
   stderr, which lands in recorded evidence.

## Commands actually run (synthesizer, worktree on `a8daded`)
```
ruff check src tests eval            → All checks passed!
ruff format --check src tests eval   → 57 files already formatted
mypy                                 → Success: no issues found in 20 source files
mypy --ignore-missing-imports eval   → Success: no issues found in 4 source files
pytest --cov --cov-fail-under=90     → 1031 passed; Total coverage: 95.47%
pytest -q (second full run)          → passed
pip-audit -r requirements.txt --strict → No known vulnerabilities found
git diff --stat b271b87..a8daded -- tests/fixtures src/eris/schemas.py → (empty)
```

## Unresolved risks
1. **The lesson, unimplemented:** the durable fix remains a format-derived
   audit — enumerate git's documented on-disk state and each verification
   tool's config-discovery surface, and assert coverage against THAT, rather
   than against symptoms. Eight findings say symptom-driven hardening does not
   converge.
2. `objects/info/*` completeness beyond alternates is UNKNOWN.
3. `--config-file nul` on Windows is untested (`os.devnull` differs).
4. A trusted `pytest` still executes repository code by design; that channel
   dwarfs everything fixed here.
5. E1 stands: workers still read outside the snapshot, so scored
   defect/ABSTAIN runs remain gated regardless of this work.

## Proportionality
Eight rounds is far past a normal stopping point. It was justified each time
only because the finding was arbitrary code execution, which always blocks.
The honest cost note is that all of this hardens corpus runs that the E1
decision still prevents scoring, while the live `indep_verify` run — the thing
that would tell us whether Eris's protocol works at all — remains untouched.
That is the recommended next work, and the user's call.

## Rollback
`git revert -m 1 <merge>`; no runtime state; goldens and `SCHEMA_VERSION`
untouched.

## Recommendation
SHIP.
