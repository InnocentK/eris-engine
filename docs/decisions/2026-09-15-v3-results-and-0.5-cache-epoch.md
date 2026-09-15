# v3 results and the 0.5.0 cache epoch

Date: 2026-09-15 · Status: 0.5.0 CANDIDATE, pending independent exact-commit
review and final mechanical certification · Base revision:
`b9c21a4eb3e9fdd34e78eab70300ada2790ac8a2`

This is a contained correction and beta integration boundary for the Phase 0
evaluation harness. It is not the Eris engine, a public 1.0 release, a completed
Phase 0 corpus, or evidence that the draft build rule cleared. It changes no
protocol, schema, launcher, policy, prompt, key, metric, prediction, decision
rule, or frozen campaign artifact.

## Campaign evidence

v2 remains frozen at exact revision
`acbdfce225ecdf19f887bf8968144b5da1de5520`:

- `summaries/v2.json` sha256:
  `69412d2b38c25425229ec7399a7a97d6f954c2766d0cd0dfba59266033cbfca4`;
- declared/scored 10, operationally complete 6, incomplete 4;
- committed cost $10.673464, complete;
- W1, W2, W4, and W5 were falsified wholly or as conjunctions; W3 was
  indeterminate because the classifier defect prevented both drill verdicts.

The full v2 result and classifier disposition remain separate in
[`2026-09-15-v2-results-and-session-limit-identity.md`](2026-09-15-v2-results-and-session-limit-identity.md).
Nothing here rescored or rewrote v2.

v3 ran against the reviewed classifier fix at exact clean revision
`b9c21a4eb3e9fdd34e78eab70300ada2790ac8a2`:

- `summaries/v3.json` sha256:
  `4e924ba9245671d406b099810922f419dc375487836e44c8e8eef02f9ead1921`;
- policy sha256:
  `7aee1a0a8bea76dfbd1b05a49bb15c36a81db9a590ad03aa3a0aeb5b6b271533`;
- campaign id `v3`; arms `indep_verify,indep_verify_critique`; repeat 0;
  panel `claude,grok`; five scored control/plan tasks;
- declared 10, scored 10, operationally complete 10, missing `[]`, unexpected
  `[]`, skipped declared 0, inputs unbound `[]`, ledger invalid `[]`;
- finalized with committed/spent-known cost $17.359096, complete; reserved $0;
- containment was null. Cells were reported uncontaminated and scan-complete,
  but absence of a canary hit is not containment proof.

The authorized operator recorded these commands and exits:

- `CAMPAIGN_IDS='v3' SINGLE_RUN_IDS='' bash eval/live_preconditions.sh` -> 0;
- `.venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id v3 --arms indep_verify,indep_verify_critique --repeats 1 --panel claude,grok --dry-run` -> 0, 10 cells;
- `PYTHONUNBUFFERED=1 .venv/bin/python eval/run.py campaign --corpus eval/corpus --campaign-id v3 --arms indep_verify,indep_verify_critique --repeats 1 --panel claude,grok` -> 0;
- `.venv/bin/python eval/run.py campaign status --campaign-id v3` -> 0,
  finalized;
- `.venv/bin/python eval/score.py --campaign-dir runs/v3 --corpus eval/corpus > summaries/v3.json` -> 0.

Independent regeneration reproduced the v3 summary byte-for-byte. No paid
replacement run is authorized or needed for this candidate.

## W1-W5 and the flip test

| Prediction | Result |
|---|---|
| W1 | Confirmed: the matrix is exactly 10/10 and the pooled comparison is not blocked. |
| W2 | Indeterminate / NOT TRIGGERED: no session ceiling fired, so v3 neither demonstrated nor refuted live POLICY_TERMINAL classification. The hermetic versioned-path regression remains the direct evidence. |
| W3 | Measured, split: `plan-restore-drill` was ACCEPT in arm 3 and REVISE/wrong-reject in arm 4. The second-plan flip trigger fired for arm 4. |
| W4 | Falsified as a conjunction: rollout verdicts were recovered (ESCALATE/REVISE), but arm 4 vs arm 3 paired support was 0/5. |
| W5 | Falsified: no arm-3 cross-campaign proposal replay occurred, arm 4 replayed only one within-v3 proposal per cell, and $17.359096 exceeded v1's $15.25. |

One scored arm-3 cell carried `DISSENT_EMPTY_WITH_CONTEST`; enforcement forced
ESCALATE for unresolved claims, while that finding itself remained `acted=false`
and had no verdict power. This is the explicitly tolerated malformed outcome,
not ledger invalidity. Its standing revisit trigger did not fire.

The draft Phase 0 build rule did not clear. In particular, the 0/5 byte-paired
support prevents a causal arm-4-vs-arm-3 reading. Descriptive per-arm outcomes
remain recordable; a paired arm effect does not.

## Root cause

The idempotency key deliberately excludes the arm, so sibling arms have the
same proposal key. Before 0.5.0, however, every key had one global write-once
pointer at `cache/keys/<idempotency_key>`. In v3 that pointer still named the v2
entry. Default lookup correctly refused the entry because its campaign differed,
but the fresh v3 call could not replace the global pointer. Its sibling arm
therefore spawned again and produced different proposal bytes. Ten
`cache.conflict` events followed, and every 4-vs-3 pair failed.

The key was correct; the pointer namespace was too coarse.

## Decision

Default pointers are campaign-epoch scoped:

`cache/keys/campaigns/<epoch>/<idempotency_key>`

- A non-null campaign id becomes
  `sha256-<sha256("eris-cache-campaign\\0" + UTF-8 campaign id)>`. This is
  path-safe, collision-resistant, and domain-separated.
- Calls outside a campaign use the explicit reserved epoch `none`; the literal
  campaign id `"none"` hashes into the non-null namespace and cannot alias it.
- Entry files and blobs remain content-addressed and shared.
- Within one campaign, pointer creation remains `O_EXCL`, first-writer-wins. A
  different result remains a conflict and nothing is overwritten.
- The legacy unscoped pointer remains the first-writer-wins index selected only
  by explicit `--reuse-across-campaigns`. Default lookup never falls back to it.
  A stale, conflicting, malformed, or symlinked legacy index is refused and
  recorded, but cannot block the current campaign's scoped pointer.
- Cache store events report the cross-campaign index outcome separately from
  the campaign-scoped store outcome.

Rejected alternatives:

- adding `campaign_id` to the idempotency key: that breaks the key's protocol
  identity and defeats explicit cross-campaign reuse;
- deleting or overwriting legacy pointers: that destroys write-once evidence;
- `--fresh` or no cache: that still does not guarantee sibling-arm pairing;
- mutating or rerunning v3: v3 is frozen evidence, not a result to repair
  post hoc.

## TDD and validation receipts

The integration regression was written first at base behavior and run as:

`.venv/bin/python -m pytest tests/test_arms.py::test_paired_ablation_uses_current_campaign_entries_when_legacy_pointers_are_old -q`

RED -> exit 1. The v2-seeded campaign produced fresh current-campaign proposals,
but its sibling produced different proposal blob hashes; the equality assertion
failed. After the scoped-pointer implementation, the same command exited 0.
The current campaign's first arm is fresh and differs from the prior campaign;
the sibling reuses both current-campaign proposals byte-for-byte.

Additional focused command:

`.venv/bin/python -m pytest tests/test_cache.py tests/test_stages.py tests/test_arms.py tests/test_run_harness.py tests/test_invariants_doc.py tests/test_version.py -q`

Result: exit 0. It includes same-campaign conflict, explicit cross-campaign
reuse, null/hostile campaign namespaces, legacy-index refusal, existing
symlink/tamper cases, pairing, event payload, docs, and version coverage.

Canonical gate:

`task ci`

The first run stopped at format-check exit 1 on three `cache.py` formatting
deltas; those were formatting-only and corrected. The complete rerun exited 0:
ruff check and format-check passed; mypy passed 20 source files and 4 eval
files; 1269 tests passed; branch coverage was 95.45% against the 90% floor;
`pip-audit --strict` found no known vulnerabilities.

Packaging used pip's PEP 517 build isolation because the existing project venv
contains neither `setuptools` nor `wheel`; the attempted
`--no-build-isolation` build exited 2 with `BackendUnavailable: Cannot import
'setuptools.build_meta'`. No project dependency was added.

Successful receipt:

- `.venv/bin/python -m pip wheel --no-deps --wheel-dir /tmp/eris-0.5.0-package.c16Ow9/dist .` -> 0;
- wheel `eris_engine-0.5.0-py3-none-any.whl`, sha256
  `a730e7105e3674827a1eb3adfab80b0a6081954f338f5664311d96bb3f132191`;
- a first fresh venv made with the host `/usr/bin/python3` correctly refused
  install because that interpreter is 3.9.6 and the package requires >=3.12;
- `.venv/bin/python -m venv /tmp/eris-0.5.0-package.c16Ow9/venv314` -> 0;
- fresh-venv wheel install with declared runtime dependencies -> 0;
- fresh-venv `eris --help` -> 0 and listed `doctor` and `policy`;
- fresh-venv `pip show eris-engine` -> version `0.5.0`, installed under the
  temporary Python 3.14 environment.

## Boundaries, residuals, and rollback

- `SCHEMA_VERSION` is unchanged. No migration exists in either direction.
- `runs/v2`, `runs/v3`, `summaries/v2.json`, and `summaries/v3.json` remain
  read-only evidence and are not part of the candidate diff.
- Live POLICY_TERMINAL on the currently pinned Claude binary remains
  undemonstrated because v3 did not trigger it. Verify it on the next naturally
  occurring ceiling; do not buy a campaign merely to force one.
- E1 remains: containment is null, scan-clean is not proof of clean execution,
  and only control/plan tasks are scorable.
- The five scored tasks are a validation subset, not the planned corpus. No
  Phase 0/build claim is permitted.
- OpenAI model-identity dissent and the user-ratified unmonitorable residual
  remain open; no revisit trigger fired.
- License status is unchanged: no license file, all rights reserved.
- Rollback is `git revert <the 0.5.0 candidate commit>`. Cache data needs no
  migration or deletion; older code ignores the new scoped pointers and still
  sees the unchanged legacy cross-campaign index.

Recommendation: SHIP-to-independent-review. Do not merge, tag, publish, or call
this a release until the exact candidate passes the pre-created reviewer and
final mechanical tester gates.
