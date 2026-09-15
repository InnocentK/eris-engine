# Automatic CLI re-verification and local pin refresh

Status: implementation candidate (Structural milestone; user-approved on `t_8f099e77`)

## Decision

Add a deterministic `eris policy refresh detect|verify|apply|preflight` boundary.
The helper observes exact executable identities before campaign spend, verifies
only an explicitly authorized candidate SHA with provider-specific manifests,
and publishes only registered, content-addressed receipts under compare-and-swap.
The default rollout is audit-only. No provider patch auto-publish is enabled by
this change. Agy is always `REVIEW_REQUIRED` and is never executed or repinned
by refresh until a separately authorized stable update-cycle audit succeeds.

This is Structural because it changes executable authorization, policy pinning,
and campaign preconditions. The approved process uses one writer in this
worktree, a different-family advisor, an independent final review, and a final
exact-revision gate.

## Synthesis of the four blind plans

All four plans agree on strict independently versioned campaign specs and
receipts, exact campaign-derived scope, transitive alias groups, provider-
specific checks, typed non-secret output projection, fail-closed UNKNOWNs,
audit-only rollout, immutable model identifiers, executable SHA retention in
idempotency/cache identity, and a crash-durable compare-and-swap sidecar.
They also agree that detect and scheduled use execute no candidate, unused drift
is reported without probing or publication, live probes are opt-in and
single-shot, and unsupported safe filesystem semantics must refuse.

Two initial disagreements were resolved by repository evidence and explicit
human decisions:

1. The approved design allowed one automatic candidate restart. The security
   plan showed that even help/version/auth commands execute arbitrary changed
   bytes, and the no-model experiment observed agy replacing itself. The human
   decision therefore requires zero restart or chase: authority binds one SHA;
   any identity change terminates the attempt.
2. The original campaign spec did not bind the repository runner. Because the
   package installs only `src/` while `eval/run.py` is repository-only and
   cwd-sensitive, the human decision requires canonical absolute repo root,
   exact clean HEAD, literal `eval/run.py`, and exact runner SHA.

The reliability plan further resolves the transaction oracle: after
`os.replace`, a failed directory fsync is `MANIFEST_NOT_DURABLE/BLOCKED`; the
nonterminal journal and lock remain and no speculative rollback is attempted.
Only a durably recorded replacement with an ordinary postcheck failure may roll
back through CAS. Windows apply is refused until ACL and no-follow guarantees
exist.

## Selected design details

- `CampaignSpecV1` is strict JSON and renders the existing campaign argv in a
  fixed order. It includes every campaign input plus repository/runner binding.
- Scope is the ordered union of panel workers, critics only for the critique
  arm, judge only for judged/summarized arms, git for every evidence pack, task
  battery commands, and all declared verification commands when selected arms
  can request model-proposed evidence.
- Detection records locator `lstat`, symlink target, strict realpath, regular-
  file identity, SHA-256, policy SHA, pins SHA, and manifest version without
  spawning a process.
- Verification requires explicit exact-SHA authority. Candidate output is
  bounded in memory and projected into allowlisted booleans/enums/counts; raw
  stdout/stderr, auth/account data, usernames, and arbitrary model text are not
  persisted. A durable claim is written before any optional live probe.
- Apply accepts only a locally registered canonical receipt digest, reparses
  and re-hashes it, re-derives scope, aliases, observations, version decision,
  and all CAS inputs, then consumes the receipt before mutation.
- Candidate safety is re-derived at verify, around every candidate execution,
  and again at apply. Missing, special, hardlinked, or identity-changing paths
  refuse. Alias closure is based on shared realpath plus device/inode identity,
  never merely a common CLI label. Generated canonical argv is checked against
  each provider manifest's forbidden-token set and recorded as a typed result.
- Publication uses an exclusive-create lock that is never automatically
  broken, immutable content-addressed history, mode-0600 same-directory temp,
  file fsync, strict reload/secret scan/authorized-diff, `os.replace`, and
  directory fsync. An existing owner-owned, single-link, non-group/other-
  writable legacy pins file (including mode 0644) may be read; successful
  replacement hardens it to mode 0600. Private transaction, receipt, history,
  and lock state remains strictly owner-private. Uncertain durability remains
  visibly blocked.
- Bootstrap `policy pin` may fill missing entries only. Existing changed pins
  refuse; normal drift uses refresh.
- Preflight validates the exact clean source candidate, refreshes only an
  enabled eligible path, reruns selected launch-time checks, the scoped free
  gate, and the exact frozen dry-run, then rechecks all identities.

## Rejected alternatives

Rejected: blind hash-and-accept; generic provider manifests; version-text-only
acceptance; executing or rewriting unused workers; trusting receipt-supplied
paths or decisions; partial alias publication; raw-output redaction as the
primary secret control; stale-lock breaking; automatic updater chasing; using
`RunWriter`'s `flock`/`os.rename`; importing repository-only `eval.run` into the
installed package; weakening Windows semantics; changing frozen prompts,
corpus, keys, metrics, model ids, cache rules, summaries, or `runs/`.

## Scope and non-goals

Expected code surface is `src/eris/refresh.py`, bounded integrations in
`policy.py`, `cli.py`, and `eval/live_preconditions.sh`, focused tests, and
security/invariant/changelog documentation. No ledger wire-schema change,
engine/orchestrator, containment claim, campaign/model call, scheduler,
notification subsystem, tracked policy mutation, or public release is part of
this milestone.

## Validation receipt

Candidate validation at exact worktree base `5dab66f7ae92ca6bd09ebbbed8c0b049a19ca498`:

- The first post-commit focused gate found four failures: apply incorrectly
  treated the historically mode-0644 non-secret pins sidecar as private state.
  The remediation separated pins permissions from private state permissions,
  added legacy-hardening and writable/symlink/hardlink/special/foreign-owner/
  private-state refusal tests, and reran the exact focused command: PASS.
- `bash -n eval/live_preconditions.sh`: PASS.
- `git diff --check`: PASS.
- Advisor-remediation focused command (`test_refresh`, `test_policy`,
  `test_cache`, `test_launch`, `test_hermeticity`, `test_doctor`, and
  `test_invariants_doc`): PASS.
- The first remediation `task ci` stopped at Ruff's import-format check; the
  import block was corrected before any later gate. Final exact `task ci`:
  PASS — Ruff check and format clean; mypy clean for 21 source and 4 eval
  files; 1,321 tests passed; 93.58% total coverage against a 90% floor;
  `pip-audit` reported no known vulnerabilities.

No live provider, network, campaign, pin publication, merge, push, tag, or
release was performed. The suite injected every process/probe behavior.

## Review, residual risk, and rollback

Implementation model/family: GPT-5.6/OpenAI. The required xAI advisor round 1
reproduced two High findings: unsafe hardlinked candidates
could reach verify/apply, and same-CLI/different-file workers were incorrectly
grouped. It also raised a Medium dead forbidden-token manifest field and missing
named safety/portability tests. All are remediated: unsafe paths now refuse at
every boundary, aliases use executable identity only, canonical argv produces a
typed forbidden-token check, agy refusal is re-derived by apply, and tests now
cover identity replacement, Windows refusal, exclusive-lock contention, and
cache invalidation after a pin SHA change. Advisor confirmation and the later
independent final review remain pending at this handoff. Known residuals are same-user malicious vendor
bytes, absent independently trusted vendor checksums, possible network/model
spend by arbitrary candidate bytes, UNKNOWN Codex/agy executed identity,
incomplete secret-shape detection, pathname ABA/hash-to-exec races, and weaker
power-loss semantics on unsupported filesystems. These can only block or require
human review; they never create `AUTO_ACCEPT`.

Rollback before integration is deletion of the isolated worktree/branch. After
a future authorized integration, revert the milestone commit and run `task ci`;
machine-local sidecar recovery uses the named content-addressed prior generation
and requires an operator to prove the expected SHA before removing any retained
lock/journal.

Recommendation: REVISE pending the xAI advisor, independent final review, and
exact-revision gate. The implementation and local gates are complete; no
integration or publication is authorized.
