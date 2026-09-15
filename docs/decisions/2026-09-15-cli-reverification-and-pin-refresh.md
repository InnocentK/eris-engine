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
- Publication uses an exclusive-create lock that is never automatically
  broken, immutable content-addressed history, mode-0600 same-directory temp,
  file fsync, strict reload/secret scan/authorized-diff, `os.replace`, and
  directory fsync. Uncertain durability remains visibly blocked.
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

- Focused refresh/policy/cache/launch/hermeticity/doctor/invariant suite: PASS.
- `bash -n eval/live_preconditions.sh`: PASS.
- `git diff --check`: PASS.
- Exact `task ci`: PASS — Ruff check and format clean; mypy clean for 21 source
  and 4 eval files; 1,302 tests passed; 93.42% total coverage against a 90%
  floor; `pip-audit` reported no known vulnerabilities.

No live provider, network, campaign, pin publication, merge, push, tag, or
release was performed. The suite injected every process/probe behavior.

## Review, residual risk, and rollback

Implementation model/family: GPT-5.6/OpenAI. The required xAI advisor and later
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
