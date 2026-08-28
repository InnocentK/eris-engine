# Multi-family review before live testing — 2026-08-26

Reviewed commit `2e0e523` (v0.3.14, SCHEMA_VERSION 0.1.5), clean tree.
Scope: `src/eris` + `eval` + the full test suite. Question answered:
**"is this safe and correct to run live for the first time?"**

## Panel

Four families, four complementary lenses, each given the real files (not a
summary), each read-only, each blind to the others.

| Family | Model | Lens | Result |
|---|---|---|---|
| Anthropic | `claude -p` (fresh session) | protocol correctness & architecture | 11 findings |
| OpenAI | `gpt-5.6-sol` (high effort) | security & abuse | 8 findings |
| xAI | `grok-4.6` | reliability & operability | 12 findings |
| Google | `gemini-3.1-pro-high` | test-suite quality | 5 findings |

I did **not** sit on the panel. I supervised or wrote all of this code and am
the least independent reviewer available; I drove the panel and reconciled.

**Adversarial round.** Each of the three highest-value findings was sent to a
*different* family with instructions to refute it. Results below.

**Reconciliation rule.** Reproducible evidence outranks any model's opinion and
outranks their agreement. Every finding kept below was re-verified by me
directly against the code; where a reviewer's severity did not survive that
check, I say so and why.

## Baseline evidence (mechanical, run by me)

`task ci` at `2e0e523`: **exit 0** — ruff clean, mypy strict clean,
**1039 passed** in 100.07s, coverage **95.47%** (floor 90), pip-audit
"No known vulnerabilities found".

The gate being green is the starting point of this review, not a conclusion
from it. Every finding below is a defect the green gate does not detect.

---

## CRITICAL

### C1 — The paired ablation is not real for the default panel, and a documented invariant is false in production

**Found by** Anthropic. **Refutation attempt** by xAI: *could not refute*
("VERDICT: CONFIRMED", after independently tracing every sharing path).
**My verification: Verified** — all four legs checked directly.

Arms 3 / 3b / 4 are supposed to differ *only* in what the adjudicator sees, by
sharing one set of proposals. The only mechanism that shares proposals across
arms is the call cache. That cache refuses any entry without `model_executed`:

- `src/eris/cache.py:316` — `if not entry.get("model_executed"): raise CacheMissError`
- `src/eris/launch.py:918` — `parse_codex` returns `model_executed=None` unconditionally
- `src/eris/launch.py:1014` — `parse_agy` returns `model_executed=None` unconditionally
- default panel is `claude, codex, grok, agy` (`policies/default.yaml`)

So **two of the four default workers can never be served from cache.** Each arm
re-invokes them and gets different proposal text. Meanwhile the scorer decides
pairing purely by comparing idempotency keys, which exclude worker output by
construction:

- `eval/score.py:565` — `if sorted(s_treat.propose_keys) != sorted(s_base.propose_keys)`

Identical keys, different proposals → `entry["paired"] = True`, and
`delta_precision` / `delta_recall` / `delta_confident_wrong` are computed
between arms that did not share a world.

**The worst part.** `docs/INVARIANTS.md` records this as a do-not-break rule —
*"PAIRED ABLATION: one world, arms 3/3b/4 → ONE set of propose spawns; 3b/4
carry `invocation.reused`; propose blob hashes equal across run dirs"* — and
names `test_arms.py::test_paired_ablation_one_set_of_propose_spawns_across_arms_3_3b_4`
as its enforcing test. That test drives a Spy which sets
`model_executed=call.policy.model or "claude-fable-5"` (`tests/test_stages.py:123`)
— it *always* supplies a model id, so the cache always hits. The fake never
produces the one value production always produces for codex and agy, so the
test cannot fail on the defect it exists to prevent.

`_pick_model` (`launch.py:725`) also returns `None` whenever `modelUsage` names
more than one model, so claude and grok can drop out of pairing per-call too.

**Impact.** Any measured "critique helps" / "iteration helps" from a default-panel
campaign is confounded with proposal variance, and nothing in the ledger or the
score output says so. Also silently costs 2–3× the intended proposer calls.

**Blocks:** the scored Phase 0 campaign. **Does not block:** a plumbing or
control live run (single arm, no pairing).

---

## HIGH

### H2 — `containment: container` is a declaration with no mechanism behind it

**Found by** OpenAI. **My verification: Verified**, with an important correction
to how OpenAI framed it.

`grep` for `docker|podman|nsjail|bubblewrap` across `src/`, `eval/`, `policies/`
returns **nothing**. The field is `Literal["container"] | None`
(`src/eris/policy.py:236`) and the E1 gate accepts it at `eval/score.py:409`.
An operator who sets it makes the gate pass with no isolation whatsoever, and
`revert`/`planted`/`insufficient` results — the ones the gate exists to
protect — are then scored as valid evidence.

**Correction to the reviewer.** OpenAI presented this as a hidden hole. It is
not hidden: `CONTAINMENT_BASIS` (`eval/score.py:77`) says *"the scorer gates on
the declaration and cannot verify it - M2c builds the container"*, the policy
comment says *"A declaration, not a verification"*, and the basis string is
emitted into the score report. The residual risk is **operator error**, not
concealment. I keep it at High anyway because the consequence is scoring
contaminated results as evidence and the fix is small (refuse the literal, or
have `doctor` warn, until a mechanism exists).

### H3 — The verdict is not bound to evidence

**Found by** Anthropic (rated Medium). **My verification: Verified.**
**I am raising this above the reviewer's severity** — see below.

`src/eris/validate.py:207-228`: the only thing that can change a verdict is the
cumulative downgrade count reaching `ESCALATE_AT`. Nothing requires an `ACCEPT`
to rest on a single supported ruling. An adjudication of
`{verdict: ACCEPT, rulings: []}` passes through unchanged, is written to the
ledger as ACCEPT with zero evidence citations, and on a `control` task the
scorer counts it as correct. A judge that self-declares every ruling
`UNSUPPORTED` also reaches ACCEPT, because a self-declared UNSUPPORTED is not a
*downgrade* and never arms the escalation guard.

Separately, `_check_refs` (`validate.py:118`) rejects only `MODEL_ASSERTED`
origin / `MODEL_ASSERTION` kind. It does **not** require `mechanically_observed`.
A ruling can therefore be SUPPORTED by `HUMAN_ENTERED` text — including the task
question itself, which `build_evidence_pack` puts in the pack as a
`DOCUMENT_QUOTE`. "The null guard is missing at line 42" can be SUPPORTED by the
question that asked about it.

**Why I overrode the reviewer's Medium.** The reviewer was right that this
matches `PROTOCOL.md` as written, which is why it rated Medium. But
`AGENTS.md` states the project's headline rule as *"Evidence is
`mechanically_observed`"*, and the enforced rule is strictly weaker than that.
The gap between the stated principle and the enforced one is the single thing
this system exists to prevent, so it is High regardless of which document the
code currently matches. This is a specification decision for you, not a bug I
should pick unilaterally.

### H4 — Workers have a full read-only shell, which weakens accept-and-scan

**Found by** OpenAI. **My verification: Verified**, with the exploit bounded.

`tests/fixtures/envelopes/codex/0.147.0/exec_readonly.jsonl:4` is a captured
real envelope showing codex under `-s read-only` invoking
`/bin/zsh -lc 'touch CODEX_WROTE … curl -s https://example.com …'`.

I checked what it achieved: `touch: CODEX_WROTE: Operation not permitted`,
`FILE: FAILED`, `NET: FAILED`. **Writes and network were blocked by the OS
sandbox.** OpenAI's "Critical" is therefore too high — but its residual point
stands and is sharper than the known E1 finding: this is not "the model can be
asked to read a file", it is "the model has a shell". A shell can read *and
transform* (base64, paraphrase, arithmetic) before answering, which is exactly
what defeats a substring contamination scanner. `docs/SECURITY.md:333` already
says scan silence is not evidence of cleanliness; this shows why.

This is your accepted E1 accept-and-scan posture, so it is not a new decision —
but the mechanism is worse than "workers read the parent directory", and the
E1 gate that contains it is H2 above.

---

## MEDIUM

| # | Finding | Source | My check |
|---|---|---|---|
| M1 | Every engine validator finding except the downgrade count is **inert**: `validate.findings` is written at `stages.py:1049` and read by nothing in `src/` or `eval/`. `REF_MISSING`, `CLAIM_MISSING`, `DISSENT_EMPTY_WITH_CONTEST` are error-severity and change no exit code, no score, no verdict. | Anthropic | Verified (grep: only test assertions reference it) |
| M2 | `VerificationResult` has **no producer anywhere** in `src/` or `eval/` — only an origin rule in `validate.py:307`. `Challenge.status` is only ever written `UNVERIFIED` (`stages.py:523`), so `_contest_exists` (`validate.py:149`) is true whenever any challenge exists and carries no information. `PROTOCOL.md:114` lists the record as produced. | Anthropic | Verified (grep) |
| M3 | STOP **finalizes** the campaign (`run.py:1630`, only SIGINT is exempt), so `campaign --resume` hits `RunExists` (`writer.py:205`) and returns EXIT_CONFIG. `docs/INVARIANTS.md:276` claims a finalized campaign "refuses without `--resume`", implying resume works; the test whose comment says it covers this never exercises it. | xAI (High) → Anthropic refuted down to Medium | Verified. Anthropic found two real workarounds (per-cell `run --runs-dir runs/<campaign> --resume <cell>`, and a new campaign id with `--reuse-across-campaigns`) and confirmed no data is lost — the scorer reads cell dirs, not the campaign manifest. Downgrade accepted. |
| M4 | `--resume` refuses when the scratch dir still exists (`run.py:790`), so a SIGKILL/OOM/power-loss run cannot be resumed without a manual delete. The refusal is deliberate ("nothing is created and NOTHING is deleted") but the recovery procedure is documented nowhere. | xAI | Verified — by design, undocumented |
| M5 | SIGINT (or a raising `on_spawn`) between `Popen` returning and entering the `try` around `proc.wait` escapes without `_kill_group`, orphaning a live billing worker. `on_spawn` does an fsync, which widens the window. | **xAI and OpenAI independently** | Verified: `launch.py:620-652` — the `except KeyboardInterrupt: _kill_group(...)` exists but `on_spawn` and the drain setup sit outside it. Cross-family independent discovery. |
| M6 | codex and agy report no cost, so every call reserves `per_call_usd` ($2). The campaign trips its $200 ceiling on **reservations** long before real spend, and because cells run in fixed arm order the truncation is not arm-neutral — arm 4 is dropped first. | Anthropic + xAI + OpenAI (all three) | Verified mechanism; the arithmetic is Inference (I did not run a campaign) |
| M7 | `unsupported_claim_rate` reads only the **last** adjudication, and downgrades restart at zero each judge iteration (`AdjudicationOut` has no `downgrades` field), so arm 3b is structurally advantaged on the metric it is compared on, and 2 downgrades × 3 iterations never trips `ESCALATE_AT`. `PROTOCOL.md:134` describes escalation as *cumulative*. | Anthropic | Verified by reading; Inference on the magnitude |
| M8 | Redaction skips exact env values shorter than 8 chars (`redact.py:33`) and credential-file values shorter than 16 (`redact.py:378`). A short secret survives into a persisted blob. | OpenAI | Verified — deliberate false-positive tradeoff, undocumented consequence |
| M9 | Snapshot hashing reads whole files into memory (`sanitize.py:330`) with no byte, file-count, or time bound anywhere in `SanitizePolicy`. A hostile snapshot exhausts memory before any worker timeout or budget applies. | OpenAI | Verified. Exploitability in Phase 0 is low (you author the corpus); it matters under the stated "task repo is hostile" model. |
| M10 | Resume restores attempt *numbers* but a fresh `RetryState`, so the weight-3 retry budget resets across resumes. | xAI | Verified by reading |
| M11 | A crash between `proposal.recorded` and `stage.finished` re-spawns the worker and leaves two `proposal.recorded` rows; for `Arm.SINGLE` the scorer iterates all of them, double-counting findings. | xAI | Verified by reading; Inference on scorer impact |

---

## LOW / INFORMATIONAL

- **Golden immutability is a tripwire, not an enforcement.** Google rated the
  circularity High. Overstated: three assertions fire on an edit, and
  `set(PINNED_MANIFEST_BLOCKS) == set(_manifest())` means nothing committed is
  unpinned. A developer *can* still silence it by editing the constant, and
  there is no automated test that a serialization change requires a version
  bump — the enforcement is the `AGENTS.md` rule plus review. **Low.**
- **Precision macro-averaging.** Anthropic rated High: dropping zero-prediction
  cells lets a silent arm out-score a talkative one. Google's refutation largely
  succeeded — precision measuring only the assertions actually made is its
  definition, and recall (which returns 0.0, not None) plus `confident_wrong`
  carry the other side of the tradeoff. **Downgraded to Low.** The residual
  Google did *not* address: in `paired_deltas`, a silent cell yields
  `delta_precision: None` while `paired` stays `True`, so the delta is averaged
  over a favourable subset. Worth reporting the per-delta cell count.
- Cells whose run dir lacks a manifest vanish from the score report entirely —
  not in `cells`, `ledger_invalid`, or `skipped` (`score.py:602`). Recoverable
  via `campaign status`, but the score output gives no hint cells went missing.
- A ruling naming a nonexistent claim yields `CLAIM_MISSING` but is **not**
  downgraded (`validate.py:170`); `tests/test_validate.py:184` asserts this
  deliberately. Ledger-integrity issue, no scoring impact.
- Doc drift: evidence pack is built once per **cell**, not per (task, repeat) as
  `evidence.py:1-7` claims; `evidence.py:25` comments describe running commands
  on the ORIGINAL snapshot when the code passes the verification copy; the critic
  DATA document has a fourth key (`lens`) not in `PROTOCOL.md:44`;
  `PROTOCOL.md:173` omits `snapshot_sha` from the key inputs.

---

## Findings I rejected

- **Google, Critical, "the containment boundary is mocked out entirely,
  bypassing the OS boundary it claims to verify."** **Refuted.**
  `tests/test_verify_real_git.py` is 1,391 lines under
  `pytestmark = pytest.mark.real_subprocess(allow=["git"])` exercising the guard
  with **real git subprocesses** — including the guard tripping on index
  mutations, `diff.external`, `textconv`, `info/attributes`, planted
  `alternates`, gitlinks, split-index, and a config-grammar conformance suite
  against git itself. Google never found the file.
- **Google, Critical, "the system has never been tested live."** True, and
  already recorded — but I stated it as a premise in the brief. It is a
  restatement of the input, not a discovery.
- **OpenAI, Critical, "workers read outside their working copy."** True, known,
  measured in E1, documented in `docs/SECURITY.md`, and accepted by you on
  2026-08-22. Not a new finding; the new part is H4 above.

---

## Coverage and what stayed unverified

**Process failures in this review, stated plainly:**

- My first codex invocation **hung on stdin** for 10 minutes and produced
  nothing (my bug: no `< /dev/null`). Relaunched successfully; no coverage lost.
- **The Google test-quality lens is the weakest of the four and its conclusions
  should carry the least weight.** It sampled the suite rather than reading it,
  missed `test_verify_real_git.py` entirely — the single most important test
  module for the claims it was assessing — and two of its five findings did not
  survive verification. Treat "the test suite is sound" as *not established by
  this review*.

**Not covered by any family:** `doctor.py`, `snapshot.py`, the `openai-api`
worker path, Windows fallbacks (flock/killpg), `docs/` beyond cited lines, and
`eval/make_control_snapshot.py`.

**Not verifiable statically:** every claim about real CLI behaviour under load,
real vendor billing, whether the git battery is byte-deterministic on a real
snapshot, and `fcntl.flock` on anything but local macOS.

**Not instrumented:** panel cost. I used text output rather than JSON, so I have
no token or dollar accounting for this review. My error; harmless, but I cannot
tell you what it cost.

---

## Recommendation

**Split, because the two things you might mean by "live testing" have different
answers.**

**A plumbing / control live run — PROCEED.** The gate is green, no Critical or
High finding blocks a single-arm run on a clean control snapshot, and the two
defects the first live run found are fixed. C1 does not apply (no pairing), H2
does not apply (control is not a gated category), H4 is your accepted posture.

**A scored Phase 0 campaign — REVISE FIRST.** C1 must be fixed or the headline
comparison is confounded and you will not be able to tell. Minimum before a
scored campaign:

1. **C1** — either populate `model_executed` for codex/agy from a trustworthy
   source, or make `paired_deltas` require positive evidence of sharing
   (`invocation.reused`, or equal propose blob hashes) rather than key equality.
   Whichever you pick, the ablation test must drive a fake that returns
   `model_executed=None`, or it will keep passing on a broken world.
2. **H2** — refuse `containment: container` until something implements it.
3. **H3** — decide whether `ACCEPT` must rest on a supported ruling, and whether
   `HUMAN_ENTERED` evidence may support a claim. This is a specification call
   for you; `AGENTS.md` and `validate.py` currently disagree.

**HUMAN REVIEW REQUIRED** on H3 specifically — it is a protocol decision, not a
defect with an obvious fix.

---

# Live plumbing/control run — 2026-08-27

Executed the run this record recommended. Steps 1 and 2 **passed**; step 3
found a new defect. `--repeat-index 2` (r0/r1 dirs hold the failed attempts).

| Step | Arm | Panel | Result |
|---|---|---|---|
| 1 | `single` | claude | **exit 0, complete** |
| 2 | `indep_verify` | claude,grok + judge | **exit 0, complete** |
| 3 | `indep_verify_critique` | claude,grok, critic codex | exit 3, incomplete (defect C) |

## Both original defects confirmed fixed, live

- **Defect A (`USER`)**: no `worker.absent` for claude; propose succeeded.
- **Defect B (git index guard)**: the default battery ran all four commands
  with `--no-optional-locks` and produced 6 `mechanically_observed` items with
  **no `snapshot.violated`** and no `pack.incomplete`.

## The first real adjudication

Arm 3 produced verdict **ACCEPT**, `downgrades: 0`, `validate.findings: []`,
citing pack evidence ids. The judge's rationale states: *"agreement between P1
and P2 was not used as evidence, only the pack items were."*

`invocation.reused` fired for claude in step 2 — the cache correctly replayed
step 1's proposal. Consistent with C1: claude caches because it reports
`model_executed`; codex and agy structurally cannot.

The allowlist refused two model-requested commands live (`python3` not
allowlisted; a control character in argv) — the control working as designed.

## Two environmental blockers (not harness bugs)

1. **Pins go stale on their own.** claude auto-updated 2.1.240 → 2.1.247
   (Aug 27 07:58) → **2.1.248 (Aug 27 20:14, during this session)**; agy
   1.1.18 → 1.1.22 (Aug 27 08:08). `~/.local/bin/claude` is a symlink into
   `versions/`; `DISABLE_AUTOUPDATER=1` covers only the worker subprocess, not
   the interactive CLI that shares the binary. Re-pinned via
   `eris policy pin` (only agy/claude/judge hashes changed; codex, grok and all
   four verify tools were byte-identical).
   **Open risk: a long campaign can have a worker update mid-run and start
   refusing.** Consider pinning the resolved versioned path, or disabling
   auto-update globally.
2. **grok authenticates by env var, and preflight cannot see it.** grok reads
   `XAI_API_KEY`; `~/.grok/auth.json` no longer exists. The from-`{}` env gave
   "Not signed in" — the same class as defect A. Bisected: harness env fails,
   harness env + `XAI_API_KEY` works. Fixed by `.env` + `env_allow:
   [XAI_API_KEY]` on the grok worker (every `.env` value is registered with the
   Redactor; only `env_allow` names reach a worker).

**Preflight gap (finding).** It reported `OK worker.grok` while grok was
unusable, and `OK worker.claude` for a pin that a later auto-update invalidated.
It checks binaries at a moment in time and never checks that a worker can
*authenticate*. It reads as readiness and is not.

## DEFECT C (new, High) — relative policy paths leak into worker argv

`scratch_dir: cache/scratch` is **relative** (`policies/default.yaml:16`,
default at `src/eris/policy.py:218`) and is never resolved to an absolute path.
Worker subprocesses run with `cwd` = the snapshot (or its sanitized copy), so
every relative path resolves against the *worker's* cwd, not the harness's.

Two manifestations:

1. **codex dies before emitting any event.** `launch.py:1126-1129` builds
   `--output-schema <scratch>/call-<key>/schema.json` and `-o .../last_message.json`
   from the relative `scratch_dir`. codex cannot read the schema and exits 1
   with no JSONL. Ledger: `transient_io: codex died before any event (rc 1)`,
   after 3 correctly-backed-off retries (10s/20s/40s) then
   `retry weight exhausted`.
   Reproduced exactly outside the harness:
   `Failed to read output schema file cache/scratch/nope/schema.json:
   No such file or directory (os error 2)`, RC=1, no events.
   With **absolute** paths the identical invocation returns RC=0 and writes
   `{"ok":"OK"}`. Model `gpt-5.4` was tested and is NOT the cause.
2. **Every worker gets a broken `TMPDIR`.** `stages.py:708` sets
   `tmpdir=str(ctx.scratch_dir / "tmp")` from the same relative path. claude and
   grok tolerate it silently; it is still wrong and is a latent portability bug.

**Why no test caught it:** the hermetic fakes never resolve a path against a
real subprocess cwd, so a relative path is indistinguishable from an absolute
one in the suite. Same class as defects A and B — only a live run can find it.

**Fix (not applied):** resolve `scratch_dir`/`cache_dir` to absolute at policy
load, and assert in `build_call` that every path embedded in worker argv is
absolute. Needs a test that asserts absoluteness of argv paths.

## Status

Steps 1–2 prove the pack → propose → verify → adjudicate chain end to end.
Critique remains **unproven live** (blocked by defect C). agy also showed a
transient `$HOME is not defined` failure twice, then passed 4/4 with an
identical environment — not reproducible, cause not established.

## Review of the fix itself (stop-gate, 2026-08-27)

A stop-time review flagged that `env_allow: [XAI_API_KEY]` on the grok worker
"made machine-local Grok authentication globally mandatory."

**CORRECTION (2026-08-27): the flag was RIGHT and my first answer here was
WRONG.** I originally wrote that `env_allow` is "a filter, not a requirement"
and that "a host without the key behaves exactly as before". That conclusion
came from a `preflight` test, which never reaches the launch path. It is false.

`launch.plan_call` refuses the worker outright:

    missing = [n for n in w.env_allow if n not in call.secrets]
    if missing:
        raise LaunchRefused(f"env_allow names not provided: {missing}")

Verified by running it (`run --panel grok --env-file /nonexistent/.env`):
`policy_terminal: status refused: env_allow names not provided:
['XAI_API_KEY']`, exit 3. So declaring the name in the TRACKED policy does make
a machine-local credential mandatory on every host - exactly the claim I
dismissed. Doctor's WARN is only the softer half of the story.

**What was actually fixed.** The strict refusal is deliberate and tested
(`test_launch.py::test_plan_call_builds_argv_env_cwd_without_spawning`), so it
was not weakened. Instead the DOCUMENTATION was corrected: the policy header
said `env_allow` lists names that "may be passed", which contradicts the code.
It now says declaring a name makes it REQUIRED on every host, and the grok
comment records the machine-local requirement under the existing M2c-2
portability item (the tracked policy already carries machine-specific absolute
verify executables - the same wart).

**Still open (design):** for a CLI worker there is no vocabulary for "pass this
if present". API workers have `api_key_env` for a genuinely required key;
`env_allow` is doing double duty. An `env_optional` field, or making
`env_allow` permissive with requirement expressed separately, would remove the
portability wart properly. Not done here.

Gate after the edit: `task ci` exit 0, 1039 passed, 95.47%, pip-audit clean.

---

# Fixes: v0.4.0 (branch `fix/prelive-critical-high`, 2026-08-27)

Tier: **structural** (protocol + scorer semantics). One writer, one branch,
cross-family advisor pass, gate. User decisions: H3 = **strict**, C1 = **guard
the claim**.

## What was fixed

| # | Fix | Where |
|---|---|---|
| C1 (Critical) | `paired_deltas` requires positive evidence that proposals were shared; reports `paired: false` + the unshared keys otherwise | `eval/score.py` |
| H3 (High) | Only `mechanically_observed` evidence may support a ruling (`REF_NOT_MECHANICAL`); an `ACCEPT` with no surviving evidenced ruling is forced to `ESCALATE` (`VERDICT_UNSUPPORTED`) | `src/eris/validate.py` |
| Defect C (High) | scratch/cache dirs resolved to absolute; `plan_call` refuses any non-absolute path handed to a worker | `eval/run.py`, `src/eris/launch.py` |
| H2 (High) | `containment: container` refused at policy load until a container exists | `src/eris/policy.py` |

`docs/INVARIANTS.md`'s PAIRED ABLATION row was **false in production** and is
corrected in place. `docs/PROTOCOL.md` states the new evidence and verdict
rules. Version 0.3.14 → **0.4.0** (behaviour change; `SCHEMA_VERSION` stays
0.1.5 - no serialization changed, goldens untouched).

## Advisor pass (OpenAI `gpt-5.6-sol`, different family from the implementer)

Verdict: **BLOCK**, with four actionable findings. All four were verified
against the code and fixed; the block is resolved.

1. **CRITICAL, and correct: C1 was not actually closed.** Pairing keyed off
   `invocation.reused`, but `stages.invoke` writes that event as soon as a hit
   is *replayed* - and if the replayed output fails to parse it writes
   `stage.output_rejected` and falls through to a **fresh spawn**. The ledger
   would then hold a `reused` event for a re-spawned proposal, i.e. the exact
   false pairing C1 exists to prevent. Fixed by recording `reused` on
   `stage.finished{stage: propose}` - the outcome actually KEPT - and pairing on
   that. Test: `test_a_rejected_cache_replay_is_not_recorded_as_reused`.
2. **HIGH, and correct: I regressed `invoke`.** `cmd_invoke` used the
   unresolved relative `scratch_dir`, so the new absolute-path refusal would
   have broken it with the default policy. Fixed.
3. **MEDIUM, and correct: strict H3 wrongly escalated a legitimate ACCEPT.**
   If every adverse claim is mechanically REFUTED the answer IS defensible, but
   my rule demanded a SUPPORTED ruling. Now a surviving SUPPORTED **or**
   REFUTED ruling satisfies it.
4. **HIGH: `HOME` was unchecked** by the absolute-path guard. Added.

The advisor also correctly caught that this record contained a **false claim**
about `env_allow` (see the correction above); that has been fixed.

Two advisor findings are **recorded, not fixed**:

- **Resume bypasses H3.** `load_prior` replays a prior *enforced* adjudication
  unchanged, so resuming a run started before 0.4.0 keeps its old verdict.
  Resuming a pre-0.4.0 run is not supported; a re-enforce-on-resume pass is
  follow-up work.
- **The scorer does not gate on engine version.** One campaign could aggregate
  pre- and post-0.4.0 cells under the same labels. Needs an `eris_version` gate
  in `score_campaign`.

Google (`gemini-3.1-pro-high`) produced **no output** on two attempts: headless
mode auto-denied `read_file` (my error - the diff was outside `--add-dir`) and
then `command`. That lens is **missing**; the advisor round is single-family.

## Evidence

- `task ci`: **exit 0, 1045 passed, 95.47% coverage**, pip-audit clean.
- Live `indep_verify_critique` (r3, before the advisor fixes): all six steps
  **complete**; H3 fired - 4x `REF_NOT_MECHANICAL` because the judge cited the
  task QUESTION to support four claims, then `ESCALATED`.
- Live `indep_verify_critique` (r4, after): **exit 0**, `ACCEPT` with 2
  downgrades - ACCEPT now stands when evidenced rulings survive, confirming
  fix 3. `stage.finished.reused` recorded correctly (False for both fresh
  proposers).
- The r3/r4 pair shows H3 discriminating rather than blanket-escalating.

## Still open (NOT fixed here)

The 11 Medium findings from the review above, plus H4 (workers have a read-only
shell - accepted E1 posture), the two advisor items above, and the `env_allow`
"required vs may" design gap. Critique is now proven live; the paired ablation
is honest but codex/agy still cannot share proposals, so default-panel 3b-3 and
4-3 pairs will correctly report `paired: false` until that is solved.

## Second stop-gate finding, and it was right again (2026-08-27)

"H3 can still ACCEPT a fabricated claim ID." **Confirmed by running it**, and it
was a hole in the H3 fix itself, not in the original code:

    rulings=[Ruling(claim_id="clm-deadbeef-9", status=SUPPORTED,
                    evidence_refs=["e_01"])]      # e_01 IS mechanically observed
    -> findings: ['CLAIM_MISSING']   ruling: SUPPORTED   VERDICT: ACCEPT

A ruling naming a claim nobody made is flagged `CLAIM_MISSING` but is
deliberately NOT downgraded - its refs were fine (`test_claim_missing`, a
pre-existing documented decision, recorded as a Low in this review). H3's new
rule asked only for "a surviving SUPPORTED/REFUTED ruling", so a judge could
satisfy the entire evidence-binding guarantee by inventing a claim id and
citing genuine evidence at it. ACCEPT would rest on a claim that does not exist.

Fixed: the ACCEPT rule now requires the ruling's claim to EXIST
(`r.claim_id in claims`). Same input now yields
`['CLAIM_MISSING', 'VERDICT_UNSUPPORTED']` and `ESCALATE`. The ruling is still
not downgraded - that documented behaviour is unchanged; it simply cannot prop
up a verdict. Test:
`test_a_fabricated_claim_id_cannot_satisfy_the_accept_rule`, which also asserts
that one real evidenced ruling alongside the ghost still yields ACCEPT.

Gate: exit 0, 1046 passed, 95.47%, pip-audit clean.

**Pattern worth noting: three of the last four real defects were found by
review, not by the gate or by me** - the advisor's replay/false-pairing catch,
and both stop-gate findings. The suite has been green throughout.
