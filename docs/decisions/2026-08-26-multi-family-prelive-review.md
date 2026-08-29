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

## Third stop-gate finding: the new protocol invariant was undocumented (2026-08-27)

Correct, and it had a second half the flag did not name: **`docs/PROTOCOL.md`
had become factually WRONG.** I wrote its ACCEPT paragraph after the first H3
commit, then changed the rule twice (REFUTED counts; the claim must exist) and
never revised the prose. It still said "an `ACCEPT` with no surviving
`SUPPORTED` ruling", which describes neither the code nor the intent. That is
exactly the doc-vs-code drift filed as an Informational finding in this same
review - repeated, by me, in the fix for it.

Fixed:

- **`docs/PROTOCOL.md`** now states the real rule: an ACCEPT survives only when
  some ruling survives as `SUPPORTED` **or** `REFUTED` **and** names a claim
  that exists, with the reason each half is load-bearing.
- **`docs/INVARIANTS.md`** gained the five missing do-not-break rows, each
  naming its enforcing test, per AGENTS.md ("INVARIANTS for any new
  do-not-break rule"): two validator rules (H3 origin, H3 verdict binding),
  the H2 containment refusal, the defect-C absolute-path rule, and the C1
  pairing guard.
- The corrected PAIRED ABLATION row was itself stale - it still named
  `invocation.reused` as the guard after that was replaced by
  `stage.finished{stage: propose}.reused`. Fixed.

Verified that all seven tests named in the new rows exist and pass. Gate: exit
0, 1046 passed, 95.47%, pip-audit clean.

**Running tally: four of five real defects this session came from review, not
from the gate.** The suite was green for every one. Three came from the
stop-gate alone (the `env_allow` mandate, the fabricated-claim hole, this).

## Fourth stop-gate finding: the invariant rows claimed coverage they did not have (2026-08-27)

Correct on four counts. I had verified that each named test EXISTS and PASSES -
which is not the same as verifying it tests the rule the row states. The gaps:

1. The launcher row claimed `scratch_dir`, `tmpdir` **and `home`** are refused
   when relative. `home` was never exercised: the HOME check was added on the
   advisor's finding AFTER the test was written, and nothing was added to cover
   it.
2. The verdict row claimed `REFUTED` counts toward ACCEPT. Nothing tested it -
   every H3 test used SUPPORTED. That half of the rule was implemented on the
   advisor's finding and shipped untested.
3. The scorer row claimed pairing reads `stage.finished{stage: propose}.reused`
   from the ledger. `_reused_propose_keys` - the function that does the reading,
   and the whole point of the C1 fix - had **no test**: the C1 scorer test
   builds `CellScore` objects directly and never reaches it.
4. `test_a_rejected_cache_replay_is_not_recorded_as_reused` **never exercised a
   rejected cache replay.** It ran an ordinary propose and asserted
   `reused is False`. The name asserted a guarantee the body did not test - the
   precise failure mode C1 itself was.

Fixed: the HOME case added; `test_accept_may_rest_on_a_mechanically_refuted_ruling_alone`
(which also asserts a DOWNGRADED refuted ruling cannot prop up ACCEPT);
`test_pairing_ignores_a_reused_event_whose_replay_was_rejected`, which drives
`_reused_propose_keys` against the adversarial ledger shape - two
`invocation.reused` events where only one replay survived - and asserts only the
surviving key counts; and the mis-named stages test renamed to
`test_propose_stage_finished_records_whether_the_kept_proposal_was_reused`,
with a docstring pointing at where the adversarial case is actually covered.

**Every 0.4.0 invariant test was then mutation-checked** - the rule was removed
and the test re-run - to prove it can fail:

| Rule removed | Result |
|---|---|
| HOME must be absolute | FAILS (good) |
| REFUTED satisfies ACCEPT | FAILS (good) |
| claim must EXIST | FAILS (good) |
| containment refused at load | FAILS (good) |
| mechanically_observed only | FAILS (good) |
| pairing reads the kept outcome | FAILS (good) |

All 9 tests named across the 5 rows verified to resolve to real functions.
Gate: exit 0, 1048 passed, 95.49%, pip-audit clean.

**This is the same defect as C1, one level up.** C1 was an invariant whose
enforcing test could not fail. Four of these rows were invariants whose
enforcing tests did not test the stated rule. "The named test exists and
passes" is not evidence; "the named test fails when the rule is removed" is.
Mutation-check any row added to INVARIANTS.md.

## Fifth stop-gate finding: stale same-key outcomes after resume (2026-08-27)

Correct, and it is the SAME attempt-vs-outcome error the advisor caught,
one layer further down - in my fix for that very error.

`_reused_propose_keys` collected keys with a set comprehension over every
`stage.finished{stage: propose}` payload, so **any** event with `reused: True`
marked the key shared. But a key can finish more than once: on resume a stage
whose blob does not re-hash is not trusted and the worker is re-run
(`arms.load_prior`, `test_resume_does_not_trust_a_tampered_blob`). A ledger can
therefore hold `reused: True` from the first pass followed by `reused: False`
from the re-spawn that actually produced the kept proposal - and the union would
resurrect the stale outcome and report a pairing that did not happen.

Fixed: the LAST `stage.finished` per idempotency key wins, and it must carry
both `ok` and `reused`. The test now covers both orderings (stale True then
False -> not shared; False then a genuine later replay -> shared) as well as the
`ok: False` case. Mutation-checked: restoring the "any True" comprehension makes
it fail. The INVARIANTS row states the last-wins rule.

Gate: exit 0, 1048 passed, 95.50%, pip-audit clean.

**Three times now the same error in the same fix**: pairing keyed on
`invocation.reused` (an attempt) -> keyed on any `stage.finished.reused` (still
an attempt when a key finishes twice) -> keyed on the last one (the outcome).
When a guard asks "did X happen?", the answer must come from the FINAL state of
X, and every ledger read must ask whether the event it reads can occur more than
once per key.

## Multiplicity audit of every ledger read in the scorer (2026-08-29)

Prompted by the pairing guard getting the attempt-vs-outcome error three times.
Rather than chase the next instance, every ledger read in `eval/score.py` was
enumerated and asked the same question: **can this event occur more than once
per key, and does the consumer assume it cannot?**

| Read | Can repeat? | Handling | Verdict |
|---|---|---|---|
| `records("arm.finished")` | yes (resume) | `arm_runs[-1]` | OK |
| `manifest(run_dir)` | no (one file) | - | OK |
| `records("adjudication.raw")` | yes (`adjudicate_iter`, cap 3) | `raws[-1]` | OK |
| `records("adjudication.enforced")` | yes (same) | `enforced[-1]` | OK |
| `records("scan.result")` | yes (scan + re-scan) | `scans[-1]` | OK |
| `of_kind("run.started")` | yes (resume) | `started[0]` - deliberate, the run's ORIGINAL snapshot | OK |
| `of_kind("arm.finished")` | yes | `finished[-1]` | OK |
| `payloads("stage.finished")` | yes | last-per-key (fixed `db571a4`) | OK |
| **`records("proposal.recorded")`** | **yes** | **whole list** | **DEFECT** |

Seven of nine already took the last (or deliberately the first). One did not.

**M11 confirmed and fixed.** A crash between `proposal.recorded` and
`stage.finished` leaves the stage unfinished, so resume does not trust it and
re-runs that worker - two rows for one worker. `predicted_findings` iterates
every row (`sources = cell.proposals` in BOTH branches), so the duplicate
counted that worker's findings twice and inflated tp/fp for **every arm**, not
just `single` as originally filed. `arms.load_prior` already keys proposals by
worker id (`prior.proposals[prop.worker_id] = prop`); the scorer was the only
reader that did not. Fixed by `_last_proposal_per_worker`, one row per worker,
last wins. Test `test_a_worker_that_recorded_twice_counts_once`,
mutation-checked (removing the dedup makes it fail).

Gate: exit 0, 1049 passed, 95.50%, pip-audit clean.

This closes the multiplicity class in the scorer. The same audit has NOT been
run over `eval/run.py` or `src/eris/arms.py` readers.

# Pre-merge panel (2026-08-29)

Three families, three complementary lenses, on the full 6-commit branch diff.
I was excluded: I wrote all of it.

| Family | Lens | Verdict |
|---|---|---|
| OpenAI `gpt-5.6-sol` | can each fix be DEFEATED? | **BLOCK**, 5 findings |
| xAI `grok-4.6` | ledger semantics, resume, crash paths | **APPROVE MERGE** |
| Google `gemini-3.1-pro-high` | do the tests enforce what the docs claim? | **NO OUTPUT** (headless auto-denied `command`) |

**Dissent, resolved against evidence.** OpenAI blocked; xAI approved. I verified
every OpenAI claim directly rather than counting votes. Four of five were real
and are fixed; the fifth was real and is fixed too. xAI's approval rested on the
narrower question it was asked (does this branch REGRESS resume?) - correct on
its own terms, and it independently confirmed two things that mattered:
`stage.finished.reused` is a backward-compatible optional payload key (an old
ledger simply reads as unpaired - conservative), and the scorer's last-wins rule
matches how `prior.finished` already behaves. It also found three PRE-EXISTING
attempt/outcome holes in `eval/run.py` and `src/eris/arms.py` (budget seeded
from a frozen view before the abandon cost is written; `_step_propose` treating
an `ok: False` finish as intact; SIGINT attempt numbering after a cache replay).
Those are recorded, not fixed - this branch does not touch those files.

## What the panel found, all verified and fixed

1. **Critical - the C1 guard could still false-pair.** "Treatment reused" does
   not prove "treatment used what the BASE used": pre-seed the cache with
   proposal A, run the base arm with `--fresh` so it spawns B (the write-once
   cache keeps A), then run the treatment normally - it replays A, reports
   `reused: True`, and the guard called it paired. **Fixed by changing the
   criterion to byte equality**: two arms pair only when their propose output
   blobs are identical, which is direct evidence of a shared world and is what
   `INVARIANTS.md` always claimed. This subsumes the reuse check - reuse is
   neither necessary (two spawns producing identical bytes DID share a world)
   nor sufficient (the `--fresh` case).
2. **High - the absolute-path guard was bypassable.** `plan_call` checked the
   call's `home`/`tmpdir`, but `build_env` merges the policy `env:` and
   `env_allow` secrets AFTER writing them, and neither name is on a NEVER list.
   Fixed at the chokepoint: the FINAL env is asserted absolute.
3. **High - H2 was bypassable through an existing ledger.** The load-time
   refusal only affects new policies; a ledger written earlier still carried
   `containment: container` and the E1 gate accepted it. The scorer now refuses
   it too, checked AFTER the no-ScanResult gate so neither refusal makes the
   other unreachable.
4. **High - resume replays a pre-0.4.0 enforced adjudication** rather than
   re-enforcing it, so a run started under the old rules would keep an ACCEPT
   that H3 would now escalate. Resuming a ledger whose `run.started.eris_version`
   predates 0.4.0 is now REFUSED (an absent or unparseable version counts as
   old). Rated High by OpenAI and Info by xAI; refusing is cheap and settles it.
5. **Medium - M11's dedup kept workers outside the final panel.** Resuming a run
   id with a different `--panel` leaves the old panel's proposals in the ledger;
   scoring them credits the arm with a worker it never ran. Proposals are now
   filtered to `ArmRun.panel`.

## Evidence

- `task ci`: exit 0, **1051 passed**, 95.47%, pip-audit clean.
- Every 0.4.0 invariant test mutation-checked (rule deleted -> test fails),
  including the three added this round. One of them - the final-env assertion -
  was found to have NO test by the mutation check and would otherwise have
  shipped as decoration for the second time.
- Live `indep_verify_critique` (r5): all six steps, **exit 0**, blobs recorded
  per propose key, H3 fired (ESCALATE, 3 downgrades).
- `eval/score.py` run against the real run ledgers for the first time: exit 0.
  `read_cell`, `_propose_blobs` and `_last_proposal_per_worker` exercised
  directly on three real ledgers - proposals filtered to panel, every ArmRun
  propose key carries a blob. The payload assumptions hold against real data.

## Coverage gap

The Google lens produced nothing on THREE attempts across two rounds (headless
`agy` auto-denies `read_file` outside `--add-dir`, then `command` even inside
it). **The test-enforcement lens was never covered by an independent family** -
only by my own mutation checks. That is the weakest part of this review.

## Sixth stop-gate finding: ACCEPT could ignore unresolved claims (2026-08-29)

Correct, and it was a hole in H3's ACCEPT rule as merged. The rule asked whether
ACCEPT **rested on** something evidenced; it never asked whether ACCEPT had
**resolved** what the panel raised. Verified by running it:

    3 claims exist; the judge rules on ONE and ignores two
      -> verdict ACCEPT, findings []          (no complaint at all)
    one claim ruled CONTESTED, the rest supported
      -> verdict ACCEPT, findings [DISSENT_EMPTY_WITH_CONTEST]  (inert, M1)

`claims` is every claim from every proposal (`stages.py:1049`), so a claim with
no ruling was never adjudicated. A proposer asserting "there is a null deref at
line 42" could be silently ignored and the answer declared defensible - the
exact failure this engine exists to prevent. And `CONTESTED` is an open dispute,
not a resolution; its only existing signal was a finding, and findings change
nothing (M1, still open).

Fixed: an `ACCEPT` is forced to `ESCALATE` unless BOTH (a) some ruling survives
as SUPPORTED/REFUTED naming a real claim (`VERDICT_UNSUPPORTED`), and (b) every
claim carries a ruling and none is `CONTESTED` (`VERDICT_UNRESOLVED_CLAIMS`).
`UNSUPPORTED` IS a resolution - "that claim was not backed" - and does not
block ACCEPT, which keeps the legitimate control-task path open.

Both halves mutation-checked. Gate: exit 0, 1052 passed, 95.49%, pip-audit
clean. PROTOCOL.md, INVARIANTS.md and CHANGELOG.md updated together.

**Six stop-gate findings, and the shape has been consistent**: I fix the
proposition I was shown and not the proposition that matters. "Rests on
evidence" is not "resolves the question", just as "an attempt was reused" was
not "the arms used the same bytes". The generalisable check before shipping a
guard: state the guarantee in one sentence, then ask what a hostile-but-valid
input could do while satisfying the code and violating the sentence.

## Seventh stop-gate finding: contradictory duplicate rulings bypassed ACCEPT (2026-08-29)

Correct. Probed the shapes rather than reasoning about them, and found it:

    c_01 SUPPORTED *and* UNSUPPORTED, c_02 SUPPORTED  ->  ACCEPT, findings []

Coverage was a SET membership test (`ruled = {r.claim_id for r in ...}`), so one
claim carrying two contradictory rulings satisfied BOTH new conditions at once:
the claim id appears in `ruled` (so nothing is "unresolved") and the bogus
`SUPPORTED` duplicate is an evidenced surviving ruling (so ACCEPT "rests on"
something). A judge could pair every adverse ruling with a contradicting
duplicate and reach ACCEPT with no complaint at all.

Fixed: a claim may be ruled EXACTLY ONCE (`PROTOCOL.md` already said so).
A repeat is a `DUPLICATE_RULING` error, the claim counts as UNRESOLVED, and a
duplicated claim cannot be what ACCEPT rests on. Redundant identical duplicates
are errors too - deciding which pairs "contradict" is a worse rule than
requiring one ruling per claim.

All three halves mutation-checked. Gate: exit 0, 1053 passed, 95.49%.

**Seven findings, one shape, now stated as a rule.** Every one of my guards has
been defeated by an input that satisfies its *encoding* while violating its
*meaning*: a set test where a multiset was meant, an attempt where an outcome
was meant, "rests on" where "resolves" was meant. Before shipping a guard,
enumerate the DEGENERATE shapes of its inputs - empty, duplicated, contradictory,
absent, repeated-after-resume - and run them. That is a five-minute probe and it
has now found four of the last five defects.

### Eighth finding, found by applying the rule instead of waiting for it

Immediately after writing the degenerate-shapes rule above, I ran it against the
pairing guard rather than waiting for the next stop-gate. It failed:

    both arms recorded NO proposals at all  ->  paired: True

Empty key sets make "nothing differs" trivially true, so the guard reported a
controlled comparison between two cells that shared nothing because there was
nothing to share. Pairing on the ABSENCE OF A DIFFERENCE rather than on evidence
of sameness - the same inversion as every earlier instance.

Fixed: an arm that recorded no propose output never pairs. Mutation-checked.
Gate: exit 0, 1053 passed, 95.50%.

The probe cost about two minutes and found a defect that seven rounds of review,
a Codex advisor pass and a three-family panel had all missed.

## Ninth stop-gate finding: the empty-arm rule did not name its test (2026-08-29)

Correct on the contract, though the rule WAS enforced (mutation-checked) - the
assertion sat inside a test named for a different case, so `INVARIANTS.md`
stated a rule no row could be traced to. Given two earlier findings of exactly
this shape, precision here is not pedantry.

Fixed twice over:

1. The rule was extracted into its own named test,
   `test_an_arm_with_no_propose_output_never_pairs` (covering neither-arm,
   base-only and treatment-only empty), and the C1 row now cites it.
2. **The contract is now self-enforcing.** `tests/test_invariants_doc.py`
   asserts that every rule row names at least one test and that every test it
   names exists (understanding the `::test_prefix_*` wildcard the docs already
   used). Both failure modes were verified by planting them: a citation to a
   nonexistent test, and a row with an empty test column - each is CAUGHT.

Writing that check immediately paid: it flagged five citations, all of which
turned out to be the wildcard convention my first regex did not understand. I
would otherwise have "fixed" correct documentation.

What it deliberately does NOT check: whether a named test EXERCISES its rule.
That is unautomatable and is what mutation-checking a new row is for. The
register now carries a row for itself saying so.

Gate: exit 0, 1056 passed, 95.50%, pip-audit clean.

## Tenth stop-gate finding: the documentation gate itself failed open (2026-08-29)

Correct, and the gate I had just written to close a class was an instance of it.
Probed it the way the standing rule says to, and two shapes walked straight
through:

| planted citation | old gate |
|---|---|
| `:: test_foo` (stray space) | **MISSED** |
| `::tets_foo` (typo, not `test_*`) | **MISSED** |
| `tests/test_x.py::...` (path prefix) | caught |
| `Test_X.py::...` (capitalised) | caught |
| `::test_no_such_name` | caught |

Both misses share one cause: the parser **skipped what it could not interpret**.
A row still contained `::`, so "this row names a test" passed, while the text it
named was validated by nothing. The `not name.startswith("test_")` guard existed
to let prose references like `eval/score.py::score_cell` through, and it let
typos through with them.

Fixed by failing closed and by separating the two jobs structurally: prose
references live in the RULE column and are ignored; the TEST column is parsed
strictly, and **every `::` in it must yield a citation or the gate fails**
(`test_invariants_citations_are_well_formed`). Re-probed: all eight shapes are
now caught, including three I had not thought to try (`::` with nothing after
it, a nonexistent wildcard family, an emptied test column). 18 prose references
in rule columns are correctly unaffected.

Gate: exit 0, 1057 passed, 95.50%, pip-audit clean.

**Ten findings, and the shape never changed.** Guards that skip the input they
cannot interpret; comparisons that read an attempt instead of an outcome; rules
satisfied by their encoding rather than their meaning. The lesson is not "be
careful" - it is that **a new guard is itself an artifact that must be probed
with degenerate input before it is trusted**, and that includes a guard written
to enforce this very discipline.

## Eleventh stop-gate finding: the fail-closed gate still failed open, one layer up (2026-08-29)

Correct. My previous round closed the CITATION parser and I re-probed only that
layer, so I confirmed the fix I had made and not the property I had claimed.
Probing the ROW layer found it open:

| planted row | previous gate |
|---|---|
| `\|A rule with no test\|` (no spaces) | **MISSED** |
| `\| A rule \|` (single cell) | **MISSED** |
| tab-separated cells | **MISSED** |
| `\|A rule\|\`::tets_typo\`\|` | **MISSED** |
| row with no trailing pipe | **MISSED** |

`_rule_rows` collected only lines matching `startswith("| ")` split on `" | "`,
and silently dropped everything else beginning with `|`. A rule written
`|rule|test|` escaped EVERY check in the module - including the citation checks
I had just hardened. Identical defect, one layer up: skip what you cannot parse.

Fixed: any line beginning with `|` that is not a divider or header must parse as
a rule row with >= 2 cells and a trailing pipe, or the gate fails
(`test_every_table_line_parses_as_a_rule_row`). Splitting is now on `|` rather
than `" | "`, so `|a|b|`, `| a | b |` and tab-padded rows all parse.

Re-probed BOTH layers: 6 row shapes and 6 citation shapes, all CAUGHT, and the
real document is unchanged by the probe. Gate: exit 0, 1058 passed, 95.50%.

**The lesson I keep having to relearn, stated exactly:** after fixing a guard,
re-probe the PROPERTY, not the PATCH. I probed ten citation shapes and declared
the gate fail-closed, having never asked whether a row could avoid reaching the
citation parser at all. "I fixed what you showed me" has now been the shape of
eleven findings; the countermeasure is to name the guarantee ("no rule row
escapes validation") and probe every layer that could violate it, not the layer
the last finding named. That is the same lesson as commit eb4edce, "guard the
whole reporter body, not the step the last finding named" - which is in this
repository's own history, and which I have now re-derived twice.

## Twelfth stop-gate finding: rows STILL escaped (2026-08-29)

Correct a third consecutive time on the same gate, and my probe was the reason
I missed it: I planted malformed rows before a heading - OUTSIDE any table -
and separately hardened the citation parser. I never planted a malformed row
INSIDE a table body, which is where a real one would live.

Three more escapes:

| planted row (inside a table) | previous gate |
|---|---|
| no LEADING pipe (valid GFM: `A rule \| test \|`) | **MISSED** |
| no leading pipe and no test | **MISSED** |
| body row whose first cells read `Rule`/`Test` | **MISSED** |

Same root cause for the third time: rows were identified by a SYNTACTIC PREFIX
(`startswith("|")`) and by CONTENT (`cells[:2] == ["rule","test"]` meant
"header"), so anything not matching the prefix was skipped, and anything
matching the header shape was skipped wherever it appeared.

Fixed STRUCTURALLY: a table is a header line followed by a divider; every line
until the table ends is a rule row and must parse. Header and divider are
skipped **by position**, so no body row can disguise itself as either. Outer
pipes are optional per GFM. A table-shaped line outside any table is itself a
defect, because nothing would validate it.

Re-probed with rows planted INSIDE a real table: 8 row shapes, 3 citation
shapes, 2 outside-a-table shapes - **13 of 13 caught**, real document unchanged.
Gate: exit 0, 1058 passed, 95.50%.

**What actually went wrong three times running is the PROBE, not the fix.** Each
round I probed the shape the previous finding named, in the position that was
convenient, and read "all caught" as "the property holds". A probe that only
exercises the case you already know about measures nothing. The property here
was "no rule row escapes validation"; the probe must therefore place a bad row
in every position a real row can occupy - inside a table, at its edges, outside
one - not in the one position I happened to pick.

## Thirteenth stop-gate finding: a divider-shaped body row escaped (2026-08-29)

Correct, and it is the mistake I had just written the fix FOR. The previous
round's lesson was "skip the header and divider BY POSITION so nothing in a
table body can disguise itself as one" - and the divider test I shipped matched
divider SHAPE anywhere:

    if _is_divider(line) and "|" in lines[n - 2]:   # <- no position constraint

So `| --- | --- |` sitting in a table BODY was skipped as a delimiter. Five
variants escaped: pure divider, colon-aligned, single dash, tab-padded, and
`| | |`.

Fixed by adding the position constraint the comment already claimed
(`not in_table and _is_divider(...)`).

**The durable change is that the probe is now a TEST, not a habit.** This gate
regressed four consecutive times, each time letting through a shape the previous
round had not thought to plant, and each time I re-probed by hand and reported
"all caught". Every shape that ever escaped is now planted INSIDE a table body
by `test_the_gate_rejects_every_known_malformed_row` (11 parametrised cases),
with `test_the_gate_accepts_a_well_formed_table` guarding against a net that
fires on everything. Both regressions were verified by reintroducing them:
matching divider shape anywhere, and the prefix-based row filter - each is
CAUGHT.

Full re-probe: 21 shapes across three positions (inside a table, outside one,
citation-level), 0 missed, document unchanged. Gate: exit 0, 1070 passed, 95.50%.

**Four rounds on one gate is the real finding.** Hand-probing after each fix
produced four consecutive false "all caught" reports, because I could only plant
the shapes I had already thought of. Encoding the probe as a parametrised test
converts a habit I demonstrably do not have into something the gate enforces -
and it is what I should have done the first time I wrote "probe degenerate
shapes" as a lesson rather than as code.

## Fourteenth stop-gate finding: the regression NET had the same blind spot (2026-08-29)

Correct, and it lands one level up from the last one. I built the net precisely
because hand-probing had failed four times - and then built it with the identical
defect: it planted each shape in exactly ONE position (appended after the body)
and reported 11/11.

A row can occupy four positions. Testing the matrix:

| position | shapes missed |
|---|---|
| after the body (what the net tested) | none |
| first body row, under the divider | none |
| between two body rows | none |
| **the header position** | **all 11** |

The header is skipped BY POSITION - correctly, it is not a rule row - but that
means a rule placed directly above a divider is validated by NOTHING. In a
register maintained by hand that is an ordinary editing mistake, and it silently
produces a rule with no enforcing test.

Fixed on both sides:

* the gate now requires the header to PROVABLY be a header - the line above a
  divider must be exactly `Rule | Test` (every real header in the document
  already is), so a rule row cannot occupy that slot unnoticed;
* the net is parametrised over shape x position, **44 cases**, all rejected,
  with the valid table still accepted. Removing the new header check makes the
  net fail, so it is not decoration.

Gate: exit 0, 1104 passed, 95.50%, pip-audit clean.

**Five rounds, and the invariant across all of them is the same:** whatever
mechanism I build to catch a class, I build it with one instance of that class
inside it. Hand-probe -> single position. Regression net -> single position.
The countermeasure that actually worked here was enumerating the DIMENSIONS of
the input (shape x position) and taking their product, rather than listing cases
I could think of. Where a guard skips something by position, that skip is itself
an unvalidated hole and needs its own positive check.

## Fifteenth stop-gate finding: the header guard was bypassable (2026-08-29)

Correct. The bypass was an **off-by-one that fails open**: the stray-line check
read

    if "|" in line and not _is_divider(line) and n < len(lines) and not _is_divider(lines[n]):

where `n < len(lines)` was meant to guard the lookahead, but instead **exempted
the last line of the file from the check entirely**. A bad row placed at the end
of the document escaped everything. Three probe shapes were the same bug:
last line of file, last line after a valid table, and a pipe-less header (whose
bad row also happened to be last). Rewritten as `is_header = n < len(lines) and
_is_divider(lines[n])`, so a line with no successor is simply not a header.

**Two corrections to my own account of this round**, both caught by writing the
test rather than by reasoning:

1. I first reported "two bypasses closed". Attribution by reverting each fix
   independently shows the off-by-one closed ALL of them; removing the
   `"|" in lines[n-2]` precondition closed nothing. It only improves the
   diagnostic - a pipe-less header now reports the header rule instead of a
   generic "outside any table" - and is pinned by its own message-level test.
2. That precondition edit had **never actually been applied**. The edit script
   asserted on a later hunk, raised, and discarded all three of its edits before
   writing; my attribution probe then "confirmed" a no-op as a no-op, because
   the string it tried to revert was not in the file. The failing message-level
   test is what exposed it.

Both fixes are now real and independently pinned: reverting the off-by-one fails
2 tests, reverting the precondition fails 1.

Gate: exit 0, 1111 passed, 95.50%, pip-audit clean.

**A multi-hunk edit that asserts per hunk and writes once is all-or-nothing, and
silently.** Verify the edit landed - grep for it - before measuring its effect;
otherwise the measurement describes a file that was never changed.

## Sixteenth stop-gate finding: the gate rejected valid Markdown (2026-08-29)

Correct, and it is a regression I introduced LAST round with an edit that closed
no hole. Removing the `"|" in lines[n-2]` precondition meant any line built from
`|-: ` was treated as a table divider - including a **thematic break**:

    ## S
    | Rule | Test |
    |---|---|
    | a rule | `test_...` |

    Prose.

    ---            <- read as a table divider

    More prose.    <- read as table rows

The prose line above the break was rejected as a malformed header, and the prose
below it parsed as rule rows. `docs/INVARIANTS.md` happens to contain no
horizontal rule today, so the gate passed by luck; the next one would have
blocked the gate on correct documentation.

**This is the opposite failure mode and it is equally bad.** Fifteen rounds went
into stopping this gate failing OPEN, and the fix for the last one made it fail
CLOSED on valid input. A gate that rejects good documents is not "safe" - it
gets disabled, and then it protects nothing.

Fixed with the GFM rules rather than more special-casing:
* a table delimiter row must contain a `|`; a thematic break does not;
* a table row must contain a `|`, so a pipe-less line ENDS the table instead of
  being reported as a malformed row.

The permanent net now checks **both directions**: 50 malformed cases must be
rejected, and 6 ordinary-Markdown shapes must be ACCEPTED with the rule-row
count unchanged. Both new behaviours were verified by reverting them.

Gate: exit 0, 1117 passed, 95.50%, pip-audit clean.

**The net was one-sided, which is why I did not catch this myself.** Every case
in it asserted "the gate rejects X". A gate that rejected everything would have
passed all 50. Any validator's regression net needs both halves - the inputs it
must refuse AND the inputs it must accept - or it only measures strictness.

## Seventeenth stop-gate finding: pipe-less termination was fail-open (2026-08-29)

Correct, and it is the cost of last round's fix. Ending the table on a pipe-less
line stopped the thematic-break false positive, but it also meant that line was
never examined - so a rule row whose pipes were lost, carrying a citation to a
test that does not exist, ended the table and left silently:

    | Rule | Test |
    |---|---|
    | a real rule | `test_x.py::test_y` |
    a rule with no pipes `::tets_typo`      <- ends the table, validated by NOTHING

Fixed narrowly: a pipe-less line still ends the table (that is the GFM rule and
what keeps `---` working), but if it cites a test it is reported - a rule that
lost its pipes is exactly what that looks like. Prose paragraphs that reference
tests legitimately sit after a blank line or heading, where the table has
already ended, and three such paragraphs in the real document are unaffected.

**The mutation check caught my test being right for the wrong reason.** The
three new cases passed immediately, but removing the guard they were meant to
pin changed nothing - because `GOOD_ROW` has no trailing newline, so each case
concatenated into ONE line, was parsed as a table row, and was rejected by the
citation checker instead. With the newline fixed, removing the guard fails all
three. A test that passes is not evidence; a test that fails when its rule is
deleted is.

Gate: exit 0, 1121 passed, 95.50%, pip-audit clean.

**Rounds 16 and 17 are one oscillation:** the fix for failing-open created a
false positive, and the fix for THAT re-opened a narrower fail-open. Each was a
real defect and each fix was correct in isolation. What stops the oscillation is
holding both directions at once - the net now asserts 53 inputs must be rejected
AND 7 must be accepted, so neither correction can be made without the other
being re-checked.

## Eighteenth stop-gate finding: `ab46284` was itself a false positive (2026-08-29)

Correct. The lost-pipe guard I added last round triggered on ANY `::` in the
line that ends a table, which rejected ordinary prose written directly under a
table without a blank line:

    | a real rule | `test_x.py::test_y` |
    See `eris.validate::enforce_rulings` for the implementation.   <- REJECTED

Three valid shapes were affected: prose citing a symbol, prose citing a pytest
id, and a bare `::` in a sentence. All are valid Markdown.

Fixed by triggering on the SHAPE of the thing being guarded rather than on one
of its characters. A rule row's test column is LAST, so a row that lost its
pipes ends with its citation; prose continues past it. The trigger is now a
backticked citation anchored to end-of-line. Six valid shapes accepted
(including prose that ends in a citation followed by a full stop), three
lost-pipe shapes still caught.

Both directions are pinned by mutation: deleting the guard fails 3 tests,
widening it back to `"::" in line` fails 4.

Gate: exit 0, 1125 passed, 95.50%, pip-audit clean.

**This is the third correction in a row on the same guard, and the pattern is
now legible.** Each time I reached for the cheapest available signal - "contains
`|`", "contains `::`" - rather than the property that actually distinguishes the
two cases. A character test cannot separate "a rule row that lost its pipes"
from "a sentence that mentions a test"; only the STRUCTURE can (where the
citation sits in the line). When a guard oscillates between false positives and
false negatives, the trigger is measuring the wrong thing, and adding more
special cases will keep it oscillating.

## Nineteenth stop-gate finding: the heuristic is removed, not patched again (2026-08-29)

Correct - four more valid shapes were rejected: prose ending in a citation with
no full stop, a bullet ending in one, a symbol reference at end of line, and a
citation alone on a line.

**I stopped patching it.** "Prose ending in a citation" and "a rule row whose
pipes were lost" are the same string. No fifth trigger separates them, and the
three previous attempts each traded a false negative for a false positive:

| round | trigger | result |
|---|---|---|
| 16 | any divider-shaped line | rejected thematic breaks |
| 17 | pipe-less line ends the table | lost-pipe rows escaped |
| 18 | any `::` on that line | rejected prose citing a test |
| 19 | citation anchored to end-of-line | rejected prose ending in a citation |

The guard is **removed**, and the limitation is written into the register: a row
that loses its pipes stops being a table row and is not reported. It renders as
prose, so it is visibly not a rule to anyone reading the document. That is a
smaller, bounded, *stated* hazard than a check that rejects correct
documentation - which would be disabled, and would then protect nothing.

What remains is entirely structural and unambiguous: every table line parses as
a rule row; the header is exactly `Rule | Test`; every rule row cites at least
one test; every `::` in a test column parses; every cited test exists; no
table-shaped line sits outside a table. **50 malformed cases rejected, 15 valid
documents accepted**, all mutation-checked.

Gate: exit 0, 1126 passed, 95.50%, pip-audit clean.

**The real lesson of rounds 16-19: know when to stop adding checks.** Each fix
was locally correct and the sequence still converged nowhere, because the
property being detected is not decidable from the text. Recognising that a check
CANNOT be made correct - and choosing a documented limitation over an oscillating
heuristic - is the engineering judgement I should have applied three rounds
earlier, and had actually written down one round earlier without acting on it.

## Twentieth stop-gate finding: the claim outlived the code (2026-08-29)

Correct, and it is the defect class this entire review has been about, committed
by me one commit earlier. `2c08c21` accepted a deliberate fail-open path - a row
that loses its pipes is not reported - while both the module docstring and the
`INVARIANTS.md` row still asserted, without qualification, that the gate **FAILS
CLOSED**. A register whose whole purpose is that a stated rule is true was
carrying a false statement about itself.

Fixed by making the claim match the code exactly:

* the guarantee is scoped - "fails CLOSED for everything that IS part of a
  table", with the one deliberate exception named in the same sentence rather
  than a paragraph away;
* the exception is now **executable**:
  `test_a_lost_pipe_row_is_a_known_unreported_gap` asserts the gap is NOT
  reported. If someone later adds detection, that test fails and forces them to
  re-check the accept direction before re-claiming fail-closed everywhere.
  Reintroducing a detector fails 9 tests, including the accept direction.

Gate: exit 0, 1127 passed, 95.50%, pip-audit clean.

**Accepting a limitation is not finished until the claims are corrected.** I
wrote the limitation into the register and left two absolute statements standing
beside it, which is precisely the doc-vs-code drift filed as a finding at the
start of this review and repeated by me at least three times since. A documented
exception should be stated where the guarantee is stated - and pinned by a test,
so the exception cannot rot into prose nobody checks.
