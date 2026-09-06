# EDR: worker budget caps raised to $4 with a validator

Date: 2026-09-06 · Contract §11 record.

**Decision.** `claude`/`judge` `max_budget_usd` 1.0 -> 4.0; `per_call_usd`
2.0 -> 4.0; new `Policy` validator refusing any worker cap above the per-call
reservation. Rationale: at 1.0 the vendor cap aborted plan-sized critic and
adjudicator calls MID-FLIGHT, which cost b-s3 both arm-4 plan cells and its
comparison.

**Scope.** `policies/default.yaml`, `src/eris/policy.py`. Deliberately NOT
addressed: the vendor cap overshoots (observed +3.8% to +97% past the limit) -
stated in the validator's docstring rather than hidden; per-run and
per-campaign ceilings unchanged.

**Evidence.** Sizing from the 46 executed cost-reporting calls in b-s1+b-s3
(27 claude/judge - propose n=10 mean $0.583 max $0.770, critique n=3 mean
$0.803 max $0.931, adjudicate n=14 mean $0.722 max $0.920 - plus 19 grok,
uncapped and excluded from sizing). This enumeration was CHALLENGED in the
§9.9 panel (C2: "undercounts by 10") and REFUTED by three independent ledger
counts - the challenge had summed results-document prose that counts replays;
the raiser conceded against the ledger. b-s3b then ran 12/12 with no budget
abort, $12.69 fully known.

**Results.** Cap-vs-reservation validator tests PASS; deleting the validator
fails the named test (mutation executed). CI 1258 PASS at `0aee4ea`.

**Review.** §9.9 AvA~ panel + final reviewer
([`2026-09-06-diff-panel-adjudication.md`](2026-09-06-diff-panel-adjudication.md)).
C2 is the panel's one fully refuted finding.

**Risks.** Higher per-call exposure by design (a runaway call can now cost
$4). The `agy` binary has drifted from its pin on this machine since
2026-08-31 - the gate correctly FAILS; re-pinning is a deliberate human act
this EDR does not perform.

**Rollback.** Lower the numbers; the validator forces cap<=reservation
consistency in either direction.

**Recommendation: SHIP.**
