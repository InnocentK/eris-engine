# `model_executed` by output-token identity: the rule the panel forced

Date: 2026-09-14 · Trigger: claude 2.1.272 (auto-updated from the Sep 6 pin)
runs a haiku helper on EVERY call, verified live on trivial and realistic
ERIS-shaped prompts and captured as a fixture. `modelUsage` therefore always
names two models, the exactly-one-name rule read None on every claude call,
the cache refused every claude entry ("entry has no model_executed"), and
the paired design the claude+grok panel exists for was broken.

## The rule that landed (claude-only, `parse_claude`)

* exactly ONE name in `modelUsage` -> that name, even when it differs from
  the request (single-name defaulting detection unchanged);
* SEVERAL names -> the UNIQUE model whose own `outputTokens` equals the
  result's `usage.output_tokens` - authorship by the vendor's own counters,
  the REQUEST never consulted;
* no unique match (absent counters, ties, a future CLI breaking the
  identity) -> None. The degradation direction is None, never a wrong name.

## The rule that did NOT land, and why the record shows it

My first implementation - requested model appears in `modelUsage` -> record
the requested model, framed as "confirmed, not guessed" - was put to a
three-family panel and REJECTED unanimously: nothing establishes that
"requested appears in usage" means "requested produced the answer" (a
vendor can route the main turn elsewhere while the requested model does a
side task), and my framing was unsupported. Two families independently
converged on the counter identity; verified on the capture (helper 17
output tokens, primary 450 == result 450, unique). The membership rule was
reverted before landing; the confirmation round then caught my fixture
sidecar still describing it, plus two untested degradation branches - both
fixed, all three families CONFIRMED.

Also recorded, not silent: the Invocation ledger row does not carry
`models_used` (the helper list lives only in the stdout blob, which is
hashed into the ledger). Known, deliberate for now.

## Postscript, same day: the veto the stop gate forced

The identity as first landed could in principle crown a HELPER: a helper
whose counter coincidentally equals the result's while the primary's
cumulative diverges (multi-call turns). Never observed - every capture has
the primary matching exactly - but not excludable from one envelope, and my
first hardening attempt (gate on `num_turns == 1`) was falsified by the data
before landing: the 2.1.272 capture itself says `num_turns: 2` while the
identity holds. What landed instead: on the recorded result, a multi-name
counter match is kept only when it IS the requested model. The counters
still carry the authorship claim; the request only vetoes - it can suppress
a name, never supply one - so a false helper attribution now requires
primary-divergence AND the helper being the requested model, two
independent anomalies. The envelope and its hashed blob keep the unguarded
counter verdict, so the evidence of what the vendor reported is never
thinned. Veto deletion is mutation-caught.

**Standing dissent (openai seat), recorded:** the residual path - the
requested model itself being the coincidence-matching helper - should block
the rule today. Adjudicated against, on the evidence bound: that path needs
the vendor to run the requested model as a non-authoring helper AND the
true author's cumulative to diverge from the result count AND an exact
token coincidence - and no capture has ever shown even the divergence
alone. No mechanical closure exists in the envelope (it would need per-call
attribution the vendor does not emit), so the assumption is held OPENLY - and, as of the
second stop-time correction, WITHOUT any monitoring claim: the residual's
envelope signature (the requested model matching uniquely while another
model authored) is indistinguishable from the healthy case, so NO
capture-level test can monitor it. Two tripwire versions overclaimed - the
first checked uniqueness, which holds exactly when the residual fires; the
second claimed the "precondition" was requested-counter divergence, which is
a different failure - and both corrections are part of this record. What
remains in the suite is an honestly-named counter-SHAPE stability check:
if the vendor's counter shape stops supporting the identity rule, the rule
returns to review. The residual itself is accepted on its bound alone
(never-observed vendor behaviour, twice over, plus an exact coincidence),
with the openai seat's dissent standing and the xai seat accepting the
residual as named. RATIFIED by the user 2026-09-14, presented with the collapsed
monitoring claim and all three options (accept openly; block to always-None
per the dissent; split evidence from cache): accept openly, unmonitored -
the residual's bound (two never-observed vendor behaviours plus an exact
token coincidence) carries the decision on its own, with no monitoring
pretence attached.

## Re-pin

claude 2.1.272 pinned (with judge, same binary) after behavioural
re-verification: all emitted flags present; plan mode still blocks writes;
`parse_claude` reads the live envelope; sha bracketed around the probes and
equal to the pin. Gate passes end to end for v2.
