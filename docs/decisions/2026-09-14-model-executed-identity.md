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

## Re-pin

claude 2.1.272 pinned (with judge, same binary) after behavioural
re-verification: all emitted flags present; plan mode still blocks writes;
`parse_claude` reads the live envelope; sha bracketed around the probes and
equal to the pin. Gate passes end to end for v2.
