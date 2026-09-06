#!/usr/bin/env python3
"""Render a run's adjudication for a human. `eval/run.py` prints a machine
summary; this prints the review.

Reads the ledger only - no network, no re-scoring - so it is safe to run on a
finished run at any time:

    .venv/bin/python reviews/show_review.py runs/<run_id>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    events = Path(argv[1]) / "events.jsonl"
    if not events.is_file():
        print(f"no ledger at {events}", file=sys.stderr)
        return 2

    enforced: dict | None = None
    proposals: list[dict] = []
    refused: list[str] = []
    stopped = 0
    pack: list[tuple[str, str]] = []
    executed = 0
    contaminated = False
    for line in events.read_bytes().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        p = e.get("payload", {})
        if e["kind"] == "adjudication.enforced":
            enforced = p
        elif e["kind"] == "proposal.recorded":
            proposals.append(p)
        elif e["kind"] == "verify.refused":
            refused.append(str(p.get("reason", ""))[:100])
        elif e["kind"] == "verify.stopped":
            stopped += 1
        elif e["kind"] == "evidence.item":
            # `phase` separates what was assembled for the prompt from what a
            # model asked to be RUN and Eris ran. Counting only refusals printed
            # "0 executed" unconditionally - true of every campaign so far, and
            # a lie the moment the allowlist lets something through.
            if p.get("phase") == "verification":
                executed += 1
            else:
                # An excerpt is a `repo_fact` that no command produced, so its
                # `argv` is null; the git facts all carry one. `label` is NOT a
                # discriminator - it is absent from the ledger payload, which is
                # how the first version of this reported "no file excerpt" on a
                # run whose pack contained one.
                pack.append((str(p.get("kind")), p.get("argv") is None))
        elif e["kind"] == "scan.result" and p.get("contaminated"):
            contaminated = True

    if contaminated:
        print("!! CONTAMINATED - a key marker reached the output. Do not use this review.\n")

    if enforced is None:
        print("NO ADJUDICATION. This run produced no verdict.")
        print("An arm without a judge (`single`) never produces one; otherwise the")
        print("judge stage did not finish. Proposals below, unjudged.\n")
    else:
        print(f"VERDICT: {enforced.get('verdict')}")
        if enforced.get("escalated_by_engine"):
            print("  (forced by the engine, not chosen by the judge)")
        print(f"\nRATIONALE\n  {enforced.get('rationale', '')}\n")
        dissent = enforced.get("dissent") or []
        print(f"DISSENT ({len(dissent)})")
        for d in dissent:
            print(f"  - {json.dumps(d)[:300]}")
        risks = enforced.get("residual_risks") or []
        print(f"\nRESIDUAL RISKS ({len(risks)})")
        for r in risks:
            print(f"  - [{r.get('severity')}] {r.get('text')}")
        rulings = enforced.get("rulings") or []
        downgrades = enforced.get("downgrades", 0)
        print(f"\nRULINGS: {len(rulings)}, of which the engine downgraded {downgrades}")

    print(f"\nFINDINGS BY WORKER ({len(proposals)} proposal(s))")
    for prop in proposals:
        print(f"  {prop.get('worker_id')}: {len(prop.get('findings') or [])} finding(s)")
        for f in prop.get("findings") or []:
            loc = f.get("location") or {}
            where = f"{loc.get('path')}:{loc.get('line_start')}" if loc else "no location"
            print(f"    [{f.get('severity')}] {where} - {f.get('description', '')[:110]}")

    # What the reviewers were actually GIVEN. A task that declares no
    # `excerpts` sends the question and the git facts and NOT the document:
    # `TaskSpec.excerpts` defaults to an empty list and the pack builder only
    # iterates what is declared, so the review reads like a review of your
    # document while nobody was shown it.
    quotes = [k for k, _ in pack if k == "document_quote"]
    facts = [k for k, _ in pack if k == "repo_fact"]
    excerpts = [k for k, no_argv in pack if k == "repo_fact" and no_argv]
    # "document quote(s)", not "question" (panel 2026-09-06, D3): a task with
    # `plan_text` adds a second document_quote labelled "plan", and the ledger
    # payload carries no label to count by - so the count is honest and the
    # name is the kind, not a guess at its label.
    print(
        f"\nEVIDENCE PACK: {len(pack)} item(s) - {len(quotes)} document quote(s) "
        f"(the question, plus the plan text when the task carries one), "
        f"{len(facts)} repo fact(s), of which {len(excerpts)} file excerpt(s)"
    )
    if not excerpts:
        print("  !! NO FILE EXCERPT. The reviewers were given the question and the")
        print("     repository facts, but NOT the contents of any file. Declare")
        print("     `excerpts` in task.json, or this is a review of a document")
        print("     nobody was shown.")

    print(
        f"\nMECHANICAL VERIFICATION: {executed} executed, {len(refused)} refused"
        + (f", {stopped} stopped" if stopped else "")
    )
    for r in dict.fromkeys(refused):
        print(f"  refused: {r}")
    if executed == 0:
        print("\n  Nothing was mechanically verified: no check the models asked for ran.")
        print("  This is an adjudicated opinion, not a verified result. Weigh it")
        print("  accordingly.")
    else:
        print(f"\n  {executed} check(s) ran; their output is in the ledger as")
        print("  `evidence.item` with phase `verification`. Claims resting on those are")
        print("  mechanically supported; claims resting on the rest are not.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
