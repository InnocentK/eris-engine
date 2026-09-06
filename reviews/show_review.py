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

    print(
        f"\nMECHANICAL VERIFICATION: {len(refused)} request(s) REFUSED, 0 executed"
        if refused
        else "\nMECHANICAL VERIFICATION: no requests made"
    )
    if refused:
        for r in dict.fromkeys(refused):
            print(f"  refused: {r}")
        print("\n  Every check the models asked for was refused by the allowlist, so NOTHING")
        print("  here is mechanically verified. This is an adjudicated opinion, not a")
        print("  verified result. Weigh it accordingly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
