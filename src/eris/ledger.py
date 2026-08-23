"""Read-only view of a run ledger (``events.jsonl``): validation, typed
record extraction and cost totals. Imports nothing that executes - used by
resume (``eris.arms``) and by ``eval/score.py``."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from pydantic import ValidationError

from eris.schemas import CostRecord, Event, Record
from eris.validate import Finding, validate_events

R = TypeVar("R", bound=Record)


class LedgerCorrupt(RuntimeError):
    """A complete invalid line (any position): the cell is ``corrupt``."""

    def __init__(self, findings: Sequence[Finding]) -> None:
        self.findings = list(findings)
        super().__init__(
            "ledger invalid: "
            + "; ".join(f"{f.code}@{f.record_id}: {f.message}" for f in findings[:5])
        )


@dataclass(frozen=True)
class LedgerView:
    events: tuple[Event, ...]

    @classmethod
    def from_lines(cls, lines: Iterable[bytes], *, allow_torn_tail: bool = True) -> LedgerView:
        """Validate the chain; a torn (non-newline-terminated) tail is
        ignored when ``allow_torn_tail``; any complete invalid line raises."""
        raw = list(lines)
        if raw and allow_torn_tail and not raw[-1].endswith(b"\n"):
            raw = raw[:-1]
        findings = validate_events(raw)
        if findings:
            raise LedgerCorrupt(findings)
        events = tuple(Event.model_validate_json(line) for line in raw)
        return cls(events)

    @classmethod
    def from_path(cls, events_path: Path) -> LedgerView:
        data = Path(events_path).read_bytes()
        return cls.from_lines(data.splitlines(keepends=True))

    def kinds(self) -> list[str]:
        return [e.kind for e in self.events]

    def of_kind(self, kind: str) -> list[Event]:
        return [e for e in self.events if e.kind == kind]

    def payloads(self, kind: str) -> list[dict[str, Any]]:
        return [e.payload for e in self.events if e.kind == kind]

    def last(self, kind: str) -> dict[str, Any] | None:
        for e in reversed(self.events):
            if e.kind == kind:
                return e.payload
        return None

    def records(self, kind: str, model: type[R]) -> list[R]:
        """Eris-authored records only (never model output)."""
        out: list[R] = []
        for e in self.events:
            if e.kind == kind:
                try:
                    out.append(model.model_validate(e.payload))
                except ValidationError as exc:
                    raise LedgerCorrupt(
                        [Finding("MALFORMED_LINE", "error", f"{kind} at seq {e.seq}: {exc!s:.120}")]
                    ) from exc
        return out

    def manifest(self, run_dir: Path) -> dict[str, Any] | None:
        path = Path(run_dir) / "manifest.json"
        if not path.is_file():
            return None
        data = json.loads(path.read_bytes())
        return data if isinstance(data, dict) else None


@dataclass(frozen=True)
class CostTotals:
    spent_usd: float  # counted=True (known + pessimistic estimates)
    attributed_usd: float  # every cost record, reused calls included
    known_usd: float  # counted=True and cost_known
    reserved_usd: float  # counted=True and not cost_known
    unknown_count: int  # records with no cost at all
    by_stage_spent: dict[str, float]
    by_stage_attributed: dict[str, float]
    attempts: int


def cost_totals(view: LedgerView) -> CostTotals:
    """Totals from ``cost`` records, attributed to the stage of the
    ``invocation.finished`` record that shares the invocation id."""
    stage_of: dict[str, str] = {}
    for inv in view.payloads("invocation.finished"):
        iid = inv.get("invocation_id")
        if isinstance(iid, str):
            stage_of[iid] = str(inv.get("stage", "unknown"))
    spent = attributed = known = reserved = 0.0
    unknown = 0
    by_spent: dict[str, float] = {}
    by_attr: dict[str, float] = {}
    records = view.records("cost", CostRecord)
    for c in records:
        stage = stage_of.get(c.invocation_id, "unknown")
        if c.cost_usd is None:
            unknown += 1
            continue
        attributed += c.cost_usd
        by_attr[stage] = by_attr.get(stage, 0.0) + c.cost_usd
        if c.counted:
            spent += c.cost_usd
            by_spent[stage] = by_spent.get(stage, 0.0) + c.cost_usd
            if c.cost_known:
                known += c.cost_usd
            else:
                reserved += c.cost_usd
    return CostTotals(
        round(spent, 6),
        round(attributed, 6),
        round(known, 6),
        round(reserved, 6),
        unknown,
        {k: round(v, 6) for k, v in sorted(by_spent.items())},
        {k: round(v, 6) for k, v in sorted(by_attr.items())},
        len(records),
    )
