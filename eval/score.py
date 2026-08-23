"""Phase 0 scorer - READ-ONLY over ``runs/<campaign>/`` and ``eval/corpus/``.

Imports nothing that executes (no subprocess, socket, httpx, os.system,
``eris.launch`` or ``eris.verify``; an AST test enforces it) and opens
nothing outside the runs dir and the corpus.

Per cell (one run dir with ``manifest.json``):

* the ledger is validated (``validate_events``); any error -> excluded
  ``ledger_invalid``;
* contaminated (recorded ``scan.result`` OR a re-scan with the CURRENT key)
  or ``scan_incomplete`` -> excluded from quality metrics, counted in cost;
* an incomplete panel or missing judge -> excluded ``incomplete``; a
  BUDGET_TRIPPED cell -> ``missing``;
* E1 GATE: categories ``revert`` / ``planted`` / ``insufficient`` require
  ``ArmRun.containment == "container"``; otherwise the whole scoring run
  is REFUSED (exit 7, no metrics, no override). ``control`` and ``plan``
  score normally (user decision; the testing critic's objection that plan
  keys are as readable as the others is recorded in EVAL-PLAN).

Metrics: precision / recall over findings (path + line overlap within
``line_tolerance``, ``must_mention`` strings present; 0/0 -> None),
distractor hits (counted as FP), unsupported-claim rate
(``adjudication.enforced.downgrades`` / rulings), confident-wrong (ACCEPT
off-key, or a high/critical FP), abstention 2x2, cost spent AND attributed
by stage (None costs counted separately), wall clock, attempts. Arm 1's
findings come from the proposal (no judge); arm 2 (consensus) is scored on
the RAW summarizer verdict (pre-registration note); the other arms on the
enforced verdict. Paired deltas 3b-3 and 4-3 per (task, repeat) only when
the arms' ``propose_keys`` are identical.

Finding attribution for judged arms: a proposal finding counts as asserted
by the arm when at least one of its linked claims is ruled SUPPORTED in
the enforced adjudication, or, when it links no claim, when the verdict is
not ACCEPT/ABSTAIN.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from eris.ledger import LedgerCorrupt, LedgerView, cost_totals
from eris.scan import build_patterns, scan_run
from eris.schemas import (
    Adjudication,
    Arm,
    ArmRun,
    ArmStatus,
    ClaimStatus,
    Proposal,
    ScanResult,
    Severity,
    TaskCategory,
    Verdict,
    parse_ts,
)

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_GATE = 7
GATED_CATEGORIES: frozenset[TaskCategory] = frozenset(
    {TaskCategory.REVERT, TaskCategory.PLANTED, TaskCategory.INSUFFICIENT}
)
CONTAINMENT_ACCEPTED: frozenset[str] = frozenset({"container"})
CONTAINMENT_BASIS = (
    "policy declaration (`containment` in the policy file, recorded on the ArmRun); the "
    "scorer gates on the declaration and cannot verify it - M2c builds the container"
)
PAIRS: tuple[tuple[str, Arm, Arm], ...] = (
    ("3b-3", Arm.INDEP_VERIFY_ITER, Arm.INDEP_VERIFY),
    ("4-3", Arm.INDEP_VERIFY_CRITIQUE, Arm.INDEP_VERIFY),
)


class GateRefused(RuntimeError):
    """A gated category without containment: no metrics are produced."""


# --------------------------------------------------------------------------- key.json


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _Span(_Strict):
    path: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)

    @model_validator(mode="after")
    def _ordered(self) -> _Span:
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class KeyFinding(_Span):
    id: str = Field(min_length=1)
    severity: Severity
    must_mention: list[str] = Field(default_factory=list)


class Distractor(_Span):
    pass


class KeyScan(_Strict):
    fix_hunk_lines: list[str] = Field(default_factory=list)
    extra_strings: list[str] = Field(default_factory=list)


class Key(_Strict):
    key_version: Literal[1]
    task_id: str = Field(min_length=1)
    category: TaskCategory
    expected_verdict: list[Verdict]
    line_tolerance: int = Field(ge=0)
    findings: list[KeyFinding] = Field(default_factory=list)
    distractors: list[Distractor] = Field(default_factory=list)
    scan: KeyScan = Field(default_factory=KeyScan)
    injection_canary: bool | None = None
    source_repo: str | None = None


def load_key(corpus: Path, task_id: str) -> Key:
    path = Path(corpus) / task_id / "key.json"
    try:
        return Key.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise GateRefused(f"key for {task_id!r} unusable: {exc!s:.200}") from exc


# --------------------------------------------------------------------------- cells


@dataclass
class CellData:
    run_dir: Path
    view: LedgerView
    arm_run: ArmRun
    proposals: list[Proposal]
    raw: Adjudication | None
    enforced: Adjudication | None
    scan: ScanResult | None
    manifest: dict[str, Any]
    started_ts: str | None
    finished_ts: str | None


def read_cell(run_dir: Path) -> CellData:
    view = LedgerView.from_path(run_dir / "events.jsonl")  # raises LedgerCorrupt
    arm_runs = view.records("arm.finished", ArmRun)
    if not arm_runs:
        raise LedgerCorrupt([])
    manifest = view.manifest(run_dir) or {}
    raws = view.records("adjudication.raw", Adjudication)
    enforced = view.records("adjudication.enforced", Adjudication)
    scans = view.records("scan.result", ScanResult)
    started = view.of_kind("run.started")
    finished = view.of_kind("arm.finished")
    return CellData(
        run_dir=run_dir,
        view=view,
        arm_run=arm_runs[-1],
        proposals=view.records("proposal.recorded", Proposal),
        raw=raws[-1] if raws else None,
        enforced=enforced[-1] if enforced else None,
        scan=scans[-1] if scans else None,
        manifest=manifest,
        started_ts=started[0].ts if started else None,
        finished_ts=finished[-1].ts if finished else None,
    )


def rescan(cell: CellData, key: Key, *, home: Path, corpus: Path) -> ScanResult:
    """Read-only re-scan with the CURRENT key; the pre-fix tree is consulted
    only when the recorded snapshot lies inside the corpus."""
    started = cell.view.payloads("run.started")
    snapshot_root: Path | None = None
    if started and isinstance(started[0].get("snapshot"), str):
        candidate = Path(started[0]["snapshot"])
        try:
            candidate.resolve().relative_to(Path(corpus).resolve())
            snapshot_root = candidate if candidate.is_dir() else None
        except ValueError:
            snapshot_root = None
    patterns = build_patterns(
        snapshot_root=snapshot_root,
        home=home,
        source_repo=key.source_repo,
        fix_hunk_lines=key.scan.fix_hunk_lines,
        extra_strings=key.scan.extra_strings,
        known_texts=[str(cell.run_dir), str(cell.run_dir.parent)]
        + ([str(snapshot_root)] if snapshot_root else []),
    )
    return scan_run(
        events_path=cell.run_dir / "events.jsonl",
        blobs_dir=cell.run_dir / "blobs" / "sha256",
        patterns=patterns,
        run_id=cell.arm_run.task_id + "-rescan",
    )


# --------------------------------------------------------------------------- findings


@dataclass(frozen=True)
class Predicted:
    path: str | None
    line_start: int | None
    line_end: int | None
    severity: Severity
    description: str


def predicted_findings(cell: CellData) -> list[Predicted]:
    """Arm 1: the proposal's findings. Judged arms: findings whose linked
    claims are SUPPORTED (enforced), or unlinked findings unless the verdict
    is ACCEPT/ABSTAIN."""
    out: list[Predicted] = []
    if cell.arm_run.arm is Arm.SINGLE:
        sources = cell.proposals
        supported: set[str] | None = None
        verdict: Verdict | None = None
    else:
        sources = cell.proposals
        adj = cell.enforced
        if adj is None:
            return []
        supported = {r.claim_id for r in adj.rulings if r.status is ClaimStatus.SUPPORTED}
        verdict = adj.verdict
    for prop in sources:
        for f in prop.findings:
            if supported is not None:
                if f.claim_ids:
                    if not any(c in supported for c in f.claim_ids):
                        continue
                elif verdict in (Verdict.ACCEPT, Verdict.ABSTAIN):
                    continue
            loc = f.location
            out.append(
                Predicted(
                    loc.path if loc else None,
                    loc.line_start if loc else None,
                    loc.line_end if loc else None,
                    f.severity,
                    f.description,
                )
            )
    return out


def _overlap(a_start: int, a_end: int, b_start: int, b_end: int, tolerance: int) -> bool:
    return a_start <= b_end + tolerance and b_start <= a_end + tolerance


def _matches(pred: Predicted, kf: KeyFinding, tolerance: int) -> bool:
    if pred.path is None or pred.path != kf.path:
        return False
    ps = pred.line_start or 1
    pe = pred.line_end or ps
    if not _overlap(ps, pe, kf.line_start, kf.line_end, tolerance):
        return False
    text = pred.description.lower()
    return all(m.lower() in text for m in kf.must_mention)


@dataclass
class Matching:
    tp: int
    fp: int
    fn: int
    distractor_hits: int
    matched_ids: list[str]
    fp_severities: list[str]

    @property
    def precision(self) -> float | None:
        return None if self.tp + self.fp == 0 else self.tp / (self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return None if self.tp + self.fn == 0 else self.tp / (self.tp + self.fn)


def match_findings(predicted: Sequence[Predicted], key: Key) -> Matching:
    matched: set[str] = set()
    fp = 0
    fp_sev: list[str] = []
    distractor_hits = 0
    for pred in predicted:
        hit = next(
            (
                kf
                for kf in key.findings
                if kf.id not in matched and _matches(pred, kf, key.line_tolerance)
            ),
            None,
        )
        if hit is None:
            hit = next((kf for kf in key.findings if _matches(pred, kf, key.line_tolerance)), None)
        if hit is not None:
            matched.add(hit.id)
            continue
        fp += 1
        fp_sev.append(pred.severity.value)
        if pred.path is not None and any(
            d.path == pred.path
            and _overlap(
                pred.line_start or 1,
                pred.line_end or pred.line_start or 1,
                d.line_start,
                d.line_end,
                key.line_tolerance,
            )
            for d in key.distractors
        ):
            distractor_hits += 1
    return Matching(
        len(matched), fp, len(key.findings) - len(matched), distractor_hits, sorted(matched), fp_sev
    )


# --------------------------------------------------------------------------- scoring


@dataclass
class CellScore:
    run_id: str
    task_id: str
    arm: str
    repeat_index: int
    category: str
    included: bool
    exclusion: str | None
    verdict: str | None
    verdict_basis: str | None
    precision: float | None
    recall: float | None
    tp: int
    fp: int
    fn: int
    distractor_hits: int
    unsupported_claim_rate: float | None
    downgrades: int
    confident_wrong: bool
    abstained: bool
    expected_abstain: bool
    cost_spent_usd: float
    cost_attributed_usd: float
    cost_by_stage_spent: dict[str, float]
    cost_by_stage_attributed: dict[str, float]
    unknown_cost_records: int
    wall_ms: int | None
    attempts: int
    propose_keys: list[str]
    contaminated: bool
    scan_incomplete: bool
    rescan_contaminated: bool
    containment: str | None
    containment_basis: str = CONTAINMENT_BASIS
    missing_cells: list[dict[str, str]] = field(default_factory=list)


def score_cell(cell: CellData, key: Key, *, home: Path, corpus: Path) -> CellScore:
    ar = cell.arm_run
    # the key must be the key OF THIS LEDGER: a gated task can never be scored
    # behind an ArmRun that recorded another task or a scorable category
    if key.task_id != ar.task_id:
        raise GateRefused(
            f"{cell.run_dir.name}: key.json task_id {key.task_id!r} != ArmRun.task_id "
            f"{ar.task_id!r}; refusing the cell"
        )
    if key.category is not ar.category:
        raise GateRefused(
            f"{cell.run_dir.name}: key.json category {key.category.value!r} != the category "
            f"recorded at run time {ar.category.value!r} (task.json); refusing the cell"
        )
    if ar.category in GATED_CATEGORIES and (ar.containment or "") not in CONTAINMENT_ACCEPTED:
        raise GateRefused(
            f"{cell.run_dir.name}: category {ar.category.value} requires "
            f"ArmRun.containment in {sorted(CONTAINMENT_ACCEPTED)} (recorded {ar.containment!r}); "
            "defect-detection and ABSTAIN results without containment are not evidence (E1)"
        )
    totals = cost_totals(cell.view)
    recorded_scan = cell.scan
    if recorded_scan is None and ar.category in GATED_CATEGORIES:
        raise GateRefused(
            f"{cell.run_dir.name}: no ScanResult recorded for a {ar.category.value} cell; "
            "an unscanned defect/ABSTAIN result is not evidence"
        )
    rescanned = rescan(cell, key, home=home, corpus=corpus)
    contaminated = ar.contaminated or (recorded_scan.contaminated if recorded_scan else False)
    scan_incomplete = (
        bool(recorded_scan and recorded_scan.scan_incomplete) or rescanned.scan_incomplete
    )
    exclusion: str | None = None
    if recorded_scan is None:
        exclusion = "no_scan"  # plumbing only: never a quality metric
    elif contaminated or rescanned.contaminated or scan_incomplete:
        exclusion = "contaminated"
    elif any(m.reason.startswith("budget") for m in ar.missing_cells):
        exclusion = "missing"
    elif ar.status is not ArmStatus.COMPLETE or (
        ar.arm is not Arm.SINGLE and cell.enforced is None
    ):
        exclusion = "incomplete"
    basis: str | None
    adj: Adjudication | None
    if ar.arm is Arm.CONSENSUS:
        adj, basis = cell.raw, "raw"  # pre-registration: arm 2 is scored on the RAW verdict
    elif ar.arm is Arm.SINGLE:
        adj, basis = None, None
    else:
        adj, basis = cell.enforced, "enforced"
    verdict = adj.verdict if adj else None
    predicted = predicted_findings(cell) if exclusion is None else []
    matching = match_findings(predicted, key)
    enforced = cell.enforced
    rate = (
        enforced.downgrades / len(enforced.rulings)
        if enforced is not None and enforced.rulings
        else None
    )
    expected_abstain = (
        ar.category is TaskCategory.INSUFFICIENT or Verdict.ABSTAIN in key.expected_verdict
    )
    confident_wrong = exclusion is None and (
        (verdict is Verdict.ACCEPT and Verdict.ACCEPT not in key.expected_verdict)
        or any(s in ("high", "critical") for s in matching.fp_severities)
    )
    wall: int | None = None
    if cell.started_ts and cell.finished_ts:
        wall = int((parse_ts(cell.finished_ts) - parse_ts(cell.started_ts)).total_seconds() * 1000)
    return CellScore(
        run_id=cell.run_dir.name,
        task_id=ar.task_id,
        arm=ar.arm.value,
        repeat_index=ar.repeat_index,
        category=ar.category.value,
        included=exclusion is None,
        exclusion=exclusion,
        verdict=verdict.value if verdict else None,
        verdict_basis=basis,
        precision=matching.precision if exclusion is None else None,
        recall=matching.recall if exclusion is None else None,
        tp=matching.tp,
        fp=matching.fp,
        fn=matching.fn,
        distractor_hits=matching.distractor_hits,
        unsupported_claim_rate=rate,
        downgrades=enforced.downgrades if enforced else 0,
        confident_wrong=confident_wrong,
        abstained=verdict is Verdict.ABSTAIN,
        expected_abstain=expected_abstain,
        cost_spent_usd=totals.spent_usd,
        cost_attributed_usd=totals.attributed_usd,
        cost_by_stage_spent=dict(totals.by_stage_spent),
        cost_by_stage_attributed=dict(totals.by_stage_attributed),
        unknown_cost_records=totals.unknown_count,
        wall_ms=wall,
        attempts=totals.attempts,
        propose_keys=list(ar.propose_keys),
        contaminated=contaminated,
        scan_incomplete=scan_incomplete,
        rescan_contaminated=rescanned.contaminated,
        containment=ar.containment,
        missing_cells=[
            {"worker_id": m.worker_id, "stage": m.stage.value, "reason": m.reason}
            for m in ar.missing_cells
        ],
    )


# --------------------------------------------------------------------------- aggregation


def _mean(values: Sequence[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return round(sum(present) / len(present), 4) if present else None


def aggregate(scores: Sequence[CellScore]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for arm in sorted({s.arm for s in scores}):
        cells = [s for s in scores if s.arm == arm]
        inc = [s for s in cells if s.included]
        out[arm] = {
            "cells": len(cells),
            "included": len(inc),
            "excluded": {
                k: len([s for s in cells if s.exclusion == k])
                for k in ("contaminated", "missing", "incomplete", "ledger_invalid", "no_scan")
            },
            "precision": _mean([s.precision for s in inc]),
            "recall": _mean([s.recall for s in inc]),
            "unsupported_claim_rate": _mean([s.unsupported_claim_rate for s in inc]),
            "confident_wrong_rate": _mean([float(s.confident_wrong) for s in inc]),
            "distractor_hits": sum(s.distractor_hits for s in inc),
            "abstention": {
                "expected_and_abstained": len(
                    [s for s in inc if s.expected_abstain and s.abstained]
                ),
                "expected_not_abstained": len(
                    [s for s in inc if s.expected_abstain and not s.abstained]
                ),
                "unexpected_abstained": len(
                    [s for s in inc if not s.expected_abstain and s.abstained]
                ),
                "neither": len([s for s in inc if not s.expected_abstain and not s.abstained]),
            },
            "cost_spent_usd": round(sum(s.cost_spent_usd for s in cells), 6),
            "cost_attributed_usd": round(sum(s.cost_attributed_usd for s in cells), 6),
            "unknown_cost_records": sum(s.unknown_cost_records for s in cells),
            "mean_wall_ms": _mean([float(s.wall_ms) for s in cells if s.wall_ms is not None]),
            "attempts": sum(s.attempts for s in cells),
        }
    return out


def paired_deltas(scores: Sequence[CellScore]) -> list[dict[str, Any]]:
    """3b-3 and 4-3 per (task, repeat), only when propose_keys are identical."""
    by: dict[tuple[str, int, str], CellScore] = {
        (s.task_id, s.repeat_index, s.arm): s for s in scores
    }
    out: list[dict[str, Any]] = []
    for label, treat, base in PAIRS:
        for (task_id, repeat, arm), s_base in sorted(by.items()):
            if arm != base.value:
                continue
            s_treat = by.get((task_id, repeat, treat.value))
            if s_treat is None:
                continue
            entry: dict[str, Any] = {"pair": label, "task_id": task_id, "repeat_index": repeat}
            if sorted(s_treat.propose_keys) != sorted(s_base.propose_keys):
                entry["paired"] = False
                entry["reason"] = "propose_keys differ"
            elif not (s_treat.included and s_base.included):
                entry["paired"] = False
                entry["reason"] = f"excluded: {s_treat.exclusion or s_base.exclusion}"
            else:
                entry["paired"] = True
                for metric in ("precision", "recall"):
                    a, b = getattr(s_treat, metric), getattr(s_base, metric)
                    entry[f"delta_{metric}"] = None if a is None or b is None else round(a - b, 4)
                entry["delta_confident_wrong"] = int(s_treat.confident_wrong) - int(
                    s_base.confident_wrong
                )
                entry["delta_cost_spent_usd"] = round(
                    s_treat.cost_spent_usd - s_base.cost_spent_usd, 6
                )
                entry["delta_cost_attributed_usd"] = round(
                    s_treat.cost_attributed_usd - s_base.cost_attributed_usd, 6
                )
            out.append(entry)
    return out


# --------------------------------------------------------------------------- campaign


def cell_dirs(campaign_dir: Path) -> list[Path]:
    """Finalized cell dirs; a symlinked entry is never followed (a link could
    point a scorer at a run dir outside the campaign)."""
    return sorted(
        p
        for p in Path(campaign_dir).iterdir()
        if p.is_dir() and not p.is_symlink() and (p / "manifest.json").is_file()
    )


def score_campaign(campaign_dir: Path, corpus: Path, *, home: Path) -> dict[str, Any]:
    scores: list[CellScore] = []
    invalid: list[dict[str, str]] = []
    for run_dir in cell_dirs(campaign_dir):
        try:
            cell = read_cell(run_dir)
        except LedgerCorrupt as exc:
            invalid.append({"run_id": run_dir.name, "error": str(exc)[:200]})
            continue
        key = load_key(corpus, cell.arm_run.task_id)
        scores.append(score_cell(cell, key, home=home, corpus=corpus))
    return {
        "campaign_dir": str(campaign_dir),
        "cells": [asdict(s) for s in scores],
        "ledger_invalid": invalid,
        "per_arm": aggregate(scores),
        "paired": paired_deltas(scores),
        "pre_registration_notes": [
            "arm consensus is scored on the RAW summarizer verdict (enforced is also recorded)",
            "categories revert/planted/insufficient require ArmRun.containment == container (E1)",
            "containment basis: " + CONTAINMENT_BASIS,
            "plan tasks are scored without containment by user decision; plan keys are as "
            "readable as the others (testing critic) - recorded caveat",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eval/score.py", description=__doc__)
    parser.add_argument("--campaign-dir", required=True)
    parser.add_argument("--corpus", default="eval/corpus")
    parser.add_argument(
        "--home", default=None, help="default: the user's home (vendor memory paths)"
    )
    args = parser.parse_args(argv)
    home = Path(args.home) if args.home else Path.home()
    try:
        summary = score_campaign(Path(args.campaign_dir), Path(args.corpus), home=home)
    except GateRefused as exc:
        print(
            json.dumps({"status": "refused", "exit_code": EXIT_GATE, "error": str(exc)}),
            file=sys.stdout,
        )
        return EXIT_GATE
    except OSError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stdout)
        return EXIT_CONFIG
    print(json.dumps(summary, indent=2, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
