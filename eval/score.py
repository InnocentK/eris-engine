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
  is REFUSED (exit 7, no metrics, no override). A task whose ``task.json``
  says ``"scored": false`` is a PLUMBING task: its cells are reported under
  ``skipped`` (``"not a scored corpus task"``) and never enter a metric,
  and campaign discovery does not sweep it up in the first place.
  ``control`` and ``plan``
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
from eris.scan import build_patterns, fold, scan_run
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
    sha256_hex,
)
from eris.validate import UNHANDLED_CODES

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_GATE = 7
GATED_CATEGORIES: frozenset[TaskCategory] = frozenset(
    {TaskCategory.REVERT, TaskCategory.PLANTED, TaskCategory.INSUFFICIENT}
)
CONTAINMENT_ACCEPTED: frozenset[str] = frozenset({"container"})
CONTAINMENT_BASIS = (
    "policy declaration (`containment` in the policy file, recorded on the ArmRun); the "
    "scorer gates on the declaration and cannot verify it - M2c builds the container. "
    "Since 0.4.0 (H2) a declaration is REFUSED at policy load AND refused here when it "
    "appears in an older ledger, because no containment mechanism exists: until M2c, "
    "revert/planted/insufficient cannot be scored at all"
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
    # The widest a prediction may be and still count as POINTING AT a finding,
    # in lines. None = unbounded, which is the behaviour every key had before
    # this existed. Set it where overlap alone is too easy to satisfy - a short
    # prose document whose findings sit a few lines apart - and leave it unset
    # where a wide prediction is a legitimate way to name a defect, as on code.
    max_prediction_span: int | None = Field(default=None, ge=1)
    findings: list[KeyFinding] = Field(default_factory=list)
    distractors: list[Distractor] = Field(default_factory=list)
    scan: KeyScan = Field(default_factory=KeyScan)
    injection_canary: bool | None = None
    source_repo: str | None = None

    @model_validator(mode="after")
    def _finding_ids_are_unique(self) -> Key:
        """Coverage is a SET of finding ids and `fn` is a list length, so two
        findings sharing an id disagree by construction: the stop review
        reproduced two fully detected findings scoring recall 0.5, with one of
        them counted as a redundant repeat of the other."""
        ids = [f.id for f in self.findings]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(
                f"duplicate key finding id(s) {', '.join(dupes)}. Ids identify WHICH planted "
                "finding was caught, so a repeated id makes two findings indistinguishable and "
                "understates recall."
            )
        return self

    @model_validator(mode="after")
    def _control_has_nothing_to_find(self) -> Key:
        """A `control` key must plant nothing.

        `_control_block` reports a false-positive rate on the premise that a
        control has no findings, and nothing enforced that premise. A control key
        that carried findings turned matching predictions into true positives
        while the same block still called the result a clean-control FPR - an
        understated number with no warning attached (panel, 2026-08-30).
        """
        if self.category is TaskCategory.CONTROL and self.findings:
            raise ValueError(
                f"control task {self.task_id!r} has {len(self.findings)} key finding(s). "
                "A control is clean by definition: its whole purpose is to measure how often "
                "an arm invents a defect where there is none, and the control false-positive "
                "rate is computed on that premise."
            )
        return self


def task_is_scored(corpus: Path, task_id: str) -> bool:
    """``task.json``'s ``scored`` flag (default True). False marks a PLUMBING
    task - one that exercises the harness and is deliberately excluded from
    Phase 0 metrics. A missing or unparsable task.json is NOT a silent skip:
    it scores, and the key gate below fails on it if it is really broken."""
    path = Path(corpus) / task_id / "task.json"
    try:
        data = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return True
    # Read as data, deliberately NOT through eris.evidence.TaskSpec: importing
    # it would drag eris.verify (and subprocess) into the scorer, which the
    # import guard forbids. Only a literal `false` opts out; anything else is
    # a malformed task file and fails loudly on the key gate instead.
    return isinstance(data, dict) and data.get("scored", True) is not False


def keys_dir_for(corpus: Path) -> Path:
    """Where answer keys live: a SIBLING of the corpus, never inside it.

    A worker runs with cwd = `<corpus>/<task>/snapshot`, and E1 established that
    claude, codex and grok all read the snapshot's parent and sibling
    directories. A `key.json` in `<corpus>/<task>/` is therefore in the first
    place a worker looks. `scan.build_patterns` deliberately does NOT pattern
    match `must_mention` strings ("a correct answer must be allowed to say
    them"), so a worker that read the key and paraphrased it would score
    perfectly and never be marked contaminated.
    """
    return Path(corpus).resolve().parent / "keys"


def key_path_for(task_dir: Path) -> Path:
    """The answer key for one corpus task DIRECTORY.

    One resolver, used by the scorer and by `eval/run.py`. They built the path
    separately before, from different inputs - the scorer from `task_id`, the
    runner from the directory name - so a task whose directory did not match its
    `task_id` was scanned against one key and graded against another. `load_task`
    now refuses that mismatch outright; sharing the construction is what keeps
    the two from drifting again.
    """
    task_dir = Path(task_dir)
    return keys_dir_for(task_dir.parent) / f"{task_dir.name}.json"


def find_leaked_keys(task_dir: Path) -> list[Path]:
    """Every answer key sitting anywhere inside one corpus task directory.

    The whole subtree, not one exact path. Checking only
    `<task>/key.json` refused the file that had actually been there and nothing
    else - `files/key.json`, `snapshot/key.json` (the worker's own cwd), a
    nested copy, or `KEY.json` on a case-sensitive filesystem all passed
    (panel, 2026-08-30). Matched case-insensitively so the refusal does not
    depend on which filesystem the corpus is authored on.
    """
    task_dir = Path(task_dir)
    if not task_dir.is_dir():
        return []
    return sorted(
        p
        for p in task_dir.rglob("*")
        if p.is_file() and p.name.lower() in ("key.json", "answer.json")
    )


MAX_LEAK_SCAN_BYTES = 8 << 20


def find_key_content_in_task(task_dir: Path, canary: str) -> list[Path]:
    """Files inside a corpus task that contain the key's canary token.

    The name-based check is not enough, and its gap is not theoretical: a
    symlink in `files/` pointing at the key is DEREFERENCED by
    `shutil.copytree`, so the key's plaintext lands in `snapshot/` - the
    worker's own cwd - under whatever name the link had, and nothing called
    `key.json` exists to find. A symlinked directory inside the task is not
    walked by `rglob` at all (stop review, 2026-08-30).

    So this asks the question directly: does the token that appears ONLY in the
    answer key appear anywhere the worker can reach in this task? Symlinks are
    followed, because the worker follows them; already-visited real directories
    are skipped so a cycle cannot hang the check. Files above
    `MAX_LEAK_SCAN_BYTES` are reported as unreadable rather than skipped
    silently - a check that quietly gives up is worse than none.
    """
    task_dir = Path(task_dir)
    if not task_dir.is_dir() or not canary:
        return []
    needle = fold(canary)
    hits: list[Path] = []
    seen: set[tuple[int, int]] = set()
    # `Path.walk`, not `os.walk`: `eval/score.py` keeps an explicit import
    # allowlist asserted by an AST guard, and `os` carries `system`/`popen`/
    # `execv` - the exact things a read-only scorer must not be able to reach.
    for dirpath, dirnames, filenames in Path(task_dir).walk(follow_symlinks=True):
        try:
            st = dirpath.stat()
        except OSError:
            continue
        if (st.st_dev, st.st_ino) in seen:
            dirnames[:] = []
            continue
        seen.add((st.st_dev, st.st_ino))
        for name in sorted(filenames):
            f = dirpath / name
            try:
                if f.stat().st_size > MAX_LEAK_SCAN_BYTES:
                    hits.append(f)  # unreadable at this size: refuse, do not assume clean
                    continue
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if needle in fold(text):
                hits.append(f)
    return sorted(set(hits))


def require_real_key_file(path: Path) -> None:
    """The key must be a real file in the keys directory, not an alias to one.

    `is_file()` and `read_bytes()` both follow symlinks, so
    `eval/keys/t.json -> ../corpus/t/ground-truth.json` loads perfectly while
    the actual bytes sit inside the task tree the worker reads - under a name no
    filename check looks for (stop review, 2026-08-30). Moving the key out of
    the corpus means moving the BYTES, not the path that names them.
    """
    path = Path(path)
    # The symlink test is the whole check, and deliberately so. A "does it
    # resolve outside the keys directory" test sounds stronger and is dead: when
    # the file itself is not a link, `path.resolve().parent` and
    # `path.parent.resolve()` are equal for every shape, including a symlinked
    # keys directory. A guard that cannot fire reads like protection and is not.
    if path.is_symlink():
        raise GateRefused(
            f"{path} is a symlink to {path.readlink()}. The key must be a real file: a link "
            f"leaves the bytes wherever they were, which is what moving the key out of the "
            f"corpus was meant to change."
        )


def load_key(corpus: Path, task_id: str) -> Key:
    """Load `<corpus>/../keys/<task_id>.json`, refusing a key inside the corpus.

    The in-corpus refusal is the point: it makes the leak structurally
    impossible to reintroduce by accident, instead of relying on everyone
    remembering why the file moved.
    """
    leaked = find_leaked_keys(Path(corpus) / task_id)
    if leaked:
        raise GateRefused(
            f"{', '.join(str(p) for p in leaked)} inside the corpus, where a worker running in "
            f"{task_id}/snapshot can read it (E1: workers read the snapshot's parent, and "
            f"`snapshot/` IS the worker's cwd). Answer keys belong in {keys_dir_for(corpus)}/. "
            "Move it; do not score with it in place."
        )
    path = keys_dir_for(corpus) / f"{task_id}.json"
    require_real_key_file(path)
    try:
        key = Key.model_validate_json(path.read_bytes())
    except (OSError, ValidationError) as exc:
        raise GateRefused(f"key for {task_id!r} unusable: {exc!s:.200}") from exc
    _require_canary(key, task_id)
    return key


CANARY_PREFIX = "ERIS-KEY-CANARY-"
# The canary must identify WHICH key it came from, so a hit names the leak.
CANARY_MIN_SUFFIX = 8


def _require_canary(key: Key, task_id: str) -> None:
    """Every scored key must carry a canary in `scan.extra_strings`.

    Moving the key REDUCES exposure; it cannot eliminate it, because a worker
    that walks far enough up the tree can still find it. The canary converts
    "we cannot know" into a measurement: the token exists ONLY in the key, so a
    worker that emits it demonstrably read the key, and `scan.build_patterns`
    turns `extra_strings` into scan patterns over the ledger and blobs.

    It detects a VERBATIM read, not a paraphrase - stated plainly here so no
    report can claim the canary proves the key was not used. A worker that reads
    the key and restates its findings in its own words emits no canary and is
    reported `contaminated: false`. Absence of a hit is NOT evidence of a clean
    run, and `docs/EVAL-PLAN.md` says so where the numbers are published.

    The token must carry a per-task suffix. A bare `ERIS-KEY-CANARY-` would
    satisfy a prefix test while being shared by every key, so a hit would not say
    WHICH key was read - and a shared token is far likelier to appear in the
    repository by accident, where `build_patterns` drops it.
    """
    if not any(
        s.startswith(CANARY_PREFIX) and len(s) >= len(CANARY_PREFIX) + CANARY_MIN_SUFFIX
        for s in key.scan.extra_strings
    ):
        raise GateRefused(
            f"key for {task_id!r} has no {CANARY_PREFIX}<suffix> token of at least "
            f"{CANARY_MIN_SUFFIX} further characters in scan.extra_strings. Without it a key "
            "read cannot be detected at all, and the quality metrics would be unfalsifiable."
        )


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


def _last_proposal_per_worker(view: LedgerView, arm_run: ArmRun) -> list[Proposal]:
    """One proposal per worker: the LAST recorded.

    A worker can record a proposal more than once in a cell. A crash between
    `proposal.recorded` and `stage.finished` leaves the stage unfinished, so
    resume does not trust it and re-runs that worker (`arms.load_prior`) -
    leaving two rows for one worker. `predicted_findings` iterates every row, so
    the duplicate would count that worker's findings twice and inflate tp/fp for
    EVERY arm, not just `single`. `arms.load_prior` already keys proposals by
    worker id; the scorer is the only reader that did not.
    """
    by_worker: dict[str, Proposal] = {}
    for prop in view.records("proposal.recorded", Proposal):
        by_worker[prop.worker_id] = prop
    # ...and only workers the FINAL arm spec actually used. Resuming a run id
    # with a different `--panel` leaves proposals from the old panel in the
    # ledger; scoring them would credit the arm with a worker it did not run.
    panel = set(arm_run.panel)
    return [p for w, p in by_worker.items() if w in panel]


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
        proposals=_last_proposal_per_worker(view, arm_runs[-1]),
        raw=raws[-1] if raws else None,
        enforced=enforced[-1] if enforced else None,
        scan=scans[-1] if scans else None,
        manifest=manifest,
        started_ts=started[0].ts if started else None,
        finished_ts=finished[-1].ts if finished else None,
    )


def require_inputs_unchanged(cell: CellData, corpus: Path) -> None:
    """The task and key on disk must be the ones this cell was measured against.

    `run.started` records `task_sha256` and `key_sha256`. The scorer REREADS
    both files, so without this check the answer key can be edited after
    execution: delete a planted finding the run missed and recall rises, flip
    `scored` to false and the whole task disappears into `skipped`. Nothing in
    the output would say the files had moved (stop review, 2026-08-30).

    A ledger written before 0.4.3 carries neither hash. Those cells are reported
    `inputs_bound: false` rather than refused - they are real runs - but the
    absence is stated in the summary instead of reading like a pass.
    """
    started = cell.view.payloads("run.started")
    rec = started[0] if started else {}
    task_id = cell.arm_run.task_id
    task_file = Path(corpus) / task_id / "task.json"
    key_file = keys_dir_for(corpus) / f"{task_id}.json"
    for label, recorded, path in (
        ("task.json", rec.get("task_sha256"), task_file),
        ("key", rec.get("key_sha256"), key_file),
    ):
        if recorded is None:
            continue
        current = sha256_hex(path.read_bytes()) if path.is_file() else None
        if current != recorded:
            raise GateRefused(
                f"{path} changed after {cell.run_dir.name} ran: recorded {recorded[:12]}, "
                f"now {(current or 'missing')[:12]}. The scorer rereads the {label}, so an edit "
                f"between running and scoring silently rewrites what the run is measured "
                f"against."
            )


def inputs_are_bound(cell: CellData) -> bool:
    """Whether this cell recorded the hashes `require_inputs_unchanged` checks."""
    started = cell.view.payloads("run.started")
    return bool(started) and started[0].get("task_sha256") is not None


def require_manifest_agrees(cell: CellData) -> None:
    """The finalized manifest must describe the ledger that is actually there.

    The manifest carries `event_count`, `last_sha256` (the sha256 of the last
    event LINE) and `torn_tail_truncated`, and the scorer merely loaded it -
    every field unchecked. A truncated finalized ledger, or one with events
    appended behind the manifest, was read as sound (stop review, 2026-08-30).

    `LedgerView` already validates the hash chain, so this is not a second
    integrity check of the same thing: it is the check that the SEAL matches
    what was sealed.
    """
    m = cell.manifest
    if not m:
        return
    if m.get("torn_tail_truncated"):
        raise GateRefused(
            f"{cell.run_dir.name}: the manifest records a torn tail. A finalized run whose "
            "last event was cut off is not a complete record of what happened."
        )
    count = m.get("event_count")
    if isinstance(count, int) and count != len(cell.view.events):
        raise GateRefused(
            f"{cell.run_dir.name}: the manifest seals {count} events, the ledger holds "
            f"{len(cell.view.events)}. Events behind a manifest are events nobody sealed."
        )
    last = m.get("last_sha256")
    if isinstance(last, str) and last:
        lines = (cell.run_dir / "events.jsonl").read_bytes().splitlines()
        if not lines or sha256_hex(lines[-1]) != last:
            raise GateRefused(
                f"{cell.run_dir.name}: the manifest's last_sha256 does not match the ledger's "
                "final event. The seal is not of this file."
            )


def run_health(cell: CellData) -> dict[str, Any]:
    """Failures the cell recorded about ITSELF, which scoring ignored entirely.

    `run.error` (a modified snapshot, a scratch directory that would not clean
    up) and `manifest.post_scan_errors` are written precisely because something
    went wrong, and a clean-scanned cell carrying one was still contributing
    quality numbers. Counted here and turned into an exclusion by `score_cell`.

    `orphan_invocations` is separate and cheap: cost totals are derived from
    `cost` records alone, and `attempts` is their count, so an
    `invocation.finished` whose cost record never landed reads as zero cost and
    zero attempts rather than as unknown. The two appends are separate
    statements, so a crash between them is possible even though every ledger in
    this repository pairs them 1:1.
    """
    errors = [str(p.get("kind", "run.error")) for p in cell.view.payloads("run.error")]
    post = cell.manifest.get("post_scan_errors") or []
    finished = cell.view.payloads("invocation.finished")
    inv = {p.get("invocation_id") for p in finished} - {None}
    costed = {p.get("invocation_id") for p in cell.view.payloads("cost")} - {None}
    return {
        "run_errors": sorted(errors),
        "post_scan_errors": len(post) if isinstance(post, list) else 0,
        "orphan_invocations": len(inv - costed),
        # Calls this cell actually MADE, as opposed to replayed from cache. An
        # arm can reach the end of its steps having spawned nothing: b-s3b's
        # `indep_verify_iter` replayed all 12 of its invocations from
        # `indep_verify`, adjudication included, because the judge requested no
        # evidence and `adjudicate_iter` therefore broke out of its loop on the
        # first pass. A delta between such an arm and its base compares a cell
        # with a copy of itself; `paired_deltas` refuses it.
        "executed_invocations": sum(
            1 for p in finished if not p.get("reused_from") and p.get("status") == "ok"
        ),
        # Calls the cell ATTEMPTED itself, counted from `invocation.spawned`,
        # which is written only when a process group is actually started.
        #
        # Distinct from `executed_invocations`, which requires status ok: an arm
        # whose calls all failed, or were aborted mid-flight by the vendor's own
        # cap, has zero of THOSE while having spawned, run and paid for work.
        # Labelling it a no-op replay would overclaim.
        #
        # And distinct from "non-replay `invocation.finished`", which was the
        # first definition and counts calls that were never made: `retry.py`
        # prechecks the budget "before EVERY spawn ... nothing is spawned on a
        # trip" and then still records an attempt, so an Eris budget trip leaves
        # a finished record for a call that never ran. Counting it would say the
        # treatment tried, in precisely the case where it was refused before
        # trying. No such trip occurs in b-s0/b-s1/b-s3/b-s3b - spawned and
        # non-replay-finished agree on every cell there - so this is a latent
        # defect, fixed on the code rather than on an observation.
        "attempted_invocations": len(cell.view.of_kind("invocation.spawned")),
        "replayed_invocations": sum(1 for p in finished if p.get("reused_from")),
    }


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


def _matches(pred: Predicted, kf: KeyFinding, tolerance: int, max_span: int | None = None) -> bool:
    if pred.path is None or pred.path != kf.path:
        return False
    if pred.line_start is None:
        # A prediction that names no line is not a location claim, and the key
        # match is defined as a location overlap. Defaulting the missing line to
        # 1 silently turned "something is wrong in this file" into a hit on any
        # finding at the top of it - mechanically reproduced by the stop review:
        # a bare path scored precision and recall 1.0 against a line-1 key.
        return False
    ps = pred.line_start
    pe = pred.line_end or ps
    # Overlap alone is symmetric, so a prediction spanning a whole document
    # overlaps every finding in it: one sentence across a 47-line plan covered
    # all three planted findings and scored recall 1.0 for identifying nothing.
    # `max_prediction_span` bounds that, and it is a property of the KEY rather
    # than a global rule, because the right answer differs by task. On a plan
    # document a sweep is meaningless. On a CODE defect it is not: a model that
    # reports the whole function containing a four-line fix hunk has located
    # the defect, and a global bound would count that as a false positive AND a
    # miss - the same double penalty a brittle `must_mention` inflicts.
    # Unset means unbounded, so no key that does not ask for this is affected.
    if max_span is not None and (pe - ps + 1) > max_span:
        return False
    if not _overlap(ps, pe, kf.line_start, kf.line_end, tolerance):
        return False
    text = pred.description.lower()
    return all(m.lower() in text for m in kf.must_mention)


@dataclass
class Matching:
    """Two questions with two different denominators, kept apart.

    RECALL asks about key findings: how many planted defects did the run
    identify. Its numerator is `covered` - key findings named by AT LEAST ONE
    prediction. It is a COVERAGE, not an assignment, because a run that names
    two defects in one sentence found two defects, and because coverage cannot
    be inflated by saying the same thing twice.

    PRECISION asks about predictions: of the distinct claims made, how many were
    true. Its numerator is `tp`, the number of DISTINCT true claims - predictions
    matching the same set of key findings are one claim repeated, so the first
    counts and the rest are `redundant`.

    An earlier version credited both from a single maximum matching, which made
    both wrong in opposite directions: one prediction naming two key findings
    scored recall 0.5, and REPEATING that prediction scored 1.0, because each
    copy was assigned to a different key finding. A run was rewarded for
    repeating itself. (Panel, 2026-08-30, mechanically reproduced.)
    """

    covered: int
    tp: int
    fp: int
    fn: int
    distractor_hits: int
    matched_ids: list[str]
    fp_severities: list[str]
    # Predictions that matched exactly the key findings some earlier prediction
    # already claimed: the same claim said again. Not false - what they say is
    # true - so they are NOT charged as false positives and NOT entered in
    # `fp_severities`; a run is not "confidently wrong" for repeating something
    # correct. Counted and reported rather than dropped, because dropping them
    # shrank precision's denominator silently: ten copies of one true finding
    # beside one false one used to read 0.909 instead of 0.5.
    redundant: int = 0

    @property
    def precision(self) -> float | None:
        """Of the DISTINCT true claims and the false ones, the fraction true.

        Asymmetric on purpose, and the asymmetry is stated because it is not
        obvious: repeated TRUE claims collapse into one `tp`, while repeated
        FALSE claims each count in `fp`. Collapsing true repeats is what stops a
        run diluting its false positives by restating a correct finding; not
        collapsing false ones costs the run nothing it did not say, and there is
        no incentive to exploit. `micro_with_redundant` in the aggregate puts the
        repeats back so a reader can overrule the choice.
        """
        return None if self.tp + self.fp == 0 else self.tp / (self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return None if self.covered + self.fn == 0 else self.covered / (self.covered + self.fn)


def match_findings(predicted: Sequence[Predicted], key: Key) -> Matching:
    # Which key findings each prediction names. No assignment is made: a
    # prediction may legitimately name several, and several may name the same
    # one. Iterative and flat - the previous augmenting-path search recursed
    # once per key finding and raised RecursionError on a key of >1000 findings
    # (panel, mechanically reproduced), a limit nothing validated.
    adj = [
        frozenset(
            kf.id
            for kf in key.findings
            if _matches(pred, kf, key.line_tolerance, key.max_prediction_span)
        )
        for pred in predicted
    ]
    covered: set[str] = set()
    for ids in adj:
        covered |= ids

    claimed: set[frozenset[str]] = set()
    tp = 0
    fp = 0
    redundant = 0
    fp_sev: list[str] = []
    distractor_hits = 0
    for pred, ids in zip(predicted, adj, strict=True):
        if ids:
            if ids in claimed:
                redundant += 1
            else:
                claimed.add(ids)
                tp += 1
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
        len(covered),
        tp,
        fp,
        len(key.findings) - len(covered),
        distractor_hits,
        sorted(covered),
        fp_sev,
        redundant,
    )


# --------------------------------------------------------------------------- scoring


@dataclass
class CellScore:
    run_id: str
    task_id: str
    arm: str
    # The `single` arm expands to ONE CELL PER PANEL WORKER, and every one of
    # them carries `arm: "single"`. Aggregated by arm alone, three separate
    # single-model baselines became one number in which a strong lineage masks a
    # weak one, and `single` carried three times the weight of every other arm
    # in the support check (stop review, 2026-08-30). `arm_key` is what the
    # aggregate groups on.
    panel: list[str]
    arm_key: str
    repeat_index: int
    category: str
    included: bool
    exclusion: str | None
    verdict: str | None
    verdict_basis: str | None
    precision: float | None
    recall: float | None
    covered: int
    tp: int
    fp: int
    fn: int
    redundant: int
    distractor_hits: int
    # the severities of the FALSE positives, so a report can ask about severe
    # ones directly, rather than through a combined flag that also fires on a
    # wrong ACCEPT and so answers a different question
    fp_severities: list[str]
    unsupported_claim_rate: float | None
    # the counts behind that rate. Without them the aggregate could only average
    # per-cell ratios, which answers a different question than "of every ruling,
    # how many were downgraded" and drops cells with no rulings entirely
    downgrades_n: int
    rulings_n: int
    # failures the cell recorded about itself, and invocations whose cost record
    # never landed (which would otherwise read as zero cost, zero attempts)
    run_errors: list[str]
    post_scan_errors: int
    orphan_invocations: int
    downgrades: int
    # SPLIT deliberately (user decision, 2026-08-30). `wrong_accept` is
    # mechanical: the engine said ACCEPT where the key says it must not, and
    # nothing a model writes about itself can move it. `severe_false_positive`
    # reads the model's OWN severity label on its OWN claim, so an arm can lower
    # it by grading its claims more mildly with no change in what it got right.
    # They were one field, `confident_wrong`, and the pre-registered
    # build/don't-build rule read that field - meaning one of the two branches
    # authorising a whole orchestrator could be satisfied by a tone change. The
    # rule now reads `wrong_accept`; the severity number is reported beside it
    # and is not load-bearing.
    wrong_accept: bool
    wrong_reject: bool
    severe_false_positive: bool
    abstained: bool
    expected_abstain: bool
    cost_spent_usd: float
    cost_attributed_usd: float
    executed_invocations: int
    attempted_invocations: int
    replayed_invocations: int
    cost_by_stage_spent: dict[str, float]
    cost_by_stage_attributed: dict[str, float]
    unknown_cost_records: int
    wall_ms: int | None
    attempts: int
    propose_keys: list[str]
    # C1: propose key -> stdout blob shas of the KEPT proposal. Key equality
    # alone does NOT mean two arms shared proposals - the key excludes worker
    # output, and codex/agy report no `model_executed` so `Cache.lookup` refuses
    # them and every arm re-spawns them with different text. Pairing requires
    # byte-identical output, which is the only direct evidence of a shared world.
    propose_blobs: dict[str, list[str]]
    # M1: engine validator findings on the FINAL adjudication. `None` means the
    # cell has no adjudication to judge - never conflate that with "clean".
    validator_errors: int | None
    validator_codes: dict[str, int]
    # "acted" (exact) | "coarse_codes" (>=1 finding lacked `acted`) | None
    validator_basis: str | None
    contaminated: bool
    scan_incomplete: bool
    rescan_contaminated: bool
    containment: str | None
    containment_basis: str = CONTAINMENT_BASIS
    missing_cells: list[dict[str, str]] = field(default_factory=list)


def _propose_blobs(cell: CellData) -> dict[str, list[str]]:
    """Propose key -> the stdout blob shas of the proposal that was KEPT.

    Blob equality is the real evidence that two arms shared a world: equal shas
    mean byte-identical worker output. `reused: True` is NOT sufficient - a
    treatment arm can replay a cached proposal A while the base arm was run with
    `--fresh` and produced B, so the treatment "reused" something the base never
    used. It is also not necessary: two spawns that produced identical bytes did
    share a world.

    LAST event per key wins. A key can finish more than once: on resume a stage
    whose blob does not re-hash is NOT trusted and the worker is re-run
    (`arms.load_prior`), so a ledger can hold the stale outcome ahead of the
    re-spawn that replaced it.
    """
    last: dict[str, dict[str, Any]] = {}
    for p in cell.view.payloads("stage.finished"):
        if p.get("stage") == "propose" and "idempotency_key" in p:
            last[str(p["idempotency_key"])] = p
    out: dict[str, list[str]] = {}
    for k, p in last.items():
        if k in set(cell.arm_run.propose_keys) and p.get("ok"):
            blobs = p.get("blobs")
            out[k] = sorted(str(b) for b in blobs) if isinstance(blobs, list) else []
    return out


def _matched_findings(cell: CellData) -> list[dict[str, Any]] | None:
    """The findings of the cell's FINAL adjudication, or None if there are none
    to judge. One extractor, so `_validator_errors` and `_validator_basis` can
    never disagree about WHICH findings they are describing."""
    final_id = cell.arm_run.final_adjudication_id
    if final_id is None:
        return None
    matched = [
        p for p in cell.view.payloads("validate.findings") if p.get("adjudication_id") == final_id
    ]
    if not matched:
        return None
    # The LAST event per id wins. Adjudication ids are deterministic
    # (`stages.py`: `adj-{prefix}`), so a crash after `validate.findings` but
    # before `stage.finished` leaves a stale event that a clean re-run reproduces
    # under the SAME id. Taking every match would let the abandoned attempt
    # exclude the outcome that replaced it.
    return [f for f in (matched[-1].get("findings") or []) if isinstance(f, dict)]


def _validator_basis(cell: CellData) -> str | None:
    """How `_validator_errors` classified this cell's findings.

    `"acted"` - EVERY finding records `Finding.acted`, so the classification is
    exact. `"coarse_codes"` - at least one does not, so at least one finding was
    classified by the coarse `UNHANDLED_CODES` fallback, which calls every
    `REF_*` handled and therefore UNDER-REPORTS malformation.

    Conservative by ALL, not ANY: classification is per FINDING, so a single
    event mixing findings with and without `acted` has some classified exactly
    and some coarsely. Asking "does any finding have `acted`" reported such a
    cell as exact and hid the coarse ones, bypassing the comparison gate.
    """
    findings = _matched_findings(cell)
    if not findings:
        return None
    return "acted" if all("acted" in f for f in findings) else "coarse_codes"


def _validator_errors(cell: CellData) -> tuple[int | None, dict[str, int]]:
    """(error count, per-code counts) for the cell's FINAL adjudication.

    Joined on `adjudication_id == ArmRun.final_adjudication_id`, not "the last
    event": `adjudicate_iter` writes one `validate.findings` per judge call, so
    a malformed early iteration that was superseded by a clean one must not
    count - and a clean early iteration must not excuse a malformed final one.
    Matching by id also survives resume, which replays a stored adjudication
    rather than re-deriving it.

    An error counts when the engine did NOT act on it - `Finding.acted is
    False` - WHATEVER its code. `validate.UNHANDLED_CODES` is only the fallback
    for legacy ledgers that carry no `acted` at all; on those it classifies by
    code, calling every `REF_*` handled and so UNDER-reporting.

    An earlier version of this docstring said "only codes in UNHANDLED_CODES
    count" and named REF_NOT_MECHANICAL as one that must never exclude, because
    excluding on it "would delete the denominator for normal, already-handled
    behaviour". That described the fallback, not the behaviour: b-s3b excluded a
    cell on a REF_NOT_MECHANICAL carrying `acted: false`, which is the code
    working as designed and the docstring being wrong. Across every ledger in
    this repository, REF_NOT_MECHANICAL appears 13 times - 11 legacy (no
    `acted`), 1 acted, 1 unacted.

    Since 2026-09-04 the count no longer excludes anything; it is reported as
    `validator.malformed_rate`. Findings are counted as a MULTISET - three
    `CLAIM_MISSING`s are three errors, not one.

    Returns `None` when the cell has no final adjudication, or none of its
    findings events match it. A cell with no adjudication has not been shown to
    be clean, and must never be reported as if it were.
    """
    findings = _matched_findings(cell)
    if findings is None:
        return None, {}
    # The LAST matching event wins. Adjudication ids are deterministic
    # (`stages.py`: `adj-{prefix}`), so a crash after `validate.findings` but
    # before `stage.finished` leaves a stale event that a clean re-run reproduces
    # under the SAME id. Summing every match would let the abandoned attempt
    # exclude the outcome that replaced it - the attempt-vs-outcome error again.
    counts: dict[str, int] = {}
    for f in findings:
        if f.get("severity") == "error":
            code = str(f.get("code", "?"))
            if "acted" in f:
                # The producer told us. Classifying by CODE is wrong:
                # `REF_MISSING` downgrades a SUPPORTED/REFUTED ruling but is
                # INERT on a CONTESTED or UNSUPPORTED one, since only those
                # two statuses are downgraded - so the same code is handled
                # in one ruling and ignored in the next.
                if f.get("acted"):
                    continue
            elif code not in UNHANDLED_CODES:
                # Legacy ledgers (<= 0.4.1) carry no `acted`. Fall back to
                # the code set, which is coarser: it calls every `REF_*`
                # handled and so under-reports on those ledgers.
                continue
            counts[code] = counts.get(code, 0) + 1
    return sum(counts.values()), dict(sorted(counts.items()))


def arm_key(arm: str, panel: Sequence[str]) -> str:
    """How an arm is named in the aggregate.

    `single` is not one arm: it is one cell per panel worker, each a different
    model lineage answering alone, and pooling them answers no question anyone
    asked. Reported as `single:<worker>` so the three baselines stay three.
    Every other arm names its whole panel by design and keeps its plain name.
    """
    return f"{arm}:{panel[0]}" if arm == Arm.SINGLE.value and len(panel) == 1 else arm


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
    # H2: a policy declaring `containment: container` is refused at LOAD, but a
    # ledger written BEFORE that refusal still carries the declaration and the
    # gate above would accept it. No container exists anywhere in the tree, so
    # such a declaration is false by construction. Checked AFTER the scan gate
    # so neither refusal makes the other unreachable.
    if ar.category in GATED_CATEGORIES and ar.containment is not None:
        raise GateRefused(
            f"{cell.run_dir.name}: ArmRun declares containment={ar.containment!r}, but no "
            "containment mechanism is implemented (H2) - the declaration cannot be true. "
            "This ledger was written by a policy that predates the load-time refusal."
        )
    rescanned = rescan(cell, key, home=home, corpus=corpus)
    contaminated = ar.contaminated or (recorded_scan.contaminated if recorded_scan else False)
    scan_incomplete = (
        bool(recorded_scan and recorded_scan.scan_incomplete) or rescanned.scan_incomplete
    )
    validator_errors, validator_codes = _validator_errors(cell)
    health = run_health(cell)
    exclusion: str | None = None
    if health["run_errors"] or health["post_scan_errors"]:
        # The cell recorded a failure about ITSELF - a modified snapshot, a
        # scratch dir that would not clean up, an error raised after the seal -
        # and scoring looked at none of them, so a clean-scanned cell with a
        # `snapshot_modified` error still contributed quality numbers even
        # though its run exited non-zero (stop review, 2026-08-30). Excluding is
        # safe to do late: the support check blocks any comparison whose arms
        # lost different cells.
        exclusion = "run_error"
    elif recorded_scan is None:
        exclusion = "no_scan"  # plumbing only: never a quality metric
    elif contaminated or rescanned.contaminated or scan_incomplete:
        exclusion = "contaminated"
    elif any(m.reason.startswith("budget") for m in ar.missing_cells):
        exclusion = "missing"
    elif ar.status is not ArmStatus.COMPLETE or (
        ar.arm is not Arm.SINGLE and cell.enforced is None
    ):
        exclusion = "incomplete"
    elif ar.final_adjudication_id is not None and validator_errors is None:
        # The cell HAS a final adjudication but no findings event for it, so the
        # engine's verdict on that record is unknown. Unknown is not clean: the
        # docstring above says so, and this is the branch that makes it true
        # rather than merely stated. (`final_adjudication_id is None` - arm 1,
        # which has no judge - stays scoreable; there is no adjudication to
        # judge, which is different from one we cannot vouch for.)
        exclusion = "validator_unknown"
    # A validator ERROR no longer excludes the cell (user decision 2026-09-04,
    # after a three-family panel; see
    # `docs/decisions/2026-09-04-validator-errors-stop-excluding-cells.md`).
    # M1 excluded it on the reasoning that "a record the engine judged
    # incoherent is not evidence". The trigger for that exclusion is
    # `Finding.acted == False` - the engine DECLINING to change anything - so
    # the exclusion gave a finding the power to delete a cell in exactly the
    # case where the recorded protocol decision denied it any power over the
    # verdict. It is also post-treatment selection: whether an arm's judge emits
    # a malformed adjudication is an OUTCOME of that arm, so dropping those
    # cells measures the arm on a cleaner subsample of its own work.
    #
    # Measured, on b-s3b: the one excluded cell was ITSELF an arm-4 failure
    # (REVISE on an ACCEPT-expected control). Removing the exclusion moved arm
    # 4's `wrong_reject_rate` 0.333 -> 0.5 and unblocked the pooled comparison.
    # The exclusion was hiding a failure of the arm under test.
    #
    # `validator_unknown` above is NOT affected: that is an absent record, not
    # an arm outcome, and nothing has been shown to be clean.
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
    wrong_accept = exclusion is None and (
        verdict is Verdict.ACCEPT and Verdict.ACCEPT not in key.expected_verdict
    )
    # The other direction, which `wrong_accept` cannot see by construction: a
    # verdict that REFUSES work the key says should have been accepted.
    # b-s3b's arm 4 returned REVISE on all four tasks - right on the two plan
    # tasks, wrong on both controls - and scored a perfect `wrong_accept` of 0
    # for it, because an arm that never accepts can never wrongly accept. The
    # pre-registered rule reads `wrong_accept`, so on a corpus that is half
    # ACCEPT-expected a constant-REVISE judge satisfies it while being wrong
    # half the time. REJECT and ESCALATE count with REVISE: all three refuse the
    # work. ABSTAIN does not - it declines to judge rather than claiming a
    # defect - and is handled by `expected_abstain`.
    wrong_reject = exclusion is None and (
        verdict in (Verdict.REVISE, Verdict.ESCALATE, Verdict.REJECT)
        and Verdict.ACCEPT in key.expected_verdict
        and verdict not in key.expected_verdict
    )
    severe_false_positive = exclusion is None and any(
        s in ("high", "critical") for s in matching.fp_severities
    )
    wall: int | None = None
    if cell.started_ts and cell.finished_ts:
        wall = int((parse_ts(cell.finished_ts) - parse_ts(cell.started_ts)).total_seconds() * 1000)
    return CellScore(
        run_id=cell.run_dir.name,
        task_id=ar.task_id,
        arm=ar.arm.value,
        panel=list(ar.panel),
        arm_key=arm_key(ar.arm.value, ar.panel),
        repeat_index=ar.repeat_index,
        category=ar.category.value,
        included=exclusion is None,
        exclusion=exclusion,
        verdict=verdict.value if verdict else None,
        verdict_basis=basis,
        precision=matching.precision if exclusion is None else None,
        recall=matching.recall if exclusion is None else None,
        covered=matching.covered,
        tp=matching.tp,
        fp=matching.fp,
        fn=matching.fn,
        redundant=matching.redundant,
        fp_severities=list(matching.fp_severities),
        distractor_hits=matching.distractor_hits,
        unsupported_claim_rate=rate,
        run_errors=list(health["run_errors"]),
        post_scan_errors=int(health["post_scan_errors"]),
        orphan_invocations=int(health["orphan_invocations"]),
        executed_invocations=int(health["executed_invocations"]),
        attempted_invocations=int(health["attempted_invocations"]),
        replayed_invocations=int(health["replayed_invocations"]),
        downgrades_n=enforced.downgrades if enforced is not None else 0,
        rulings_n=len(enforced.rulings) if enforced is not None else 0,
        downgrades=enforced.downgrades if enforced else 0,
        wrong_accept=wrong_accept,
        wrong_reject=wrong_reject,
        severe_false_positive=severe_false_positive,
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
        propose_blobs=_propose_blobs(cell),
        validator_errors=validator_errors,
        validator_codes=validator_codes,
        validator_basis=_validator_basis(cell),
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


def _rates(inc: Sequence[CellScore], which: Literal["precision", "recall"]) -> dict[str, Any]:
    """Pooled and per-cell rates side by side, plus the denominators.

    `micro` pools the counts: EVAL-PLAN's "per-finding" reading, and the one
    "catch rate" means in the pre-registered decision rule - of every planted
    finding, how many were caught. `macro` averages the per-cell rates, which
    weighs a one-finding task equally with a ten-finding one.

    `cells_counted` is reported because macro SILENTLY DROPS cells whose rate is
    None. For precision that is every cell where the arm predicted nothing: an
    arm that stays silent half the time would otherwise have its precision
    computed only over the half where it spoke, and silence would be free. The
    count makes that visible instead; `silent_cells` names it outright.
    """
    # Different numerators on purpose: precision counts distinct true CLAIMS,
    # recall counts key FINDINGS that were covered. They coincided only while a
    # single matching produced both, which is exactly what made both wrong.
    tp = sum(s.tp if which == "precision" else s.covered for s in inc)
    other = sum(s.fp for s in inc) if which == "precision" else sum(s.fn for s in inc)
    per_cell = [getattr(s, which) for s in inc]
    out: dict[str, Any] = {
        "micro": round(tp / (tp + other), 4) if tp + other else None,
        "macro": _mean(per_cell),
        "cells_counted": len([v for v in per_cell if v is not None]),
        "cells_included": len(inc),
    }
    if which == "precision":
        red = sum(s.redundant for s in inc)
        # The per-utterance rate: the same pooled precision with redundant
        # repeats back in the denominator. `Matching.precision` leaves them out
        # deliberately - repeating a true finding is not asserting a false one -
        # and this is the number that makes that choice reversible by a reader
        # who disagrees, rather than something only the code knows.
        out["micro_with_redundant"] = (
            round(tp / (tp + other + red), 4) if tp + other + red else None
        )
        out["silent_cells"] = len([s for s in inc if s.tp + s.fp + s.redundant == 0])
    return out


def _control_block(inc: Sequence[CellScore]) -> dict[str, Any]:
    """What the clean controls measure, which precision and recall cannot.

    A control task has NO planted finding, so its recall is undefined and it
    contributes nothing to the pooled catch rate. Its whole purpose is the
    opposite question - does the arm invent a defect in code that has none - and
    that answer was reaching the summary only as a diluted term inside an
    overall precision, where a high catch rate on the planted tasks can hide it.

    Reported as a RATE over control cells (how often the arm flagged anything at
    all) as well as a mean count, because one arm that fires once on every
    control and one that fires ten times on a tenth of them are different
    failures and sum(fp) alone cannot tell them apart.
    """
    ctl = [s for s in inc if s.category == TaskCategory.CONTROL.value]
    # One shape whether or not there are controls, so a report can read every
    # field without a KeyError on an arm that happened to score none. `None`
    # says "not measured"; it is never rounded down to a reassuring 0.0.
    if not ctl:
        return {
            "cells": 0,
            "flagged_cells": None,
            "fpr": None,
            "mean_false_positives": None,
            "severe_cells": None,
        }
    flagged = len([s for s in ctl if s.fp > 0])
    return {
        "cells": len(ctl),
        "flagged_cells": flagged,
        "fpr": round(flagged / len(ctl), 4),
        "mean_false_positives": round(sum(s.fp for s in ctl) / len(ctl), 4),
        # Computed from the FALSE-POSITIVE severities directly, not from
        # the combined flag that also fires on a wrong ACCEPT verdict, which
        # answers a different question than "invented a severe defect in clean
        # code". Same severity caveat as `severe_false_positive_rate`: this is
        # the model's own label on its own claim.
        "severe_cells": len(
            [s for s in ctl if any(v in ("high", "critical") for v in s.fp_severities)]
        ),
    }


def _by_category(inc: Sequence[CellScore]) -> dict[str, dict[str, Any]]:
    """The same rates, stratified.

    Pooled over every category, an arm's headline moves with the CATEGORY MIX
    of the cells that survived exclusion - and cells are excluded per arm, for
    contamination, budget and validator findings, so the mix is not guaranteed
    equal across the arms being compared. An arm can win on the pooled number
    while losing on each category it shares with the other. Stratifying makes
    that visible; it does not fix it, and nothing here re-weights or pools the
    strata back into a single "adjusted" figure, which would be a new choice
    hidden inside a number.
    """
    return {
        cat: {
            "cells": len(cells),
            "precision": _rates(cells, "precision"),
            "recall": _rates(cells, "recall"),
            "wrong_accept_rate": _mean([float(s.wrong_accept) for s in cells]),
            "wrong_reject_rate": _mean([float(s.wrong_reject) for s in cells]),
            "severe_false_positive_rate": _mean([float(s.severe_false_positive) for s in cells]),
            "distractor_hits": sum(s.distractor_hits for s in cells),
            "redundant": sum(s.redundant for s in cells),
        }
        for cat in sorted({s.category for s in inc})
        for cells in ([s for s in inc if s.category == cat],)
    }


def aggregate(scores: Sequence[CellScore]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    # grouped on `arm_key`, so the three `single` lineages stay three
    for arm in sorted({s.arm_key for s in scores}):
        cells = [s for s in scores if s.arm_key == arm]
        inc = [s for s in cells if s.included]
        out[arm] = {
            "cells": len(cells),
            "included": len(inc),
            "excluded": {
                k: len([s for s in cells if s.exclusion == k])
                for k in (
                    "contaminated",
                    "missing",
                    "incomplete",
                    "ledger_invalid",
                    "no_scan",
                    "run_error",
                    # kept as a schema key so a reader diffing summaries sees
                    # it go to zero rather than vanish; `score_cell` no longer
                    # assigns it (2026-09-04) and it is always 0 on a ledger
                    # scored by this version
                    "validator_errors",
                    "validator_unknown",
                )
            },
            # M1: first-class, not a footnote. `malformed` counts cells whose
            # FINAL adjudication carried an error-severity validator finding;
            # `unknown` counts cells with no adjudication to judge. An arm with
            # a higher malformed rate has not earned a better precision.
            "validator": {
                "malformed": len([s for s in cells if s.validator_errors]),
                "unknown": len([s for s in cells if s.validator_errors is None]),
                "errors": sum(s.validator_errors or 0 for s in cells),
                # a RATE, not just counts: 1-of-1 and 2-of-100 are not comparable
                # as counts, and EVAL-PLAN's rule is stated in terms of a rate
                "malformed_rate": (
                    round(len([s for s in cells if s.validator_errors]) / len(cells), 4)
                    if cells
                    else None
                ),
                "codes": {
                    c: sum(s.validator_codes.get(c, 0) for s in cells)
                    for c in sorted({c for s in cells for c in s.validator_codes})
                },
            },
            # EVAL-PLAN pre-registers "per-finding precision AND recall", which
            # is the POOLED (micro) rate: every key finding counts once,
            # wherever it lives. The previous single number was the mean of
            # per-CELL rates (macro), under which a task carrying one planted
            # bug weighs as much as a task carrying ten - so an arm could win
            # the headline by doing well on the thin tasks. Both are reported,
            # each named, because a reader must not be able to quote "the"
            # precision without having chosen which one.
            "precision": _rates(inc, "precision"),
            "recall": _rates(inc, "recall"),
            # pooled AND per-cell, like precision and recall: the per-cell mean
            # of 0/1 and 1/9 is 0.0556 while the per-RULING rate is 1/10 = 0.1,
            # and cells with no rulings silently vanish from the mean
            "unsupported_claim_rate": {
                "micro": (
                    round(sum(s.downgrades_n for s in inc) / sum(s.rulings_n for s in inc), 4)
                    if sum(s.rulings_n for s in inc)
                    else None
                ),
                "macro": _mean([s.unsupported_claim_rate for s in inc]),
                "downgrades": sum(s.downgrades_n for s in inc),
                "rulings": sum(s.rulings_n for s in inc),
                "cells_counted": len([s for s in inc if s.unsupported_claim_rate is not None]),
                "cells_included": len(inc),
            },
            # the decision rule reads `wrong_accept_rate`. `severe_false_positive_rate`
            # is reported beside it and is NOT an input to any rule: it is the
            # model's own severity label on its own claim.
            "wrong_accept_rate": _mean([float(s.wrong_accept) for s in inc]),
            "wrong_reject_rate": _mean([float(s.wrong_reject) for s in inc]),
            "severe_false_positive_rate": _mean([float(s.severe_false_positive) for s in inc]),
            "distractor_hits": sum(s.distractor_hits for s in inc),
            # Predictions that repeated a key finding another prediction was
            # already credited with. Outside `precision` by definition (see
            # `Matching.precision`), reported so that choice stays visible: an
            # arm with a high count produced redundant output, and precision
            # does not charge it for that.
            "redundant": sum(s.redundant for s in inc),
            # A5: clean controls answer a question precision cannot, and the
            # pooled rates move with the surviving category mix. Both are
            # first-class rather than derivable-in-principle from `cells`.
            "control": _control_block(inc),
            "by_category": _by_category(inc),
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
    # every (task, repeat) either arm reached, so a pair whose members are not
    # both present is reported as unpaired instead of never being iterated. A
    # missing treatment used to `continue` and a treatment without a base was
    # never looked at, so pair coverage could read complete while half the cells
    # were absent (stop review, 2026-08-30).
    coords = sorted({(s.task_id, s.repeat_index) for s in scores})
    for label, treat, base in PAIRS:
        for task_id, repeat in coords:
            s_base = by.get((task_id, repeat, base.value))
            s_treat = by.get((task_id, repeat, treat.value))
            if s_base is None or s_treat is None:
                missing = [a.value for a, s in ((base, s_base), (treat, s_treat)) if s is None]
                out.append(
                    {
                        "pair": label,
                        "task_id": task_id,
                        "repeat_index": repeat,
                        "paired": False,
                        "reason": f"no scored cell for arm(s): {', '.join(missing)}",
                    }
                )
                continue
            entry: dict[str, Any] = {"pair": label, "task_id": task_id, "repeat_index": repeat}
            differing = sorted(
                k
                for k in set(s_treat.propose_keys) | set(s_base.propose_keys)
                if s_treat.propose_blobs.get(k) != s_base.propose_blobs.get(k)
                or not s_treat.propose_blobs.get(k)
            )
            if not s_treat.propose_blobs or not s_base.propose_blobs:
                # Degenerate: an arm recorded no propose output at all (every
                # worker absent, or the stage never finished ok). Empty key sets
                # would otherwise make `differing` empty and report a controlled
                # comparison between two cells that shared NOTHING - pairing on
                # the absence of a difference rather than on evidence of sameness.
                entry["paired"] = False
                entry["reason"] = "no propose output recorded for one or both arms"
            elif sorted(s_treat.propose_keys) != sorted(s_base.propose_keys):
                entry["paired"] = False
                entry["reason"] = "propose_keys differ"
            elif differing:
                # C1: identical keys, but the two arms' proposals are not the
                # same BYTES - the treatment re-spawned those proposers instead
                # of replaying the base arm's output (or one arm ran --fresh).
                # The arms did not share a world, so any delta between them is
                # confounded with proposal variance. Refuse to call it paired.
                entry["paired"] = False
                entry["reason"] = (
                    f"proposals not shared: {len(differing)} of "
                    f"{len(s_treat.propose_keys)} propose calls produced different "
                    "output bytes from the base arm (or recorded none)"
                )
                entry["unshared_propose_keys"] = differing
            elif (
                s_treat.exclusion == "validator_unknown" or s_base.exclusion == "validator_unknown"
            ):
                # An ABSENT validator record: nothing has been shown to be
                # clean, so there is no basis for a delta.
                #
                # A validator ERROR no longer refuses the pair. It used to, on
                # the M1 reasoning that the delta would be "confounded with
                # this judge emitted CLAIM_MISSING". A malformed adjudication is
                # not a confound - it is the treatment's own output, so
                # refusing the pair drops the arm's failures at the dyad level
                # exactly as the cell exclusion did at the pooled level. Keeping
                # only one of the two would have moved the bias rather than
                # removed it (panel, unanimous, 2026-09-04).
                entry["paired"] = False
                entry["reason"] = (
                    f"validator record absent: treatment {s_treat.exclusion}, "
                    f"base {s_base.exclusion}"
                )
            elif not (s_treat.included and s_base.included):
                entry["paired"] = False
                entry["reason"] = f"excluded: {s_treat.exclusion or s_base.exclusion}"
            else:
                entry["paired"] = True
                for metric in ("precision", "recall"):
                    a, b = getattr(s_treat, metric), getattr(s_base, metric)
                    entry[f"delta_{metric}"] = None if a is None or b is None else round(a - b, 4)
                entry["delta_wrong_accept"] = int(s_treat.wrong_accept) - int(s_base.wrong_accept)
                entry["delta_wrong_reject"] = int(s_treat.wrong_reject) - int(s_base.wrong_reject)
                entry["delta_severe_false_positive"] = int(s_treat.severe_false_positive) - int(
                    s_base.severe_false_positive
                )
                entry["delta_cost_spent_usd"] = round(
                    s_treat.cost_spent_usd - s_base.cost_spent_usd, 6
                )
                entry["delta_cost_attributed_usd"] = round(
                    s_treat.cost_attributed_usd - s_base.cost_attributed_usd, 6
                )
                # A paired delta exists BECAUSE the arms share proposals, and a
                # shared proposal is paid for by whichever arm ran first. So
                # `delta_cost_spent_usd` measures campaign ORDER, not the arms:
                # in b-s3b it read -$1.02 to -$1.56 in favour of an arm that
                # made no calls at all. `delta_cost_attributed_usd` charges each
                # arm for what it used, replayed or not, and is the comparable
                # figure. Flagged rather than dropped, because spent is the real
                # money and worth seeing - just not worth comparing.
                entry["delta_cost_spent_is_order_dependent"] = bool(
                    s_treat.replayed_invocations or s_base.replayed_invocations
                )
                # The treatment made no call of its own: every invocation was
                # replayed from the base arm, so every delta above is zero BY
                # CONSTRUCTION. b-s3b's `indep_verify_iter` did this on all four
                # tasks - the judge requested no evidence, so `adjudicate_iter`
                # broke out of its loop on the first pass and the arm reduced to
                # `indep_verify`.
                #
                # ANNOTATED, NOT DROPPED. An earlier version refused to pair
                # these rows, which is post-treatment selection: whether the arm
                # executed anything is an OUTCOME of the treatment, so filtering
                # on it keeps the cells where the mechanism engaged and discards
                # the ones where it did not - exactly the subset most likely to
                # show an effect, and the estimate is biased upward by the
                # dropping. A cell where the treatment did nothing has a delta of
                # zero, and zero is a measurement. It belongs in the mean.
                # ATTEMPTED, not executed: a treatment whose calls all failed
                # spawned work and is not a no-op replay, even though it
                # produced no ok invocation.
                entry["treatment_executed_no_calls"] = s_treat.attempted_invocations == 0
            out.append(entry)
    return out


# --------------------------------------------------------------------------- campaign


def cell_dirs(campaign_dir: Path) -> list[Path]:
    """Finalized cell dirs. A symlinked entry is skipped BEFORE it is stat'ed
    through (lstat first): a link could point the scorer at a run dir outside
    the campaign. The manifest itself must be a real file too."""
    out: list[Path] = []
    for entry in sorted(Path(campaign_dir).iterdir()):
        if entry.is_symlink():  # lstat-first: never followed
            continue
        if not entry.is_dir():
            continue
        manifest = entry / "manifest.json"
        if manifest.is_symlink() or not manifest.is_file():
            continue
        out.append(entry)
    return out


# The BINDING M1 pre-registration rule, stated once. `docs/EVAL-PLAN.md` must
# carry this text verbatim (whitespace-normalised) - asserted by
# `test_score.py::test_the_binding_pre_registration_matches_the_scorer`, because
# the plan previously kept stating a rule the scorer had stopped implementing.
M1_PRE_REGISTRATION = (
    "A validator finding NO LONGER excludes a cell (user decision 2026-09-04, on a "
    "three-family panel that was unanimous). Malformation is REPORTED - per arm as "
    "`validator.malformed_rate`, per cell as `validator_codes` - and the cell is scored on "
    "its enforced verdict like any other. Until then, an error-severity finding the engine "
    "did NOT act on excluded the cell from quality metrics and from paired deltas, on the "
    "reasoning that a record the engine judged incoherent is not evidence. Two things were "
    "wrong with that. The trigger is `Finding.acted == False`, the engine DECLINING to "
    "change anything, so the exclusion gave a finding the power to delete a cell in exactly "
    "the case where the recorded protocol decision denied it any power over the verdict. And "
    "whether an arm's judge emits a malformed adjudication is an OUTCOME of that arm, so "
    "dropping those cells is post-treatment selection: it measures the arm on a cleaner "
    "subsample of its own work. Measured on b-s3b - the one excluded cell was itself an "
    "arm-4 failure (REVISE on an ACCEPT-expected control), and restoring it moved arm 4's "
    "`wrong_reject_rate` from 0.333 to 0.5. A previous version of this text asserted that "
    "'only arm 4 passes critiques to the validator and so only it can emit "
    "`DISSENT_EMPTY_WITH_CONTEST`'; that is FALSE - the only occurrence observed in this "
    "repository is on an arm 3 cell, because `_contest_exists` also fires on a CONTESTED "
    "ruling, which needs no critique. Whether a finding was acted on is recorded per finding "
    "as `Finding.acted`, NOT inferred from its code - only SUPPORTED/REFUTED rulings are "
    "downgraded, so the same code (e.g. `REF_MISSING`) is consequential on one ruling and "
    "inert on a CONTESTED or UNSUPPORTED one. A ledger written before 0.4.2 carries no "
    "`Finding.acted`, so those findings are classified by code using the coarse "
    "`validate.UNHANDLED_CODES` fallback, which treats every `REF_*` as handled and "
    "therefore UNDER-REPORTS malformation; classification is per FINDING, so a cell is "
    "`validator_basis: coarse_codes` when ANY of its findings lacks `acted`. "
    "`summary.comparison` reports which arms were scored that way and is BLOCKED while any "
    "were, because an arm scored by code and an arm scored by `acted` are measured against "
    "two different definitions of malformed. An ABSENT validator record "
    "(`validator_unknown`) still excludes: nothing has been shown to be clean."
)


def _comparison_block(
    scores: Sequence[CellScore], matrix: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Whether the per-arm quality means may be compared at all.

    Blocked when any arm dropped cells for `validator_errors`/`validator_unknown`:
    its mean is then over a cleaner subsample than the arms it is being compared
    with, and "catch rate" stops meaning the same thing per arm. Mechanical, so
    a reader cannot quote `per_arm[*].recall` without seeing it.
    """
    per_arm: dict[str, dict[str, Any]] = {}
    for arm in sorted({s.arm_key for s in scores}):
        cells = [s for s in scores if s.arm_key == arm]
        # Two DIFFERENT quantities that were one until 2026-09-04, when a
        # validator error stopped excluding cells:
        #   `dropped_for_validator` - cells removed from the comparison because
        #     their validator record is ABSENT (`validator_unknown`). This is
        #     what blocks the comparison, below.
        #   `malformed_rate`        - cells whose adjudication carried an
        #     unacted error. These are now SCORED, not dropped.
        # `malformed_rate` used to be derived from the drop count, which was
        # correct only while malformation implied exclusion. After the exclusion
        # was removed it reported 0.0 for an arm with malformed cells - the same
        # arm reading 0.25 in `per_arm[*].validator.malformed_rate`, two fields
        # of the same name disagreeing. Deriving a rate from a consequence
        # rather than from the thing itself is what made that possible.
        dropped = len([s for s in cells if s.exclusion == "validator_unknown"])
        malformed = len([s for s in cells if s.validator_errors])
        per_arm[arm] = {
            "cells": len(cells),
            "dropped_for_absent_validator_record": dropped,
            "malformed_cells": malformed,
            "malformed_rate": round(malformed / len(cells), 4) if cells else None,
        }
    coarse = sorted({s.arm_key for s in scores if s.validator_basis == "coarse_codes"})
    for arm, v in per_arm.items():
        v["coarsely_scored_cells"] = len(
            [s for s in scores if s.arm_key == arm and s.validator_basis == "coarse_codes"]
        )
    # Every arm's INCLUDED support, as the set of (task, repeat) it actually
    # scored. Arms are excluded cell by cell - contamination, budget, missing,
    # incomplete, no_scan, validator - and those exclusions are NOT the same per
    # arm, so two arms' pooled rates can be computed over different task
    # populations while nothing says so. An arm that lost its hardest cells to
    # contamination reads better for having lost them (panel, 2026-08-30:
    # a worker can even provoke its own exclusion by emitting a scan marker).
    support = {
        arm: {(s.task_id, s.repeat_index) for s in scores if s.arm_key == arm and s.included}
        for arm in per_arm
    }
    common = set.intersection(*support.values()) if support else set()
    for arm, v in per_arm.items():
        v["included_cells"] = len(support[arm])
        v["outside_common_support"] = sorted(
            f"{tid}#{rep}" for tid, rep in sorted(support[arm] - common)
        )
    unequal = sorted(a for a in per_arm if support[a] != common)

    offenders = sorted(a for a, v in per_arm.items() if v["dropped_for_absent_validator_record"])
    reasons: list[str] = []
    missing = (matrix or {}).get("missing")
    if missing:
        reasons.append(
            f"{len(missing)} declared cell(s) never produced a scored result "
            f"({', '.join(missing[:8])}{', ...' if len(missing) > 8 else ''}), so the arms were "
            "not measured on the matrix the campaign declared"
        )
    if len(support) > 1 and unequal:
        reasons.append(
            "arms " + ", ".join(unequal) + " scored a different set of (task, repeat) cells "
            f"than the {len(common)} cell(s) every arm has in common, so their pooled rates "
            "are over different task populations. `common_support` lists what they share; a "
            "difference between arms here is confounded with the difference in what they were "
            "measured on"
        )
    if offenders:
        reasons.append(
            "arms " + ", ".join(offenders) + " dropped cells for validator findings; their "
            "quality means are over a cleaner subsample than the other arms"
        )
    if coarse:
        # Honesty about the fallback: wherever `acted` is absent the coarse code set
        # calls every REF_* handled, so malformation is UNDER-reported there.
        # Comparing such an arm with one scored on `acted` compares two different
        # definitions of malformed.
        reasons.append(
            "arms " + ", ".join(coarse) + " have cells where at least one finding lacks "
            "`Finding.acted` and was therefore classified by the coarse code set - a ledger "
            "written before 0.4.2, or a cell mixing findings that carry it with findings that "
            "do not. That fallback calls every `REF_*` handled, so it under-reports malformation"
        )
    return {
        "blocked": bool(reasons),
        "reason": "; ".join(reasons) + ". NOT comparable." if reasons else None,
        "common_support": sorted(f"{tid}#{rep}" for tid, rep in sorted(common)),
        "per_arm": per_arm,
    }


def declared_cells(campaign_dir: Path) -> list[dict[str, Any]] | None:
    """The cell matrix the campaign said it would run, from `campaign.started`.

    None when the campaign has no readable ledger of its own - an older campaign
    dir, or one assembled by hand.
    """
    try:
        view = LedgerView.from_path(Path(campaign_dir) / "events.jsonl")
    except (LedgerCorrupt, OSError):
        return None
    payloads = view.payloads("campaign.started")
    if not payloads:
        return None
    cells = payloads[-1].get("cells")
    return cells if isinstance(cells, list) else None


def _matrix_block(campaign_dir: Path, scores: Sequence[CellScore]) -> dict[str, Any]:
    """What the campaign declared against what was actually scored.

    Cells were discovered by listing finalized directories and never compared
    with the matrix the campaign recorded. A cell that never finished simply
    vanished, an extra directory was scored as if it belonged, and two
    directories for the same `(task, repeat, arm)` were both aggregated - so an
    arm could be missing entirely and the summary would read as complete (stop
    review, 2026-08-30).

    Missing cells are NOT an error: a budget-tripped cell is pre-registered as
    MISSING, which is a legitimate outcome. They are reported, and they block
    the comparison. Extra and duplicate coordinates ARE refused: neither is a
    thing a campaign can legitimately produce.
    """
    declared = declared_cells(campaign_dir)
    # Keyed on run_id, which is unique per declared cell. `(task, repeat, arm)`
    # is NOT: the `single` arm expands to one cell per panel worker and all of
    # them carry `arm: "single"`, so three lineages collapse into one coordinate
    # and losing two of them would look like losing none.
    counts: dict[str, int] = {}
    for s in scores:
        counts[s.run_id] = counts.get(s.run_id, 0) + 1
    dupes = sorted(r for r, n in counts.items() if n > 1)
    if dupes:
        raise GateRefused(
            f"the campaign has more than one scored cell for {', '.join(dupes)}. Duplicate "
            "coordinates are all aggregated, so one of them silently double-weights an arm."
        )
    if declared is None:
        return {"declared": None, "scored": len(scores), "missing": None, "unexpected": None}
    want = {c["run_id"] for c in declared if isinstance(c, dict) and c.get("run_id")}
    have = set(counts)
    unexpected = sorted(have - want)
    if unexpected:
        raise GateRefused(
            f"the campaign scored cells it never declared: {', '.join(unexpected)}. A cell "
            "directory that is not in `campaign.started` did not come from this matrix."
        )
    return {
        "declared": len(want),
        "scored": len(have),
        "missing": sorted(want - have),
        "unexpected": [],
    }


def score_campaign(campaign_dir: Path, corpus: Path, *, home: Path) -> dict[str, Any]:
    scores: list[CellScore] = []
    invalid: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    unbound: list[dict[str, str]] = []
    for run_dir in cell_dirs(campaign_dir):
        try:
            cell = read_cell(run_dir)
        except LedgerCorrupt as exc:
            invalid.append({"run_id": run_dir.name, "error": str(exc)[:200]})
            continue
        task_id = cell.arm_run.task_id
        # BEFORE the `scored` check, not after: flipping `"scored": false` after
        # a run is one of the edits this guards against, and checking it second
        # would let that particular edit skip the guard by removing the task
        # from scoring altogether.
        require_manifest_agrees(cell)
        require_inputs_unchanged(cell, corpus)
        if not inputs_are_bound(cell):
            unbound.append({"run_id": run_dir.name, "task_id": task_id})
        if not task_is_scored(corpus, task_id):
            skipped.append(
                {
                    "run_id": run_dir.name,
                    "task_id": task_id,
                    "skipped": "not a scored corpus task",
                }
            )
            continue
        key = load_key(corpus, task_id)
        scores.append(score_cell(cell, key, home=home, corpus=corpus))
    matrix = _matrix_block(campaign_dir, scores)
    return {
        "campaign_dir": str(campaign_dir),
        "cells": [asdict(s) for s in scores],
        "ledger_invalid": invalid,
        "skipped": skipped,
        # cells from a ledger written before task/key hashes were recorded: their
        # inputs cannot be shown to be the ones they ran against
        "inputs_unbound": unbound,
        "per_arm": aggregate(scores),
        "matrix": matrix,
        "paired": paired_deltas(scores),
        # M1 (panel): excluding malformed cells creates a NEW bias - only arm 4
        # passes critiques to the validator, so only it can emit
        # DISSENT_EMPTY_WITH_CONTEST, and an arm that drops its malformed cells
        # is left with a cleaner SUBSAMPLE that can win on catch rate. The
        # per-arm means are then computed over different populations and are not
        # comparable. Saying so in prose is advice; this says it in the output,
        # the way the E1 gate does.
        "comparison": _comparison_block(scores, matrix),
        "validator": {
            "malformed_cells": len([s for s in scores if s.validator_errors]),
            "unknown_cells": len([s for s in scores if s.validator_errors is None]),
            "total_errors": sum(s.validator_errors or 0 for s in scores),
            "codes": {
                c: sum(s.validator_codes.get(c, 0) for s in scores)
                for c in sorted({c for s in scores for c in s.validator_codes})
            },
        },
        "pre_registration_notes": [
            "arm consensus is scored on the RAW summarizer verdict (enforced is also recorded)",
            "`wrong_accept_rate` sees ONE direction and `wrong_reject_rate` is reported beside "
            "it for the other. An arm that never accepts cannot wrongly accept: b-s3b's arm 4 "
            "returned REVISE on all four tasks - correct on the two plan tasks, wrong on both "
            "controls - and scored wrong_accept 0 for it, moving the pre-registered rule in the "
            "direction that authorises building. Read the two together; the rule still reads "
            "`wrong_accept_rate` (user decision 2026-08-30) and `wrong_reject_rate` is an input "
            "to no rule.",
            "In a paired delta, read `delta_cost_attributed_usd`, not "
            "`delta_cost_spent_usd`. The pair exists because the arms share proposals, and a "
            "shared proposal is paid for by whichever arm ran first, so spent measures campaign "
            "order: in b-s3b it read -$1.02 to -$1.56 in favour of an arm that made no calls. "
            "`delta_cost_spent_is_order_dependent` marks every such row.",
            M1_PRE_REGISTRATION,
            "categories revert/planted/insufficient require ArmRun.containment == container (E1)",
            "containment basis: " + CONTAINMENT_BASIS,
            "The decision rule reads `wrong_accept_rate`, NOT severity. A single "
            "`confident_wrong` flag combined a mechanical fact (the engine said ACCEPT where "
            "the key says it must not) with the model's OWN severity label on its OWN claim - "
            "an unmatched `critical` prediction set it, the identical prediction labelled "
            "`low` did not - and there is no confidence field anywhere in the wire schema. One "
            "of the two branches authorising a whole orchestrator could therefore be satisfied "
            "by an arm grading its claims more mildly. Split by user decision 2026-08-30: "
            "`severe_false_positive_rate` is reported beside it and is an input to no rule.",
            "PANEL 2026-08-30: the canary detects a VERBATIM emission of the key token and "
            "nothing else. A worker that reads the key and paraphrases it emits no canary, is "
            "reported `contaminated: false`, and scores as if it had reasoned. Absence of a "
            "canary hit is NOT evidence of a clean run, and no quality number here may be "
            "reported as if it were.",
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
