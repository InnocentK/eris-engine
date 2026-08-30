"""eval/score.py: key.json format, the E1 gate, exclusions, metrics, paired
deltas, the AST/import guard and the read-path audit."""

from __future__ import annotations

import ast
import builtins
import io
import json
from pathlib import Path
from typing import Any

import pytest
from eval import score
from eval.run import main as run_main
from eval.score import (
    EXIT_GATE,
    EXIT_OK,
    GateRefused,
    Key,
    Predicted,
    aggregate,
    load_key,
    match_findings,
    paired_deltas,
    read_cell,
    score_campaign,
)
from pydantic import ValidationError

from eris.schemas import Severity
from tests.test_run_harness import (
    ADJ,
    FIX_HUNK,
    Popen,
    base_args,
    claude_envelope,
    grok_envelope,
    world,
)
from tests.test_stages import GOOD_CRITIQUE, GOOD_PROPOSAL

SCORE_PY = Path(__file__).resolve().parents[1] / "eval" / "score.py"


def key_dict(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "key_version": 1,
        "task_id": "t_01",
        "category": "control",
        "expected_verdict": ["REVISE"],
        "line_tolerance": 2,
        "findings": [
            {
                "id": "k1",
                "path": "src/app.py",
                "line_start": 9,
                "line_end": 13,
                "severity": "high",
                "must_mention": ["null"],
            }
        ],
        "distractors": [{"path": "src/app.py", "line_start": 30, "line_end": 32}],
        "scan": {"fix_hunk_lines": [FIX_HUNK], "extra_strings": []},
    }
    base.update(over)
    return base


def write_key(w: dict[str, Path], **over: Any) -> None:
    (w["corpus"] / "t_01" / "key.json").write_text(json.dumps(key_dict(**over)))


def campaign(
    w: dict[str, Path], tmp_path: Path, arms: str, popen: Popen | None = None, cid: str = "c1"
) -> Path:
    out = io.StringIO()
    rc = run_main(
        [
            "campaign",
            *base_args(w),
            "--campaign-id",
            cid,
            "--corpus",
            str(w["corpus"]),
            "--repeats",
            "1",
            "--arms",
            arms,
        ],
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=popen
        or Popen({"grok": [grok_envelope(GOOD_PROPOSAL)], "claude": [claude_envelope(ADJ)]}),
        killpg=lambda *_: None,
    )
    assert rc == EXIT_OK, out.getvalue()
    return w["runs"] / cid


# --------------------------------------------------------------------------- key + guards


def test_key_format_is_strict() -> None:
    k = Key.model_validate(key_dict())
    assert k.findings[0].must_mention == ["null"] and k.line_tolerance == 2
    for bad in (
        {"key_version": 2},
        {"extra": 1},
        {
            "findings": [
                {"id": "x", "path": "p", "line_start": 1, "line_end": 1, "severity": "huge"}
            ]
        },
        {"expected_verdict": ["MAYBE"]},
        {"line_tolerance": -1},
    ):
        with pytest.raises(ValidationError):
            Key.model_validate(key_dict(**bad))


def test_score_imports_nothing_that_executes() -> None:
    """Item 13: the AST guard asserts the REAL import set of eval/score.py -
    an explicit allowlist - so a new executing import cannot slip in."""
    tree = ast.parse(SCORE_PY.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    assert names == {
        "__future__",
        "argparse",
        "json",
        "sys",
        "collections.abc",
        "dataclasses",
        "pathlib",
        "typing",
        "pydantic",
        "eris.ledger",
        "eris.scan",
        # M1: pure, never raises, no subprocess - the single source of truth for
        # which validator findings the engine acts on (`UNHANDLED_CODES`)
        "eris.validate",
        "eris.schemas",
    }, names
    # eval/score.py itself may not even import os/shutil (no os.system, no rmtree)
    direct_forbidden = {
        "subprocess",
        "socket",
        "httpx",
        "os",
        "shutil",
        "asyncio",
        "eris.launch",
        "eris.verify",
    }
    assert not (names & direct_forbidden), names & direct_forbidden
    # transitively, only the modules that can EXECUTE something are forbidden
    # (eris.scan walks the tree with os.walk, the writer fsyncs with os - fine)
    forbidden = {"subprocess", "socket", "httpx", "asyncio", "eris.launch", "eris.verify"}
    body = SCORE_PY.read_text().replace(ast.get_docstring(tree) or "", "")
    assert "os.system" not in body and "os.popen" not in body and "Popen" not in body
    # TRANSITIVE closure: follow every first-party import to its file and keep
    # walking, so an executing import two hops away is caught as well
    import importlib.util

    def module_imports(path: Path) -> set[str]:
        tree_ = ast.parse(path.read_text())
        out: set[str] = set()
        for node in ast.walk(tree_):
            if isinstance(node, ast.Import):
                out.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                out.add(node.module)
        return out

    seen: set[str] = set()
    frontier = {n for n in names if n.startswith("eris.")}
    reachable: set[str] = set(names)
    while frontier:
        mod = frontier.pop()
        if mod in seen:
            continue
        seen.add(mod)
        spec = importlib.util.find_spec(mod)
        assert spec is not None and spec.origin, mod
        found = module_imports(Path(spec.origin))
        reachable |= found
        frontier |= {n for n in found if n.startswith("eris.") and n not in seen}
    assert not (reachable & forbidden), sorted(reachable & forbidden)
    assert seen >= {"eris.ledger", "eris.scan", "eris.schemas", "eris.validate"}, seen


def test_scorer_opens_nothing_outside_runs_and_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    w = world(tmp_path)
    write_key(w)
    cdir = campaign(w, tmp_path, "single,indep_verify")
    opened: list[Path] = []
    real_open = builtins.open
    real_read_bytes = Path.read_bytes

    def spy_open(file: Any, *a: Any, **k: Any) -> Any:
        if isinstance(file, (str, Path)):
            opened.append(Path(file))
        return real_open(file, *a, **k)

    def spy_read_bytes(self: Path) -> bytes:
        opened.append(self)
        return real_read_bytes(self)

    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(Path, "read_bytes", spy_read_bytes)
    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    assert summary["per_arm"]
    allowed = (w["runs"].resolve(), w["corpus"].resolve())
    for p in opened:
        rp = p.resolve()
        assert any(str(rp).startswith(str(a)) for a in allowed), p


# --------------------------------------------------------------------------- gate + exclusions


def test_e1_gate_refuses_defect_categories_without_containment(tmp_path: Path) -> None:
    w = world(tmp_path)
    task = json.loads(w["task"].read_text())
    (w["task"]).write_text(json.dumps({**task, "category": "planted"}))
    write_key(w, category="planted")
    cdir = campaign(w, tmp_path, "single")
    with pytest.raises(GateRefused, match="containment"):
        score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    rc = score.main(
        [
            "--campaign-dir",
            str(cdir),
            "--corpus",
            str(w["corpus"]),
            "--home",
            str(tmp_path / "home"),
        ]
    )
    assert rc == EXIT_GATE
    # there is no CLI override
    with pytest.raises(SystemExit):
        score.main(["--campaign-dir", str(cdir), "--corpus", str(w["corpus"]), "--force"])
    # control and plan score normally
    for category in ("control", "plan"):
        w2 = world(tmp_path / category)
        t2 = json.loads(w2["task"].read_text())
        w2["task"].write_text(json.dumps({**t2, "category": category}))
        write_key(w2, category=category)
        cdir2 = campaign(w2, tmp_path / category, "single")
        summary = score_campaign(cdir2, w2["corpus"], home=tmp_path / category / "home")
        assert summary["cells"][0]["included"] is True


def test_contaminated_missing_and_incomplete_cells_are_excluded_but_costed(tmp_path: Path) -> None:
    w = world(tmp_path)
    write_key(w)
    dirty = {**GOOD_PROPOSAL, "summary": f"I saw {FIX_HUNK}"}
    popen = Popen({"grok": [grok_envelope(dirty)], "claude": [claude_envelope(ADJ)]})
    popen.hang.add("claude")
    out = io.StringIO()
    run_main(
        [
            "campaign",
            *base_args(w),
            "--campaign-id",
            "c1",
            "--corpus",
            str(w["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "single,indep_verify",
        ],
        out=out,
        err=io.StringIO(),
        home=tmp_path / "home",
        popen=popen,
        killpg=lambda *_: None,
    )
    summary = score_campaign(w["runs"] / "c1", w["corpus"], home=tmp_path / "home")
    by = {c["run_id"]: c for c in summary["cells"]}
    single = by["t_01-r0-single-grok"]
    assert single["included"] is False and single["exclusion"] == "contaminated"
    assert single["contaminated"] and single["rescan_contaminated"] and single["precision"] is None
    assert single["cost_spent_usd"] > 0  # counted in cost
    iv = by["t_01-r0-indep_verify"]
    assert iv["exclusion"] == "contaminated"  # the reused dirty proposal contaminates arm 3 too
    per_arm = summary["per_arm"]["single"]
    assert (
        per_arm["included"] == 0
        and per_arm["excluded"]["contaminated"] == 1
        and per_arm["cost_spent_usd"] > 0
    )
    # a budget-tripped cell is MISSING; an incomplete judge is incomplete
    w2 = world(tmp_path / "b")
    write_key(w2)
    policy = w2["policy"].read_text().replace("per_run_usd: 5.0", "per_run_usd: 0.5")
    w2["policy"].write_text(policy)
    popen2 = Popen({"grok": [grok_envelope(GOOD_PROPOSAL)], "claude": [claude_envelope(ADJ)]})
    run_main(
        [
            "campaign",
            *base_args(w2),
            "--campaign-id",
            "c2",
            "--corpus",
            str(w2["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "indep_verify",
        ],
        out=io.StringIO(),
        err=io.StringIO(),
        home=tmp_path / "b" / "home",
        popen=popen2,
        killpg=lambda *_: None,
    )
    summary2 = score_campaign(w2["runs"] / "c2", w2["corpus"], home=tmp_path / "b" / "home")
    cell = summary2["cells"][0]
    assert cell["exclusion"] == "missing" and cell["missing_cells"][0]["reason"].startswith(
        "budget"
    )
    w3 = world(tmp_path / "c")
    write_key(w3)
    popen3 = Popen({"grok": [grok_envelope(GOOD_PROPOSAL)], "claude": [claude_envelope(ADJ)]})
    popen3.hang.add("claude")
    run_main(
        [
            "campaign",
            *base_args(w3),
            "--campaign-id",
            "c3",
            "--corpus",
            str(w3["corpus"]),
            "--repeats",
            "1",
            "--arms",
            "indep_verify",
        ],
        out=io.StringIO(),
        err=io.StringIO(),
        home=tmp_path / "c" / "home",
        popen=popen3,
        killpg=lambda *_: None,
    )
    summary3 = score_campaign(w3["runs"] / "c3", w3["corpus"], home=tmp_path / "c" / "home")
    assert summary3["cells"][0]["exclusion"] == "incomplete"


def test_ledger_invalid_cells_are_listed_not_scored(tmp_path: Path) -> None:
    w = world(tmp_path)
    write_key(w)
    cdir = campaign(w, tmp_path, "single")
    events = cdir / "t_01-r0-single-grok" / "events.jsonl"
    lines = events.read_bytes().splitlines(keepends=True)
    lines[1] = b"{not json}\n"
    events.write_bytes(b"".join(lines))
    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    assert (
        summary["cells"] == [] and summary["ledger_invalid"][0]["run_id"] == "t_01-r0-single-grok"
    )


# --------------------------------------------------------------------------- metrics


def test_matching_precision_recall_tolerance_must_mention_and_distractors() -> None:
    key = Key.model_validate(key_dict())
    hit = Predicted(
        "src/app.py", 14, 15, Severity.HIGH, "null deref at the guard"
    )  # within tolerance 2
    miss_text = Predicted(
        "src/app.py", 10, 12, Severity.HIGH, "something else"
    )  # must_mention fails -> FP
    far = Predicted("src/app.py", 20, 21, Severity.LOW, "null but far away")
    distractor = Predicted("src/app.py", 31, 31, Severity.CRITICAL, "null in the distractor")
    nopath = Predicted(None, None, None, Severity.INFO, "null")
    m = match_findings([hit, miss_text, far, distractor, nopath], key)
    assert m.tp == 1 and m.fp == 4 and m.fn == 0 and m.distractor_hits == 1
    assert m.precision == 0.2 and m.recall == 1.0 and "critical" in m.fp_severities
    empty = match_findings([], Key.model_validate(key_dict(findings=[])))
    assert empty.precision is None and empty.recall is None
    assert match_findings([], key).recall == 0.0 and match_findings([], key).precision is None


def test_cells_are_scored_with_verdict_basis_costs_and_paired_deltas(tmp_path: Path) -> None:
    w = world(tmp_path)
    write_key(w)
    supported = {**ADJ, "rulings": []}
    accept = {**ADJ, "verdict": "ACCEPT"}
    popen = Popen(
        {
            "grok": [grok_envelope(GOOD_PROPOSAL), grok_envelope(GOOD_CRITIQUE)],
            "claude": [
                claude_envelope(accept),
                claude_envelope(supported),
                claude_envelope(supported),
            ],
        }
    )
    cdir = campaign(
        w,
        tmp_path,
        "single,consensus,indep_verify,indep_verify_iter,indep_verify_critique",
        popen=popen,
    )
    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    by = {c["arm"]: c for c in summary["cells"]}
    assert set(by) == {
        "single",
        "consensus",
        "indep_verify",
        "indep_verify_iter",
        "indep_verify_critique",
    }
    # M1: the critique fixture returns a contest with EMPTY DISSENT - a finding
    # the engine emits and then does nothing about - so that cell is no longer
    # scored as evidence. The consensus fixture's ACCEPT findings (VERDICT_*)
    # are HANDLED (the verdict was forced to ESCALATE), so it stays included:
    # excluding already-corrected behaviour would delete the denominator for
    # something the engine got right.
    assert by["indep_verify_critique"]["exclusion"] == "validator_errors"
    assert by["indep_verify_critique"]["validator_codes"] == {"DISSENT_EMPTY_WITH_CONTEST": 1}
    assert by["consensus"]["validator_errors"] == 0 and by["consensus"]["included"] is True
    assert all(c["included"] for c in by.values() if c["arm"] != "indep_verify_critique")
    # a cell with no adjudication at all is UNKNOWN, never "clean"
    assert by["single"]["validator_errors"] is None
    # arm 1: findings from the proposal, no verdict
    assert (
        by["single"]["verdict"] is None
        and by["single"]["tp"] == 1
        and by["single"]["recall"] == 1.0
    )
    # arm 2: raw verdict (the summarizer's ACCEPT), confident-wrong since ACCEPT is off-key
    assert by["consensus"]["verdict_basis"] == "raw" and by["consensus"]["verdict"] == "ACCEPT"
    # the consensus fixture's findings are HANDLED (VERDICT_* forced ESCALATE),
    # so the cell is NOT excluded and still feeds quality metrics
    assert by["consensus"]["confident_wrong"] is True
    # judged arms: enforced verdict; unlinked finding rule (the proposal's finding links a claim
    # ruled nothing -> not asserted) -> recall 0 with tolerance
    assert (
        by["indep_verify"]["verdict_basis"] == "enforced"
        and by["indep_verify"]["verdict"] == "REVISE"
    )
    assert by["indep_verify"]["recall"] == 0.0 and by["indep_verify"]["precision"] is None
    assert (
        by["indep_verify"]["unsupported_claim_rate"] is None
        and by["indep_verify"]["downgrades"] == 0
    )
    # costs: spent vs attributed, by stage, reused proposals attributed only
    iv, ivc = by["indep_verify"], by["indep_verify_critique"]
    assert ivc["cost_attributed_usd"] >= ivc["cost_spent_usd"]
    assert (
        "propose" in ivc["cost_by_stage_attributed"]
        and ivc["cost_by_stage_spent"].get("propose", 0.0) == 0.0
    )
    assert iv["attempts"] >= 2 and iv["wall_ms"] is not None and iv["wall_ms"] >= 0
    assert iv["containment"] is None and iv["propose_keys"] == ivc["propose_keys"]
    # paired deltas exist for both pairs; 3b-3 pairs (both adjudications clean),
    # 4-3 does NOT - its treatment arm's adjudication is malformed, so any delta
    # would be confounded with the malformation rather than measuring critique.
    pairs = {p["pair"]: p for p in summary["paired"]}
    assert set(pairs) == {"3b-3", "4-3"}
    assert pairs["3b-3"]["paired"] is True
    assert pairs["4-3"]["paired"] is False and "validator errors" in pairs["4-3"]["reason"]
    assert "delta_recall" not in pairs["4-3"]  # no delta is emitted for an unpaired cell
    per_arm = summary["per_arm"]
    assert per_arm["single"]["recall"] == 1.0
    # M1 reporting: the malformation is first-class per arm, and the campaign
    # summary carries the same counts across all cells
    assert per_arm["indep_verify_critique"]["validator"]["malformed"] == 1
    assert per_arm["indep_verify_critique"]["excluded"]["validator_errors"] == 1
    assert per_arm["consensus"]["confident_wrong_rate"] == 1.0
    assert per_arm["indep_verify_critique"]["validator"]["codes"] == {
        "DISSENT_EMPTY_WITH_CONTEST": 1
    }
    assert per_arm["single"]["validator"]["unknown"] == 1  # no adjudication to judge
    assert summary["validator"]["malformed_cells"] == 1
    assert summary["validator"]["total_errors"] == 1
    assert per_arm["indep_verify"]["abstention"]["neither"] == 1
    assert summary["pre_registration_notes"]
    # CLI
    rc = score.main(
        [
            "--campaign-dir",
            str(cdir),
            "--corpus",
            str(w["corpus"]),
            "--home",
            str(tmp_path / "home"),
        ]
    )
    assert rc == EXIT_OK


def test_paired_deltas_require_identical_propose_keys_and_inclusion() -> None:
    def cell(
        arm: str,
        keys: list[str],
        included: bool = True,
        recall: float | None = 0.5,
        blobs: dict[str, list[str]] | None = None,
    ) -> Any:
        from eval.score import CellScore

        return CellScore(
            run_id=f"r-{arm}",
            task_id="t",
            arm=arm,
            repeat_index=0,
            category="control",
            included=included,
            exclusion=None if included else "contaminated",
            verdict="REVISE",
            verdict_basis="enforced",
            precision=0.5,
            recall=recall,
            tp=1,
            fp=1,
            fn=1,
            distractor_hits=0,
            unsupported_claim_rate=0.0,
            downgrades=0,
            confident_wrong=False,
            abstained=False,
            expected_abstain=False,
            cost_spent_usd=1.0,
            cost_attributed_usd=1.0,
            cost_by_stage_spent={},
            cost_by_stage_attributed={},
            unknown_cost_records=0,
            wall_ms=1,
            attempts=1,
            propose_keys=keys,
            # default: identical output bytes for every key, i.e. the arms
            # really did share a world (C1)
            validator_errors=0,
            validator_codes={},
            validator_basis="acted",
            propose_blobs={k: ["sha-" + k] for k in keys} if blobs is None else blobs,
            contaminated=False,
            scan_incomplete=False,
            rescan_contaminated=False,
            containment=None,
        )

    same = ["a" * 64]
    out = paired_deltas(
        [
            cell("indep_verify", same),
            cell("indep_verify_iter", ["b" * 64]),
            cell("indep_verify_critique", same, recall=1.0),
        ]
    )
    by = {p["pair"]: p for p in out}
    assert by["3b-3"]["paired"] is False and "propose_keys differ" in by["3b-3"]["reason"]
    assert by["4-3"]["paired"] is True and by["4-3"]["delta_recall"] == 0.5
    out = paired_deltas(
        [cell("indep_verify", same, included=False), cell("indep_verify_critique", same)]
    )
    assert out[0]["paired"] is False and "excluded" in out[0]["reason"]
    agg = aggregate([cell("indep_verify", same), cell("indep_verify", same, included=False)])
    assert agg["indep_verify"]["cells"] == 2 and agg["indep_verify"]["included"] == 1
    assert agg["indep_verify"]["excluded"]["contaminated"] == 1


def test_read_cell_and_load_key_errors(tmp_path: Path) -> None:
    w = world(tmp_path)
    cdir = campaign(w, tmp_path, "single")
    with pytest.raises(GateRefused, match="unusable"):
        load_key(w["corpus"], "nope")
    cell = read_cell(cdir / "t_01-r0-single-grok")
    assert cell.arm_run.arm.value == "single" and cell.enforced is None and cell.scan is not None


def test_cells_without_a_scan_result_are_refused_when_gated_and_plumbing_otherwise(
    tmp_path: Path,
) -> None:
    """Item 10: no ScanResult -> gated categories are refused (exit 7);
    control/plan cells are excluded as `no_scan` (never a quality metric)."""
    w = world(tmp_path)
    write_key(w)
    cdir = campaign(w, tmp_path, "single")
    events = cdir / "t_01-r0-single-grok" / "events.jsonl"
    from eris.redact import Redactor
    from eris.writer import RunWriter as RW

    # rebuild the ledger without its scan.result lines (a valid chain again)
    lines = [json.loads(line) for line in events.read_bytes().splitlines()]
    kept = [e for e in lines if e["kind"] != "scan.result"]
    (cdir / "t_01-r0-single-grok" / "manifest.json").unlink()
    events.unlink()
    (cdir / "t_01-r0-single-grok" / ".lock").unlink(missing_ok=True)
    rw = RW(cdir / "t_01-r0-single-grok", Redactor(), run_id="t_01-r0-single-grok").open()
    for e in kept:
        rw.append(e["kind"], e["payload"])
    rw.finalize({"arm": "single"})
    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    cell = summary["cells"][0]
    assert cell["included"] is False and cell["exclusion"] == "no_scan"
    assert summary["per_arm"]["single"]["excluded"]["no_scan"] == 1
    # the same cell under a gated category is refused outright
    task = json.loads(w["task"].read_text())
    w["task"].write_text(json.dumps({**task, "category": "planted"}))
    write_key(w, category="planted")
    arm_run = next(e for e in kept if e["kind"] == "arm.finished")
    rw2_lines = [e for e in kept]
    for e in rw2_lines:
        if e["kind"] == "arm.finished":
            e["payload"] = {**arm_run["payload"], "category": "planted", "containment": "container"}
    (cdir / "t_01-r0-single-grok" / "manifest.json").unlink()
    events.unlink()
    rw = RW(cdir / "t_01-r0-single-grok", Redactor(), run_id="t_01-r0-single-grok").open()
    for e in rw2_lines:
        rw.append(e["kind"], e["payload"])
    rw.finalize({"arm": "single"})
    with pytest.raises(GateRefused, match="no ScanResult"):
        score_campaign(cdir, w["corpus"], home=tmp_path / "home")


def test_a_stale_containment_declaration_in_an_old_ledger_is_refused(tmp_path: Path) -> None:
    """H2: a policy declaring `containment: container` is refused at LOAD, but a
    ledger written BEFORE that refusal still carries the declaration and the E1
    gate would accept it as satisfied. No container exists anywhere in the tree,
    so such a declaration is false by construction and must be refused at score
    time too - otherwise an uncontained defect run is scored as evidence.

    Checked AFTER the no-ScanResult gate, so neither refusal makes the other
    unreachable (that test asserts the scan message on the same shape).
    """
    from eris.redact import Redactor
    from eris.writer import RunWriter as RW

    w = world(tmp_path)
    write_key(w)
    cdir = campaign(w, tmp_path, "single")
    cell = cdir / "t_01-r0-single-grok"
    events = cell / "events.jsonl"
    kept = [json.loads(line) for line in events.read_bytes().splitlines()]

    task = json.loads(w["task"].read_text())
    w["task"].write_text(json.dumps({**task, "category": "planted"}))
    write_key(w, category="planted")
    for e in kept:
        if e["kind"] == "arm.finished":
            e["payload"] = {**e["payload"], "category": "planted", "containment": "container"}
    (cell / "manifest.json").unlink()
    events.unlink()
    (cell / ".lock").unlink(missing_ok=True)
    rw = RW(cell, Redactor(), run_id="t_01-r0-single-grok").open()
    for e in kept:
        rw.append(e["kind"], e["payload"])
    rw.finalize({"arm": "single"})

    with pytest.raises(GateRefused, match="no containment mechanism is implemented"):
        score_campaign(cdir, w["corpus"], home=tmp_path / "home")


def test_key_must_match_the_ledger_task_and_category(tmp_path: Path) -> None:
    """Item 3: a gated task can never be scored behind a `control` ArmRun:
    key.task_id and key.category must equal what the ledger recorded."""
    w = world(tmp_path)
    write_key(w)
    cdir = campaign(w, tmp_path, "single")
    write_key(w, category="planted")  # the key says planted; the ledger recorded control
    with pytest.raises(GateRefused, match="category"):
        score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    write_key(w, task_id="t_99")
    with pytest.raises(GateRefused, match="task_id"):
        score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    write_key(w)
    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    assert summary["cells"][0]["containment_basis"].startswith("policy declaration")
    assert any("containment basis" in n for n in summary["pre_registration_notes"])


def test_key_line_order_and_symlinked_cell_dirs(tmp_path: Path) -> None:
    """Item 13: key spans need line_end >= line_start; a symlinked entry in
    the campaign dir is never followed."""
    with pytest.raises(ValidationError, match="line_end"):
        Key.model_validate(
            key_dict(
                findings=[
                    {"id": "k", "path": "p", "line_start": 9, "line_end": 3, "severity": "low"}
                ]
            )
        )
    with pytest.raises(ValidationError, match="line_end"):
        Key.model_validate(key_dict(distractors=[{"path": "p", "line_start": 5, "line_end": 1}]))
    w = world(tmp_path)
    write_key(w)
    cdir = campaign(w, tmp_path, "single")
    elsewhere = tmp_path / "elsewhere-cell"
    import shutil

    shutil.copytree(cdir / "t_01-r0-single-grok", elsewhere)
    (cdir / "linked-cell").symlink_to(elsewhere)
    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    assert [c["run_id"] for c in summary["cells"]] == ["t_01-r0-single-grok"]


def test_symlinked_cell_dirs_and_manifests_are_never_followed(tmp_path: Path) -> None:
    """cond 13: discovery is lstat-first - a symlinked cell dir (even one
    pointing at a valid finalized run) and a symlinked manifest are skipped."""
    from eval.score import cell_dirs

    w = world(tmp_path)
    write_key(w)
    cdir = campaign(w, tmp_path, "single")
    real = cdir / "t_01-r0-single-grok"
    outside = tmp_path / "outside-cell"
    import shutil

    shutil.copytree(real, outside)
    (cdir / "linked-cell").symlink_to(outside)
    faked = cdir / "faked-cell"
    faked.mkdir()
    (faked / "manifest.json").symlink_to(real / "manifest.json")
    found = [p.name for p in cell_dirs(cdir)]
    assert found == ["t_01-r0-single-grok"]
    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    assert [c["run_id"] for c in summary["cells"]] == ["t_01-r0-single-grok"]


def test_scorer_skips_an_unscored_plumbing_task_and_says_so(tmp_path: Path) -> None:
    """M2c: a task.json with `"scored": false` never enters a metric. The
    scorer reports its cells under `skipped` with the reason, rather than
    silently dropping them or quietly folding them into the aggregates."""
    w = world(tmp_path)
    cdir = campaign(w, tmp_path, "single")
    write_key(w, expected_verdict=["ACCEPT"])
    scored = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    assert scored["cells"] and scored["skipped"] == []

    spec = json.loads((w["corpus"] / "t_01" / "task.json").read_text())
    spec["scored"] = False
    (w["corpus"] / "t_01" / "task.json").write_text(json.dumps(spec))
    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    assert summary["cells"] == []
    assert [c["skipped"] for c in summary["skipped"]] == ["not a scored corpus task"]
    assert {c["task_id"] for c in summary["skipped"]} == {"t_01"}
    assert all(not v for v in summary["per_arm"].values()) or summary["per_arm"] is not None


def test_the_repo_plumbing_control_task_is_marked_unscored() -> None:
    """The corpus entry's own claim ("a plumbing control, not a scored task")
    must be true in the file the tools read, not only in its README."""
    from eris.evidence import TaskSpec

    task_file = Path(__file__).resolve().parents[1] / "eval" / "corpus" / "plumbing-control"
    spec = TaskSpec.model_validate_json((task_file / "task.json").read_bytes())
    assert spec.task_id == "plumbing-control" and spec.scored is False


def test_paired_deltas_refuse_to_pair_arms_that_did_not_share_proposals() -> None:
    """C1: identical propose_keys do NOT prove shared proposals.

    The key excludes worker output, and `Cache.lookup` refuses any entry without
    `model_executed` - which `parse_codex`/`parse_agy` never populate. So with
    the default panel those two workers are re-spawned by every arm and return
    DIFFERENT text while the keys stay identical. The scorer used to call that
    `paired: true` and emit deltas confounded with proposal variance.

    Pairing therefore requires byte-identical propose output, not merely a
    cache hit: a treatment arm can replay a cached proposal A while the base
    arm ran `--fresh` and produced B, so "the treatment reused something" does
    not mean "the two arms shared a world".
    """
    from eval.score import CellScore

    ka, kb = "a" * 64, "b" * 64

    def cell(arm: str, blobs: dict[str, list[str]]) -> Any:
        return CellScore(
            run_id=f"r-{arm}",
            task_id="t",
            arm=arm,
            repeat_index=0,
            category="control",
            included=True,
            exclusion=None,
            verdict="REVISE",
            verdict_basis="enforced",
            precision=0.5,
            recall=0.5,
            tp=1,
            fp=1,
            fn=1,
            distractor_hits=0,
            unsupported_claim_rate=0.0,
            downgrades=0,
            confident_wrong=False,
            abstained=False,
            expected_abstain=False,
            cost_spent_usd=1.0,
            cost_attributed_usd=1.0,
            cost_by_stage_spent={},
            cost_by_stage_attributed={},
            unknown_cost_records=0,
            wall_ms=1,
            attempts=1,
            propose_keys=[ka, kb],
            validator_errors=0,
            validator_codes={},
            validator_basis="acted",
            propose_blobs=blobs,
            contaminated=False,
            scan_incomplete=False,
            rescan_contaminated=False,
            containment=None,
        )

    base = {ka: ["sha-a"], kb: ["sha-b"]}

    # codex/agy case: one proposer re-spawned and produced different bytes
    out = {
        p["pair"]: p
        for p in paired_deltas(
            [
                cell("indep_verify", base),
                cell("indep_verify_critique", {ka: ["sha-a"], kb: ["sha-DIFFERENT"]}),
            ]
        )
    }
    assert out["4-3"]["paired"] is False
    assert "proposals not shared" in out["4-3"]["reason"]
    assert "1 of 2" in out["4-3"]["reason"]
    assert out["4-3"]["unshared_propose_keys"] == [kb]
    assert "delta_recall" not in out["4-3"]  # no delta for an unpaired cell

    # the `--fresh` hole: the treatment REPLAYED a cached proposal the base arm
    # never used. A reuse-based guard called this paired; byte equality does not.
    out = {
        p["pair"]: p
        for p in paired_deltas(
            [
                cell("indep_verify", {ka: ["sha-FRESH-B"], kb: ["sha-b"]}),
                cell("indep_verify_iter", base),  # replayed cached A
            ]
        )
    }
    assert out["3b-3"]["paired"] is False and out["3b-3"]["unshared_propose_keys"] == [ka]

    # a cell that recorded no propose blob at all is never paired
    out = {
        p["pair"]: p
        for p in paired_deltas(
            [cell("indep_verify", base), cell("indep_verify_critique", {ka: ["sha-a"]})]
        )
    }
    assert out["4-3"]["paired"] is False

    # genuine sharing still pairs
    out = {
        p["pair"]: p
        for p in paired_deltas([cell("indep_verify", base), cell("indep_verify_critique", base)])
    }
    assert out["4-3"]["paired"] is True and out["4-3"]["delta_recall"] == 0.0


def test_a_worker_that_recorded_twice_counts_once() -> None:
    """M11 / multiplicity audit: one proposal per worker, the LAST recorded.

    A crash between `proposal.recorded` and `stage.finished` leaves the stage
    unfinished, so resume does not trust it and re-runs that worker - leaving
    two `proposal.recorded` rows for one worker. `predicted_findings` iterates
    every row, so the duplicate would count that worker's findings twice and
    inflate tp/fp for EVERY arm. `arms.load_prior` already keys proposals by
    worker id; the scorer was the only reader that did not.
    """
    from types import SimpleNamespace

    from eval.score import _last_proposal_per_worker

    golden = json.loads(
        (Path(__file__).parent / "fixtures" / "records" / "0.1.5" / "proposal.json").read_text()
    )

    def prop(worker: str, desc: str) -> dict[str, Any]:
        return {
            **golden,
            "worker_id": worker,
            "findings": [
                {
                    **golden["findings"][0],
                    "description": desc,
                }
            ],
        }

    class _View:
        def __init__(self, rows: list[dict[str, Any]]) -> None:
            self._rows = rows

        def records(self, kind: str, model: Any) -> list[Any]:
            return [model.model_validate(r) for r in self._rows]

    # the stale first row and the re-spawn that replaced it
    arm_run = SimpleNamespace(panel=["claude", "grok"])
    out = _last_proposal_per_worker(
        _View([prop("claude", "stale"), prop("claude", "kept"), prop("grok", "other")]), arm_run
    )
    assert len(out) == 2, "the duplicated worker must collapse to one proposal"
    by_worker = {p.worker_id: p for p in out}
    assert [f.description for f in by_worker["claude"].findings] == ["kept"]
    assert [f.description for f in by_worker["grok"].findings] == ["other"]

    # a worker left over from a resume with a DIFFERENT --panel is not scored:
    # the arm did not run it, so crediting its findings would be fabrication
    out = _last_proposal_per_worker(
        _View([prop("claude", "stale-panel"), prop("grok", "kept")]),
        SimpleNamespace(panel=["grok"]),
    )
    assert [p.worker_id for p in out] == ["grok"]


def test_propose_blobs_read_the_kept_outcome_not_an_attempt() -> None:
    """C1, at the ledger-reading layer: `_propose_blobs` must report the blob of
    the proposal that was KEPT.

    Two ways an attempt can be mistaken for the outcome:
    * a cache hit is replayed (`invocation.reused` is written) and the replayed
      output then fails to parse, so `stages.invoke` falls through to a FRESH
      spawn - the ledger holds a reuse for a proposal that was re-spawned;
    * on resume a stage whose blob does not re-hash is not trusted and the
      worker is re-run, so a stale `stage.finished` precedes the one that
      produced the kept proposal.
    In both cases the LAST `stage.finished` per key is the truth.
    """
    from types import SimpleNamespace

    from eval.score import _propose_blobs

    k = "a" * 64

    class _View:
        def __init__(self, payloads: dict[str, list[dict[str, Any]]]) -> None:
            self._p = payloads

        def payloads(self, kind: str) -> list[dict[str, Any]]:
            return self._p.get(kind, [])

    def cell(rows: list[dict[str, Any]], reused: bool = False) -> Any:
        p: dict[str, list[dict[str, Any]]] = {"stage.finished": rows}
        if reused:
            p["invocation.reused"] = [{"invocation_id": f"inv-{k[:16]}-a1", "reused_from": "x"}]
        return SimpleNamespace(view=_View(p), arm_run=SimpleNamespace(propose_keys=[k]))

    fin = {"stage": "propose", "idempotency_key": k, "ok": True}

    # stale first pass, then the re-spawn that replaced it: the LAST wins
    assert _propose_blobs(cell([{**fin, "blobs": ["stale"]}, {**fin, "blobs": ["kept"]}])) == {
        k: ["kept"]
    }
    # an `invocation.reused` event does not override the kept outcome
    assert _propose_blobs(cell([{**fin, "blobs": ["kept"]}], reused=True)) == {k: ["kept"]}
    # a stage that did not finish ok contributes no blob, so it can never pair
    assert _propose_blobs(cell([{**fin, "ok": False, "blobs": ["x"]}])) == {}
    # a key the ArmRun never recorded is ignored
    other = {"stage": "propose", "idempotency_key": "z" * 64, "ok": True, "blobs": ["z"]}
    assert _propose_blobs(cell([{**fin, "blobs": ["kept"]}, other])) == {k: ["kept"]}


def test_an_arm_with_no_propose_output_never_pairs() -> None:
    """C1, degenerate shape: an arm that recorded NO propose output must not pair.

    Empty key sets make "nothing differs" trivially true, so the guard would
    report a controlled comparison between two cells that shared nothing because
    there was nothing to share - pairing on the ABSENCE OF A DIFFERENCE rather
    than on evidence of sameness. Reachable whenever every worker in an arm is
    absent, or no propose stage finished ok.
    """
    from eval.score import CellScore

    def cell(arm: str, keys: list[str], blobs: dict[str, list[str]]) -> Any:
        return CellScore(
            run_id=f"r-{arm}",
            task_id="t",
            arm=arm,
            repeat_index=0,
            category="control",
            included=True,
            exclusion=None,
            verdict="REVISE",
            verdict_basis="enforced",
            precision=0.5,
            recall=0.5,
            tp=1,
            fp=1,
            fn=1,
            distractor_hits=0,
            unsupported_claim_rate=0.0,
            downgrades=0,
            confident_wrong=False,
            abstained=False,
            expected_abstain=False,
            cost_spent_usd=1.0,
            cost_attributed_usd=1.0,
            cost_by_stage_spent={},
            cost_by_stage_attributed={},
            unknown_cost_records=0,
            wall_ms=1,
            attempts=1,
            propose_keys=keys,
            validator_errors=0,
            validator_codes={},
            validator_basis="acted",
            propose_blobs=blobs,
            contaminated=False,
            scan_incomplete=False,
            rescan_contaminated=False,
            containment=None,
        )

    k = "a" * 64
    # neither arm produced a proposal
    out = {
        p["pair"]: p
        for p in paired_deltas(
            [cell("indep_verify", [], {}), cell("indep_verify_critique", [], {})]
        )
    }
    assert out["4-3"]["paired"] is False
    assert "no propose output" in out["4-3"]["reason"]
    assert "delta_recall" not in out["4-3"]

    # only the BASE arm is empty
    out = {
        p["pair"]: p
        for p in paired_deltas(
            [cell("indep_verify", [], {}), cell("indep_verify_critique", [k], {k: ["s"]})]
        )
    }
    assert out["4-3"]["paired"] is False and "no propose output" in out["4-3"]["reason"]

    # only the TREATMENT arm is empty
    out = {
        p["pair"]: p
        for p in paired_deltas(
            [cell("indep_verify", [k], {k: ["s"]}), cell("indep_verify_iter", [], {})]
        )
    }
    assert out["3b-3"]["paired"] is False and "no propose output" in out["3b-3"]["reason"]


def test_validator_errors_are_read_from_the_FINAL_adjudication_only() -> None:
    """M1: engine validator findings must be consequential, and must describe the
    adjudication the cell actually ended on.

    `adjudicate_iter` writes one `validate.findings` event per judge call, and a
    resumed run replays a stored adjudication rather than re-deriving it. Reading
    "the last findings event" would therefore count an ATTEMPT; the join is on
    `adjudication_id == ArmRun.final_adjudication_id`.
    """
    from types import SimpleNamespace

    from eval.score import _validator_errors

    class _View:
        def __init__(self, payloads: list[dict[str, Any]]) -> None:
            self._p = payloads

        def payloads(self, kind: str) -> list[dict[str, Any]]:
            return self._p if kind == "validate.findings" else []

    def ev(adj_id: str, *codes: tuple[str, str]) -> dict[str, Any]:
        return {
            "adjudication_id": adj_id,
            "findings": [{"code": c, "severity": s} for c, s in codes],
        }

    def cell(payloads: list[dict[str, Any]], final: str | None) -> Any:
        return SimpleNamespace(
            view=_View(payloads), arm_run=SimpleNamespace(final_adjudication_id=final)
        )

    # a malformed EARLY iteration superseded by a clean final one does not count
    assert _validator_errors(
        cell([ev("adj-1", ("CLAIM_MISSING", "error")), ev("adj-2")], "adj-2")
    ) == (0, {})
    # ...and a clean early iteration does not excuse a malformed final one
    assert _validator_errors(
        cell([ev("adj-1"), ev("adj-2", ("CLAIM_MISSING", "error"))], "adj-2")
    ) == (1, {"CLAIM_MISSING": 1})
    # info severity is not an error: ESCALATED accompanies every legitimate
    # escalation and would otherwise mark every such cell malformed
    assert _validator_errors(cell([ev("adj-1", ("ESCALATED", "info"))], "adj-1")) == (0, {})
    # findings are a MULTISET - three of one code are three errors, not one
    assert _validator_errors(cell([ev("adj-1", *[("CLAIM_MISSING", "error")] * 3)], "adj-1")) == (
        3,
        {"CLAIM_MISSING": 3},
    )
    # TWO events share the final id: adjudication ids are deterministic, so a
    # crash after `validate.findings` and before `stage.finished` leaves a stale
    # event that the clean re-run reproduces under the SAME id. The LAST wins;
    # summing would let the abandoned attempt exclude the outcome that replaced it.
    assert _validator_errors(
        cell([ev("adj-1", ("CLAIM_MISSING", "error")), ev("adj-1")], "adj-1")
    ) == (0, {})
    assert _validator_errors(
        cell([ev("adj-1"), ev("adj-1", ("CLAIM_MISSING", "error"))], "adj-1")
    ) == (1, {"CLAIM_MISSING": 1})
    # no adjudication at all is UNKNOWN, never "clean"
    assert _validator_errors(cell([], None)) == (None, {})
    # an adjudication whose findings event is absent is also UNKNOWN
    assert _validator_errors(cell([ev("adj-other")], "adj-1")) == (None, {})


def test_an_adjudication_with_no_findings_event_is_excluded_not_scored() -> None:
    """M1, panel finding: `None` must have a CONSEQUENCE, not just a value.

    A cell with a final adjudication but no matching `validate.findings` event
    leaves the engine's verdict on that record unknown. Unknown is not clean, so
    it is excluded (`validator_unknown`) and cannot pair. A cell with NO
    adjudication at all (arm 1 has no judge) is different - there is nothing to
    vouch for - and stays scoreable.
    """
    from eval.score import CellScore, paired_deltas

    def cell(arm: str, errors: int | None, exclusion: str | None) -> Any:
        return CellScore(
            run_id=f"r-{arm}",
            task_id="t",
            arm=arm,
            repeat_index=0,
            category="control",
            included=exclusion is None,
            exclusion=exclusion,
            verdict="REVISE",
            verdict_basis="enforced",
            precision=0.5,
            recall=0.5,
            tp=1,
            fp=1,
            fn=1,
            distractor_hits=0,
            unsupported_claim_rate=0.0,
            downgrades=0,
            confident_wrong=False,
            abstained=False,
            expected_abstain=False,
            cost_spent_usd=1.0,
            cost_attributed_usd=1.0,
            cost_by_stage_spent={},
            cost_by_stage_attributed={},
            unknown_cost_records=0,
            wall_ms=1,
            attempts=1,
            propose_keys=["a" * 64],
            validator_errors=errors,
            validator_codes={},
            validator_basis="acted",
            propose_blobs={"a" * 64: ["sha"]},
            contaminated=False,
            scan_incomplete=False,
            rescan_contaminated=False,
            containment=None,
        )

    # an unknown-validator cell must not pair, even though its error count is falsy
    out = {
        p["pair"]: p
        for p in paired_deltas(
            [
                cell("indep_verify", 0, None),
                cell("indep_verify_critique", None, "validator_unknown"),
            ]
        )
    }
    assert out["4-3"]["paired"] is False
    assert out["4-3"]["reason"].startswith("validator errors/unknown:")
    assert "delta_recall" not in out["4-3"]

    # two well-formed cells still pair
    out = {
        p["pair"]: p
        for p in paired_deltas([cell("indep_verify", 0, None), cell("indep_verify_iter", 0, None)])
    }
    assert out["3b-3"]["paired"] is True


def test_a_cell_whose_findings_event_is_missing_is_excluded_end_to_end(tmp_path: Path) -> None:
    """M1, panel finding: the `validator_unknown` exclusion must fire on a real
    ledger, not only in a constructed CellScore.

    Rebuilds a scored cell's ledger without its `validate.findings` event. The
    adjudication is still there and still final, so the engine's verdict on that
    record is unknown - and unknown must not be scored as clean.
    """
    from eris.redact import Redactor
    from eris.writer import RunWriter as RW

    w = world(tmp_path)
    write_key(w)
    cdir = campaign(w, tmp_path, "indep_verify")
    cell = next(d for d in cdir.iterdir() if d.is_dir() and (d / "manifest.json").exists())
    events = cell / "events.jsonl"
    lines = [json.loads(line) for line in events.read_bytes().splitlines()]
    assert any(e["kind"] == "validate.findings" for e in lines), "fixture must have one to drop"
    kept = [e for e in lines if e["kind"] != "validate.findings"]

    (cell / "manifest.json").unlink()
    events.unlink()
    (cell / ".lock").unlink(missing_ok=True)
    rw = RW(cell, Redactor(), run_id=cell.name).open()
    for e in kept:
        rw.append(e["kind"], e["payload"])
    rw.finalize({"arm": "indep_verify"})

    summary = score_campaign(cdir, w["corpus"], home=tmp_path / "home")
    scored = next(c for c in summary["cells"] if c["run_id"] == cell.name)
    assert scored["validator_errors"] is None
    assert scored["exclusion"] == "validator_unknown"
    assert scored["included"] is False
    assert summary["per_arm"]["indep_verify"]["excluded"]["validator_unknown"] == 1


def test_comparison_is_blocked_when_an_arm_drops_cells_for_validator_findings() -> None:
    """M1, panel finding: EXCLUDING creates a new bias, so say so mechanically.

    Only arm 4 passes critiques to the validator, so only it can emit
    `DISSENT_EMPTY_WITH_CONTEST`. An arm that drops its malformed cells is left
    with a cleaner SUBSAMPLE and can win on catch rate against arms that kept
    theirs. Prose in EVAL-PLAN is advice; `summary.comparison.blocked` is a gate
    a reader cannot quote `per_arm[*].recall` without seeing.
    """
    from eval.score import CellScore, _comparison_block

    def cell(arm: str, exclusion: str | None) -> Any:
        return CellScore(
            run_id=f"r-{arm}-{exclusion}",
            task_id="t",
            arm=arm,
            repeat_index=0,
            category="control",
            included=exclusion is None,
            exclusion=exclusion,
            verdict="REVISE",
            verdict_basis="enforced",
            precision=0.5,
            recall=0.5,
            tp=1,
            fp=1,
            fn=1,
            distractor_hits=0,
            unsupported_claim_rate=0.0,
            downgrades=0,
            confident_wrong=False,
            abstained=False,
            expected_abstain=False,
            cost_spent_usd=1.0,
            cost_attributed_usd=1.0,
            cost_by_stage_spent={},
            cost_by_stage_attributed={},
            unknown_cost_records=0,
            wall_ms=1,
            attempts=1,
            propose_keys=[],
            validator_errors=0,
            validator_codes={},
            validator_basis="acted",
            propose_blobs={},
            contaminated=False,
            scan_incomplete=False,
            rescan_contaminated=False,
            containment=None,
        )

    clean = _comparison_block([cell("indep_verify", None), cell("indep_verify_critique", None)])
    assert clean["blocked"] is False and clean["reason"] is None

    biased = _comparison_block(
        [
            cell("indep_verify", None),
            cell("indep_verify_critique", None),
            cell("indep_verify_critique", "validator_errors"),
        ]
    )
    assert biased["blocked"] is True
    assert "indep_verify_critique" in biased["reason"] and "NOT comparable" in biased["reason"]
    assert biased["per_arm"]["indep_verify_critique"]["malformed_rate"] == 0.5
    assert biased["per_arm"]["indep_verify"]["malformed_rate"] == 0.0

    # `validator_unknown` counts too - an uncheckable record is not a clean one
    unknown = _comparison_block(
        [cell("indep_verify", None), cell("indep_verify_iter", "validator_unknown")]
    )
    assert unknown["blocked"] is True


def test_an_inert_REF_error_excludes_the_cell_even_though_its_code_is_handled() -> None:
    """M1, stop-gate finding: the scorer must use `acted`, not the code.

    `REF_MISSING` is in the HANDLED family - it downgrades a SUPPORTED ruling -
    but on a CONTESTED or UNSUPPORTED ruling it is flagged and then ignored. A
    code-keyed rule calls that handled and leaves the cell in the denominator,
    which is exactly the M1 hole. `acted: false` in the event is authoritative.
    """
    from types import SimpleNamespace

    from eval.score import _validator_errors

    class _View:
        def __init__(self, payloads: list[dict[str, Any]]) -> None:
            self._p = payloads

        def payloads(self, kind: str) -> list[dict[str, Any]]:
            return self._p if kind == "validate.findings" else []

    def cell(findings: list[dict[str, Any]]) -> Any:
        return SimpleNamespace(
            view=_View([{"adjudication_id": "adj-1", "findings": findings}]),
            arm_run=SimpleNamespace(final_adjudication_id="adj-1"),
        )

    inert = {"code": "REF_MISSING", "severity": "error", "acted": False}
    acted = {"code": "REF_MISSING", "severity": "error", "acted": True}

    # inert REF_MISSING counts, despite its code being in the "handled" family
    assert _validator_errors(cell([inert])) == (1, {"REF_MISSING": 1})
    # the same code, actually acted on, does not
    assert _validator_errors(cell([acted])) == (0, {})
    # mixed: only the inert one counts
    assert _validator_errors(cell([acted, inert, acted])) == (1, {"REF_MISSING": 1})
    # an acted VERDICT_* finding does not count either
    assert _validator_errors(
        cell([{"code": "VERDICT_UNSUPPORTED", "severity": "error", "acted": True}])
    ) == (0, {})

    # LEGACY ledger with no `acted` key falls back to the code set
    legacy_ref = {"code": "REF_MISSING", "severity": "error"}
    legacy_claim = {"code": "CLAIM_MISSING", "severity": "error"}
    assert _validator_errors(cell([legacy_ref])) == (0, {})  # coarse: assumed handled
    assert _validator_errors(cell([legacy_claim])) == (1, {"CLAIM_MISSING": 1})


def test_the_binding_pre_registration_matches_the_scorer() -> None:
    """`docs/EVAL-PLAN.md` must carry the scorer's OWN rule, verbatim.

    The pre-registration is binding on the experiment, so a rule stated there
    that the code does not implement is worse than one stated nowhere. It
    happened: after the exclusion rule moved from a code set to `Finding.acted`,
    the plan still said cells were excluded by `UNHANDLED_CODES` and that `REF_*`
    never excludes - both false, in the document the decision rule is read from.

    Whitespace is normalised so the plan may wrap the text; nothing else may
    differ. If the rule changes, this fails until the plan is updated too.
    """
    from eval.score import M1_PRE_REGISTRATION

    plan = (Path(__file__).resolve().parent.parent / "docs" / "EVAL-PLAN.md").read_text()
    norm = " ".join(plan.split())
    canonical = " ".join(M1_PRE_REGISTRATION.split())
    assert canonical in norm, (
        "docs/EVAL-PLAN.md does not carry eval/score.py::M1_PRE_REGISTRATION verbatim.\n"
        "The binding pre-registration must state the rule the scorer actually applies.\n"
        f"expected:\n{canonical}"
    )
    # ...and INSIDE the binding bullet, not merely somewhere after its heading.
    # The bullet runs from the heading to the next top-level `* ` item.
    head = plan.index("**Pre-registration notes (binding for the scorer):**")
    tail = plan.index("\n* ", head)
    bullet = " ".join(plan[head:tail].split())
    assert canonical in bullet, (
        "the M1 rule is in the document but OUTSIDE the binding bullet - a rule the "
        "decision maker is not obliged to read is advice again"
    )


def test_a_legacy_ledger_is_scored_coarsely_and_blocks_the_comparison() -> None:
    """M1, stop-gate finding: the binding rule must not contradict the code.

    The rule says `acted` is used "NOT inferred from its code" - but a ledger
    written before 0.4.2 carries no `acted`, so the scorer DOES fall back to the
    coarse code set, which calls every `REF_*` handled and under-reports
    malformation. Six real ledgers in `runs/` are of that vintage. The exception
    is now stated in the rule AND surfaced: such cells are reported as
    `validator_basis: "legacy_codes"` and block the comparison, because an arm
    scored by code and one scored by `acted` are measured against two different
    definitions of malformed.
    """
    from types import SimpleNamespace

    from eval.score import CellScore, _comparison_block, _validator_basis, _validator_errors

    class _View:
        def __init__(self, payloads: list[dict[str, Any]]) -> None:
            self._p = payloads

        def payloads(self, kind: str) -> list[dict[str, Any]]:
            return self._p if kind == "validate.findings" else []

    def cellview(findings: list[dict[str, Any]]) -> Any:
        return SimpleNamespace(
            view=_View([{"adjudication_id": "adj-1", "findings": findings}]),
            arm_run=SimpleNamespace(final_adjudication_id="adj-1"),
        )

    modern = cellview([{"code": "REF_MISSING", "severity": "error", "acted": False}])
    legacy = cellview([{"code": "REF_MISSING", "severity": "error"}])
    assert _validator_basis(modern) == "acted"
    assert _validator_basis(legacy) == "coarse_codes"

    # MIXED: classification is per FINDING, so one event can have some findings
    # classified exactly and some coarsely. Asking "does ANY finding carry
    # `acted`" reported such a cell as exact and hid the coarse ones, bypassing
    # the gate entirely. The basis is conservative: ALL, not ANY.
    mixed_f = cellview(
        [
            {"code": "VERDICT_UNSUPPORTED", "severity": "error", "acted": True},
            {"code": "REF_MISSING", "severity": "error"},  # no `acted` -> coarse
        ]
    )
    assert _validator_basis(mixed_f) == "coarse_codes", (
        "a cell with ANY finding lacking `acted` was classified coarsely at least once "
        "and must not report itself as exact"
    )
    # the same inert finding: exact on a modern ledger, invisible on a legacy one
    assert _validator_errors(modern) == (1, {"REF_MISSING": 1})
    assert _validator_errors(legacy) == (0, {})

    def score(arm: str, basis: str | None) -> Any:
        return CellScore(
            run_id=f"r-{arm}-{basis}",
            task_id="t",
            arm=arm,
            repeat_index=0,
            category="control",
            included=True,
            exclusion=None,
            verdict="REVISE",
            verdict_basis="enforced",
            precision=0.5,
            recall=0.5,
            tp=1,
            fp=1,
            fn=1,
            distractor_hits=0,
            unsupported_claim_rate=0.0,
            downgrades=0,
            confident_wrong=False,
            abstained=False,
            expected_abstain=False,
            cost_spent_usd=1.0,
            cost_attributed_usd=1.0,
            cost_by_stage_spent={},
            cost_by_stage_attributed={},
            unknown_cost_records=0,
            wall_ms=1,
            attempts=1,
            propose_keys=[],
            validator_errors=0,
            validator_codes={},
            validator_basis=basis,
            propose_blobs={},
            contaminated=False,
            scan_incomplete=False,
            rescan_contaminated=False,
            containment=None,
        )

    clean = _comparison_block([score("indep_verify", "acted"), score("indep_verify_iter", "acted")])
    assert clean["blocked"] is False

    mixed = _comparison_block(
        [score("indep_verify", "acted"), score("indep_verify_iter", "coarse_codes")]
    )
    assert mixed["blocked"] is True
    assert "indep_verify_iter" in mixed["reason"]
    assert "at least one finding lacks" in mixed["reason"]
    assert "under-reports malformation" in mixed["reason"]
    # the explanation must not claim the ledger has NO `acted` - a mixed cell has some
    assert "ledgers with no" not in mixed["reason"]
    assert mixed["per_arm"]["indep_verify_iter"]["coarsely_scored_cells"] == 1
    assert mixed["per_arm"]["indep_verify"]["coarsely_scored_cells"] == 0

    # a MIXED cell reports `legacy_codes`, so the gate fires on it too
    assert (
        _comparison_block(
            [score("indep_verify", "acted"), score("indep_verify_iter", _validator_basis(mixed_f))]
        )["blocked"]
        is True
    )


def test_the_gate_explanation_is_true_for_a_mixed_cell() -> None:
    """A gate that fires for the right reason must also SAY the right reason.

    The first wording said the arm "has cells from ledgers with no
    `Finding.acted`". For a cell that MIXES findings carrying `acted` with
    findings that do not, that is false twice over - the ledger does have
    `acted`, and only some findings were classified coarsely. A reader would
    hunt for a pre-0.4.2 ledger and find none, and conclude the gate was wrong.
    """
    from eval.score import CellScore, _comparison_block

    def score(arm: str, basis: str | None) -> Any:
        return CellScore(
            run_id=f"r-{arm}",
            task_id="t",
            arm=arm,
            repeat_index=0,
            category="control",
            included=True,
            exclusion=None,
            verdict="REVISE",
            verdict_basis="enforced",
            precision=0.5,
            recall=0.5,
            tp=1,
            fp=1,
            fn=1,
            distractor_hits=0,
            unsupported_claim_rate=0.0,
            downgrades=0,
            confident_wrong=False,
            abstained=False,
            expected_abstain=False,
            cost_spent_usd=1.0,
            cost_attributed_usd=1.0,
            cost_by_stage_spent={},
            cost_by_stage_attributed={},
            unknown_cost_records=0,
            wall_ms=1,
            attempts=1,
            propose_keys=[],
            validator_errors=0,
            validator_codes={},
            validator_basis=basis,
            propose_blobs={},
            contaminated=False,
            scan_incomplete=False,
            rescan_contaminated=False,
            containment=None,
        )

    block = _comparison_block(
        [score("indep_verify", "acted"), score("indep_verify_critique", "coarse_codes")]
    )
    assert block["blocked"] is True
    reason = block["reason"]
    # true of BOTH causes: an old ledger and a mixed cell
    assert "at least one finding lacks" in reason
    assert "written before 0.4.2, or a cell mixing findings" in reason
    # and it must not assert the stronger, sometimes-false claim. Case-insensitive:
    # the first version of this check missed a mutation that only changed "ledgers"
    # to "Ledgers".
    low = reason.lower()
    assert "ledgers with no `finding.acted`" not in low
    assert "with no `finding.acted`" not in low
    assert block["per_arm"]["indep_verify_critique"]["coarsely_scored_cells"] == 1
