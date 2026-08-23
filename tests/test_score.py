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
        "eris.schemas",
    }, names
    forbidden = {
        "subprocess",
        "socket",
        "httpx",
        "os",
        "shutil",
        "asyncio",
        "eris.launch",
        "eris.verify",
    }
    assert not (names & forbidden)
    body = SCORE_PY.read_text().replace(ast.get_docstring(tree) or "", "")
    assert "os.system" not in body and "os.popen" not in body and "Popen" not in body
    # the transitive closure of the scorer's eris imports never reaches the launcher/verifier
    import importlib

    for mod in ("eris.ledger", "eris.scan", "eris.schemas"):
        module = importlib.import_module(mod)
        src = Path(module.__file__ or "").read_text()
        imports = {
            n.module for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ImportFrom) and n.module
        } | {a.name for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Import) for a in n.names}
        assert not ({"eris.launch", "eris.verify", "subprocess", "socket", "httpx"} & imports), mod


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
    assert all(c["included"] for c in by.values())
    # arm 1: findings from the proposal, no verdict
    assert (
        by["single"]["verdict"] is None
        and by["single"]["tp"] == 1
        and by["single"]["recall"] == 1.0
    )
    # arm 2: raw verdict (the summarizer's ACCEPT), confident-wrong since ACCEPT is off-key
    assert by["consensus"]["verdict_basis"] == "raw" and by["consensus"]["verdict"] == "ACCEPT"
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
    # paired deltas exist for 3b-3 and 4-3 and are paired (identical propose keys)
    pairs = {p["pair"]: p for p in summary["paired"]}
    assert set(pairs) == {"3b-3", "4-3"} and all(p["paired"] for p in pairs.values())
    assert pairs["4-3"]["delta_recall"] == 0.0 and "delta_cost_spent_usd" in pairs["4-3"]
    per_arm = summary["per_arm"]
    assert (
        per_arm["single"]["recall"] == 1.0 and per_arm["consensus"]["confident_wrong_rate"] == 1.0
    )
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
    def cell(arm: str, keys: list[str], included: bool = True, recall: float | None = 0.5) -> Any:
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
