"""eris.scan: run-time pattern derivation, distinctiveness, coverage
(blobs, event payloads, pack, cache entries), scan_incomplete, and the
ledger never carrying pattern text."""

from __future__ import annotations

import json
from pathlib import Path

from eris.redact import Redactor
from eris.scan import (
    BUILTIN_MARKERS,
    MIN_PATTERN_CHARS,
    PatternSet,
    build_patterns,
    fold,
    scan_and_record,
    scan_run,
    scan_text,
)
from eris.schemas import ScanResult, WorkerStatus, canonical_bytes, sha256_hex
from eris.validate import validate_events
from eris.writer import RunWriter
from tests.examples import example_records

FIX_HUNK = "    if response.text is None:  # planted null guard"
SECOND_HUNK = "        return _fallback_answer(prompt, retries=3)"
SOURCE_REPO = "/Users/USER/Documents/Projects/Claude/Athena/athena-assistant"


def snapshot(tmp_path: Path) -> Path:
    root = tmp_path / "snap"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("def handler(x):\n    return x\n\ncommon phrase here\n")
    (root / "README.md").write_text("present-in-the-tree-already\n")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text(FIX_HUNK + "\n")  # .git is never consulted
    return root


def patterns(tmp_path: Path, **kw: object) -> PatternSet:
    args: dict[str, object] = {
        "snapshot_root": snapshot(tmp_path)
        if not (tmp_path / "snap").exists()
        else tmp_path / "snap",
        "home": tmp_path / "home",
        "source_repo": SOURCE_REPO,
        "fix_hunk_lines": [FIX_HUNK, SECOND_HUNK],
        "extra_strings": ["CANARY-7f3a9c2e-eris-e1"],
    }
    args.update(kw)
    return build_patterns(**args)  # type: ignore[arg-type]


def test_patterns_are_derived_at_runtime_and_folded(tmp_path: Path) -> None:
    ps = patterns(tmp_path)
    folded = {p.folded for p in ps.patterns}
    assert fold(FIX_HUNK) in folded and fold(SECOND_HUNK) in folded
    assert SOURCE_REPO in folded and "CANARY-7f3a9c2e-eris-e1" in folded
    assert {str(tmp_path / "home" / r) for r in (".claude/projects", ".codex/sessions")} <= folded
    assert str(tmp_path / "home" / ".gemini/antigravity-cli/brain") in folded
    assert set(BUILTIN_MARKERS) <= folded  # short markers are exempt from the length floor
    for p in ps.patterns:
        assert p.sha256 == sha256_hex(p.folded.encode()) and p.folded == fold(p.folded)
    assert (
        len(ps.patterns_sha256) == 64 and ps.patterns_sha256 == patterns(tmp_path).patterns_sha256
    )
    # must_mention-like strings are simply not an input; the API has no such parameter
    assert "must_mention" not in build_patterns.__code__.co_varnames


def test_nondistinctive_patterns_are_dropped_and_counted(tmp_path: Path) -> None:
    ps = patterns(
        tmp_path,
        extra_strings=[
            "return",  # a common word: too short
            "x" * (MIN_PATTERN_CHARS - 1),
            "common phrase here",  # present in the pre-fix tree (src/app.py)
            "present-in-the-tree-already",  # README.md
            FIX_HUNK,  # duplicate of a fix hunk: merged, not counted as dropped
            "   if response.text is None:   # planted null guard  ",  # same after folding
        ],
    )
    folded = {p.folded for p in ps.patterns}
    assert "return" not in folded and "common phrase here" not in folded
    assert "present-in-the-tree-already" not in folded
    assert fold(FIX_HUNK) in folded
    assert ps.dropped_reasons["too_short"] == 2 and ps.dropped_reasons["in_pre_fix_tree"] == 2
    assert ps.dropped_reasons["duplicate"] == 2
    assert ps.dropped_nondistinctive == 4
    # a fix hunk that the pre-fix tree already contains is dropped too (it cannot discriminate)
    ps2 = patterns(tmp_path, fix_hunk_lines=["def handler(x):"])
    assert "def handler(x):" not in {p.folded for p in ps2.patterns}
    assert ps2.dropped_reasons["in_pre_fix_tree"] == 1


def test_harness_own_paths_cannot_be_patterns(tmp_path: Path) -> None:
    """Eris records the snapshot path in run.started and Invocation.cwd; a
    marker those necessarily contain (a snapshot under eval/corpus/) would
    flag every run, so it is dropped as non-distinctive and counted."""
    snap = tmp_path / "eval" / "corpus" / "t_01" / "snapshot"
    snap.mkdir(parents=True)
    ps = build_patterns(
        snapshot_root=snap, home=tmp_path / "home", known_texts=[str(snap), str(tmp_path / "runs")]
    )
    folded = {p.folded for p in ps.patterns}
    assert "eval/corpus/" not in folded and "key.json" in folded and "athena-assistant" in folded
    assert ps.dropped_reasons["in_known_texts"] == 1
    # without the known texts the marker survives
    assert "eval/corpus/" in {
        p.folded for p in build_patterns(snapshot_root=snap, home=tmp_path).patterns
    }


def test_scan_text_folds_whitespace_and_counts(tmp_path: Path) -> None:
    ps = patterns(tmp_path)
    sha = sha256_hex(fold(FIX_HUNK).encode())
    wrapped = "if response.text\n    is None:  #\tplanted   null guard"
    assert scan_text(wrapped, ps) == {sha: 1}
    assert scan_text(wrapped + "\n" + wrapped, ps)[sha] == 2
    assert scan_text("nothing to see", ps) == {}
    assert scan_text("", PatternSet((), 0, {})) == {}


def test_scan_covers_blobs_events_pack_and_cache_and_records_hashes_only(tmp_path: Path) -> None:
    ps = patterns(tmp_path)
    w = RunWriter(tmp_path / "runs" / "r1", Redactor(), run_id="r1").open()
    w.append("run.started", {"snapshot": str(tmp_path / "snap")})
    w.put_blob(b"clean output\n")
    dirty = w.put_blob(f"worker said:\n{FIX_HUNK}\nand also {SOURCE_REPO}/x.py\n".encode())
    w.append("proposal.raw", {"text": f"I read {SECOND_HUNK} somewhere"})
    inv = example_records()["invocation"].model_copy(update={"stdout_truncated": False})
    w.append("invocation.finished", inv)
    pack = "evidence: " + FIX_HUNK
    cache_entry = json.dumps({"text": "CANARY-7f3a9c2e-eris-e1"})
    result = scan_and_record(w, ps, extra_texts={"pack": pack, f"cache:{'a' * 64}": cache_entry})
    assert result.contaminated and not result.scan_incomplete
    assert result.scanned_blobs == 2 and result.scanned_events == 3
    assert result.pattern_count == ps.count and result.patterns_sha256 == ps.patterns_sha256
    where = {(h.where, h.pattern_sha256): h.count for h in result.hits}
    fix_sha = sha256_hex(fold(FIX_HUNK).encode())
    second_sha = sha256_hex(fold(SECOND_HUNK).encode())
    repo_sha = sha256_hex(SOURCE_REPO.encode())
    canary_sha = sha256_hex(b"CANARY-7f3a9c2e-eris-e1")
    assert where[(f"blob:{dirty.sha256}", fix_sha)] == 1
    assert where[(f"blob:{dirty.sha256}", repo_sha)] == 1
    assert where[("event:1", second_sha)] == 1  # proposal.raw payload (seq 1)
    assert where[("pack", fix_sha)] == 1 and where[(f"cache:{'a' * 64}", canary_sha)] == 1
    # the scan.result event carries hashes + counts only; no pattern text anywhere in it
    lines = w.events_path.read_bytes().splitlines(keepends=True)
    assert validate_events(lines) == []
    last = json.loads(lines[-1])
    assert last["kind"] == "scan.result"
    recorded = ScanResult.model_validate(last["payload"])
    assert recorded == result
    blob = canonical_bytes(result).decode()
    for p in ps.patterns:
        assert p.folded not in blob and p.folded not in json.dumps(last)
    w.close()
    # no fix-hunk or source-path text under runs/ except the worker's own blob/payload
    # (those ARE the contamination evidence); the ledger's scan line has none
    assert fold(FIX_HUNK) not in lines[-1].decode() and SOURCE_REPO not in lines[-1].decode()


def test_rescanning_over_the_scan_event_itself_adds_no_hits(tmp_path: Path) -> None:
    ps = patterns(tmp_path)
    w = RunWriter(tmp_path / "runs" / "r2", Redactor(), run_id="r2").open()
    w.put_blob(f"{FIX_HUNK}\n".encode())
    first = scan_and_record(w, ps)
    second = scan_and_record(w, ps)  # the ledger now contains the first scan.result event
    assert first.contaminated and second.contaminated
    assert {(h.where, h.pattern_sha256, h.count) for h in second.hits} == {
        (h.where, h.pattern_sha256, h.count) for h in first.hits
    }
    assert second.scanned_events == first.scanned_events + 1  # it DID scan the scan event
    w.close()
    # a read-only re-scan (what score.py does) over the finalized dir agrees
    again = scan_run(events_path=w.events_path, blobs_dir=w.blobs_dir, patterns=ps, run_id="r2")
    assert again.hits[0].pattern_sha256 == first.hits[0].pattern_sha256
    assert again.scanned_events == second.scanned_events + 1


def test_scan_incomplete_on_truncated_stdout_or_empty_timeout(tmp_path: Path) -> None:
    ps = patterns(tmp_path)
    inv = example_records()["invocation"]
    for update in (
        {"stdout_truncated": True},
        {"status": WorkerStatus.TIMEOUT, "timed_out": True, "stdout_sha256": None},
    ):
        w = RunWriter(tmp_path / "runs" / f"r-{len(update)}", Redactor(), run_id="x").open()
        w.append("invocation.finished", inv.model_copy(update=update))
        res = scan_and_record(w, ps)
        w.close()
        assert res.scan_incomplete and not res.contaminated
    w = RunWriter(tmp_path / "runs" / "r-ok", Redactor(), run_id="x").open()
    w.append(
        "invocation.finished",
        inv.model_copy(update={"status": WorkerStatus.TIMEOUT, "timed_out": True}),
    )
    assert not scan_and_record(w, ps).scan_incomplete  # a timeout WITH stdout is scannable
    w.close()


def test_scan_run_tolerates_missing_dirs_malformed_lines_and_symlinked_blobs(
    tmp_path: Path,
) -> None:
    ps = patterns(tmp_path)
    empty = scan_run(
        events_path=tmp_path / "none.jsonl", blobs_dir=tmp_path / "noblobs", patterns=ps, run_id="e"
    )
    assert not empty.contaminated and empty.scanned_blobs == 0 and empty.scanned_events == 0
    assert empty.scan_id.startswith("scan-e-")
    run = tmp_path / "r"
    (run / "blobs" / "sha256").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text(FIX_HUNK)
    (run / "blobs" / "sha256" / ("b" * 64)).symlink_to(outside)  # never followed
    (run / "blobs" / "sha256" / ".tmp").write_text(FIX_HUNK)  # temp files skipped
    (run / "events.jsonl").write_bytes(b"{not json " + FIX_HUNK.encode() + b"\n\n[1,2]\n")
    res = scan_run(
        events_path=run / "events.jsonl",
        blobs_dir=run / "blobs" / "sha256",
        patterns=ps,
        run_id="r",
    )
    assert res.scanned_blobs == 0 and res.scanned_events == 2
    assert [h.where for h in res.hits] == ["line:0"]  # raw malformed line is still scanned
