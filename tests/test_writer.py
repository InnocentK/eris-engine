from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from eris.redact import Redactor
from eris.schemas import SCHEMA_VERSION, Event, canonical_bytes, sha256_hex
from eris.validate import validate_events
from eris.writer import (
    LedgerInvalid,
    RunExists,
    RunWriter,
    WriterClosed,
    WriterError,
    WriterLocked,
)
from tests.examples import example_records

SECRET = "sk-proj-" + "Qx7" * 16
EXACT = "exact-secret-value-from-dotenv"
TS = iter(f"2026-08-21T10:00:{i:02d}Z" for i in range(60))


def clock() -> str:
    return next(TS)


def make_writer(tmp_path: Path, **kw: object) -> RunWriter:
    return RunWriter(tmp_path / "run_01", Redactor([EXACT]), clock=clock, **kw)  # type: ignore[arg-type]


def read_lines(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines(keepends=True)


# --------------------------------------------------------------------------- chain


def test_seq_and_prev_sha_chain_validate(tmp_path: Path) -> None:
    with make_writer(tmp_path) as w:
        e0 = w.append("run.started", {"a": 1})
        e1 = w.append("invocation.finished", example_records()["invocation"])
        e2 = w.append("run.finished", {"z": None})
        assert w.seq == 3
    lines = read_lines(w.events_path)
    assert [e.seq for e in (e0, e1, e2)] == [0, 1, 2]
    assert e0.prev_sha256 is None
    assert e1.prev_sha256 == sha256_hex(lines[0].rstrip(b"\n"))
    assert e2.prev_sha256 == sha256_hex(lines[1].rstrip(b"\n"))
    assert validate_events(lines) == []
    for line in lines:
        ev = Event.model_validate_json(line)
        assert ev.schema_version == SCHEMA_VERSION and ev.run_id == "run_01"
        assert ev.payload_sha256 == sha256_hex(canonical_bytes(ev.payload))


def test_fsync_is_called_for_every_durable_write(tmp_path: Path) -> None:
    calls: list[int] = []

    def fsync(fd: int) -> None:
        calls.append(fd)
        os.fsync(fd)

    w = RunWriter(tmp_path / "r", Redactor(), fsync=fsync, clock=clock).open()
    w.append("k", {"x": 1})
    n_after_append = len(calls)
    assert n_after_append == 1  # the events file
    w.put_blob(b"hello")
    assert len(calls) == n_after_append + 2  # blob file + blobs dir
    w.finalize()
    assert len(calls) == n_after_append + 4  # manifest file + run dir


# --------------------------------------------------------------------------- blobs


def test_put_blob_is_redacted_before_hashing_and_atomic(tmp_path: Path) -> None:
    with make_writer(tmp_path) as w:
        ref = w.put_blob(f"out {SECRET} and {EXACT}\n".encode())
        again = w.put_blob(f"out {SECRET} and {EXACT}\n".encode())
    assert ref == again  # content-addressed: redacted bytes hash equal
    assert ref.redaction_counts == {"openai_key": 1, "exact": 1}
    data = ref.path.read_bytes()
    assert sha256_hex(data) == ref.sha256 and ref.size_bytes == len(data)
    assert SECRET.encode() not in data and EXACT.encode() not in data
    assert b"[REDACTED:openai_key#1]" in data
    assert ref.sha256 != sha256_hex(f"out {SECRET} and {EXACT}\n".encode())
    assert list(w.blobs_dir.iterdir()) == [ref.path]  # no temp files left


def test_write_failure_raises_and_leaves_no_partial_blob(tmp_path: Path) -> None:
    boom = OSError("disk full")

    def fsync(_fd: int) -> None:
        raise boom

    w = RunWriter(tmp_path / "r", Redactor(), fsync=fsync, clock=clock).open()
    with pytest.raises(OSError, match="disk full"):
        w.put_blob(b"payload")
    assert list(w.blobs_dir.iterdir()) == []
    with pytest.raises(OSError, match="disk full"):
        w.append("k", {"x": 1})
    with pytest.raises(OSError, match="disk full"):
        w.finalize()
    assert not w.manifest_path.exists()
    assert not any(p.name.startswith(".manifest") for p in w.run_dir.iterdir())
    w.close()


# --------------------------------------------------------------------------- finalize


def test_finalize_writes_manifest_last_and_closes(tmp_path: Path) -> None:
    w = make_writer(tmp_path).open()
    w.append("k", {"x": 1})
    blob = w.put_blob(b"b")
    assert not w.manifest_path.exists()
    path = w.finalize({"note": f"extra {EXACT}"})
    manifest = json.loads(path.read_bytes())
    assert manifest["event_count"] == 1 and manifest["last_sha256"] == w.last_sha256
    assert manifest["blobs"] == [{"sha256": blob.sha256, "size_bytes": 1}]
    assert manifest["extra"] == {"note": "extra [REDACTED:exact#1]"}
    assert manifest["schema_version"] == SCHEMA_VERSION
    with pytest.raises(WriterClosed):
        w.append("k", {})
    with pytest.raises(WriterClosed):
        w.put_blob(b"")
    with pytest.raises(RunExists):
        make_writer(tmp_path, resume=True).open()


# --------------------------------------------------------------------------- resume


def test_torn_tail_truncated_only_on_resume(tmp_path: Path) -> None:
    w = make_writer(tmp_path).open()
    w.append("k", {"n": 0})
    w.append("k", {"n": 1})
    w.close()
    with open(w.events_path, "ab") as fh:
        fh.write(b'{"seq":2,"ts":"2026-08-21T10:00:00Z","run_id":"run_01","kind":"k","prev_sha')
    with pytest.raises(RunExists):
        make_writer(tmp_path).open()  # no resume -> refuse, file untouched
    assert read_lines(w.events_path)[-1].startswith(b'{"seq":2')
    r = make_writer(tmp_path, resume=True).open()
    assert r.torn_tail_truncated is True and r.resumed_from_seq == 2 and r.seq == 2
    lines = read_lines(r.events_path)
    assert len(lines) == 2 and all(line.endswith(b"\n") for line in lines)
    ev = r.append("k", {"n": 2})
    assert ev.seq == 2 and ev.prev_sha256 == sha256_hex(lines[1].rstrip(b"\n"))
    r.finalize()
    assert validate_events(read_lines(r.events_path)) == []
    assert json.loads(r.manifest_path.read_bytes())["torn_tail_truncated"] is True


def test_complete_but_unparsable_last_line_is_a_torn_tail(tmp_path: Path) -> None:
    w = make_writer(tmp_path).open()
    w.append("k", {"n": 0})
    w.close()
    with open(w.events_path, "ab") as fh:
        fh.write(b"{garbage\n")
    r = make_writer(tmp_path, resume=True).open()
    assert r.torn_tail_truncated and r.seq == 1
    r.close()


def test_malformed_middle_line_is_invalid(tmp_path: Path) -> None:
    w = make_writer(tmp_path).open()
    for i in range(3):
        w.append("k", {"n": i})
    w.close()
    original = read_lines(w.events_path)
    lines = list(original)
    lines[1] = b"{not json}\n"
    w.events_path.write_bytes(b"".join(lines))
    with pytest.raises(LedgerInvalid, match="MALFORMED_LINE"):
        make_writer(tmp_path, resume=True).open()
    assert read_lines(w.events_path) == lines  # refused, not truncated
    # tampering (valid JSON, broken chain) is also invalid
    lines = list(original)
    data = json.loads(lines[1])
    data["payload"]["n"] = 99
    lines[1] = canonical_bytes(data) + b"\n"
    w.events_path.write_bytes(b"".join(lines))
    with pytest.raises(LedgerInvalid, match="HASH_MISMATCH"):
        make_writer(tmp_path, resume=True).open()
    assert not (tmp_path / "run_01" / ".lock").is_dir()


def test_resume_reindexes_blobs_and_drops_abandoned_temp(tmp_path: Path) -> None:
    w = make_writer(tmp_path).open()
    ref = w.put_blob(b"keep me")
    w.append("k", {})
    w.close()
    (w.blobs_dir / ".deadbeef.tmp").write_bytes(b"partial")
    r = make_writer(tmp_path, resume=True).open()
    assert not (w.blobs_dir / ".deadbeef.tmp").exists()
    assert r.put_blob(b"keep me").sha256 == ref.sha256
    r.close()


def test_resume_of_empty_file_is_fine(tmp_path: Path) -> None:
    w = make_writer(tmp_path).open()
    w.close()
    r = make_writer(tmp_path, resume=True).open()
    assert r.seq == 0 and r.last_sha256 is None and not r.torn_tail_truncated
    r.close()


# --------------------------------------------------------------------------- lock


def test_lock_is_single_writer_in_process(tmp_path: Path) -> None:
    w = make_writer(tmp_path).open()
    with pytest.raises(WriterLocked):
        make_writer(tmp_path, resume=True).open()
    w.close()
    r = make_writer(tmp_path, resume=True).open()  # released on close
    r.close()


CHILD = """
import sys
from pathlib import Path
from eris.redact import Redactor
from eris.writer import RunWriter, WriterLocked
try:
    RunWriter(Path(sys.argv[1]), Redactor(), resume=True).open()
except WriterLocked:
    print("LOCKED")
else:
    print("ACQUIRED")
"""


@pytest.mark.real_subprocess
def test_lock_is_single_writer_across_processes(tmp_path: Path) -> None:
    w = make_writer(tmp_path).open()
    out = subprocess.run(
        [sys.executable, "-c", CHILD, str(w.run_dir)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert out.stdout.strip() == "LOCKED", out.stderr
    w.close()
    out = subprocess.run(
        [sys.executable, "-c", CHILD, str(w.run_dir)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert out.stdout.strip() == "ACQUIRED", out.stderr


# --------------------------------------------------------------------------- secrets on disk


def test_no_secret_anywhere_on_disk(tmp_path: Path) -> None:
    secrets = [SECRET, EXACT, "xai-" + "Lm4" * 12]
    b64 = base64.b64encode(secrets[0].encode()).decode()
    with make_writer(tmp_path) as w:
        w.put_blob(" ".join(secrets).encode())
        w.put_blob(f"\x1b[31m{secrets[0][:10]}\x1b[0m{secrets[0][10:]}".encode())
        w.put_blob(f"b64 {b64}".encode())
        w.append("k", {"stdout": secrets[1], "nested": {"list": secrets}})
        w.finalize({"argv": ["--key", secrets[2]]})
    for path in (tmp_path / "run_01").rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            for s in secrets:
                assert s.encode() not in data, f"{s[:6]}... leaked into {path.name}"
                assert s[-10:].encode() not in data
            assert b64.encode() not in data


def test_writer_error_hierarchy() -> None:
    assert issubclass(WriterLocked, WriterError)
    assert issubclass(LedgerInvalid, WriterError)
    assert issubclass(RunExists, WriterError)
    assert issubclass(WriterClosed, WriterError)
