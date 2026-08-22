from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
from pydantic import ValidationError

from eris.schemas import (
    RECORD_TYPES,
    SCHEMA_VERSION,
    Adjudication,
    Claim,
    Event,
    Invocation,
    Origin,
    Record,
    Task,
    Verdict,
    canonical_bytes,
    now_ts,
    parse_ts,
    record_sha256,
)
from tests.examples import T1, example_records

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "records" / SCHEMA_VERSION


@pytest.mark.parametrize("name", sorted(example_records()))
def test_golden_bytes_pinned(name: str) -> None:
    """canonical_bytes(example) must equal the committed golden file byte for byte."""
    record = example_records()[name]
    golden = (GOLDEN_DIR / f"{name}.json").read_bytes()
    assert canonical_bytes(record) == golden, (
        f"serialization of {name} changed; if intended, bump SCHEMA_VERSION and regenerate"
    )


@pytest.mark.parametrize("name", sorted(example_records()))
def test_golden_round_trip(name: str) -> None:
    record = example_records()[name]
    parsed = type(record).model_validate_json((GOLDEN_DIR / f"{name}.json").read_bytes())
    assert parsed == record
    assert record_sha256(parsed) == record_sha256(record)


def test_every_record_type_has_a_golden_file() -> None:
    covered = {type(r) for r in example_records().values()}
    assert covered == set(RECORD_TYPES)


def test_every_record_carries_origin_and_schema_version() -> None:
    for record in example_records().values():
        data = json.loads(canonical_bytes(record))
        assert data["schema_version"] == SCHEMA_VERSION
        assert data["origin"] in {o.value for o in Origin}


def test_canonical_bytes_are_sorted_compact_utf8() -> None:
    data = canonical_bytes({"b": 1, "a": {"z": [1, 2], "y": "é"}})
    assert data == '{"a":{"y":"é","z":[1,2]},"b":1}'.encode()


def test_canonical_bytes_refuse_nan() -> None:
    with pytest.raises(ValueError):
        canonical_bytes({"x": math.nan})


def test_extra_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        Task.model_validate({**example_records()["task"].model_dump(), "surprise": 1})


def test_records_are_frozen() -> None:
    task = example_records()["task"]
    with pytest.raises(ValidationError):
        task.task_id = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    "bad",
    ["2026-08-21 10:00:00Z", "2026-08-21T10:00:00", "2026-08-21T10:00:00+00:00", "now"],
)
def test_timestamps_must_be_rfc3339_z(bad: str) -> None:
    with pytest.raises(ValidationError):
        Claim(claim_id="c", text="t", revised_at=bad)
    with pytest.raises(ValueError):
        parse_ts(bad)


def test_now_ts_round_trips() -> None:
    ts = now_ts()
    assert parse_ts(ts).tzinfo is not None
    assert parse_ts(T1).microsecond == 250000


def test_origin_cannot_be_blurred() -> None:
    with pytest.raises(ValidationError):
        Claim(claim_id="c", text="t", revised_at=T1, origin="observed")  # type: ignore[arg-type]


def test_adjudication_allows_empty_dissent_and_risks() -> None:
    """Honest ABSTAIN must be expressible: empty lists are schema-valid."""
    adj = Adjudication(
        adjudication_id="a",
        task_id="t",
        invocation_id=None,
        verdict=Verdict.ABSTAIN,
        rulings=[],
        dissent=[],
        residual_risks=[],
    )
    assert adj.dissent == [] and adj.residual_risks == []
    with pytest.raises(ValidationError):
        Adjudication.model_validate(
            {
                "adjudication_id": "a",
                "task_id": "t",
                "invocation_id": None,
                "verdict": "ABSTAIN",
                "rulings": [],
            }
        )


def test_event_prev_sha_may_be_none_only_as_explicit_null() -> None:
    ev = Event(
        seq=0,
        ts=T1,
        run_id="r",
        kind="run.started",
        prev_sha256=None,
        payload_sha256="0" * 64,
        payload={},
    )
    assert b'"prev_sha256":null' in canonical_bytes(ev)
    with pytest.raises(ValidationError):
        Event(
            seq=0,
            ts=T1,
            run_id="r",
            kind="Bad Kind",
            prev_sha256=None,
            payload_sha256="0" * 64,
            payload={},
        )


def test_record_base_requires_origin() -> None:
    class Minimal(Record):
        x: int

    with pytest.raises(ValidationError):
        Minimal(x=1)
    assert Minimal(x=1, origin=Origin.HUMAN_ENTERED).origin is Origin.HUMAN_ENTERED


# --------------------------------------------------------------------------- versioning

RECORDS_ROOT = Path(__file__).parent / "fixtures" / "records"


def _manifest() -> dict[str, dict[str, str]]:
    return json.loads((RECORDS_ROOT / "MANIFEST.json").read_text())  # type: ignore[no-any-return]


def test_committed_goldens_are_immutable() -> None:
    """Every golden of every committed SCHEMA_VERSION must hash exactly as
    MANIFEST.json records. Changing a record's serialization requires a NEW
    version directory + manifest entry, never editing an old golden."""
    import hashlib

    manifest = _manifest()
    on_disk = {
        d.name: {
            f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(d.glob("*.json"))
        }
        for d in RECORDS_ROOT.iterdir()
        if d.is_dir()
    }
    assert on_disk == manifest, "golden fixtures drifted from MANIFEST.json"


def test_current_schema_version_has_a_manifest_entry() -> None:
    assert SCHEMA_VERSION in _manifest()
    assert sorted(_manifest()[SCHEMA_VERSION]) == sorted(f"{n}.json" for n in example_records())


# sha256 of the canonical JSON of each HISTORICAL manifest block, taken before
# 0.1.2 was added. These pin the manifest entries themselves so that editing a
# committed golden together with its manifest line is still caught.
HISTORICAL_MANIFEST_BLOCKS = {
    "0.1.0": "46df57acc986804a99037db9fb21e8070e4c7944a31cf21e88d90752fb3b5c0c",
    "0.1.1": "715e86bccfd674c7743c4e722bdd3f5081060002608a312cc0314b8a154c464e",
}


def test_historical_goldens_are_byte_identical_to_their_pinned_manifest() -> None:
    """0.1.0 and 0.1.1 were committed before the 0.1.2 bump and must never
    change: their manifest blocks hash to the values pinned here, and every
    file on disk still hashes to its manifest line."""
    import hashlib

    manifest = _manifest()
    for version, expected in HISTORICAL_MANIFEST_BLOCKS.items():
        block = json.dumps(manifest[version], sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(block).hexdigest() == expected, f"manifest block {version} edited"
        for name, digest in manifest[version].items():
            on_disk = hashlib.sha256((RECORDS_ROOT / version / name).read_bytes()).hexdigest()
            assert on_disk == digest, f"{version}/{name} edited"
    assert SCHEMA_VERSION not in HISTORICAL_MANIFEST_BLOCKS  # the current version is pinned above


def test_invocation_0_1_2_fields() -> None:
    """0.1.2 added ``conversation_id`` and ``worker_reported_duration_ms``
    (both optional, default None). The 0.1.2 golden exercises them; the 0.1.1
    golden has no such keys (the serialization changed, hence the bump)."""
    inv = example_records()["invocation"]
    data = json.loads(canonical_bytes(inv))
    assert data["conversation_id"] == "ed889929-a04c-457f-91d1-194be848aa04"
    assert data["worker_reported_duration_ms"] == 2646 and data["duration_ms"] == 300250
    old = json.loads((RECORDS_ROOT / "0.1.1" / "invocation.json").read_bytes())
    assert "conversation_id" not in old and "worker_reported_duration_ms" not in old
    bare = Invocation.model_validate(
        {
            k: v
            for k, v in data.items()
            if k not in ("conversation_id", "worker_reported_duration_ms")
        }
    )
    assert bare.conversation_id is None and bare.worker_reported_duration_ms is None
    with pytest.raises(ValidationError):
        Invocation.model_validate({**data, "worker_reported_duration_ms": -1})


def test_old_schema_versions_are_rejected_on_parse() -> None:
    """No migrations in 0.x: a record carrying any other schema_version fails."""
    older = sorted(v for v in _manifest() if v != SCHEMA_VERSION)
    assert older, "expected at least one historical schema version directory"
    for version in older:
        raw = (RECORDS_ROOT / version / "task.json").read_bytes()
        assert json.loads(raw)["schema_version"] == version
        with pytest.raises(ValidationError):
            Task.model_validate_json(raw)
    with pytest.raises(ValidationError):
        Task.model_validate({**example_records()["task"].model_dump(), "schema_version": "9.9.9"})
