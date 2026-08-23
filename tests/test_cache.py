"""eris.cache: store-once / hit requirements / refusals / replay."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from eris.cache import (
    Cache,
    CacheError,
    CacheHit,
    CacheMiss,
    CacheRefused,
    CacheUnsupported,
    replay_hit,
)
from eris.launch import WorkerResult, idempotency_material, invocation_id_for, run_worker
from eris.redact import Redactor
from eris.schemas import SCHEMA_VERSION, Invocation, Transport, WorkerStatus, sha256_hex
from eris.validate import validate_events
from eris.writer import BlobRef, RunWriter
from tests.conftest import FakeProcessFactory
from tests.test_launch import grok_ok, make_call, make_policy

SECRET = "xai-CACHEPLANTEDSECRET0123456789abcdefghij"


def _writer(tmp_path: Path, run_id: str, secrets: list[str] | None = None) -> RunWriter:
    return RunWriter(tmp_path / "runs" / run_id, Redactor(secrets or []), run_id=run_id).open()


def _invocation(result: WorkerResult, blobs: dict[str, BlobRef], prompt_sha: str) -> Invocation:
    return Invocation(
        invocation_id=invocation_id_for(result.idempotency_key, 1),
        task_id="t_01",
        worker_id=result.worker_id,
        provider=result.provider,
        transport=Transport.CLI,
        model_requested=result.model_requested,
        model_executed=result.model_executed,
        stage="propose",
        repeat_index=0,
        attempt=1,
        idempotency_key=result.idempotency_key,
        argv=result.argv,
        env_names=result.env_names,
        cwd=result.cwd,
        executable_sha256=result.executable_sha256,
        cli_version=None,
        started_at="2026-08-22T10:00:00Z",
        finished_at="2026-08-22T10:00:01Z",
        duration_ms=result.duration_ms,
        exit_code=result.exit_code,
        timed_out=False,
        stdout_truncated=False,
        stderr_truncated=False,
        status=result.status,
        error=result.error,
        usage=result.usage,
        cost_usd=result.cost_usd,
        stdout_sha256=blobs["stdout"].sha256 if "stdout" in blobs else None,
        stderr_sha256=blobs["stderr"].sha256 if "stderr" in blobs else None,
        prompt_sha256=prompt_sha,
        warning=result.warning,
    )


class World:
    """An origin run that produced one OK grok call and stored it."""

    def __init__(
        self,
        tmp_path: Path,
        fake_process: Callable[..., FakeProcessFactory],
        *,
        text: str = '{"verdict": "ok"}',
        campaign: str | None = "camp-1",
        scan_hits: int = 0,
        stderr: bytes = b"warn line\n",
    ) -> None:
        self.tmp_path = tmp_path
        self.policy = make_policy(tmp_path)
        self.call = make_call(tmp_path, self.policy)
        self.prompt_sha = sha256_hex(self.call.prompt.encode())
        self.result = run_worker(
            self.call,
            popen=fake_process(stdout=grok_ok(text), stderr=stderr),
            killpg=lambda *_: None,
        )
        assert self.result.status is WorkerStatus.OK
        self.origin = _writer(tmp_path, "origin", [SECRET])
        self.blobs = {"stdout": self.origin.put_blob(self.result.stdout)}
        if self.result.stderr:
            self.blobs["stderr"] = self.origin.put_blob(self.result.stderr)
        self.invocation = _invocation(self.result, self.blobs, self.prompt_sha)
        self.origin.append("invocation.finished", self.invocation)
        self.cache = Cache(tmp_path / "cache", runs_dir=tmp_path / "runs")
        self.campaign = campaign
        self.stored = self.cache.store(
            self.origin,
            result=self.result,
            invocation=self.invocation,
            key_material=idempotency_material(self.call),
            prompt_sha256=self.prompt_sha,
            blobs=self.blobs,
            scan_hits=scan_hits,
            campaign_id=campaign,
        )
        self.origin.close()

    def lookup(self, **over: Any) -> CacheHit | CacheMiss:
        args: dict[str, Any] = {
            "idempotency_key": self.result.idempotency_key,
            "prompt_sha256": self.prompt_sha,
            "executable_sha256": self.policy.executable_sha256,
            "campaign_id": self.campaign,
        }
        args.update(over)
        return self.cache.lookup(**args)

    def entry_path(self) -> Path:
        return self.cache.entries_dir / self.stored.entry_sha256

    def key_path(self) -> Path:
        return self.cache.keys_dir / self.result.idempotency_key


def test_store_then_hit_replays_blobs_and_records_reuse(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = World(tmp_path, fake_process, text=f'{{"note": "{SECRET}"}}')
    assert w.stored.outcome == "stored"
    # layout: entry named by its (redacted) hash, key pointer, blob copies; nothing under runs/
    assert (
        w.entry_path().is_file()
        and sha256_hex(w.entry_path().read_bytes()) == w.stored.entry_sha256
    )
    assert w.key_path().read_text().strip() == w.stored.entry_sha256
    for ref in w.blobs.values():
        assert (w.cache.blobs_dir / ref.sha256).read_bytes() == ref.path.read_bytes()
    for path in (tmp_path / "cache").rglob("*"):
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes(), path
    entry = json.loads(w.entry_path().read_bytes())
    assert entry["schema_version"] == SCHEMA_VERSION and entry["scan_hits"] == 0
    assert entry["key_material"]["executable_sha256"] == w.policy.executable_sha256
    assert "[REDACTED:exact#" in entry["text"] and entry["origin_run_id"] == "origin"
    hit = w.lookup()
    assert isinstance(hit, CacheHit), hit
    assert hit.invocation == w.invocation and set(hit.blobs) == {"stdout", "stderr"}
    assert hit.result.parse_mode == "cache" and hit.result.status is WorkerStatus.OK
    assert hit.result.model_executed == "grok-4.6" and hit.result.cost_usd == 0.01
    # replay into a NEW run
    new = _writer(tmp_path, "replayed", [SECRET])
    replay = replay_hit(new, hit, campaign_id="camp-1")
    new.close()
    assert replay.invocation.reused_from == w.invocation.invocation_id
    assert replay.invocation.invocation_id == w.invocation.invocation_id
    assert replay.cost.counted is False and replay.cost.cost_known and replay.cost.cost_usd == 0.01
    lines = (tmp_path / "runs" / "replayed" / "events.jsonl").read_bytes().splitlines(keepends=True)
    assert validate_events(lines) == []
    events = [json.loads(line) for line in lines]
    assert [e["kind"] for e in events] == ["invocation.finished", "cost", "invocation.reused"]
    assert events[0]["payload"]["reused_from"] == w.invocation.invocation_id
    assert events[1]["payload"]["counted"] is False
    reused = events[2]["payload"]
    assert reused["origin_run_id"] == "origin" and reused["contaminated"] is False
    assert reused["entry_sha256"] == w.stored.entry_sha256
    for ref in w.blobs.values():  # blobs were copied into the new run via put_blob
        assert (tmp_path / "runs" / "replayed" / "blobs" / "sha256" / ref.sha256).is_file()


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"executable_sha256": "e" * 64}, "executable_sha256 differs"),
        ({"executable_sha256": "UNPINNED"}, "unpinned or disabled"),
        ({"executable_sha256": None}, "unpinned or disabled"),
        ({"prompt_sha256": "f" * 64}, "prompt_sha256 mismatch"),
        ({"campaign_id": "camp-2"}, "campaign"),
        ({"idempotency_key": "0" * 64}, "missing"),
        ({"idempotency_key": "not-a-key"}, "not a sha256"),
    ],
)
def test_hit_requirements_each_refuse(
    tmp_path: Path,
    fake_process: Callable[..., FakeProcessFactory],
    override: dict[str, Any],
    reason: str,
) -> None:
    w = World(tmp_path, fake_process)
    miss = w.lookup(**override)
    assert isinstance(miss, CacheMiss) and reason in miss.reason, miss


def test_reuse_across_campaigns_flag_and_fresh(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = World(tmp_path, fake_process)
    assert isinstance(w.lookup(campaign_id="other"), CacheMiss)
    relaxed = Cache(tmp_path / "cache", runs_dir=tmp_path / "runs", reuse_across_campaigns=True)
    assert isinstance(
        relaxed.lookup(
            idempotency_key=w.result.idempotency_key,
            prompt_sha256=w.prompt_sha,
            executable_sha256=w.policy.executable_sha256,
            campaign_id="other",
        ),
        CacheHit,
    )
    fresh = Cache(tmp_path / "cache", runs_dir=tmp_path / "runs", fresh=True)
    miss = fresh.lookup(
        idempotency_key=w.result.idempotency_key,
        prompt_sha256=w.prompt_sha,
        executable_sha256=w.policy.executable_sha256,
        campaign_id=w.campaign,
    )
    assert isinstance(miss, CacheMiss) and "fresh" in miss.reason
    # fresh still stores when absent, and reports "exists" for the same entry
    # (the same origin run id: the entry names its origin, so it must match byte for byte)
    again = RunWriter(tmp_path / "again" / "origin", Redactor(), run_id="origin").open()
    res = fresh.store(
        again,
        result=w.result,
        invocation=w.invocation,
        key_material=idempotency_material(w.call),
        prompt_sha256=w.prompt_sha,
        blobs={k: again.put_blob(v.path.read_bytes()) for k, v in w.blobs.items()},
        scan_hits=0,
        campaign_id=w.campaign,
    )
    assert res.outcome == "exists" and res.entry_sha256 == w.stored.entry_sha256
    # the same call stored from ANOTHER run is a different entry (origin differs): conflict
    other = _writer(tmp_path, "other-run")
    res = fresh.store(
        other,
        result=w.result,
        invocation=w.invocation,
        key_material=idempotency_material(w.call),
        prompt_sha256=w.prompt_sha,
        blobs={k: other.put_blob(v.path.read_bytes()) for k, v in w.blobs.items()},
        scan_hits=0,
        campaign_id=w.campaign,
    )
    other.close()
    again.close()
    assert res.outcome == "conflict" and res.existing_sha256 == w.stored.entry_sha256


def test_contaminated_failed_or_modelless_entries_never_hit(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = World(tmp_path, fake_process, scan_hits=2)
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "scan_hits=2" in miss.reason
    # status not ok: rewrite the entry consistently (new hash + pointer) via the store path
    (tmp_path / "b").mkdir()
    w2 = World(tmp_path / "b", fake_process)
    entry = json.loads(w2.entry_path().read_bytes())
    for mutate, reason in (
        ({"status": "failed"}, "not ok"),
        ({"model_executed": None}, "no model_executed"),
        ({"schema_version": "0.1.2"}, "schema_version"),
        ({"idempotency_key": "1" * 64}, "idempotency_key mismatch"),
        ({"blob_shas": {"stdout": "2" * 64}}, "missing"),
        ({"invocation": {**entry["invocation"], "status": "failed"}}, "does not match"),
    ):
        data = json.dumps({**entry, **mutate}, sort_keys=True, separators=(",", ":")).encode()
        sha = sha256_hex(data)
        (w2.cache.entries_dir / sha).write_bytes(data)
        w2.key_path().write_text(sha + "\n")
        miss = w2.lookup()
        assert isinstance(miss, CacheMiss) and reason in miss.reason, (mutate, miss)


def test_tampered_entry_symlinked_files_and_bad_blobs_are_refused(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = World(tmp_path, fake_process)
    entry_bytes = w.entry_path().read_bytes()
    # hash mismatch: bytes edited in place under the same name
    w.entry_path().write_bytes(entry_bytes.replace(b'"scan_hits":0', b'"scan_hits":1'))
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "do not hash to the entry name" in miss.reason
    w.entry_path().write_bytes(entry_bytes)
    assert isinstance(w.lookup(), CacheHit)
    # symlinked entry
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_bytes(entry_bytes)
    w.entry_path().unlink()
    w.entry_path().symlink_to(elsewhere)
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and any(
        r in miss.reason for r in ("not a regular file", "outside the cache root", "is a symlink")
    )
    w.entry_path().unlink()
    w.entry_path().write_bytes(entry_bytes)
    # symlinked key pointer
    pointer = w.key_path().read_bytes()
    w.key_path().unlink()
    (tmp_path / "ptr").write_bytes(pointer)
    w.key_path().symlink_to(tmp_path / "ptr")
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and any(
        r in miss.reason for r in ("not a regular file", "outside the cache root", "is a symlink")
    )
    w.key_path().unlink()
    w.key_path().write_bytes(pointer)
    # key pointing at garbage
    w.key_path().write_text("nonsense\n")
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "does not name an entry" in miss.reason
    w.key_path().write_bytes(pointer)
    # blob tampered / symlinked
    blob = w.cache.blobs_dir / w.blobs["stdout"].sha256
    good = blob.read_bytes()
    blob.write_bytes(b"tampered")
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "does not hash" in miss.reason
    blob.unlink()
    (tmp_path / "blob").write_bytes(good)
    blob.symlink_to(tmp_path / "blob")
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and any(
        r in miss.reason for r in ("not a regular file", "outside the cache root", "is a symlink")
    )
    blob.unlink()
    blob.write_bytes(good)
    assert isinstance(w.lookup(), CacheHit)


def test_write_once_conflict_never_overwrites(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = World(tmp_path, fake_process)
    first_entry = w.entry_path().read_bytes()
    # a different result under the SAME key (e.g. a re-run that produced other text)
    other = run_worker(
        w.call, popen=fake_process(stdout=grok_ok('{"verdict": "other"}')), killpg=lambda *_: None
    )
    assert other.idempotency_key == w.result.idempotency_key
    run2 = _writer(tmp_path, "run2")
    blobs = {"stdout": run2.put_blob(other.stdout)}
    inv2 = _invocation(other, blobs, w.prompt_sha)
    res = w.cache.store(
        run2,
        result=other,
        invocation=inv2,
        key_material=idempotency_material(w.call),
        prompt_sha256=w.prompt_sha,
        blobs=blobs,
        scan_hits=0,
        campaign_id="camp-1",
    )
    run2.close()
    assert res.outcome == "conflict" and res.existing_sha256 == w.stored.entry_sha256
    assert res.entry_sha256 != w.stored.entry_sha256
    assert w.entry_path().read_bytes() == first_entry  # untouched
    assert w.key_path().read_text().strip() == w.stored.entry_sha256  # still the first
    assert not (w.cache.entries_dir / res.entry_sha256).exists()  # nothing new written
    hit = w.lookup()
    assert isinstance(hit, CacheHit) and hit.result.text == '{"verdict": "ok"}'


def test_replay_refuses_a_blob_that_changes_under_redaction(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """A secret that was unknown when the entry was written is redacted by
    the replaying run; the blob hash changes -> refused, never replayed."""
    later_secret = "later-known-plain-secret-0123456789"
    w = World(tmp_path, fake_process, text=f'{{"note": "{later_secret}"}}')
    hit = w.lookup()
    assert isinstance(hit, CacheHit)
    strict = RunWriter(
        tmp_path / "runs" / "strict", Redactor([later_secret]), run_id="strict"
    ).open()
    with pytest.raises(CacheRefused, match="re-redaction"):
        replay_hit(strict, hit, campaign_id="camp-1")
    assert strict.seq == 0  # nothing was appended
    strict.close()


def test_cache_refuses_runs_dir_and_platforms_without_o_nofollow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(CacheError, match="must not be under"):
        Cache(tmp_path / "runs" / "cache", runs_dir=tmp_path / "runs")
    with pytest.raises(CacheError, match="must not be under"):
        Cache(tmp_path / "runs", runs_dir=tmp_path / "runs")
    Cache(tmp_path / "cache", runs_dir=tmp_path / "runs")  # fine
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(CacheUnsupported, match="documented refusal"):
        Cache(tmp_path / "cache")


def test_store_refuses_mismatched_key_and_symlinked_dirs(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = World(tmp_path, fake_process)
    run2 = _writer(tmp_path, "run2")
    bad_inv = w.invocation.model_copy(update={"idempotency_key": "9" * 64})
    with pytest.raises(CacheError, match="disagree"):
        w.cache.store(
            run2,
            result=w.result,
            invocation=bad_inv,
            key_material={},
            prompt_sha256=w.prompt_sha,
            blobs={},
            scan_hits=0,
            campaign_id=None,
        )
    other_root = tmp_path / "cache2"
    other_root.mkdir()
    (other_root / "entries").symlink_to(tmp_path / "elsewhere-dir")
    c2 = Cache(other_root)
    with pytest.raises(CacheError, match="symlink"):
        c2.store(
            run2,
            result=w.result,
            invocation=w.invocation,
            key_material={},
            prompt_sha256=w.prompt_sha,
            blobs={},
            scan_hits=0,
            campaign_id=None,
        )
    run2.close()


def test_ancestor_symlink_out_of_the_cache_root_is_refused(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """Item 9: the realpath of every key/entry/blob must lie under the cache
    root's realpath - a `keys` (or `blobs`) directory replaced by a symlink
    to elsewhere is a reasoned miss on lookup and a refusal on store."""
    w = World(tmp_path, fake_process)
    assert isinstance(w.lookup(), CacheHit)
    outside = tmp_path / "outside-keys"
    shutil.copytree(w.cache.keys_dir, outside)
    shutil.rmtree(w.cache.keys_dir)
    w.cache.keys_dir.symlink_to(outside)
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "outside the cache root" in miss.reason
    run2 = _writer(tmp_path, "run2")
    with pytest.raises(CacheError, match="outside the cache root|symlink"):
        w.cache.store(
            run2,
            result=w.result,
            invocation=w.invocation,
            key_material=idempotency_material(w.call),
            prompt_sha256=w.prompt_sha,
            blobs={k: run2.put_blob(v.path.read_bytes()) for k, v in w.blobs.items()},
            scan_hits=0,
            campaign_id=w.campaign,
        )
    run2.close()
    w.cache.keys_dir.unlink()
    shutil.copytree(outside, w.cache.keys_dir)
    assert isinstance(w.lookup(), CacheHit)
    # a blobs dir behind a symlink is refused the same way
    outside_blobs = tmp_path / "outside-blobs"
    shutil.copytree(w.cache.blobs_dir, outside_blobs)
    shutil.rmtree(w.cache.blobs_dir)
    w.cache.blobs_dir.symlink_to(outside_blobs)
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "outside the cache root" in miss.reason


def test_a_final_component_symlink_inside_the_cache_is_still_refused(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """cond 9: a key/entry/blob that IS a symlink is refused even when its
    target sits inside the cache root - an alias is never followed."""
    w = World(tmp_path, fake_process)
    assert isinstance(w.lookup(), CacheHit)
    # the key file becomes a symlink to a copy of itself INSIDE the cache
    twin = w.cache.keys_dir / "twin"
    twin.write_bytes(w.key_path().read_bytes())
    w.key_path().unlink()
    w.key_path().symlink_to(twin)
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "is a symlink" in miss.reason
    w.key_path().unlink()
    w.key_path().write_bytes(twin.read_bytes())
    assert isinstance(w.lookup(), CacheHit)
    # the same for the entry file
    entry_twin = w.cache.entries_dir / "entry-twin"
    entry_twin.write_bytes(w.entry_path().read_bytes())
    w.entry_path().unlink()
    w.entry_path().symlink_to(entry_twin)
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "is a symlink" in miss.reason
    w.entry_path().unlink()
    w.entry_path().write_bytes(entry_twin.read_bytes())
    # and for a blob
    blob = w.cache.blobs_dir / w.blobs["stdout"].sha256
    blob_twin = w.cache.blobs_dir / "blob-twin"
    blob_twin.write_bytes(blob.read_bytes())
    blob.unlink()
    blob.symlink_to(blob_twin)
    miss = w.lookup()
    assert isinstance(miss, CacheMiss) and "is a symlink" in miss.reason
