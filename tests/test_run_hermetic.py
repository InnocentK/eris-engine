from __future__ import annotations

import hashlib
import io
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from eval.run import default_run_id, main, run_dir_for, validate_run_id

from eris.launch import resolve_user
from eris.policy import UNPINNED
from eris.validate import validate_events
from tests.conftest import FakeProcessFactory

FIX = Path(__file__).parent / "fixtures" / "envelopes"
PLANTED = "xai-PLANTEDSECRETVALUE0123456789abcdefgh"
CRED = "codex-refresh-token-PLANTED-" + "q" * 24


def setup_world(tmp_path: Path, *, pinned: bool = True) -> dict[str, Path]:
    exe = tmp_path / "bin" / "grok"
    exe.parent.mkdir()
    exe.write_bytes(b"#!/bin/sh\necho fake\n")
    exe.chmod(0o755)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "README.md").write_text("hello\n")
    prompt = tmp_path / "prompt.md"
    prompt.write_text("Review this repository. Reply in JSON.\n")
    env = tmp_path / ".env"
    env.write_text(f"XAI_API_KEY={PLANTED}\n")
    cred = tmp_path / "auth.json"
    cred.write_text(json.dumps({"tokens": {"refresh_token": CRED}}))
    policy = {
        "policy_version": "t",
        "runs_dir": str(tmp_path / "runs"),
        "scratch_dir": str(tmp_path / "scratch"),
        "path_env": "/usr/bin:/bin",
        "vendors_allowed": ["xai"],
        "credential_files": [str(cred)],
        "workers": {
            "grok": {
                "transport": "cli",
                "cli": "grok",
                "provider": "xai",
                "model": "grok-4.6",
                "executable": str(exe),
                "executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest()
                if pinned
                else UNPINNED,
                "timeout_s": 5,
                "max_stdout_bytes": 100_000,
                "env_allow": ["XAI_API_KEY"],
            }
        },
        "budgets": {"per_run_usd": 1, "per_call_usd": 1},
    }
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    return {"policy": policy_path, "env": env, "prompt": prompt, "snapshot": snapshot, "exe": exe}


def common_args(w: dict[str, Path]) -> list[str]:
    return [
        "--policy",
        str(w["policy"]),
        "--env-file",
        str(w["env"]),
        "--worker",
        "grok",
        "--prompt-file",
        str(w["prompt"]),
        "--snapshot",
        str(w["snapshot"]),
        "--task-id",
        "t_01",
        "--repeat-index",
        "2",
    ]


def test_dry_run_prints_plan_and_spawns_nothing(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = setup_world(tmp_path)
    factory = fake_process(stdout=b"never")
    out = io.StringIO()
    rc = main(["dry-run", *common_args(w)], out=out, home=tmp_path, popen=factory)
    assert rc == 0 and factory.instances == []
    plan = json.loads(out.getvalue())
    assert plan["argv"][0] == str(w["exe"]) and "--permission-mode" in plan["argv"]
    assert plan["cwd"] == str(w["snapshot"].resolve())
    assert "XAI_API_KEY" in plan["env_names"] and PLANTED not in out.getvalue()
    assert len(plan["idempotency_key"]) == 64 and plan["pinned"] is True
    # the key is stable for the same inputs and changes with repeat_index
    out2 = io.StringIO()
    main(["dry-run", *common_args(w)], out=out2, home=tmp_path, popen=factory)
    assert json.loads(out2.getvalue())["idempotency_key"] == plan["idempotency_key"]
    out3 = io.StringIO()
    main(["dry-run", *common_args(w)[:-1], "3"], out=out3, home=tmp_path, popen=factory)
    assert json.loads(out3.getvalue())["idempotency_key"] != plan["idempotency_key"]


def test_dry_run_refusal_and_errors(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = setup_world(tmp_path)
    out = io.StringIO()
    rc = main(
        ["dry-run", *common_args(w), "--worker", "nope"],
        out=out,
        home=tmp_path,
        popen=fake_process(),
    )
    assert rc == 2 and "not declared" in out.getvalue()
    w["env"].write_text("")  # env_allow name missing -> plan refused, no spawn
    out = io.StringIO()
    rc = main(["dry-run", *common_args(w)], out=out, home=tmp_path, popen=fake_process())
    assert rc == 2 and json.loads(out.getvalue())["status"] == "refused"
    out = io.StringIO()
    rc = main(
        ["dry-run", *common_args(w), "--policy", str(tmp_path / "missing.yaml")],
        out=out,
        home=tmp_path,
    )
    assert rc == 2 and json.loads(out.getvalue())["status"] == "error"


def test_invoke_full_path_is_hermetic_and_redacted(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = setup_world(tmp_path)
    grok = json.loads((FIX / "grok" / "1.0.5" / "plan.json").read_bytes())
    grok["text"] = f"found key {PLANTED} and token {CRED} in config"
    grok["stopReason"] = "stop"
    factory = fake_process(stdout=json.dumps(grok).encode(), stderr=f"warn {PLANTED}\n".encode())
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(tmp_path / "runs"), "--run-id", "run_a"],
        out=out,
        home=tmp_path,
        popen=factory,
        killpg=lambda *_: None,
    )
    assert rc == 0, out.getvalue()
    summary = json.loads(out.getvalue())
    assert summary["status"] == "ok" and summary["model_executed"] == "grok-4.6"
    assert summary["cost_usd"] == 0.031262 and summary["redactions"]["exact"] >= 1
    run_dir = tmp_path / "runs" / "run_a"
    lines = (run_dir / "events.jsonl").read_bytes().splitlines(keepends=True)
    assert validate_events(lines) == []
    kinds = [json.loads(line)["kind"] for line in lines]
    assert kinds == ["run.started", "invocation.finished", "cost", "proposal.raw"]
    manifest = json.loads((run_dir / "manifest.json").read_bytes())
    assert manifest["event_count"] == 4 and manifest["extra"]["status"] == "ok"
    inv = json.loads(lines[1])["payload"]
    assert inv["status"] == "ok" and inv["idempotency_key"] == json.loads(lines[0])["payload"].get(
        "idempotency_key", inv["idempotency_key"]
    )
    assert inv["invocation_id"] == f"inv-{inv['idempotency_key'][:16]}-a1"  # F2: per attempt
    assert inv["env_names"] == sorted(inv["env_names"]) and "XAI_API_KEY" in inv["env_names"]
    # M2c defect A: USER is part of the from-{} environment and is the
    # harness's OWN resolved account (never a filtered os.environ read).
    assert "USER" in inv["env_names"]
    assert factory.instances[0].popen_kwargs["env"]["USER"] == resolve_user()
    # the worker saw the secret VALUE; the ledger never does
    assert factory.instances[0].popen_kwargs["env"]["XAI_API_KEY"] == PLANTED
    for path in run_dir.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert PLANTED.encode() not in data, path
            assert CRED.encode() not in data, path
    blobs = list((run_dir / "blobs" / "sha256").iterdir())
    assert len(blobs) == 2
    assert any(b"[REDACTED:exact#" in b.read_bytes() for b in blobs)


def test_invoke_records_absence_for_unpinned_worker(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = setup_world(tmp_path, pinned=False)
    factory = fake_process(stdout=b"{}")
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(tmp_path / "runs")],
        out=out,
        home=tmp_path,
        popen=factory,
    )
    assert rc == 3 and factory.instances == []
    summary = json.loads(out.getvalue())
    assert summary["status"] == "refused" and "UNPINNED" in summary["error"]
    run_dir = Path(summary["run_dir"])
    kinds = [
        json.loads(line)["kind"] for line in (run_dir / "events.jsonl").read_bytes().splitlines()
    ]
    assert kinds == ["run.started", "invocation.finished", "cost", "worker.absent"]
    assert (run_dir / "manifest.json").exists()


def test_invoke_failed_worker_is_recorded(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = setup_world(tmp_path)
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(tmp_path / "runs"), "--run-id", "r"],
        out=out,
        home=tmp_path,
        popen=fake_process(stdout=b"not json", returncode=1),
        killpg=lambda *_: None,
    )
    assert rc == 3
    summary = json.loads(out.getvalue())
    assert summary["status"] == "failed"
    manifest = json.loads((tmp_path / "runs" / "r" / "manifest.json").read_bytes())
    assert manifest["extra"]["status"] == "failed"


@pytest.mark.parametrize(
    "bad", ["../x", "/abs/x", "a/b", "", "x" * 65, "run id", "r\n", ".", "..", "~x", "x;y"]
)
def test_invoke_refuses_unsafe_run_ids_before_touching_disk(
    tmp_path: Path, bad: str, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = setup_world(tmp_path)
    runs = tmp_path / "runs"
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(runs), "--run-id", bad],
        out=out,
        home=tmp_path,
        popen=fake_process(stdout=b"{}"),
    )
    assert rc == 2 and json.loads(out.getvalue())["status"] == "error"
    assert not runs.exists()
    assert not (tmp_path / "x").exists() and not Path("/abs/x").exists()
    with pytest.raises(ValueError):
        validate_run_id(bad)


def test_run_id_helpers(tmp_path: Path) -> None:
    assert validate_run_id("t_01-grok-r2") == "t_01-grok-r2"
    assert run_dir_for(tmp_path, "ok_1") == (tmp_path / "ok_1").resolve()
    with pytest.raises(ValueError):
        run_dir_for(tmp_path, "../escape")
    generated = default_run_id("task.with:odd/chars", "grok", 3)
    assert validate_run_id(generated) == generated and len(generated) <= 64
    assert generated.startswith("task_with_odd_chars-grok-r3-")


def test_invoke_key_includes_snapshot_sha_from_git_head(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = setup_world(tmp_path)
    sha = "f" * 40
    out_a = io.StringIO()
    main(["dry-run", *common_args(w)], out=out_a, home=tmp_path, popen=fake_process())
    key_none = json.loads(out_a.getvalue())
    assert key_none["snapshot_sha"] is None  # no .git in the scratch snapshot
    (w["snapshot"] / ".git").mkdir()
    (w["snapshot"] / ".git" / "HEAD").write_text(f"{sha}\n")
    out_b = io.StringIO()
    main(["dry-run", *common_args(w)], out=out_b, home=tmp_path, popen=fake_process())
    key_head = json.loads(out_b.getvalue())
    assert key_head["snapshot_sha"] == sha
    assert key_head["idempotency_key"] != key_none["idempotency_key"]
    # The base commit is mechanically observed from the snapshot; there is no
    # flag to assert it (a user-supplied value would be recorded as observed).
    with pytest.raises(SystemExit):
        main(
            ["dry-run", *common_args(w), "--snapshot-sha", "e" * 40],
            out=io.StringIO(),
            home=tmp_path,
        )


def test_invoke_scratch_lives_under_scratch_dir_and_a_planted_entry_is_refused(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """Every ephemeral file lives under the policy scratch_dir (never under
    runs/). The sweep never touches the CURRENT run's path (it could belong to
    a run starting concurrently), so a planted symlink there is REFUSED, never
    followed and never deleted; an old orphan is swept."""
    w = setup_world(tmp_path)
    runs = tmp_path / "runs"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep").write_text("x")
    scratch_dir = tmp_path / "scratch"
    scratch_dir.mkdir()
    (scratch_dir / "r").symlink_to(elsewhere)
    orphan = scratch_dir / "old-orphan"
    orphan.mkdir()
    old = time.time() - 86_400
    os.utime(orphan, (old, old))
    factory = fake_process(stdout=b"{}")
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(runs), "--run-id", "r"],
        out=out,
        home=tmp_path,
        popen=factory,
        killpg=lambda *_: None,
    )
    assert rc == 2 and "already exists (or is a symlink)" in json.loads(out.getvalue())["error"]
    assert factory.instances == []  # nothing spawned into a planted workspace
    assert (scratch_dir / "r").is_symlink()  # refused, not deleted, not followed
    assert sorted(p.name for p in elsewhere.iterdir()) == ["keep"]
    assert not orphan.exists()  # the old orphan WAS swept
    assert not (runs / "r" / "scratch").exists()
    extra = {p.relative_to(runs / "r").as_posix() for p in (runs / "r").rglob("*")}
    assert all(
        e in (".lock", "events.jsonl", "manifest.json", "blobs", "blobs/sha256")
        or e.startswith("blobs/sha256/")
        for e in extra
    )


def test_invoke_reserves_the_scratch_before_the_writer_opens(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Final item 2 (invoke path): the reservation is the mkdir, and it happens
    BEFORE the writer opens. An entry appearing between the precheck and the
    mkdir refuses with no run directory created and the entry left alone."""
    import eval.run as run_module

    w = setup_world(tmp_path)
    runs = tmp_path / "runs"
    scratch_dir = tmp_path / "scratch"
    scratch_dir.mkdir()
    real = run_module.make_private_dir
    planted: list[Path] = []

    def racing_make_private_dir(path: Path) -> None:
        if not planted:
            Path(path).mkdir(parents=True)
            (Path(path) / "not-ours").write_text("planted")
            planted.append(Path(path))
        real(path)

    monkeypatch.setattr(run_module, "make_private_dir", racing_make_private_dir)
    factory = fake_process(stdout=b"{}")
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(runs), "--run-id", "raced"],
        out=out,
        home=tmp_path,
        popen=factory,
        killpg=lambda *_: None,
    )
    assert rc == 2 and "refusing" in json.loads(out.getvalue())["error"]
    assert factory.instances == []  # nothing spawned
    assert not (runs / "raced").exists()  # no ledger, no run dir
    assert planted[0].is_dir() and (planted[0] / "not-ours").read_text() == "planted"


def test_invoke_surfaces_cleanup_failure_as_run_error(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A WorkerResult carrying cleanup_error becomes a run.error event, is
    recorded on the Invocation and the manifest, and yields exit code 4 even
    though the worker itself succeeded. Never silent."""
    import eval.run as harness

    from eris.launch import run_worker as real_run_worker

    w = setup_world(tmp_path)
    grok = json.loads((FIX / "grok" / "1.0.5" / "plan.json").read_bytes())
    grok["stopReason"] = "stop"

    def flaky_cleanup(call: object, **kw: object) -> object:
        res = real_run_worker(call, **kw)  # type: ignore[arg-type]
        res.cleanup_error = "scratch cleanup failed for /x: EBUSY"
        return res

    monkeypatch.setattr(harness, "run_worker", flaky_cleanup)
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(tmp_path / "runs"), "--run-id", "r"],
        out=out,
        home=tmp_path,
        popen=fake_process(stdout=json.dumps(grok).encode()),
        killpg=lambda *_: None,
    )
    summary = json.loads(out.getvalue())
    assert rc == 4 and summary["status"] == "ok" and "EBUSY" in summary["cleanup_error"]
    run_dir = tmp_path / "runs" / "r"
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_bytes().splitlines()]
    kinds = [e["kind"] for e in events]
    assert kinds == ["run.started", "invocation.finished", "run.error", "cost", "proposal.raw"]
    assert events[1]["payload"]["cleanup_error"] == "scratch cleanup failed for /x: EBUSY"
    assert events[2]["payload"] == {
        "kind": "scratch_cleanup_failed",
        "error": "scratch cleanup failed for /x: EBUSY",
    }
    manifest = json.loads((run_dir / "manifest.json").read_bytes())
    assert "EBUSY" in manifest["extra"]["cleanup_error"]


def test_invoke_persists_output_file_truncation_on_invocation(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The persisted Invocation record (read back from events.jsonl) carries
    output_file_truncated / output_file_size, and the capped bytes are a blob."""
    import eval.run as harness

    from eris.launch import run_worker as real_run_worker
    from eris.schemas import Invocation

    w = setup_world(tmp_path)
    grok = json.loads((FIX / "grok" / "1.0.5" / "plan.json").read_bytes())
    grok["stopReason"] = "stop"
    capped = b"y" * 4096

    def truncating_worker(call: object, **kw: object) -> object:
        res = real_run_worker(call, **kw)  # type: ignore[arg-type]
        res.output_file = capped
        res.output_file_truncated = True
        res.output_file_size = 10_000
        return res

    monkeypatch.setattr(harness, "run_worker", truncating_worker)
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(tmp_path / "runs"), "--run-id", "r"],
        out=out,
        home=tmp_path,
        popen=fake_process(stdout=json.dumps(grok).encode()),
        killpg=lambda *_: None,
    )
    assert rc == 0
    run_dir = tmp_path / "runs" / "r"
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_bytes().splitlines()]
    inv_payload = next(e["payload"] for e in events if e["kind"] == "invocation.finished")
    inv = Invocation.model_validate(inv_payload)  # the persisted record round-trips
    assert inv.output_file_truncated is True and inv.output_file_size == 10_000
    assert inv.output_file_sha256 is not None
    assert (run_dir / "blobs" / "sha256" / inv.output_file_sha256).read_bytes() == capped
    raw = next(e["payload"] for e in events if e["kind"] == "proposal.raw")
    assert raw["output_file_truncated"] is True and raw["output_file_size"] == 10_000
    assert raw["output_file_sha256"] == inv.output_file_sha256


def test_invoke_agy_persists_conversation_id_and_worker_duration(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    """0.1.2: the persisted Invocation (read back from events.jsonl) carries
    agy's conversation_id and worker_reported_duration_ms; duration_ms stays
    Eris's clock figure; the argv on record is the hardened agy argv."""
    from eris.schemas import Invocation

    w = setup_world(tmp_path)
    policy = yaml.safe_load(w["policy"].read_text())
    policy["vendors_allowed"] = ["xai", "google"]
    policy["workers"]["agy"] = {
        "transport": "cli",
        "cli": "agy",
        "provider": "google",
        "model": "gemini-3.1-pro-high",
        "executable": str(w["exe"]),
        "executable_sha256": hashlib.sha256(w["exe"].read_bytes()).hexdigest(),
        "timeout_s": 600,
        "max_stdout_bytes": 100_000,
        "env": {"AGY_CLI_DISABLE_AUTO_UPDATE": "1"},
    }
    w["policy"].write_text(yaml.safe_dump(policy))
    args = [a if a != "grok" else "agy" for a in common_args(w)]
    factory = fake_process(stdout=(FIX / "agy" / "1.1.18" / "plain.json").read_bytes())
    out = io.StringIO()
    rc = main(
        ["invoke", *args, "--runs-dir", str(tmp_path / "runs"), "--run-id", "r"],
        out=out,
        home=tmp_path,
        popen=factory,
        killpg=lambda *_: None,
    )
    assert rc == 0, out.getvalue()
    assert json.loads(out.getvalue())["model_executed"] is None  # agy emits no model id
    run_dir = tmp_path / "runs" / "r"
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_bytes().splitlines()]
    inv = Invocation.model_validate(
        next(e["payload"] for e in events if e["kind"] == "invocation.finished")
    )
    assert inv.conversation_id == "ed889929-a04c-457f-91d1-194be848aa04"
    assert inv.worker_reported_duration_ms == 2646
    assert inv.duration_ms is not None and inv.duration_ms >= 0  # Eris's clock, separate field
    assert inv.status.value == "ok" and inv.model_requested == "gemini-3.1-pro-high"
    assert inv.argv[1:3] == ["-p", "Review this repository. Reply in JSON.\n"]
    assert (
        "--print-timeout" in inv.argv and inv.argv[inv.argv.index("--print-timeout") + 1] == "570s"
    )
    assert "-c" not in inv.argv and "AGY_CLI_DISABLE_AUTO_UPDATE" in inv.env_names
    # the declared workspace on record is the snapshot realpath = the spawn cwd
    assert inv.argv.count("--add-dir") == 1
    assert inv.argv[inv.argv.index("--add-dir") + 1] == inv.cwd == str(w["snapshot"].resolve())
    assert factory.instances[0].popen_kwargs["cwd"] == inv.cwd
    # a grok invocation records neither field
    grok = json.loads((FIX / "grok" / "1.0.5" / "plan.json").read_bytes())
    grok["stopReason"] = "stop"
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(tmp_path / "runs"), "--run-id", "g"],
        out=out,
        home=tmp_path,
        popen=fake_process(stdout=json.dumps(grok).encode()),
        killpg=lambda *_: None,
    )
    assert rc == 0
    events = [
        json.loads(line)
        for line in (tmp_path / "runs" / "g" / "events.jsonl").read_bytes().splitlines()
    ]
    payload = next(e["payload"] for e in events if e["kind"] == "invocation.finished")
    assert payload["conversation_id"] is None and payload["worker_reported_duration_ms"] is None


def test_invoke_refuses_unparsable_credential_file(
    tmp_path: Path, fake_process: Callable[..., FakeProcessFactory]
) -> None:
    w = setup_world(tmp_path)
    (tmp_path / "auth.json").write_text("{broken")
    out = io.StringIO()
    rc = main(
        ["invoke", *common_args(w), "--runs-dir", str(tmp_path / "runs"), "--run-id", "r"],
        out=out,
        home=tmp_path,
        popen=fake_process(stdout=b"{}"),
    )
    assert rc == 2 and "cannot be parsed" in json.loads(out.getvalue())["error"]
    assert not (tmp_path / "runs" / "r" / "events.jsonl").exists()


def test_preflight_prints_doctor(tmp_path: Path) -> None:
    w = setup_world(tmp_path)
    out = io.StringIO()
    rc = main(
        ["preflight", "--policy", str(w["policy"]), "--env-file", str(w["env"])],
        out=out,
        home=tmp_path,
    )
    text = out.getvalue()
    assert rc == 0 and "doctor:" in text and PLANTED not in text
