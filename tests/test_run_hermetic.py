from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Callable
from pathlib import Path

import yaml
from eval.run import main

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
    assert inv["env_names"] == sorted(inv["env_names"]) and "XAI_API_KEY" in inv["env_names"]
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
