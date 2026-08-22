"""Hardened, read-only invocation of worker CLIs.

The flags are load-bearing (verified 2026-08-21 on this machine, see
tests/fixtures/envelopes/*/*.meta.json and docs/EVAL-PLAN.md):

* claude: ``-p <prompt> --safe-mode --permission-mode plan --tools <list|"">
  --no-session-persistence --output-format json [--json-schema S]
  --max-budget-usd N``. ``--bare`` is FORBIDDEN (breaks OAuth).
* codex: ``exec -C <cwd> -s read-only --ephemeral --ignore-user-config
  --ignore-rules -c project_doc_max_bytes=0 --skip-git-repo-check -m <model>
  --json [--output-schema F] [-o F] <prompt>``.
* gemini: ``-p <prompt> -m <model> --approval-mode plan -o json`` (CLI
  unusable here on 2026-08-21; builder kept, absence recorded).
* grok: ``-p <prompt> -m <model> --permission-mode plan --disable-web-search
  --output-format json [--json-schema S]``.

Process hygiene: argv list, ``shell=False``, env built from ``{}`` (never a
filtered ``os.environ``), ``stdin=DEVNULL``, ``cwd`` = snapshot realpath,
``start_new_session=True``, process-group SIGTERM then SIGKILL on timeout,
stdout AND stderr byte caps drained concurrently, ANSI stripped in the
parsed text, pinned executable path + sha256 checked before spawn.

A failed or missing worker is a recorded absence (``WorkerResult.status``),
never a substitution. ``run_worker`` does not raise.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Protocol

from eris.policy import WorkerPolicy, sha256_file
from eris.redact import strip_ansi
from eris.schemas import Stage, Usage, WorkerStatus, canonical_bytes, sha256_hex


class LaunchRefused(RuntimeError):
    """The call would violate policy; nothing was spawned."""


# --------------------------------------------------------------------------- argv

FORBIDDEN_ARGV_TOKENS: tuple[str, ...] = (
    "--bare",
    "bypasspermissions",
    "workspace-write",
    "danger-full-access",
    "yolo",
    "--dangerously-skip-permissions",
    "--full-auto",
    "acceptedits",
    "--skip-trust",
    "--allow-all",
)


def assert_argv_safe(argv: Iterable[str]) -> None:
    argv = list(argv)
    if not argv:
        raise LaunchRefused("empty argv")
    for i, arg in enumerate(argv):
        if not isinstance(arg, str):
            raise LaunchRefused(f"argv[{i}] is not a str")
        if "\x00" in arg:
            raise LaunchRefused(f"argv[{i}] contains NUL")
        low = arg.lower()
        for token in FORBIDDEN_ARGV_TOKENS:
            if token in low:
                raise LaunchRefused(f"forbidden token {token!r} in argv[{i}]")


def _prompt_ok(prompt: str) -> str:
    if not prompt.strip():
        raise LaunchRefused("empty prompt")
    if prompt.lstrip().startswith("-"):
        raise LaunchRefused("prompt starts with '-' and could be parsed as a flag")
    return prompt


def build_argv_claude(
    executable: str,
    prompt: str,
    *,
    tools: Iterable[str] = (),
    model: str | None = None,
    schema_json: str | None = None,
    max_budget_usd: float | None = None,
) -> list[str]:
    argv = [
        executable,
        "-p",
        _prompt_ok(prompt),
        "--safe-mode",
        "--permission-mode",
        "plan",
        "--tools",
        ",".join(tools),  # "" disables every tool
        "--no-session-persistence",
        "--output-format",
        "json",
    ]
    if model:
        argv += ["--model", model]
    if schema_json is not None:
        argv += ["--json-schema", schema_json]
    if max_budget_usd is not None:
        argv += ["--max-budget-usd", f"{max_budget_usd:g}"]
    assert_argv_safe(argv)
    return argv


def build_argv_codex(
    executable: str,
    prompt: str,
    *,
    cwd: Path,
    model: str,
    schema_path: Path | None = None,
    output_path: Path | None = None,
) -> list[str]:
    argv = [
        executable,
        "exec",
        "-C",
        str(cwd),
        "-s",
        "read-only",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "-c",
        "project_doc_max_bytes=0",
        "--skip-git-repo-check",
        "-m",
        model,
        "--json",
    ]
    if schema_path is not None:
        argv += ["--output-schema", str(schema_path)]
    if output_path is not None:
        argv += ["-o", str(output_path)]
    argv.append(_prompt_ok(prompt))
    assert_argv_safe(argv)
    return argv


def build_argv_gemini(executable: str, prompt: str, *, model: str) -> list[str]:
    argv = [
        executable,
        "-p",
        _prompt_ok(prompt),
        "-m",
        model,
        "--approval-mode",
        "plan",
        "-o",
        "json",
    ]
    assert_argv_safe(argv)
    return argv


def build_argv_grok(
    executable: str, prompt: str, *, model: str, schema_json: str | None = None
) -> list[str]:
    argv = [
        executable,
        "-p",
        _prompt_ok(prompt),
        "-m",
        model,
        "--permission-mode",
        "plan",
        "--disable-web-search",
        "--output-format",
        "json",
    ]
    if schema_json is not None:
        argv += ["--json-schema", schema_json]
    assert_argv_safe(argv)
    return argv


# --------------------------------------------------------------------------- env

NEVER_ENV_EXACT: frozenset[str] = frozenset(
    {
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5OPT",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "GEMINI_CLI_TRUST_WORKSPACE",
        "EDITOR",
        "VISUAL",
    }
)
NEVER_ENV_PREFIXES: tuple[str, ...] = ("LD_", "DYLD_", "GIT_", "AWS_", "PYTEST_", "CODEX_SANDBOX")

# Eris's own hardening. These are the ONLY GIT_* names allowed, set by Eris.
GIT_HARDENING: dict[str, str] = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0",
}

BASE_ENV: dict[str, str] = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TERM": "dumb",
    "NO_COLOR": "1",
    "PAGER": "cat",
    "PYTHONDONTWRITEBYTECODE": "1",
    "CI": "1",
}

PER_CLI_ENV: dict[str, dict[str, str]] = {
    "claude": {
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_TELEMETRY": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    },
    "codex": {},
    "gemini": {},
    "grok": {},
}

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def assert_env_safe(env: Mapping[str, str]) -> None:
    for name, value in env.items():
        if not _ENV_NAME_RE.fullmatch(name):
            raise LaunchRefused(f"bad env name {name!r}")
        if "\x00" in value:
            raise LaunchRefused(f"env {name} contains NUL")
        if name in GIT_HARDENING and value == GIT_HARDENING[name]:
            continue
        if name in NEVER_ENV_EXACT or name.startswith(NEVER_ENV_PREFIXES):
            raise LaunchRefused(f"env {name} is on the NEVER list")


def build_env(
    cli: str,
    *,
    path_env: str,
    home: str,
    tmpdir: str,
    policy_env: Mapping[str, str] | None = None,
    secrets: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the subprocess environment from ``{}``. ``os.environ`` is never
    consulted; the caller passes HOME/TMPDIR explicitly."""
    env: dict[str, str] = {}
    env.update(BASE_ENV)
    env["PATH"] = path_env
    env["HOME"] = home
    env["TMPDIR"] = tmpdir
    env.update(PER_CLI_ENV.get(cli, {}))
    for name, value in dict(policy_env or {}).items():
        env[name] = value
    for name, value in dict(secrets or {}).items():
        env[name] = value
    assert_env_safe(env)
    env.update(GIT_HARDENING)
    return env


# --------------------------------------------------------------------------- spawn


class PopenLike(Protocol):
    pid: int
    stdout: IO[bytes] | None
    stderr: IO[bytes] | None
    returncode: int | None

    def wait(self, timeout: float | None = None) -> int: ...
    def poll(self) -> int | None: ...


PopenFactory = Callable[..., PopenLike]
KillPg = Callable[[int, int], None]


@dataclass
class SpawnResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    duration_ms: int
    killed_with: int | None = None


class _Drain(threading.Thread):
    def __init__(self, stream: IO[bytes] | None, cap: int) -> None:
        super().__init__(daemon=True)
        self.stream = stream
        self.cap = cap
        self.chunks: list[bytes] = []
        self.size = 0
        self.truncated = False

    def run(self) -> None:
        if self.stream is None:
            return
        while True:
            chunk = self.stream.read(65536)
            if not chunk:
                break
            if self.size >= self.cap:
                self.truncated = True
                continue  # keep draining so the child never blocks on a full pipe
            room = self.cap - self.size
            if len(chunk) > room:
                self.chunks.append(chunk[:room])
                self.size += room
                self.truncated = True
            else:
                self.chunks.append(chunk)
                self.size += len(chunk)

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


def _kill_group(proc: PopenLike, killpg: KillPg, grace_s: float) -> int:
    for sig, wait_s in ((signal.SIGTERM, grace_s), (signal.SIGKILL, max(grace_s, 1.0))):
        try:
            killpg(proc.pid, sig)
        except ProcessLookupError:
            return int(sig)
        try:
            proc.wait(timeout=wait_s)
            return int(sig)
        except subprocess.TimeoutExpired:
            continue
    raise LaunchRefused(f"process group {proc.pid} survived SIGKILL")


def spawn(
    argv: list[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    timeout_s: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    popen: PopenFactory = subprocess.Popen,
    killpg: KillPg = os.killpg,
    grace_s: float = 2.0,
    clock: Callable[[], float] = time.monotonic,
) -> SpawnResult:
    assert_argv_safe(argv)
    assert_env_safe(env)
    cwd = Path(cwd).resolve()
    if not cwd.is_dir():
        raise LaunchRefused(f"cwd {cwd} is not a directory")
    t0 = clock()
    proc = popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd),
        env=dict(env),
        start_new_session=True,
        shell=False,
        close_fds=True,
    )
    out = _Drain(proc.stdout, max_stdout_bytes)
    err = _Drain(proc.stderr, max_stderr_bytes)
    out.start()
    err.start()
    timed_out = False
    killed_with: int | None = None
    try:
        exit_code: int | None = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        killed_with = _kill_group(proc, killpg, grace_s)
        exit_code = proc.poll()
    out.join(timeout=grace_s + 5)
    err.join(timeout=grace_s + 5)
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()
    return SpawnResult(
        exit_code=exit_code,
        stdout=out.data,
        stderr=err.data,
        stdout_truncated=out.truncated or out.is_alive(),
        stderr_truncated=err.truncated or err.is_alive(),
        timed_out=timed_out,
        duration_ms=int((clock() - t0) * 1000),
        killed_with=killed_with,
    )


# --------------------------------------------------------------------------- envelopes


@dataclass
class Envelope:
    text: str | None
    model_executed: str | None
    usage: Usage | None
    cost_usd: float | None
    is_error: bool
    error: str | None
    parse_mode: str
    structured: Any = None
    models_used: list[str] = field(default_factory=list)
    raw: Any = None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _float_or_none(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _pick_model(model_usage: Any) -> tuple[str | None, list[str]]:
    """Primary model = highest costUSD (then outputTokens) in ``modelUsage``."""
    if not isinstance(model_usage, dict) or not model_usage:
        return None, []
    names = [str(k) for k in model_usage]

    def score(name: str) -> tuple[float, int]:
        entry = model_usage.get(name)
        if not isinstance(entry, dict):
            return (0.0, 0)
        return (
            _float_or_none(entry.get("costUSD")) or 0.0,
            _int_or_none(entry.get("outputTokens")) or 0,
        )

    return max(names, key=score), names


def _structured_from_text(text: str | None) -> Any:
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(stripped)
        except ValueError:
            return None
    return None


def _json_object(stdout: bytes, cli: str) -> tuple[dict[str, Any] | None, Envelope | None]:
    text = strip_ansi(stdout.decode("utf-8", errors="replace"))
    try:
        data = json.loads(text)
    except ValueError as exc:
        return None, Envelope(
            None,
            None,
            None,
            None,
            True,
            f"{cli}: stdout is not JSON ({exc})",
            "none",
            raw=text[:2000],
        )
    if not isinstance(data, dict):
        return None, Envelope(
            None, None, None, None, True, f"{cli}: stdout JSON is not an object", "none", raw=data
        )
    return data, None


def parse_claude(stdout: bytes) -> Envelope:
    """claude 2.1.239 ``--output-format json``. ``is_error`` is checked BEFORE
    the shape so an auth failure is reported as the error it is."""
    data, bad = _json_object(stdout, "claude")
    if data is None:
        assert bad is not None
        return bad
    result = data.get("result")
    if data.get("is_error") is True:
        return Envelope(
            None,
            None,
            None,
            None,
            True,
            str(result) if result is not None else "is_error",
            "json",
            raw=data,
        )
    if data.get("type") != "result" or not isinstance(result, str):
        return Envelope(
            None,
            None,
            None,
            None,
            True,
            "claude: unexpected envelope shape (no type=result/result)",
            "json",
            raw=data,
        )
    usage_raw = _dict(data.get("usage"))
    details = _dict(usage_raw.get("output_tokens_details"))
    usage = Usage(
        input_tokens=_int_or_none(usage_raw.get("input_tokens")),
        output_tokens=_int_or_none(usage_raw.get("output_tokens")),
        cached_input_tokens=_int_or_none(usage_raw.get("cache_read_input_tokens")),
        reasoning_tokens=_int_or_none(details.get("thinking_tokens")),
    )
    model, names = _pick_model(data.get("modelUsage"))
    structured = data.get("structured_output")
    if structured is None:
        structured = _structured_from_text(result)
    return Envelope(
        text=result,
        model_executed=model,
        usage=usage,
        cost_usd=_float_or_none(data.get("total_cost_usd")),
        is_error=False,
        error=None
        if data.get("subtype") == "success"
        else f"claude: subtype={data.get('subtype')!r}",
        parse_mode="json",
        structured=structured,
        models_used=names,
        raw=data,
    )


def parse_codex(stdout: bytes) -> Envelope:
    """codex 0.147.0 ``exec --json`` JSONL: usage from ``turn.completed``, text
    from the LAST ``agent_message`` item. No model id is emitted, so
    ``model_executed`` is None (recorded as unknown, never guessed)."""
    text = strip_ansi(stdout.decode("utf-8", errors="replace"))
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    if not events:
        return Envelope(
            None,
            None,
            None,
            None,
            True,
            "codex: no JSONL events on stdout",
            "none",
            raw=text[:2000],
        )
    last_message: str | None = None
    usage: Usage | None = None
    completed = False
    error: str | None = None
    for ev in events:
        kind = ev.get("type")
        if kind == "item.completed":
            item = ev.get("item")
            if (
                isinstance(item, dict)
                and item.get("type") == "agent_message"
                and isinstance(item.get("text"), str)
            ):
                last_message = item["text"]
        elif kind == "turn.completed":
            completed = True
            u = _dict(ev.get("usage"))
            usage = Usage(
                input_tokens=_int_or_none(u.get("input_tokens")),
                output_tokens=_int_or_none(u.get("output_tokens")),
                cached_input_tokens=_int_or_none(u.get("cached_input_tokens")),
                reasoning_tokens=_int_or_none(u.get("reasoning_output_tokens")),
            )
        elif kind in ("error", "turn.failed"):
            error = f"codex: {ev.get('message') or ev.get('error') or kind}"
    if not completed and error is None:
        error = "codex: no turn.completed event"
    return Envelope(
        text=last_message,
        model_executed=None,
        usage=usage,
        cost_usd=None,
        is_error=error is not None,
        error=error,
        parse_mode="jsonl",
        structured=_structured_from_text(last_message),
        raw=events,
    )


def parse_grok(stdout: bytes) -> Envelope:
    """grok 1.0.5 ``--output-format json``: text, modelUsage, usage, total_cost_usd."""
    data, bad = _json_object(stdout, "grok")
    if data is None:
        assert bad is not None
        return bad
    text = data.get("text")
    if not isinstance(text, str):
        return Envelope(
            None, None, None, None, True, "grok: envelope has no text", "json", raw=data
        )
    u = _dict(data.get("usage"))
    usage = Usage(
        input_tokens=_int_or_none(u.get("input_tokens")),
        output_tokens=_int_or_none(u.get("output_tokens")),
        cached_input_tokens=_int_or_none(u.get("cache_read_input_tokens")),
        reasoning_tokens=_int_or_none(u.get("reasoning_tokens")),
    )
    model, names = _pick_model(data.get("modelUsage"))
    stop = data.get("stopReason")
    is_error = stop == "error"
    return Envelope(
        text=text,
        model_executed=model,
        usage=usage,
        cost_usd=_float_or_none(data.get("total_cost_usd")),
        is_error=is_error,
        error=f"grok: stopReason={stop!r}"
        if stop not in (None, "stop", "end_turn", "completed")
        else None,
        parse_mode="json",
        structured=_structured_from_text(text),
        models_used=names,
        raw=data,
    )


def first_balanced_json(text: str) -> str | None:
    """The first balanced ``{...}`` in ``text`` (string-aware), or None."""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        start = text.find("{", start + 1)
    return None


def parse_gemini(stdout: bytes) -> Envelope:
    """gemini ``-o json`` - shape UNKNOWN (not capturable on 2026-08-21).
    Defensive: whole-stdout JSON, else the first balanced JSON object, else
    plain text. ``parse_mode`` records which path was taken."""
    text = strip_ansi(stdout.decode("utf-8", errors="replace"))
    data: Any = None
    mode = "none"
    try:
        data = json.loads(text)
        mode = "json"
    except ValueError:
        candidate = first_balanced_json(text)
        if candidate is not None:
            try:
                data = json.loads(candidate)
                mode = "balanced_extract"
            except ValueError:
                data = None
    if not isinstance(data, dict):
        stripped = text.strip()
        return Envelope(
            stripped or None,
            None,
            None,
            None,
            not stripped,
            None if stripped else "gemini: empty stdout",
            "none",
            raw=text[:2000],
        )
    response: Any = None
    for key in ("response", "text", "result", "output"):
        if isinstance(data.get(key), str):
            response = data[key]
            break
    stats = _dict(data.get("stats"))
    models = _dict(stats.get("models"))
    model = next(iter(models), None) if models else None
    err = data.get("error")
    return Envelope(
        text=response,
        model_executed=str(model) if model else None,
        usage=None,
        cost_usd=None,
        is_error=err is not None or response is None,
        error=str(err)
        if err is not None
        else (None if response is not None else "gemini: no response text"),
        parse_mode=mode,
        structured=_structured_from_text(response),
        raw=data,
    )


PARSERS: dict[str, Callable[[bytes], Envelope]] = {
    "claude": parse_claude,
    "codex": parse_codex,
    "grok": parse_grok,
    "gemini": parse_gemini,
}


# --------------------------------------------------------------------------- worker calls


@dataclass(frozen=True)
class WorkerCall:
    worker_id: str
    policy: WorkerPolicy
    prompt: str
    cwd: Path
    task_id: str
    stage: Stage
    repeat_index: int
    policy_sha256: str
    schema: Mapping[str, Any] | None = None
    scratch_dir: Path | None = None
    home: str = "/nonexistent"
    tmpdir: str = "/tmp"
    path_env: str = "/usr/bin:/bin"
    secrets: Mapping[str, str] = field(default_factory=dict)


def idempotency_key(call: WorkerCall) -> str:
    """Excludes the experimental arm (so arms share proposals); includes repeat_index."""
    material = {
        "worker_id": call.worker_id,
        "provider": call.policy.provider,
        "model": call.policy.model,
        "stage": call.stage.value,
        "task_id": call.task_id,
        "prompt_sha256": sha256_hex(call.prompt.encode("utf-8")),
        "schema_sha256": sha256_hex(canonical_bytes(dict(call.schema))) if call.schema else None,
        "repeat_index": call.repeat_index,
        "policy_sha256": call.policy_sha256,
    }
    return sha256_hex(canonical_bytes(material))


@dataclass
class Plan:
    argv: list[str]
    env: dict[str, str]
    cwd: Path
    idempotency_key: str
    executable: str
    schema_path: Path | None = None
    output_path: Path | None = None


def plan_call(call: WorkerCall) -> Plan:
    """Everything needed to spawn, computed WITHOUT spawning (used by --dry-run)."""
    w = call.policy
    if w.cli is None:
        raise LaunchRefused(f"worker {call.worker_id!r} is not a cli worker")
    if w.executable is None:
        raise LaunchRefused(
            f"worker {call.worker_id!r} has no executable path (run `eris policy pin`)"
        )
    cwd = Path(call.cwd).resolve()
    schema_json = json.dumps(call.schema, sort_keys=True) if call.schema else None
    schema_path: Path | None = None
    output_path: Path | None = None
    if w.cli == "claude":
        argv = build_argv_claude(
            w.executable,
            call.prompt,
            tools=w.tools,
            model=w.model,
            schema_json=schema_json,
            max_budget_usd=w.max_budget_usd,
        )
    elif w.cli == "codex":
        if not w.model:
            raise LaunchRefused("codex requires a model in policy")
        if call.schema is not None:
            if call.scratch_dir is None:
                raise LaunchRefused("codex --output-schema needs scratch_dir")
            schema_path = Path(call.scratch_dir) / "schema.json"
            output_path = Path(call.scratch_dir) / "last_message.json"
        argv = build_argv_codex(
            w.executable,
            call.prompt,
            cwd=cwd,
            model=w.model,
            schema_path=schema_path,
            output_path=output_path,
        )
    elif w.cli == "gemini":
        if not w.model:
            raise LaunchRefused("gemini requires a model in policy")
        argv = build_argv_gemini(w.executable, call.prompt, model=w.model)
    else:
        if not w.model:
            raise LaunchRefused("grok requires a model in policy")
        argv = build_argv_grok(w.executable, call.prompt, model=w.model, schema_json=schema_json)
    missing = [n for n in w.env_allow if n not in call.secrets]
    if missing:
        raise LaunchRefused(f"env_allow names not provided: {missing}")
    secrets = {n: call.secrets[n] for n in w.env_allow}
    env = build_env(
        w.cli,
        path_env=call.path_env,
        home=call.home,
        tmpdir=call.tmpdir,
        policy_env=w.env,
        secrets=secrets,
    )
    return Plan(argv, env, cwd, idempotency_key(call), w.executable, schema_path, output_path)


def preflight_executable(
    policy: WorkerPolicy, *, hasher: Callable[[Path], str] = sha256_file
) -> str:
    """Refuse unless the pinned path exists, is a regular file and hashes to the pin."""
    if policy.executable is None:
        raise LaunchRefused("no executable path (unpinned)")
    path = Path(policy.executable)
    if not path.is_file():
        raise FileNotFoundError(str(path))
    if not policy.pinned:
        raise LaunchRefused(f"{path} is UNPINNED; run `eris policy pin`")
    actual = hasher(path)
    if actual != policy.executable_sha256:
        raise LaunchRefused(
            f"{path} sha256 {actual[:12]}... != pinned {policy.executable_sha256[:12]}..."
        )
    return actual


@dataclass
class WorkerResult:
    worker_id: str
    provider: str
    model_requested: str | None
    model_executed: str | None
    status: WorkerStatus
    error: str | None
    text: str | None
    structured: Any
    usage: Usage | None
    cost_usd: float | None
    duration_ms: int
    exit_code: int | None
    argv: list[str]
    env_names: list[str]
    cwd: str
    idempotency_key: str
    executable_sha256: str | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    parse_mode: str
    models_used: list[str] = field(default_factory=list)


def _absent(call: WorkerCall, status: WorkerStatus, error: str, key: str = "") -> WorkerResult:
    return WorkerResult(
        worker_id=call.worker_id,
        provider=call.policy.provider,
        model_requested=call.policy.model,
        model_executed=None,
        status=status,
        error=error,
        text=None,
        structured=None,
        usage=None,
        cost_usd=None,
        duration_ms=0,
        exit_code=None,
        argv=[],
        env_names=[],
        cwd=str(call.cwd),
        idempotency_key=key or idempotency_key(call),
        executable_sha256=None,
        stdout=b"",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=False,
        parse_mode="none",
    )


def run_worker(
    call: WorkerCall,
    *,
    popen: PopenFactory = subprocess.Popen,
    killpg: KillPg = os.killpg,
    hasher: Callable[[Path], str] = sha256_file,
    clock: Callable[[], float] = time.monotonic,
) -> WorkerResult:
    """launch -> drain -> parse. Never raises; absence is a status."""
    try:
        plan = plan_call(call)
    except LaunchRefused as exc:
        return _absent(call, WorkerStatus.REFUSED, str(exc))
    try:
        digest = preflight_executable(call.policy, hasher=hasher)
    except FileNotFoundError as exc:
        return _absent(
            call, WorkerStatus.MISSING, f"executable not found: {exc}", plan.idempotency_key
        )
    except LaunchRefused as exc:
        return _absent(call, WorkerStatus.REFUSED, str(exc), plan.idempotency_key)
    if plan.schema_path is not None and call.schema is not None:
        plan.schema_path.parent.mkdir(parents=True, exist_ok=True)
        plan.schema_path.write_text(json.dumps(call.schema, sort_keys=True), encoding="utf-8")
    w = call.policy
    try:
        spawned = spawn(
            plan.argv,
            env=plan.env,
            cwd=plan.cwd,
            timeout_s=w.timeout_s,
            max_stdout_bytes=w.max_stdout_bytes,
            max_stderr_bytes=w.max_stderr_bytes,
            popen=popen,
            killpg=killpg,
            clock=clock,
        )
    except LaunchRefused as exc:
        return _absent(call, WorkerStatus.REFUSED, str(exc), plan.idempotency_key)
    except OSError as exc:
        return _absent(call, WorkerStatus.FAILED, f"spawn failed: {exc}", plan.idempotency_key)
    assert w.cli is not None
    envelope = PARSERS[w.cli](spawned.stdout)
    error: str | None
    if spawned.timed_out:
        status = WorkerStatus.TIMEOUT
        error = f"timed out after {w.timeout_s}s (killed with signal {spawned.killed_with})"
    elif envelope.is_error:
        status = WorkerStatus.FAILED
        error = envelope.error or "worker reported an error"
    elif spawned.exit_code not in (0, None):
        status = WorkerStatus.FAILED
        error = f"exit code {spawned.exit_code}"
    else:
        status = WorkerStatus.OK
        error = envelope.error
    return WorkerResult(
        worker_id=call.worker_id,
        provider=w.provider,
        model_requested=w.model,
        model_executed=envelope.model_executed,
        status=status,
        error=error,
        text=envelope.text,
        structured=envelope.structured,
        usage=envelope.usage,
        cost_usd=envelope.cost_usd,
        duration_ms=spawned.duration_ms,
        exit_code=spawned.exit_code,
        argv=list(plan.argv),
        env_names=sorted(plan.env),
        cwd=str(plan.cwd),
        idempotency_key=plan.idempotency_key,
        executable_sha256=digest,
        stdout=spawned.stdout,
        stderr=spawned.stderr,
        stdout_truncated=spawned.stdout_truncated,
        stderr_truncated=spawned.stderr_truncated,
        timed_out=spawned.timed_out,
        parse_mode=envelope.parse_mode,
        models_used=envelope.models_used,
    )
