"""Hardened, read-only invocation of worker CLIs.

The flags are load-bearing (verified 2026-08-21/22 on this machine, see
tests/fixtures/envelopes/*/*.meta.json and docs/EVAL-PLAN.md):

* claude: ``-p <prompt> --safe-mode --permission-mode plan --tools <list|"">
  --no-session-persistence --output-format json [--json-schema S]
  --max-budget-usd N``. ``--bare`` is FORBIDDEN (breaks OAuth).
* codex: ``exec -C <cwd> -s read-only --ephemeral --ignore-user-config
  --ignore-rules -c project_doc_max_bytes=0 --skip-git-repo-check -m <model>
  --json [--output-schema F] [-o F] <prompt>``.
* agy (Antigravity, the Google lineage; probed on 1.1.18, argv re-verified
  flag-by-flag on 1.1.27 at the 2026-09-06 re-pin - note 1.1.27 warns that
  ``--mode plan`` has no effect beside ``--disable-slash-commands``, see
  SECURITY.md): ``-p <prompt> --model <m>
  --mode plan --sandbox --add-dir <snapshot realpath> --output-format json
  --disable-slash-commands --print-timeout <N>s [--json-schema S]`` (this
  order is canonical) with ``N = timeout_s - 30`` above 60 s, else
  ``max(1, timeout_s // 2)`` - always strictly less than ``timeout_s`` so
  agy's own timer fires first and still emits a parseable envelope; the Eris
  timeout + process-group kill is the backstop (``timeout_s < 2`` refused). ``--add-dir`` is REQUIRED and appears exactly once, equal to the
  spawn cwd: without a declared workspace agy cannot read the repository at
  all (A14), with it reads are confined to that workspace (A16). ``--sandbox``
  must be DROPPED if Eris ever wraps agy in its own sandbox-exec (nested
  seatbelt fails). The builder never emits ``-c`` (continue a conversation).
* grok: ``-p <prompt> -m <model> --permission-mode plan --disable-web-search
  --output-format json [--json-schema S]``.

Process hygiene: argv list, ``shell=False``, env built from ``{}`` (never a
filtered ``os.environ``; HOME/TMPDIR/USER are passed in explicitly - see
:func:`build_env` for why ``USER`` is required), ``stdin=DEVNULL``, ``cwd`` = snapshot realpath,
``start_new_session=True``, process-group SIGTERM then SIGKILL on timeout,
stdout AND stderr byte caps drained concurrently, ANSI stripped in the
parsed text, pinned executable path + sha256 checked before spawn.

A failed or missing worker is a recorded absence (``WorkerResult.status``),
never a substitution. ``run_worker`` does not raise.
"""

from __future__ import annotations

import getpass
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath
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
    # agy (Antigravity): edit mode, conversation resumption, interactive/stream
    # input, project/agent selection, log redirection. `--add-dir` is NOT
    # forbidden: it is REQUIRED (exactly once, = the snapshot) and checked
    # element by element in plan_call. `-c` (continue) is deliberately NOT a
    # substring token - it would hit codex `-c project_doc_max_bytes=0` and
    # git `--cached`; an exact-element test proves the agy builder never
    # emits it.
    "accept-edits",
    "--continue",
    "--conversation",
    "--prompt-interactive",
    "--input-format",
    "--new-project",
    "--project",
    "--agent",
    "--log-file",
)


def assert_argv_safe(argv: Iterable[str], *, exempt: Iterable[int] = ()) -> None:
    """Refuse forbidden tokens anywhere in argv EXCEPT the elements listed in
    ``exempt`` (the prompt, which may legitimately quote ``--bare`` etc.).
    NUL is refused everywhere."""
    argv = list(argv)
    skip = set(exempt)
    if not argv:
        raise LaunchRefused("empty argv")
    for i, arg in enumerate(argv):
        if not isinstance(arg, str):
            raise LaunchRefused(f"argv[{i}] is not a str")
        if "\x00" in arg:
            raise LaunchRefused(f"argv[{i}] contains NUL")
        if i in skip:
            continue
        low = arg.lower()
        for token in FORBIDDEN_ARGV_TOKENS:
            if token in low:
                raise LaunchRefused(f"forbidden token {token!r} in argv[{i}]")


# Index of the prompt in claude/agy/grok argv (`<exe> -p <prompt> ...`).
CLI_PROMPT_INDEX = 2


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
    assert_argv_safe(argv, exempt=(CLI_PROMPT_INDEX,))
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
    assert_argv_safe(argv, exempt=(len(argv) - 1,))
    return argv


AGY_PRINT_TIMEOUT_MARGIN_S = 30
AGY_MIN_TIMEOUT_S = 2


def agy_print_timeout_s(timeout_s: int) -> int:
    """agy's own ``--print-timeout`` in whole seconds, ALWAYS strictly less
    than Eris's ``timeout_s`` so agy's timer fires first and still emits a
    parseable ERROR envelope (A7); the Eris timeout + group kill remains the
    backstop: ``timeout_s - 30`` above 60 s, else ``max(1, timeout_s // 2)``.
    With integer seconds a 1 s policy timeout has no strictly smaller positive
    value, so ``timeout_s < 2`` is refused rather than letting the two timers
    coincide."""
    timeout_s = int(timeout_s)
    if timeout_s < AGY_MIN_TIMEOUT_S:
        raise LaunchRefused(
            f"agy needs timeout_s >= {AGY_MIN_TIMEOUT_S} so its --print-timeout can fire "
            f"before Eris's timeout (got {timeout_s})"
        )
    if timeout_s > 60:
        return timeout_s - AGY_PRINT_TIMEOUT_MARGIN_S
    return max(1, timeout_s // 2)


def build_argv_agy(
    executable: str,
    prompt: str,
    *,
    model: str,
    workspace: Path,
    print_timeout_s: int,
    schema_json: str | None = None,
) -> list[str]:
    """``workspace`` MUST be the snapshot that becomes the spawn cwd: agy only
    reads inside declared workspaces (A14: without ``--add-dir`` even
    ``README.md`` in the cwd is denied; A16: with it, reads outside are
    denied). Exactly one ``--add-dir``, resolved to its realpath.

    TODO(m2b): a declared workspace also gets its AGENTS.md / GEMINI.md rules
    injected into the model's context (A15 replied "MANGO KIWI"); there is no
    opt-out flag. Mitigation = per-worker snapshot sanitization (strip
    AGENTS.md/GEMINI.md/CLAUDE.md/.agents/ from the agy worktree copy, recorded
    in the manifest). Until then agy output is exposed to repo-authored
    instructions, same class as grok.
    """
    if print_timeout_s < 1:
        raise LaunchRefused("agy --print-timeout must be >= 1s")
    argv = [
        executable,
        "-p",
        _prompt_ok(prompt),
        "--model",
        model,
        "--mode",
        "plan",
        "--sandbox",
        "--add-dir",
        str(Path(workspace).resolve()),
        "--output-format",
        "json",
        "--disable-slash-commands",
        "--print-timeout",
        f"{int(print_timeout_s)}s",
    ]
    if schema_json is not None:
        argv += ["--json-schema", schema_json]
    assert_argv_safe(argv, exempt=(CLI_PROMPT_INDEX,))
    return argv


def assert_agy_workspace(argv: list[str], cwd: Path) -> None:
    """Exact-element check, applied in ``plan_call`` right before the plan is
    returned: ``--add-dir`` occurs exactly once (outside the prompt) and its
    value is the spawn cwd's realpath. A second workspace, a missing one, or
    one pointing elsewhere refuses the call."""
    positions = [i for i, a in enumerate(argv) if a == "--add-dir" and i != CLI_PROMPT_INDEX]
    if len(positions) != 1:
        raise LaunchRefused(f"agy argv must carry exactly one --add-dir (found {len(positions)})")
    i = positions[0]
    expected = str(Path(cwd).resolve())
    if i + 1 >= len(argv) or argv[i + 1] != expected:
        raise LaunchRefused(
            f"agy --add-dir must equal the spawn cwd {expected!r} (got "
            f"{argv[i + 1] if i + 1 < len(argv) else None!r})"
        )


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
    assert_argv_safe(argv, exempt=(CLI_PROMPT_INDEX,))
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
        # Google / Antigravity credential and endpoint overrides. `AGY_` is NOT
        # blanket-banned: the policy sets AGY_CLI_DISABLE_AUTO_UPDATE.
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_GEMINI_BASE_URL",
        "AGY_ADC_AUTH",
    }
)
NEVER_ENV_PREFIXES: tuple[str, ...] = (
    "LD_",
    "DYLD_",
    "GIT_",
    "AWS_",
    "PYTEST_",
    "CODEX_SANDBOX",
    "ANTIGRAVITY_",
)

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
    # Name taken from the binary's strings (1.1.18); effect is an ASSUMPTION.
    # agy spawns a background auto-updater that would change the pinned binary.
    "agy": {"AGY_CLI_DISABLE_AUTO_UPDATE": "1"},
    "grok": {},
}

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A plausible account name: printable, no control characters, bounded.
_USER_VALUE_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")


def _passwd_user() -> str:
    """The account name from the POSIX passwd database. No environment is
    consulted. Raises on Windows (no ``pwd``, no ``os.getuid``)."""
    import pwd  # POSIX only; the caller falls back on ImportError/AttributeError

    return str(pwd.getpwuid(os.getuid()).pw_name)


# getpass.getuser() consults these BEFORE the passwd database. If any of them
# is set, its answer is environment-derived - exactly what USER must never be.
_GETPASS_ENV_NAMES: tuple[str, ...] = ("LOGNAME", "USER", "LNAME", "USERNAME")


def resolve_user() -> str | None:
    """The account name Eris itself runs as, or ``None`` when it cannot be
    determined from the OS.

    The passwd database is the ONLY trusted source. :func:`getpass.getuser` is
    the portable fallback for platforms without ``pwd`` (Windows), but it
    reads ``LOGNAME``/``USER``/``LNAME``/``USERNAME`` before falling through to
    passwd, so it is used only when none of those names is present in the
    environment. ``os.environ`` is read here to DETECT that - never for a
    value. An environment-derived answer is treated as unresolved: ``USER`` is
    then omitted and ``eris doctor`` warns, rather than a name an attacker (or
    a stray shell export) chose being handed to a worker CLI. In practice this
    means Windows normally runs without ``USER``; that is a deliberate,
    documented refusal, not an oversight.

    A name with a control character or over 64 characters is discarded too.
    """
    name: str | None = None
    try:
        name = _passwd_user()
    except Exception:  # noqa: BLE001 - no pwd module / no passwd entry: try the fallback
        if not any(n in os.environ for n in _GETPASS_ENV_NAMES):
            try:
                name = getpass.getuser()
            except Exception:  # noqa: BLE001 - no account name available at all
                return None
    if name and _USER_VALUE_RE.fullmatch(name):
        return name
    return None


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
    user: str | None,
    policy_env: Mapping[str, str] | None = None,
    secrets: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the CLI-worker subprocess environment from ``{}``. ``os.environ``
    is never consulted; the caller passes HOME/TMPDIR/USER explicitly.

    ``USER`` is load-bearing, not cosmetic: the first live run (2026-08-23,
    M2c) showed ``claude`` reporting "Not logged in - Please run /login" from
    an environment that had HOME, PATH and TMPDIR but no ``USER``, while
    ``claude auth status`` said ``loggedIn: true``. Adding ``USER`` alone
    fixed it; ``LOGNAME`` and ``SHELL`` did not. It is an account name, not a
    secret, and is on no NEVER list. ``None`` (unresolvable account) omits it
    rather than inventing a value - ``eris doctor`` warns instead.

    API workers do NOT get this environment: they are HTTP calls with no
    subprocess, so there is nothing to authenticate by account name.

    ``USER`` is neither policy- nor secret-controllable: a policy ``env`` or an
    ``env_allow`` secret that names ``USER`` is REFUSED, and the OS-derived
    value is written LAST so nothing already in the dict can override it.
    """
    env: dict[str, str] = {}
    env.update(BASE_ENV)
    env["PATH"] = path_env
    env["HOME"] = home
    env["TMPDIR"] = tmpdir
    env.update(PER_CLI_ENV.get(cli, {}))
    for name, value in dict(policy_env or {}).items():
        if name == "USER":
            raise LaunchRefused("env USER is set by Eris from the OS; a policy may not supply it")
        env[name] = value
    for name, value in dict(secrets or {}).items():
        if name == "USER":
            raise LaunchRefused("env USER is set by Eris from the OS; a secret may not supply it")
        env[name] = value
    assert_env_safe(env)
    # Defect C, at the CHOKEPOINT. `plan_call` checks the call's own home/tmpdir,
    # but a policy `env:` (or an env_allow secret) is merged AFTER the defaults
    # above and can overwrite either - neither name is on a NEVER list. Checking
    # only the call fields left the guard bypassable, so the FINAL env is what
    # gets asserted: a worker's cwd is the snapshot, and a relative HOME/TMPDIR
    # would resolve there.
    for _name in ("HOME", "TMPDIR"):
        if not PurePath(env[_name]).is_absolute():
            raise LaunchRefused(
                f"env {_name}={env[_name]!r} must be absolute (defect C): a worker resolves "
                "it against the snapshot, not the harness cwd"
            )
    env.update(GIT_HARDENING)
    # LAST, and only from the caller's OS-derived value (see resolve_user).
    if user:
        env["USER"] = user
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
    pgid: int | None = None  # == leader pid (start_new_session); resume kills a survivor


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


EPERM_SWEEP_RETRIES = 20
EPERM_SWEEP_INTERVAL_S = 0.05


def _sweep_sigkill(proc: PopenLike, killpg: KillPg, sleep: Callable[[float], None]) -> None:
    """SIGKILL the whole group. macOS reports EPERM (not ESRCH) while a
    member that already died is still an unreaped zombie (its parent, the
    leader, is gone and launchd reaps it asynchronously): retry briefly.
    EPERM that persists means a member we cannot signal - refuse loudly."""
    for attempt in range(EPERM_SWEEP_RETRIES + 1):
        try:
            killpg(proc.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
        except PermissionError as exc:
            if attempt == EPERM_SWEEP_RETRIES:
                raise LaunchRefused(
                    f"process group {proc.pid} could not be signalled ({exc}); a member may "
                    "have survived the SIGKILL sweep"
                ) from exc
            sleep(EPERM_SWEEP_INTERVAL_S)


def _kill_group(
    proc: PopenLike, killpg: KillPg, grace_s: float, sleep: Callable[[float], None] = time.sleep
) -> int:
    """SIGTERM the group, wait for the leader, then ALWAYS sweep the group
    with SIGKILL: members may ignore SIGTERM or outlive the leader. Returns
    the signal that ended the leader."""
    try:
        killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):  # EPERM: go straight to the sweep
        pass
    leader_gone = False
    try:
        proc.wait(timeout=grace_s)
        leader_gone = True
    except subprocess.TimeoutExpired:
        pass
    _sweep_sigkill(proc, killpg, sleep)
    if leader_gone:
        return int(signal.SIGTERM)
    try:
        proc.wait(timeout=max(grace_s, 1.0))
    except subprocess.TimeoutExpired:
        raise LaunchRefused(f"process group {proc.pid} survived SIGKILL") from None
    return int(signal.SIGKILL)


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
    exempt: Iterable[int] = (),
    on_spawn: Callable[[int], None] | None = None,
) -> SpawnResult:
    assert_argv_safe(argv, exempt=exempt)
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
    if on_spawn is not None and isinstance(proc.pid, int) and proc.pid > 0:
        on_spawn(
            int(proc.pid)
        )  # the harness records the pgid BEFORE waiting (resume kills survivors)
    out = _Drain(proc.stdout, max_stdout_bytes)
    err = _Drain(proc.stderr, max_stderr_bytes)
    out.start()
    err.start()
    timed_out = False
    killed_with: int | None = None
    try:
        try:
            exit_code: int | None = proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            killed_with = _kill_group(proc, killpg, grace_s)
            exit_code = proc.poll()
        except KeyboardInterrupt:
            # Ctrl-C in the harness: the worker group is killed through the same
            # path as a timeout, then the interrupt propagates (no handler here).
            _kill_group(proc, killpg, grace_s)
            raise
        out.join(timeout=grace_s + 5)
        err.join(timeout=grace_s + 5)
    finally:
        # The pipes are closed on EVERY exit path. A refusal that escaped with
        # them open used to leak fds whose finalizer (a ResourceWarning) then
        # surfaced inside an unrelated test.
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
        pgid=int(proc.pid) if isinstance(proc.pid, int) and proc.pid > 0 else None,
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
    conversation_id: str | None = None  # agy: the worker's own session handle
    worker_reported_duration_ms: int | None = None  # agy duration_seconds; never the clock


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _float_or_none(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


WORKER_DURATION_MAX_S = 10_000_000.0  # ~115 days; anything beyond is not a duration


def _duration_ms_or_none(value: Any) -> int | None:
    """A worker-reported duration in seconds -> whole milliseconds. Only a
    finite number in ``[0, 1e7]`` is accepted; ``Infinity``/``NaN``/``1e309``,
    huge ints (``float()`` overflow), negatives, bools and strings record
    ``None`` - never an exception (``run_worker`` never raises)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        seconds = float(value)
    except OverflowError:
        return None
    if not math.isfinite(seconds) or not 0.0 <= seconds <= WORKER_DURATION_MAX_S:
        return None
    return int(round(seconds * 1000))


def _pick_model(model_usage: Any) -> tuple[str | None, list[str]]:
    """``model_executed`` from the name list alone is known only when
    ``modelUsage`` names EXACTLY one model; with several (e.g. a helper model
    plus the primary) this returns None and, for claude, the caller then
    tries ``_executor_by_output_tokens`` - authorship by the vendor's own
    counters, never by the request. All names go to ``models_used``; nothing
    is ever guessed."""
    if not isinstance(model_usage, dict) or not model_usage:
        return None, []
    names = [str(k) for k in model_usage]
    return (names[0] if len(names) == 1 else None), names


def _executor_by_output_tokens(
    model_usage: dict[str, Any], output_tokens: int | None
) -> str | None:
    """Among SEVERAL models in ``modelUsage``, the UNIQUE one whose own
    ``outputTokens`` equals the envelope's result ``usage.output_tokens`` is
    the author of the result - mechanical authorship evidence from the
    vendor's own counters, with the REQUESTED model never consulted (a
    three-family panel, 2026-09-14, rejected requested-appears-in-usage as
    unsupported and converged on this identity instead; claude 2.1.272 runs
    a haiku helper on every call, so the several-names case is now every
    call). No unique match - counters absent, zero-output ties, a future CLI
    breaking the identity - degrades to None, never to a wrong name.
    Verified on the captured 2.1.272 envelope: helper 17 output tokens,
    primary 450 == result 450."""
    if output_tokens is None:
        return None
    matches = [
        name
        for name, u in model_usage.items()
        if isinstance(u, dict) and _int_or_none(u.get("outputTokens")) == output_tokens
    ]
    return matches[0] if len(matches) == 1 else None


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


def _claude_error_message(data: dict[str, Any], result: Any) -> str:
    """``result`` verbatim when claude gave one (``Not logged in …``);
    otherwise ``claude: subtype=… terminal_reason=…: <errors joined>`` so the
    retry classifier can see ``error_max_budget_usd`` / ``budget_exhausted``;
    bare ``is_error`` when the envelope says nothing else."""
    if result is not None:
        return str(result)
    parts: list[str] = []
    subtype = data.get("subtype")
    if isinstance(subtype, str) and subtype != "success":
        parts.append(f"subtype={subtype!r}")
    reason = data.get("terminal_reason")
    if isinstance(reason, str) and reason:
        parts.append(f"terminal_reason={reason!r}")
    errors = data.get("errors")
    messages = [e for e in errors if isinstance(e, str)] if isinstance(errors, list) else []
    if not parts and not messages:
        return "is_error"
    text = "claude: " + " ".join(parts)
    if messages:
        text += (": " if parts else "") + "; ".join(messages)
    return text


def parse_claude(stdout: bytes) -> Envelope:
    """claude 2.1.239 ``--output-format json``. ``is_error`` is checked BEFORE
    the shape so an auth failure is reported as the error it is; usage, cost
    and model names are retained on error (F1)."""
    data, bad = _json_object(stdout, "claude")
    if data is None:
        assert bad is not None
        return bad
    result = data.get("result")
    usage_raw = _dict(data.get("usage"))
    details = _dict(usage_raw.get("output_tokens_details"))
    usage = Usage(
        input_tokens=_int_or_none(usage_raw.get("input_tokens")),
        output_tokens=_int_or_none(usage_raw.get("output_tokens")),
        cached_input_tokens=_int_or_none(usage_raw.get("cache_read_input_tokens")),
        reasoning_tokens=_int_or_none(details.get("thinking_tokens")),
    )
    model, names = _pick_model(data.get("modelUsage"))
    if model is None and len(names) > 1:
        model = _executor_by_output_tokens(_dict(data.get("modelUsage")), usage.output_tokens)
    if data.get("is_error") is True:
        # F1: an error envelope still carries usage and cost (T2: the
        # --max-budget-usd cap tripped at $0.129 on a $0.10 cap - the spend is
        # real and must be recorded). The message comes from `result` when
        # present, else from subtype / terminal_reason / errors[].
        return Envelope(
            None,
            model,
            usage if usage_raw else None,
            _float_or_none(data.get("total_cost_usd")),
            True,
            _claude_error_message(data, result),
            "json",
            models_used=names,
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
            # `turn.failed` carries an OBJECT {message: ...} (E2 401 capture);
            # `error` events carry a string `message`.
            detail = ev.get("message") or ev.get("error") or kind
            if isinstance(detail, dict):
                detail = detail.get("message") or detail
            error = f"codex: {detail}"
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
    """grok 1.0.5 ``--output-format json``: text, modelUsage, usage,
    total_cost_usd; with ``--json-schema`` the object is under the camelCase
    key ``structuredOutput`` (E9) and is preferred over parsing ``text``."""
    data, bad = _json_object(stdout, "grok")
    if data is None:
        assert bad is not None
        return bad
    text = data.get("text")
    if not isinstance(text, str):
        # E17: an API refusal is {type: error, message: ...} with no text key.
        message = data.get("message")
        if data.get("type") == "error" and isinstance(message, str) and message:
            return Envelope(None, None, None, None, True, f"grok: {message}", "json", raw=data)
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
    structured = data.get("structuredOutput")
    if structured is None:
        structured = _structured_from_text(text)
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
        structured=structured,
        models_used=names,
        raw=data,
    )


def parse_agy(stdout: bytes) -> Envelope:
    """agy 1.1.18 ``--output-format json``: one object with ``status``
    (SUCCESS|ERROR), ``response``, ``error``, ``conversation_id``,
    ``duration_seconds``, ``usage`` and, with ``--json-schema``,
    ``structured_output`` (+ a ``json_schema`` echo). No model id and no cost
    are emitted: ``model_executed`` is None (unknown, never guessed) and
    ``cost_usd`` is None. Usage is retained even on ERROR (A5: a denied shell
    command still consumed 45k input tokens)."""
    data, bad = _json_object(stdout, "agy")
    if data is None:
        assert bad is not None
        return bad
    status = data.get("status")
    response = data.get("response")
    text = response if isinstance(response, str) and response else None
    u = _dict(data.get("usage"))
    usage = Usage(
        input_tokens=_int_or_none(u.get("input_tokens")),
        output_tokens=_int_or_none(u.get("output_tokens")),
        cached_input_tokens=_int_or_none(u.get("cache_read_tokens")),
        reasoning_tokens=_int_or_none(u.get("thinking_tokens")),
    )
    conv = data.get("conversation_id")
    conversation_id = conv if isinstance(conv, str) and conv else None
    reported_ms = _duration_ms_or_none(data.get("duration_seconds"))
    error: str | None
    if status == "SUCCESS":
        error = None
    elif isinstance(data.get("error"), str) and data["error"]:
        error = f"agy: {data['error']}"
    elif status is None:
        error = "agy: status missing"
    else:
        error = f"agy: status={status!r}"
    structured = data.get("structured_output")  # any shape is recorded; extra keys kept
    if structured is None:
        structured = _structured_from_text(text)
    return Envelope(
        text=text,
        model_executed=None,
        usage=usage,
        cost_usd=None,
        is_error=error is not None,
        error=error,
        parse_mode="json",
        structured=structured,
        models_used=[],
        raw=data,
        conversation_id=conversation_id,
        worker_reported_duration_ms=reported_ms,
    )


PARSERS: dict[str, Callable[[bytes], Envelope]] = {
    "claude": parse_claude,
    "codex": parse_codex,
    "agy": parse_agy,
    "grok": parse_grok,
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
    # No default: every caller must decide what account the CLI runs as (see
    # build_env; a silently missing USER presents as a bogus auth failure).
    user: str | None
    schema: Mapping[str, Any] | None = None
    scratch_dir: Path | None = None
    home: str = "/nonexistent"
    tmpdir: str = "/tmp"
    path_env: str = "/usr/bin:/bin"
    secrets: Mapping[str, str] = field(default_factory=dict)
    snapshot_sha: str | None = None


def idempotency_material(call: WorkerCall) -> dict[str, Any]:
    """The key's inputs. Excludes the experimental arm (so arms share
    proposals) and the attempt; includes repeat_index, the snapshot's base
    commit (a re-snapshotted task never collides with the old one) and, since
    M2b, the pinned executable's sha256 (a cache entry produced by another
    binary is never a hit)."""
    return {
        "snapshot_sha": call.snapshot_sha,
        "worker_id": call.worker_id,
        "provider": call.policy.provider,
        "model": call.policy.model,
        "executable_sha256": call.policy.executable_sha256,
        "stage": call.stage.value,
        "task_id": call.task_id,
        "prompt_sha256": sha256_hex(call.prompt.encode("utf-8")),
        "schema_sha256": sha256_hex(canonical_bytes(dict(call.schema))) if call.schema else None,
        "repeat_index": call.repeat_index,
        "policy_sha256": call.policy_sha256,
    }


def idempotency_key(call: WorkerCall) -> str:
    return sha256_hex(canonical_bytes(idempotency_material(call)))


@dataclass
class Plan:
    argv: list[str]
    env: dict[str, str]
    cwd: Path
    idempotency_key: str
    executable: str
    prompt_index: int
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
    prompt_index = CLI_PROMPT_INDEX
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
            call_dir = Path(call.scratch_dir) / f"call-{idempotency_key(call)[:16]}"
            schema_path = call_dir / "schema.json"
            output_path = call_dir / "last_message.json"
        argv = build_argv_codex(
            w.executable,
            call.prompt,
            cwd=cwd,
            model=w.model,
            schema_path=schema_path,
            output_path=output_path,
        )
        prompt_index = len(argv) - 1
    elif w.cli == "agy":
        if not w.model:
            raise LaunchRefused("agy requires a model in policy")
        argv = build_argv_agy(
            w.executable,
            call.prompt,
            model=w.model,
            workspace=cwd,
            print_timeout_s=agy_print_timeout_s(w.timeout_s),
            schema_json=schema_json,
        )
        assert_agy_workspace(argv, cwd)  # exactly one --add-dir, == the spawn cwd
    else:
        if not w.model:
            raise LaunchRefused("grok requires a model in policy")
        argv = build_argv_grok(w.executable, call.prompt, model=w.model, schema_json=schema_json)
    # DEFECT C (2026-08-27): a worker's cwd is the SNAPSHOT, never the harness's
    # cwd, so any relative path handed to a worker resolves against the snapshot
    # and points at nothing. codex got a relative `--output-schema`, could not
    # read it, and died before emitting one JSONL event (rc 1) - three retries,
    # no diagnosis. Refuse here so the class cannot recur silently: everything
    # Eris hands a worker must already be absolute.
    if call.scratch_dir is not None and not Path(call.scratch_dir).is_absolute():
        raise LaunchRefused(
            f"scratch_dir {call.scratch_dir!r} must be absolute: a worker's cwd is the "
            "snapshot, so a relative path would resolve there (defect C)"
        )
    if not Path(call.home).is_absolute():
        raise LaunchRefused(f"home {call.home!r} must be absolute (defect C)")
    if not Path(call.tmpdir).is_absolute():
        raise LaunchRefused(
            f"tmpdir {call.tmpdir!r} must be absolute (defect C): a worker would resolve "
            "it against the snapshot, not the harness cwd"
        )
    missing = [n for n in w.env_allow if n not in call.secrets]
    if missing:
        raise LaunchRefused(f"env_allow names not provided: {missing}")
    secrets = {n: call.secrets[n] for n in w.env_allow}
    env = build_env(
        w.cli,
        path_env=call.path_env,
        home=call.home,
        tmpdir=call.tmpdir,
        user=call.user,
        policy_env=w.env,
        secrets=secrets,
    )
    return Plan(
        argv, env, cwd, idempotency_key(call), w.executable, prompt_index, schema_path, output_path
    )


def preflight_executable(
    policy: WorkerPolicy, *, hasher: Callable[[Path], str] = sha256_file
) -> tuple[str, Path]:
    """Resolve the pinned path to its realpath, require a regular file, hash
    the REALPATH and compare with the pin. Returns (sha256, realpath); the
    realpath goes into argv[0] so the hashed file is the executed one."""
    if policy.executable is None:
        raise LaunchRefused("no executable path (unpinned)")
    path = Path(policy.executable)
    try:
        real = path.resolve(strict=True)
    except FileNotFoundError:
        raise FileNotFoundError(str(path)) from None
    except (OSError, RuntimeError) as exc:
        raise LaunchRefused(f"{path} cannot be resolved: {exc}") from exc
    if not real.is_file():
        raise FileNotFoundError(str(path))
    if not policy.pinned:
        raise LaunchRefused(f"{path} is UNPINNED; run `eris policy pin`")
    actual = hasher(real)
    if actual != policy.executable_sha256:
        raise LaunchRefused(
            f"{real} sha256 {actual[:12]}... != pinned {policy.executable_sha256[:12]}..."
        )
    return actual, real


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
    output_file: bytes | None = None  # codex `-o` last message: read into memory, file deleted
    output_file_truncated: bool = False  # True when the `-o` file exceeded max_stdout_bytes
    output_file_size: int | None = None  # original size of the `-o` file
    cleanup_error: str | None = None  # scratch removal failed: a raw file MAY remain on disk
    conversation_id: str | None = None  # agy session handle (brain dir derivable at read time)
    worker_reported_duration_ms: int | None = None  # the worker's own figure; duration_ms is ours
    # F3 "OK with error": the worker completed (status OK) but flagged something
    # (grok `stopReason: cancelled`, a claude non-success subtype). The message
    # lives here, never in `error`, which is reserved for non-OK statuses.
    warning: str | None = None
    pgid: int | None = None  # process group of the spawned leader (None when nothing spawned)


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


def budget_tripped_result(call: WorkerCall, reason: str) -> WorkerResult:
    """F4: the Eris budget pre-check refused to spawn. A recorded absence with
    status BUDGET_TRIPPED; nothing ran, nothing was spent."""
    try:
        key = plan_call(call).idempotency_key
    except LaunchRefused:
        key = idempotency_key(call)
    return _absent(call, WorkerStatus.BUDGET_TRIPPED, reason, key)


def make_private_dir(path: Path) -> None:
    """Create ``path`` for this call only. Refuse a pre-existing entry or a
    symlink (a planted link could redirect the unredacted `-o` file)."""
    if path.is_symlink() or path.exists():
        raise LaunchRefused(f"scratch path {path} already exists (or is a symlink); refusing")
    parent = path.parent
    if parent.is_symlink():
        raise LaunchRefused(f"scratch parent {parent} is a symlink; refusing")
    parent.mkdir(parents=True, exist_ok=True)
    try:
        path.mkdir(exist_ok=False)
    except FileExistsError:
        raise LaunchRefused(f"scratch path {path} appeared concurrently; refusing") from None


def read_output_file(path: Path, cap: int) -> tuple[bytes | None, int | None, bool]:
    """Read a worker-written output file WITHOUT following symlinks.

    Returns (bytes capped at ``cap``, original size, truncated). A missing
    file yields (None, None, False). Anything that is not a regular file is
    refused (LaunchRefused) and never read.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None, None, False
    if not stat.S_ISREG(st.st_mode):
        raise LaunchRefused(f"worker output {path} is not a regular file; refusing to read it")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if sum(len(c) for c in chunks) < cap:
                chunks.append(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)[:cap]
    return data, size, size > cap


def run_worker(
    call: WorkerCall,
    *,
    popen: PopenFactory = subprocess.Popen,
    killpg: KillPg = os.killpg,
    hasher: Callable[[Path], str] = sha256_file,
    clock: Callable[[], float] = time.monotonic,
    on_spawn: Callable[[int], None] | None = None,
) -> WorkerResult:
    """launch -> drain -> parse. Never raises; absence is a status."""
    try:
        plan = plan_call(call)
    except LaunchRefused as exc:
        return _absent(call, WorkerStatus.REFUSED, str(exc))
    try:
        digest, real = preflight_executable(call.policy, hasher=hasher)
    except FileNotFoundError as exc:
        return _absent(
            call, WorkerStatus.MISSING, f"executable not found: {exc}", plan.idempotency_key
        )
    except LaunchRefused as exc:
        return _absent(call, WorkerStatus.REFUSED, str(exc), plan.idempotency_key)
    plan.argv[0] = str(real)  # execute exactly the file that was hashed
    plan.executable = str(real)
    call_dir = plan.schema_path.parent if plan.schema_path is not None else None
    if call_dir is not None and call.schema is not None:
        try:
            make_private_dir(call_dir)
        except LaunchRefused as exc:
            return _absent(call, WorkerStatus.REFUSED, str(exc), plan.idempotency_key)
    # From here on a scratch directory of ours exists: EVERY return path below
    # goes through the cleanup in `finally` and carries its outcome.
    cleanup_error: str | None = None
    try:
        result = _execute(
            call, plan, digest, popen=popen, killpg=killpg, clock=clock, on_spawn=on_spawn
        )
    finally:
        # Never leave the unredacted `-o` file (or the schema) on disk; the
        # caller passes output_file through RunWriter.put_blob. A cleanup
        # failure is NOT swallowed: it is reported on the result.
        if call_dir is not None:
            try:
                shutil.rmtree(call_dir)
            except OSError as exc:
                cleanup_error = f"scratch cleanup failed for {call_dir}: {exc}"
    if cleanup_error is not None:
        result.cleanup_error = cleanup_error
    return result


def _execute(
    call: WorkerCall,
    plan: Plan,
    digest: str,
    *,
    popen: PopenFactory,
    killpg: KillPg,
    clock: Callable[[], float],
    on_spawn: Callable[[int], None] | None = None,
) -> WorkerResult:
    """spawn -> read `-o` -> parse -> WorkerResult. Never raises on worker
    misbehaviour; the caller attaches cleanup_error afterwards."""
    w = call.policy
    if plan.schema_path is not None and call.schema is not None:
        try:
            plan.schema_path.write_text(json.dumps(call.schema, sort_keys=True), encoding="utf-8")
        except OSError as exc:
            return _absent(
                call, WorkerStatus.FAILED, f"cannot write schema: {exc}", plan.idempotency_key
            )
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
            exempt=(plan.prompt_index,),
            on_spawn=on_spawn,
        )
    except LaunchRefused as exc:
        return _absent(call, WorkerStatus.REFUSED, str(exc), plan.idempotency_key)
    except OSError as exc:
        return _absent(call, WorkerStatus.FAILED, f"spawn failed: {exc}", plan.idempotency_key)
    output_file: bytes | None = None
    output_size: int | None = None
    output_truncated = False
    output_refusal: str | None = None
    if plan.output_path is not None:
        try:
            output_file, output_size, output_truncated = read_output_file(
                plan.output_path, w.max_stdout_bytes
            )
        except LaunchRefused as exc:
            output_refusal = str(exc)
        except OSError as exc:
            # lstat is advisory; O_NOFOLLOW is the real guard. A swap between
            # the two (ELOOP) or any other open/read failure is a refusal.
            output_refusal = f"worker output {plan.output_path} could not be read safely: {exc}"
    assert w.cli is not None
    try:
        envelope = PARSERS[w.cli](spawned.stdout)
    except Exception as exc:  # noqa: BLE001 - a parser bug must never escape run_worker
        envelope = Envelope(
            None,
            None,
            None,
            None,
            True,
            f"{w.cli}: parser failure: {exc!s:.120}",
            "none",
            raw=spawned.stdout[:2000],
        )
    if envelope.structured is None and output_file:
        envelope.structured = _structured_from_text(output_file.decode("utf-8", errors="replace"))
    error: str | None
    warning: str | None = None
    if spawned.timed_out:
        status = WorkerStatus.TIMEOUT
        error = f"timed out after {w.timeout_s}s (killed with signal {spawned.killed_with})"
    elif output_refusal is not None:
        status = WorkerStatus.REFUSED
        error = output_refusal
    elif envelope.is_error:
        status = WorkerStatus.FAILED
        error = envelope.error or "worker reported an error"
    elif spawned.exit_code not in (0, None):
        status = WorkerStatus.FAILED
        error = f"exit code {spawned.exit_code}"
    else:
        status = WorkerStatus.OK
        error = None
        warning = envelope.error  # F3: "OK with error" is a warning, not a failure
    # Multi-model guard (stop-time review, 2026-09-14): the output-token
    # identity in parse_claude can in principle misattribute - a helper whose
    # counter coincidentally equals the result's while the primary's
    # cumulative diverges (never observed in any capture, but not excludable
    # from one envelope). When the envelope named SEVERAL models, the
    # counter-derived author is therefore recorded only if it is ALSO the
    # requested model: the counters carry the authorship claim, the request
    # only VETOES, so a false helper attribution now needs two independent
    # anomalies and the guard can only ever suppress a name, never supply
    # one. The single-name path is untouched - that is where A9-style
    # defaulting is seen, and it stays visible. The envelope (and its blob in
    # the ledger) keeps the unguarded counter verdict.
    model_executed = envelope.model_executed
    if len(envelope.models_used) > 1 and model_executed is not None and model_executed != w.model:
        model_executed = None
    return WorkerResult(
        worker_id=call.worker_id,
        provider=w.provider,
        model_requested=w.model,
        model_executed=model_executed,
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
        output_file=output_file,
        output_file_truncated=output_truncated,
        output_file_size=output_size,
        conversation_id=envelope.conversation_id,
        worker_reported_duration_ms=envelope.worker_reported_duration_ms,
        warning=warning,
        pgid=spawned.pgid,
    )


def invocation_id_for(idempotency_key: str, attempt: int) -> str:
    """F2: unique per ATTEMPT - ``inv-<key[:16]>-a<attempt>``. Two attempts of
    the same call share the key (it excludes the attempt) but never an id."""
    if attempt < 1:
        raise ValueError(f"attempt must be >= 1 (got {attempt})")
    return f"inv-{idempotency_key[:16]}-a{attempt}"
