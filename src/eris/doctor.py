"""``eris doctor``: filesystem/config-only preflight. Prints key NAMES, never
values. A missing worker is a WARN (recorded absence), never a substitution.
``--probe`` additionally runs ``<cli> --version`` through an injectable runner.
"""

from __future__ import annotations

import fcntl
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from eris.launch import build_env, resolve_user
from eris.policy import LoadedPolicy, PolicyError, load_policy, sha256_file
from eris.redact import CredentialFileError, Redactor, load_credential_values, parse_dotenv
from eris.schemas import Transport

Status = Literal["OK", "WARN", "FAIL"]
Runner = Callable[[list[str], dict[str, str]], str | None]

# Antigravity writes a transcript + SQLite state under this directory on EVERY
# run (~1 MB/run observed 2026-08-22). Eris never deletes vendor state (lock
# races, not ours); the doctor only reports its size so the user can clean up.
AGY_STATE_DIR = ".gemini/antigravity-cli"
AGY_STATE_SUBDIRS = ("brain", "conversations")
AGY_STATE_WARN_BYTES = 256 * 1024 * 1024


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            continue
    return total


@dataclass(frozen=True)
class Check:
    status: Status
    name: str
    message: str


@dataclass
class DoctorReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, status: Status, name: str, message: str) -> None:
        self.checks.append(Check(status, name, message))

    @property
    def ok(self) -> bool:
        return all(c.status != "FAIL" for c in self.checks)

    def render(self) -> str:
        lines = [f"{c.status:<5}{c.name}: {c.message}" for c in self.checks]
        worst = (
            "FAIL"
            if not self.ok
            else ("WARN" if any(c.status == "WARN" for c in self.checks) else "OK")
        )
        lines.append(f"doctor: {worst} ({len(self.checks)} checks)")
        return "\n".join(lines)


def default_probe_runner(argv: list[str], env: dict[str, str]) -> str | None:
    try:
        proc = subprocess.run(
            argv,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""


def _expand(raw: str, home: Path) -> Path:
    return Path(raw.replace("~", str(home), 1)) if raw.startswith("~") else Path(raw)


def _flock_probe(runs_dir: Path) -> tuple[Status, str]:
    try:
        runs_dir.mkdir(parents=True, exist_ok=True)
        probe = runs_dir / ".doctor.lock"
        with open(probe, "ab") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        probe.unlink()
    except OSError as exc:
        return "FAIL", f"flock probe failed in {runs_dir}: {exc.__class__.__name__}"
    return "OK", f"{runs_dir} writable; flock works"


def _env_names(env_file: Path) -> tuple[dict[str, str], Status, str]:
    """Names and (in-memory only, for the redactor) values from .env."""
    if not env_file.exists():
        return {}, "WARN", f"{env_file} not found (only needed for api workers / env_allow)"
    try:
        mode = env_file.stat().st_mode & 0o777
        values = {k: v for k, v in parse_dotenv(env_file.read_text(encoding="utf-8")).items() if v}
    except OSError as exc:
        return {}, "FAIL", f"cannot read {env_file}: {exc.__class__.__name__}"
    perm = f"; mode {mode:o} is group/world readable - chmod 600" if mode & 0o077 else ""
    return values, ("WARN" if perm else "OK"), f"{len(values)} non-empty names{perm}"


def _agy_state_check(report: DoctorReport, wid: str, home: Path) -> None:
    """Size of agy's brain/conversations state (names and byte counts only)."""
    root = home / AGY_STATE_DIR
    present = [sub for sub in AGY_STATE_SUBDIRS if (root / sub).is_dir()]
    if not present:
        report.add("OK", f"worker.{wid}.state", f"~/{AGY_STATE_DIR}/{{brain,conversations}} absent")
        return
    sizes = {sub: _dir_size(root / sub) for sub in present}
    total = sum(sizes.values())
    detail = ", ".join(f"{sub} {size / 1_048_576:.1f} MiB" for sub, size in sizes.items())
    if total >= AGY_STATE_WARN_BYTES:
        report.add(
            "WARN",
            f"worker.{wid}.state",
            f"~/{AGY_STATE_DIR}: {detail} (>= {AGY_STATE_WARN_BYTES >> 20} MiB; every run adds "
            "~1 MB; Eris never deletes vendor state - clean up manually)",
        )
    else:
        report.add("OK", f"worker.{wid}.state", f"~/{AGY_STATE_DIR}: {detail}")


def run_doctor(
    *,
    policy_path: Path,
    env_file: Path,
    probe: bool = False,
    runner: Runner = default_probe_runner,
    home: Path | None = None,
    which: Callable[[str], str | None] | None = None,
    user_resolver: Callable[[], str | None] | None = None,
) -> DoctorReport:
    home = home or Path.home()
    # Resolved at call time on purpose: a default argument would bind the
    # original function and bypass the test suite's shutil.which guard.
    which = which or shutil.which
    user_resolver = user_resolver or resolve_user
    report = DoctorReport()
    v = sys.version_info
    report.add(
        "OK" if v >= (3, 12) else "FAIL",
        "python",
        f"{v.major}.{v.minor}.{v.micro} (>= 3.12 required)",
    )
    user = user_resolver()
    report.add(
        "OK" if user else "WARN",
        "user",
        f"USER={user} (passed to every CLI worker)"
        if user
        else "the account name could not be resolved: CLI workers run without USER, "
        "which claude reports as 'Not logged in' even when the credentials are valid",
    )
    try:
        loaded: LoadedPolicy = load_policy(policy_path)
    except PolicyError as exc:
        report.add("FAIL", "policy", str(exc).splitlines()[0])
        return report
    pol = loaded.policy
    report.add(
        "OK",
        "policy",
        f"{policy_path} sha256 {loaded.sha256[:12]}; pins "
        + (f"{loaded.pins_sha256[:12]}" if loaded.pins_sha256 else "none")
        + f"; trusted={pol.trusted}",
    )
    env_values, st, msg = _env_names(env_file)
    names = set(env_values)
    report.add(st, "env-file", msg)

    credential_paths = [_expand(raw, home) for raw in pol.credential_files]
    creds_failed = False
    try:
        creds = load_credential_values(credential_paths)
    except CredentialFileError as exc:
        report.add("FAIL", "credential-file", str(exc))
        creds = None
        creds_failed = True  # the redactor would be missing those values: no probes at all
    else:
        for raw, path in zip(pol.credential_files, credential_paths, strict=True):
            present = path.exists()
            report.add(
                "OK" if present else "WARN",
                "credential-file",
                f"{raw}: {'present' if present else 'absent'}",
            )
    # Anything printed from a probe goes through the redactor (patterns +
    # every known secret value); the values themselves never leave memory.
    redactor = Redactor([*env_values.values(), *(creds.values if creds else [])])

    for wid, w in pol.workers.items():
        if w.cli == "agy":
            _agy_state_check(report, wid, home)
        if w.transport is Transport.API:
            present = w.api_key_env in names
            report.add(
                "OK" if present else "WARN",
                f"worker.{wid}",
                f"api {w.provider} {w.base_url}; key name {w.api_key_env} "
                + ("present" if present else "ABSENT in .env (worker unavailable)"),
            )
            continue
        exe = w.executable
        if exe is None:
            found = which(w.cli or "")
            if found is None:
                report.add("WARN", f"worker.{wid}", f"{w.cli} not found on PATH (recorded absence)")
            else:
                report.add(
                    "WARN",
                    f"worker.{wid}",
                    f"{w.cli} at {found} but UNPINNED (run `eris policy pin`)",
                )
            continue
        if not Path(exe).is_file():
            report.add("WARN", f"worker.{wid}", f"{exe} missing (recorded absence)")
            continue
        hash_ok = False
        if not w.pinned:
            report.add(
                "WARN", f"worker.{wid}", f"{exe} present but UNPINNED (run `eris policy pin`)"
            )
        elif sha256_file(Path(exe)) != w.executable_sha256:
            report.add(
                "FAIL",
                f"worker.{wid}",
                f"{exe} sha256 differs from pin (binary changed; re-pin deliberately)",
            )
        else:
            hash_ok = True
            report.add("OK", f"worker.{wid}", f"{exe} pinned {w.executable_sha256[:12]}")
        missing = [n for n in w.env_allow if n not in names]
        if missing:
            report.add("WARN", f"worker.{wid}.env", f"env_allow names absent from .env: {missing}")
        if probe and w.cli:
            if creds_failed:
                report.add("WARN", f"worker.{wid}.probe", "skipped (credential parse failure)")
                continue
            if not hash_ok:
                # Never execute an unpinned or mismatched binary, even for --version.
                report.add("WARN", f"worker.{wid}.probe", "skipped: binary is not pinned/verified")
                continue
            env = build_env(
                w.cli,
                path_env=pol.path_env,
                home=str(home),
                tmpdir="/tmp",
                user=user,
                policy_env=w.env,
            )
            version = runner([exe, "--version"], env)
            if version is None:
                report.add("WARN", f"worker.{wid}.probe", "--version failed")
            else:
                safe = redactor.redact(version).text.splitlines()
                report.add(
                    "OK", f"worker.{wid}.probe", f"--version: {(safe[0] if safe else '')[:80]}"
                )

    for name, cmd in pol.verify.commands.items():
        p = Path(cmd.executable)
        if not p.is_file():
            report.add("WARN", f"verify.{name}", f"{p} missing (command unavailable)")
        elif not cmd.pinned:
            report.add("WARN", f"verify.{name}", f"{p} UNPINNED")
        else:
            report.add("OK", f"verify.{name}", f"{p} pinned")

    git = which("git")
    report.add("OK" if git else "FAIL", "git", git or "git not found on PATH")
    st, msg = _flock_probe(Path(pol.runs_dir))
    report.add(st, "runs-dir", msg)
    return report
