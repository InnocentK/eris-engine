"""Hermeticity guards for the Eris test suite.

Three autouse guards apply to EVERY test:

1. ``shutil.which`` returns ``None`` for worker binaries (claude, codex, agy,
   gemini, grok, hermes, opencode, ollama) so a declared worker is never found.
2. Every subprocess entry point raises :class:`HermeticityViolation`:
   ``subprocess.Popen`` (which also covers ``run``/``call``/``check_*``,
   ``os.popen`` and asyncio's unix transport), the ``subprocess`` module
   helpers, ``os.system``/``fork``/``exec*``/``spawn*``/``posix_spawn*`` and
   ``asyncio.create_subprocess_*``.
3. Sockets cannot connect, bind, or resolve names.

A test marked ``@pytest.mark.real_subprocess`` (optionally
``real_subprocess(allow=["git"])``) gets the real ``subprocess.Popen`` back,
but argv[0] must be ``sys.executable``, ``sleep``, or one of the allowed
basenames, and ``shell=True`` is always refused. Nothing else is released.

Also provided: ``fake_process`` - a factory for Popen look-alikes used to
drive ``eris.launch.spawn`` without a real process.
"""

from __future__ import annotations

import asyncio
import getpass
import io
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

WORKER_BINARIES: frozenset[str] = frozenset(
    {"claude", "codex", "agy", "gemini", "grok", "hermes", "opencode", "ollama"}
)

# Fixture redaction list: literal -> placeholder. Captured envelopes are
# rewritten with this before they are committed, and a suite-wide test proves
# that none of the literals (derived from the running environment, so the test
# is portable) appears anywhere under tests/fixtures.
FIXTURE_REDACTIONS: dict[str, str] = {
    str(Path.home()): "/Users/USER",
    getpass.getuser(): "USER",
}

_ORIG_WHICH = shutil.which
_ORIG_POPEN_INIT = subprocess.Popen.__init__


class HermeticityViolation(RuntimeError):
    """Raised when a test tries to leave the sandbox (process, network, CLI)."""


def _raiser(what: str) -> Callable[..., Any]:
    def _blocked(*_args: Any, **_kwargs: Any) -> Any:
        raise HermeticityViolation(f"{what} is blocked in the hermetic test suite")

    _blocked.__name__ = f"blocked_{what.replace('.', '_')}"
    return _blocked


def _guarded_which(cmd: str, mode: int = os.F_OK | os.X_OK, path: str | None = None) -> str | None:
    if os.path.basename(str(cmd)) in WORKER_BINARIES:
        return None
    return _ORIG_WHICH(cmd, mode=mode, path=path)


_OS_ENTRY_POINTS = (
    "system",
    "popen",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
)
_SUBPROCESS_HELPERS = ("run", "call", "check_call", "check_output", "getoutput", "getstatusoutput")
_SOCKET_METHODS = ("connect", "connect_ex", "bind", "sendto", "sendmsg")
_SOCKET_FUNCS = (
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
)


def _argv0(args: Any) -> str:
    if isinstance(args, (str, bytes, os.PathLike)):
        return os.fsdecode(args)
    return os.fsdecode(args[0])


@pytest.fixture(autouse=True)
def _hermetic(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    marker = request.node.get_closest_marker("real_subprocess")
    allowed: frozenset[str] | None = None
    if marker is not None:
        extra = tuple(marker.kwargs.get("allow", ()))
        allowed = frozenset({os.path.basename(sys.executable), "sleep", *extra})

    monkeypatch.setattr(shutil, "which", _guarded_which)

    def guarded_popen_init(self: subprocess.Popen[Any], args: Any, *a: Any, **kw: Any) -> None:
        if allowed is None:
            raise HermeticityViolation("subprocess.Popen is blocked (mark real_subprocess)")
        if kw.get("shell"):
            raise HermeticityViolation("shell=True is never allowed")
        argv0 = _argv0(args)
        if argv0 != sys.executable and os.path.basename(argv0) not in allowed:
            raise HermeticityViolation(
                f"real_subprocess only permits {sorted(allowed)}; got {argv0!r}"
            )
        _ORIG_POPEN_INIT(self, args, *a, **kw)

    monkeypatch.setattr(subprocess.Popen, "__init__", guarded_popen_init)
    if allowed is None:
        for name in _SUBPROCESS_HELPERS:
            monkeypatch.setattr(subprocess, name, _raiser(f"subprocess.{name}"))
    for name in _OS_ENTRY_POINTS:
        if hasattr(os, name):
            monkeypatch.setattr(os, name, _raiser(f"os.{name}"))
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", _raiser("asyncio.create_subprocess_exec")
    )
    monkeypatch.setattr(
        asyncio, "create_subprocess_shell", _raiser("asyncio.create_subprocess_shell")
    )

    for name in _SOCKET_METHODS:
        monkeypatch.setattr(socket.socket, name, _raiser(f"socket.socket.{name}"))
    for name in _SOCKET_FUNCS:
        monkeypatch.setattr(socket, name, _raiser(f"socket.{name}"))
    yield


class FakeProcess:
    """A ``subprocess.Popen`` look-alike with injectable stdout/stderr/exit.

    ``hang=True`` makes ``wait`` block until a signal is delivered via
    ``send_signal``/``terminate``/``kill`` (or the injected killpg in the
    launcher tests), which is how the timeout path is exercised hermetically.
    """

    def __init__(
        self,
        args: Any,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        returncode: int = 0,
        hang: bool = False,
        pid: int = 424242,
        popen_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self.args = args
        self.popen_kwargs = popen_kwargs or {}
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.pid = pid
        self.returncode: int | None = None
        self._rc = returncode
        self.hang = hang
        self.signals: list[int] = []
        self._signalled = threading.Event()

    def poll(self) -> int | None:
        if self.hang and not self._signalled.is_set():
            return None
        # Like a real process: the FIRST delivered signal is what ended it;
        # later signals (e.g. the SIGKILL sweep) are recorded but change nothing.
        self.returncode = -self.signals[0] if self.signals else self._rc
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.hang and not self._signalled.is_set():
            if timeout is None:
                raise RuntimeError("FakeProcess(hang=True).wait() without timeout would block")
            if not self._signalled.wait(timeout):
                raise subprocess.TimeoutExpired(self.args, timeout)
        rc = self.poll()
        assert rc is not None
        return rc

    def send_signal(self, sig: int) -> None:
        self.signals.append(int(sig))
        self._signalled.set()

    def terminate(self) -> None:
        self.send_signal(signal.SIGTERM)

    def kill(self) -> None:
        self.send_signal(signal.SIGKILL)


class FakeProcessFactory:
    """Callable standing in for ``subprocess.Popen``; records every instance."""

    def __init__(self, **defaults: Any) -> None:
        self.defaults = defaults
        self.instances: list[FakeProcess] = []

    def __call__(self, args: Any, **popen_kwargs: Any) -> FakeProcess:
        proc = FakeProcess(args, popen_kwargs=popen_kwargs, **self.defaults)
        self.instances.append(proc)
        return proc


@pytest.fixture
def fake_process() -> Callable[..., FakeProcessFactory]:
    """Return ``factory(**defaults)``; pass the result as ``popen=`` to spawn()."""

    def _make(**defaults: Any) -> FakeProcessFactory:
        return FakeProcessFactory(**defaults)

    return _make
