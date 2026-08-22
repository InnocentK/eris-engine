"""Prove the three autouse hermeticity guards actually bite."""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import sys

import httpx
import pytest

from tests.conftest import WORKER_BINARIES, FakeProcess, HermeticityViolation


@pytest.mark.parametrize("name", sorted(WORKER_BINARIES))
def test_which_hides_worker_binaries(name: str) -> None:
    assert shutil.which(name) is None
    assert shutil.which(f"/opt/homebrew/bin/{name}") is None


def test_which_passes_through_non_worker_lookups() -> None:
    # git is not a worker; the guard must not lie about it.
    assert shutil.which("git") is not None


@pytest.mark.parametrize(
    "call",
    [
        lambda: subprocess.Popen(["true"]),
        lambda: subprocess.run(["true"]),
        lambda: subprocess.call(["true"]),
        lambda: subprocess.check_call(["true"]),
        lambda: subprocess.check_output(["true"]),
        lambda: subprocess.getoutput("true"),
        lambda: os.system("true"),
        lambda: os.popen("true"),
        lambda: os.fork(),
        lambda: os.posix_spawn("/usr/bin/true", ["true"], {}),
        lambda: os.execv("/usr/bin/true", ["true"]),
        lambda: os.spawnv(os.P_WAIT, "/usr/bin/true", ["true"]),
        lambda: asyncio.create_subprocess_exec("true"),
        lambda: asyncio.create_subprocess_shell("true"),
    ],
    ids=[
        "Popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "os.system",
        "os.popen",
        "os.fork",
        "os.posix_spawn",
        "os.execv",
        "os.spawnv",
        "asyncio.exec",
        "asyncio.shell",
    ],
)
def test_subprocess_entry_points_raise(call: object) -> None:
    assert callable(call)
    with pytest.raises(HermeticityViolation):
        call()


def test_sockets_cannot_connect_or_resolve() -> None:
    with pytest.raises(HermeticityViolation):
        socket.create_connection(("127.0.0.1", 9), timeout=0.1)
    with pytest.raises(HermeticityViolation):
        socket.getaddrinfo("example.com", 80)
    sock = socket.socket()
    try:
        with pytest.raises(HermeticityViolation):
            sock.connect(("127.0.0.1", 9))
        with pytest.raises(HermeticityViolation):
            sock.bind(("127.0.0.1", 0))
    finally:
        sock.close()


def test_httpx_is_blocked_at_the_socket() -> None:
    with pytest.raises(HermeticityViolation):
        httpx.get("http://127.0.0.1:9/", timeout=0.2)


@pytest.mark.real_subprocess
def test_marker_releases_only_sys_executable_and_sleep() -> None:
    out = subprocess.run(
        [sys.executable, "-c", "print('hermetic-ok')"], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "hermetic-ok"
    with pytest.raises(HermeticityViolation):
        subprocess.run(["true"])
    with pytest.raises(HermeticityViolation):
        subprocess.run("true", shell=True)
    with pytest.raises(HermeticityViolation):
        subprocess.run([sys.executable, "-c", "pass"], shell=True)
    # The other guards stay in force under the marker.
    assert shutil.which("claude") is None
    with pytest.raises(HermeticityViolation):
        os.fork()
    with pytest.raises(HermeticityViolation):
        socket.getaddrinfo("example.com", 80)


@pytest.mark.real_subprocess(allow=["git"])
def test_marker_allow_extends_the_list() -> None:
    out = subprocess.run(["git", "--version"], capture_output=True, text=True, check=True)
    assert out.stdout.startswith("git version")
    with pytest.raises(HermeticityViolation):
        subprocess.run(["true"])


def test_fake_process_contract(fake_process: object) -> None:
    assert callable(fake_process)
    factory = fake_process(stdout=b"hello", stderr=b"err", returncode=3)
    proc = factory(["x"], cwd="/tmp", env={})
    assert isinstance(proc, FakeProcess)
    assert proc.popen_kwargs == {"cwd": "/tmp", "env": {}}
    assert proc.stdout.read() == b"hello"
    assert proc.stderr.read() == b"err"
    assert proc.wait(timeout=1) == 3
    hanging = fake_process(hang=True)(["y"])
    assert hanging.poll() is None
    with pytest.raises(subprocess.TimeoutExpired):
        hanging.wait(timeout=0.01)
    hanging.terminate()
    assert hanging.wait(timeout=1) < 0
    assert factory.instances == [proc]
