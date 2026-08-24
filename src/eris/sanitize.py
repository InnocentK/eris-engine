"""Per-worker snapshot sanitization: a private copy of the snapshot with the
repository's instruction files removed.

agy injects a declared workspace's ``AGENTS.md``/``GEMINI.md`` rules (A15)
and grok was observed following repo instructions once (E1). Workers whose
policy says ``sanitize_snapshot: true`` run their proposer/critic roles on a
COPY built here; mechanical verification ALWAYS runs on the ORIGINAL
(``eris.evidence`` takes the original root explicitly).

Rules (each has a test in tests/test_sanitize.py):

* The strip list is the policy's ``sanitize`` section on top of the
  enforced minimum (``policy.SANITIZE_MIN_NAMES`` / ``SANITIZE_MIN_DIRS``):
  matched by NAME at ANY depth, case-insensitively; entries containing
  ``/`` match a relative-path suffix (``.github/copilot-instructions.md``).
  A match strips the entry whatever it is - file, directory, or symlink
  (``AGENTS.md`` as a symlink, ``.agents`` as a file).
* Files are copied (new inodes: never hardlinks); symlinks are kept only
  when relative, resolving inside the original tree and not into a stripped
  entry; every other symlink is DROPPED and recorded.
* ``.git`` is copied with ``.git/hooks`` removed (``core.hooksPath`` is
  neutralised by the launcher's git hardening) and, in the COPY's
  ``.git/config`` only, ``core.fsmonitor`` and ``core.untrackedCache``
  disabled (:func:`neutralise_git_config`). A snapshot without ``.git`` is
  fine.
* The copy lives in a ``make_private_dir`` under the run's scratch dir and
  is deleted in ``finally``; a cleanup failure raises
  :class:`SanitizeCleanupError` (the caller records a ``run.error``).
* The original is never written: tests pin its tree hash and inodes.

Residual channels (docs/SECURITY.md): comments, docstrings, READMEs and
commit messages remain in-band instruction channels, and a worker with git
tools can still ``git show HEAD:AGENTS.md``. Sanitization removes what the
CLIs load AUTOMATICALLY; it does not make a repository trustworthy.
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from eris.launch import make_private_dir
from eris.policy import SANITIZE_MIN_DIRS, SANITIZE_MIN_NAMES, Policy
from eris.schemas import (
    SnapshotSanitization,
    StrippedEntry,
    canonical_bytes,
    sha256_hex,
)

GIT_DIR = ".git"
GIT_HOOKS = (GIT_DIR, "hooks")
GIT_CONFIG = (GIT_DIR, "config")

#: ``core.*`` keys neutralised in the COPY's ``.git/config`` (lower-cased; git
#: config keys are case-insensitive). Both make git answer from a filesystem
#: cache instead of from the working tree, and both are inherited verbatim by a
#: `cp -a` of a repository that configures them.
NEUTRALISED_GIT_CONFIG_KEYS: tuple[str, ...] = ("fsmonitor", "untrackedcache")

#: Appended to the copy's ``.git/config`` after the matching entries are
#: removed. Removal alone is not enough: `.git/config` may `include` another
#: file, and a later section wins in git's config order, so an explicit
#: trailing ``[core]`` block is what actually guarantees the value.
GIT_CONFIG_NEUTRALISED_BLOCK = (
    "# eris: this is a private VERIFICATION/worker COPY, never the original.\n"
    "# Filesystem-monitor caches are disabled here so that no daemon or hook\n"
    "# can mark index entries valid mid-run and no stale cache can answer for\n"
    "# the working tree. See docs/SECURITY.md.\n"
    "[core]\n"
    "\tfsmonitor = false\n"
    "\tuntrackedCache = false\n"
)


class SanitizeError(RuntimeError):
    """The copy could not be built safely; nothing is handed to a worker."""


class SanitizeCleanupError(SanitizeError):
    """The copy could not be removed: worker-visible files MAY remain."""


@dataclass(frozen=True)
class SanitizeProfile:
    """Effective strip lists (minimum ∪ policy), lower-cased for matching."""

    names: frozenset[str]
    dirs: frozenset[str]

    @classmethod
    def from_policy(cls, policy: Policy | None) -> SanitizeProfile:
        names = set(SANITIZE_MIN_NAMES)
        dirs = set(SANITIZE_MIN_DIRS)
        if policy is not None:
            names |= set(policy.sanitize.strip_names)
            dirs |= set(policy.sanitize.strip_dirs)
        return cls(frozenset(names), frozenset(dirs))

    @property
    def sha256(self) -> str:
        return sha256_hex(canonical_bytes({"names": sorted(self.names), "dirs": sorted(self.dirs)}))

    def matches(self, relpath: PurePosixPath | str) -> bool:
        """True when the LAST component (or, for slash entries, a path
        suffix) matches an entry, case-insensitively."""
        rel = PurePosixPath(str(relpath).replace(os.sep, "/"))
        low = rel.as_posix().lower()
        name = rel.name.lower()
        for entry in (*self.names, *self.dirs):
            e = entry.lower().strip("/")
            if "/" in e:
                if low == e or low.endswith("/" + e):
                    return True
            elif name == e:
                return True
        return False


# --------------------------------------------------------------------------- tree hash


def tree_sha256(root: Path, *, skip: Callable[[PurePosixPath], bool] | None = None) -> str:
    """Order-independent hash of a tree: one line per entry (file content
    sha, directory, or symlink target), sorted by relative path. Symlinks
    are NOT followed. ``skip`` drops entries (and their subtrees) so a copy
    can be compared with "the original minus what was stripped"."""
    root = Path(root)
    lines: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(dirpath)
        keep_dirs: list[str] = []
        for d in sorted(dirnames):
            rel = _rel(base / d, root)
            if skip is not None and skip(rel):
                continue
            p = base / d
            if p.is_symlink():
                lines.append(f"L {rel.as_posix()} {os.readlink(p)}")
            else:
                lines.append(f"D {rel.as_posix()}")
                keep_dirs.append(d)
        dirnames[:] = keep_dirs
        for f in sorted(filenames):
            rel = _rel(base / f, root)
            if skip is not None and skip(rel):
                continue
            p = base / f
            if p.is_symlink():
                lines.append(f"L {rel.as_posix()} {os.readlink(p)}")
            elif stat.S_ISREG(p.lstat().st_mode):
                lines.append(f"F {rel.as_posix()} {sha256_hex(p.read_bytes())}")
            else:
                lines.append(f"S {rel.as_posix()}")  # fifo/socket/device: never opened
    lines.sort()
    return sha256_hex("\n".join(lines).encode("utf-8"))


def _rel(path: Path, root: Path) -> PurePosixPath:
    return PurePosixPath(path.relative_to(root).as_posix())


# --------------------------------------------------------------------------- sanitize


def _symlink_keepable(
    link: Path, rel: PurePosixPath, original: Path, profile: SanitizeProfile
) -> bool:
    """Relative, resolves inside the original root, and does not point into
    a stripped entry. Everything else (absolute, escaping, dangling) is dropped."""
    target = os.readlink(link)
    if os.path.isabs(target):
        return False
    try:
        resolved = (link.parent / target).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    try:
        target_rel = resolved.relative_to(original)
    except ValueError:
        return False
    parts = PurePosixPath(target_rel.as_posix()).parts
    for i in range(1, len(parts) + 1):
        if profile.matches(PurePosixPath(*parts[:i])):
            return False
    return True


def sanitize_snapshot(
    original: Path, dest: Path, *, profile: SanitizeProfile, worker_id: str
) -> SnapshotSanitization:
    """Build ``dest`` (created fresh; refused if it exists or is a symlink)
    as the sanitized copy of ``original``. Never writes to ``original``."""
    original = Path(original).resolve()
    if not original.is_dir():
        raise SanitizeError(f"snapshot {original} is not a directory")
    dest = Path(dest)
    make_private_dir(dest)
    dest = dest.resolve()
    if dest == original or _is_under(dest, original) or _is_under(original, dest):
        raise SanitizeError("the copy must not live inside the original (or vice versa)")
    original_sha = tree_sha256(original)
    stripped: list[StrippedEntry] = []
    dropped: list[str] = []
    # (source, copy) of every directory we create: their metadata is copied at
    # the END, so a read-only directory can still be written into meanwhile.
    made_dirs: list[tuple[Path, Path]] = [(original, dest)]
    for dirpath, dirnames, filenames in os.walk(original, topdown=True, followlinks=False):
        base = Path(dirpath)
        in_git = _rel(base, original).parts[:1] == (GIT_DIR,) if base != original else False
        keep_dirs: list[str] = []
        for d in sorted(dirnames):
            src = base / d
            rel = _rel(src, original)
            if rel.parts[: len(GIT_HOOKS)] == GIT_HOOKS:
                continue  # .git/hooks is never copied
            if not in_git and profile.matches(rel):
                stripped.extend(_collect(src, original))
                continue
            if src.is_symlink():
                if _symlink_keepable(src, rel, original, profile):
                    os.symlink(os.readlink(src), dest / rel)
                else:
                    dropped.append(rel.as_posix())
                continue
            (dest / rel).mkdir(mode=0o700)  # metadata copied below
            made_dirs.append((src, dest / rel))
            keep_dirs.append(d)
        dirnames[:] = keep_dirs
        for f in sorted(filenames):
            src = base / f
            rel = _rel(src, original)
            if not in_git and profile.matches(rel):
                stripped.extend(_collect(src, original))
                continue
            if src.is_symlink():
                if _symlink_keepable(src, rel, original, profile):
                    os.symlink(os.readlink(src), dest / rel)
                else:
                    dropped.append(rel.as_posix())
                continue
            st = src.lstat()
            if not stat.S_ISREG(st.st_mode):
                raise SanitizeError(f"{rel}: not a regular file, directory or symlink; refusing")
            shutil.copy2(src, dest / rel, follow_symlinks=False)  # new inode, never a hardlink
    # BEFORE the directory modes are restored (a read-only `.git` would forbid
    # the write) and before anything is handed to a caller, so the copy is
    # already neutralised when the first command runs against it
    neutralise_git_config(dest)
    # deepest first: a directory's mode may forbid writing, so it is applied
    # only once everything below it exists (fidelity, cond 4)
    for src_dir, copy_dir in reversed(made_dirs):
        shutil.copystat(src_dir, copy_dir, follow_symlinks=False)
    return SnapshotSanitization(
        worker_id=worker_id,
        profile_sha256=profile.sha256,
        original_root_sha256=original_sha,
        copy_tree_sha256=tree_sha256(dest),
        stripped=sorted(stripped, key=lambda e: e.relpath),
        dropped_symlinks=sorted(dropped),
    )


def neutralise_git_config(copy_root: Path) -> bool:
    """Disable the inherited filesystem-monitor caches in the COPY's
    ``.git/config``. Returns True when the file was rewritten.

    **The original is never opened for writing here** - the argument is the
    copy's root, and every path used is under it.

    `core.fsmonitor` and `core.untrackedCache` are the two settings that make
    git answer from a cache instead of from the working tree. Inherited by a
    raw copy of a repository that configures them, they are a problem in both
    directions: a live daemon (or a hook) can mark index entries fsmonitor-valid
    *during* a verification run, which the index digest would report as a
    violation that no verification command caused, and a stale cache can let a
    command answer from data the tree no longer supports.

    Matching entries are dropped (including any backslash-continued value), and
    an explicit ``[core]`` block setting both to ``false`` is appended: a later
    section wins in git's config order, so the appended block also covers a
    value pulled in by an ``include``/``includeIf`` directive earlier in the
    file. A ``.git`` with no regular ``config`` file (no repository, or a
    gitlink) is left alone - nothing was inherited.

    Bytes in, bytes out: the file is never decoded, so a non-UTF-8 or CRLF
    config round-trips unchanged apart from the removed lines.
    """
    cfg = Path(copy_root).joinpath(*GIT_CONFIG)
    if cfg.is_symlink() or not cfg.is_file():
        return False
    kept: list[bytes] = []
    in_core = False
    dropping = False
    for line in cfg.read_bytes().splitlines(keepends=True):
        body = line.strip()
        if dropping:  # a continued value belongs to the key that was dropped
            dropping = body.endswith(b"\\")
            continue
        if body.startswith(b"["):
            # `[core]`, `[ CORE ]`; `[core "sub"]` is a different section
            in_core = body[1:].split(b"]", 1)[0].strip().lower() == b"core"
        elif in_core and not body.startswith((b"#", b";")):
            key = body.split(b"=", 1)[0].strip().lower()
            if key in tuple(k.encode("ascii") for k in NEUTRALISED_GIT_CONFIG_KEYS):
                dropping = body.endswith(b"\\")
                continue
        kept.append(line)
    out = b"".join(kept)
    if out and not out.endswith((b"\n", b"\r")):
        out += b"\n"
    out += GIT_CONFIG_NEUTRALISED_BLOCK.encode("ascii")
    mode = cfg.stat().st_mode
    if not mode & stat.S_IWUSR:  # a read-only config in the copy is still ours
        cfg.chmod(stat.S_IMODE(mode) | stat.S_IWUSR)
    cfg.write_bytes(out)
    cfg.chmod(stat.S_IMODE(mode))  # the copy keeps the original's file mode
    return True


def _collect(path: Path, original: Path) -> list[StrippedEntry]:
    """Every stripped FILE under ``path`` (a file, a symlink, or a directory
    walked without following links). A stripped symlink records its target
    string (size and sha of the link text, never of a file outside)."""
    rel = _rel(path, original).as_posix()
    if path.is_symlink():
        target = os.readlink(path).encode("utf-8", errors="replace")
        return [StrippedEntry(relpath=rel, size=len(target), sha256=sha256_hex(target))]
    if path.is_dir():
        out: list[StrippedEntry] = []
        for dirpath, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
            base = Path(dirpath)
            for d in sorted(dirnames):
                if (base / d).is_symlink():
                    out.extend(_collect(base / d, original))
            dirnames[:] = [d for d in dirnames if not (base / d).is_symlink()]
            for f in sorted(filenames):
                out.extend(_collect(base / f, original))
        return out
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        return [StrippedEntry(relpath=rel, size=0, sha256=sha256_hex(b""))]
    data = path.read_bytes()
    return [StrippedEntry(relpath=rel, size=len(data), sha256=sha256_hex(data))]


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


VERIFICATION_PROFILE = SanitizeProfile(frozenset(), frozenset())
"""The profile used for the copy mechanical verification runs in, so a command
that executes repository code (a trusted ``pytest``) can never touch the
original. It strips NO instruction files - verification must see the repository
as it is - and differs from a raw ``cp -a`` in exactly three ways, all
inherited from :func:`sanitize_snapshot` and all deliberate:

1. ``.git/hooks`` is not copied. Our allowlist runs ``git``, and a repository
   hook would execute on the first ``git`` invocation.
2. The copy's ``.git/config`` has ``core.fsmonitor`` and
   ``core.untrackedCache`` removed and explicitly set to ``false``
   (:func:`neutralise_git_config`), so an inherited filesystem monitor cannot
   mark index entries valid mid-run and no stale cache can answer for the
   working tree. The ORIGINAL's config is never opened for writing, and the
   edit happens while the copy is being built - before any verification
   command, and before the guard takes its baseline.
3. A symlink that is absolute, dangling, or resolves outside the tree is
   dropped and recorded in ``dropped_symlinks``; links that stay inside are
   copied with their target string intact.

Everything else - the file set, the bytes, the modes, the rest of `.git` - is
identical to the original (``test_sanitize.py::test_verification_copy_
matches_the_original_except_hooks_config_and_escaping_links``)."""


# O_NOFOLLOW | O_DIRECTORY makes the chmod target unambiguous (never a symlink,
# never a file). Both are POSIX; on a platform without them (Windows) the
# fallback is a plain chmod after an lstat check, which is the same guarantee
# with a TOCTOU window inside our own private scratch dir.
_NOFOLLOW_DIR = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)


def _grant_owner_access(path: Path) -> None:
    """Add owner rwx to ``path`` if - and only if - it is a REAL directory.
    A symlink is never followed and never chmod'd; anything that is not a
    directory is left alone."""
    st = path.lstat()  # never stat(): a symlink must not be followed
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & stat.S_IRWXU == stat.S_IRWXU:
        return
    mode = stat.S_IMODE(st.st_mode) | stat.S_IRWXU
    if _NOFOLLOW_DIR:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW_DIR)
        try:
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    else:  # pragma: no cover - only on a platform without O_NOFOLLOW/O_DIRECTORY
        os.chmod(path, mode)


def _restore_owner_access(root: Path) -> None:
    """Give the owner rwx on every REAL directory INSIDE ``root`` (root
    included) so ``rmtree`` can unlink their contents: the copy preserves the
    original's directory modes, and a read-only directory blocks the removal
    of its own entries. Nothing outside ``root`` is touched - no parent, and
    no symlink (a link inside the copy may point anywhere)."""
    if root.is_symlink() or not root.is_dir():
        return
    _grant_owner_access(root)
    for dirpath, dirnames, _files in os.walk(root, topdown=True, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not (base / d).is_symlink()]
        for d in dirnames:  # top-down: a dir is made accessible before we descend
            _grant_owner_access(base / d)


def _force_writable(
    root: Path,
) -> Callable[[Callable[..., object], str, BaseException], None]:
    """Build the ``rmtree`` onexc handler for the copy rooted at ``root``.

    A PERMISSION error on a real directory inside ``root`` restores owner
    access (the pre-pass above may have raced with a mode change); anything
    else - a different errno, a symlink, a path outside the root - is
    re-raised, so a removal failure is never swallowed. The handler never
    retries ``func``: its signature is not the same for every rmtree
    primitive (``os.open`` takes flags), so calling it back is invalid."""

    def handler(_func: Callable[..., object], path: str, exc: BaseException) -> None:
        if not isinstance(exc, PermissionError):
            raise exc
        target = Path(path)
        if not _is_under(target, root):
            raise exc
        try:
            _grant_owner_access(target)  # a real directory only; never a parent
        except OSError:
            raise exc from None

    return handler


@contextmanager
def sanitized_copy(
    original: Path,
    scratch_dir: Path,
    *,
    profile: SanitizeProfile,
    worker_id: str,
    name: str | None = None,
) -> Iterator[tuple[Path, SnapshotSanitization]]:
    """``with sanitized_copy(...) as (copy_root, record):`` - the copy is a
    private dir under ``scratch_dir`` and is removed in ``finally``. A
    removal failure raises :class:`SanitizeCleanupError` (never swallowed)."""
    dest = Path(scratch_dir) / (name or f"sanitized-{worker_id}")
    record = sanitize_snapshot(original, dest, profile=profile, worker_id=worker_id)
    try:
        yield dest.resolve(), record
    finally:
        try:
            _restore_owner_access(dest)  # inside the copy only; never a parent
            shutil.rmtree(dest, onexc=_force_writable(dest))
        except OSError as exc:
            raise SanitizeCleanupError(
                f"sanitized copy {dest} could not be removed: {exc}"
            ) from exc
