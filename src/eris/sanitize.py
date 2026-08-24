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
* ``.git`` is copied with ``.git/hooks`` removed, and the COPY is CONTAINED:
  its ``.git/config`` is rewritten from an ALLOWLIST
  (:func:`rewrite_git_config`) so no repository-supplied key can make git
  execute a repository-supplied program; ``.git/objects/info/alternates``,
  its ``http-`` twin and ``.git/config.worktree`` are deleted
  (:func:`drop_git_repo_escapes`); and a copy that is not ONE self-contained
  repository - a gitlink ``.git`` FILE, ``.git/commondir``,
  ``.git/worktrees/``, ``.git/modules/`` - is REFUSED
  (:func:`assert_no_repo_escapes`, :func:`assert_git_layout_sane`). A snapshot
  without ``.git`` is fine. The config control FAILS CLOSED: a ``.git/config``
  that is a symlink resolving inside the copy is read, unlinked and replaced
  by a regular rewritten file (recorded in ``dropped_symlinks``); any other
  shape refuses the copy; and :func:`assert_git_layout_sane` then re-checks
  every ``.git`` path Eris depends on (:data:`GIT_REQUIRED_KINDS`).
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

import errno
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
GIT_CONFIG_WORKTREE = (GIT_DIR, "config.worktree")
GIT_ALTERNATES = (GIT_DIR, "objects", "info", "alternates")
GIT_HTTP_ALTERNATES = (GIT_DIR, "objects", "info", "http-alternates")
GIT_COMMONDIR = (GIT_DIR, "commondir")
GIT_WORKTREES = (GIT_DIR, "worktrees")
GIT_MODULES = (GIT_DIR, "modules")

#: The ONLY ``[core]`` keys kept in the copy's ``.git/config``, lower-cased (git
#: config keys are case-insensitive). This is an ALLOWLIST, and the bar for
#: adding one is: the REPOSITORY FORMAT needs it to open the copy correctly, and
#: its value can name neither a command nor a path git will act on.
#:
#: * ``repositoryformatversion`` - without it git assumes 0, which would silently
#:   ignore ``extensions.*`` on a version-1 repository.
#: * ``filemode``, ``symlinks``, ``ignorecase``, ``precomposeunicode`` -
#:   filesystem capability flags. Written by ``git init`` from what the
#:   filesystem actually supports; dropping them makes git re-guess from the
#:   SCRATCH filesystem the copy lives on, which can report every file as
#:   modified (a false ``snapshot.violated``). Booleans; no path, no command.
#: * ``bare`` - written by ``git init``; a wrong answer breaks every command.
#: * ``logallrefupdates`` - boolean, whether ref updates write a reflog. Kept
#:   because it is in every ``git init`` config and its absence changes what
#:   ``git reflog`` reports.
GIT_CONFIG_ALLOWED_CORE_KEYS: frozenset[str] = frozenset(
    {
        "repositoryformatversion",
        "filemode",
        "bare",
        "symlinks",
        "ignorecase",
        "precomposeunicode",
        "logallrefupdates",
    }
)

#: Whole config SECTIONS kept verbatim (no subsection; see
#: :func:`allowlist_git_config`). ``extensions`` is the repository FORMAT:
#: a sha256 repository does not open at all without ``extensions.objectformat``,
#: and a reftable repository needs ``extensions.refstorage``. No ``extensions.*``
#: value names a command; ``extensions.partialclone`` names a REMOTE, and every
#: ``remote.*`` section is dropped, so it can resolve to nothing.
GIT_CONFIG_ALLOWED_SECTIONS: frozenset[str] = frozenset({"extensions"})

#: Written at the top of every rewritten config so an operator reading the copy
#: knows it is not the original's file.
GIT_CONFIG_HEADER = (
    "# eris: this is a private VERIFICATION/worker COPY, never the original.\n"
    "# The repository's own .git/config is NOT here. This file was rewritten\n"
    "# from an ALLOWLIST: only the keys the repository FORMAT needs survive.\n"
    "# Everything else - diff.*, filter.*, alias.*, remote.*, include.*, and\n"
    "# every path-or-command core.* - is dropped, because a repository-supplied\n"
    "# config can otherwise make git execute a repository-supplied program.\n"
    "# See docs/SECURITY.md.\n"
)

#: What each path under the copy's ``.git`` that Eris DEPENDS ON must be after
#: sanitisation: ``"file"`` a regular file, ``"dir"`` a directory. ABSENT is
#: always allowed: a snapshot with no ``.git``, a repository with no ``index``
#: yet, the ``hooks`` directory Eris deliberately never copies, the paths Eris
#: drops or refuses outright.
#:
#: Anything else - a symlink, a fifo, a socket, a device, a file where a
#: directory belongs - REFUSES the copy (:func:`assert_git_layout_sane`).
#: A symlink is the case that matters: git follows one, Eris's own checks
#: ``lstat`` and do not, and that gap is exactly how a neutralisation or a
#: tripwire gets bypassed. Adding a path Eris comes to depend on is ONE LINE
#: here plus one row in ``test_sanitize.py::test_the_git_layout_assertion_
#: refuses_every_non_regular_shape``. The bar for adding one: Eris (or the
#: guard) reads it AND a normal repository can only ever have it as that type.
#: The third column is WHY, and it is appended to the refusal message.
GIT_REQUIRED_KINDS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    ((GIT_DIR,), "dir", "a `.git` FILE is a worktree/submodule gitlink, which Eris does not copy"),
    (GIT_CONFIG, "file", "git reads it whatever shape it is, so Eris must be able to rewrite it"),
    ((GIT_DIR, "index"), "file", "the verification tripwire hashes and digests it"),
    (GIT_HOOKS, "dir", "Eris deliberately never copies it"),
    (GIT_CONFIG_WORKTREE, "file", "Eris drops it: per-worktree config executes like `config`"),
    (GIT_ALTERNATES, "file", "Eris drops it: it re-exposes another repository's object store"),
    (GIT_HTTP_ALTERNATES, "file", "Eris drops it: the same escape over HTTP"),
    (
        GIT_COMMONDIR,
        "file",
        "Eris refuses it: a linked worktree is not a self-contained repository",
    ),
    (GIT_WORKTREES, "dir", "Eris refuses it: a worktree host snapshot is out of scope"),
    (GIT_MODULES, "dir", "Eris refuses it: a submodule snapshot is out of scope"),
)

#: Paths whose mere PRESENCE in the copy refuses it, whatever their shape:
#: they mean the snapshot is not one self-contained repository, so neither the
#: config rewrite nor the tripwire covers everything git would read. Refusing is
#: honest; silently verifying half a repository is not.
GIT_REFUSED_IF_PRESENT: tuple[tuple[tuple[str, ...], str], ...] = (
    (
        GIT_COMMONDIR,
        "this is a LINKED WORKTREE: its refs, config and objects live in another "
        "`.git` that Eris has not copied and cannot contain",
    ),
    (
        GIT_WORKTREES,
        "this repository HOSTS linked worktrees, each with its own "
        "`config.worktree` and gitdir outside the paths Eris rewrites",
    ),
    (
        GIT_MODULES,
        "this repository has SUBMODULE gitdirs, each a repository with its own "
        "config that Eris neither rewrites nor guards",
    ),
)

#: Removed from the copy after :func:`assert_git_layout_sane` has confirmed each
#: is a regular file or absent. ``alternates`` points git at another object
#: store: in a history-truncated snapshot it makes the very commits
#: ``eris.snapshot`` removed reachable again (measured 2026-08-24, git 2.50.1).
#: ``config.worktree`` is a second config file with the same execution risk.
GIT_DROPPED_RELPATHS: tuple[tuple[str, ...], ...] = (
    GIT_ALTERNATES,
    GIT_HTTP_ALTERNATES,
    GIT_CONFIG_WORKTREE,
)

_KIND_TEST: dict[str, Callable[[int], bool]] = {
    "file": stat.S_ISREG,
    "dir": stat.S_ISDIR,
}
_KIND_NAME = {"file": "a regular file", "dir": "a directory"}


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
    # already contained when the first command runs against it. Order is
    # load-bearing: the config rewrite is what turns a `.git/config` SYMLINK
    # into the regular file the layout assertion then insists on, the layout
    # assertion is what proves the dropped paths are regular files an `unlink`
    # can safely remove, and nothing is deleted from a copy that is about to be
    # refused outright.
    outcome = rewrite_git_config(dest)
    if outcome.replaced_symlink is not None:
        dropped.append(outcome.replaced_symlink)  # the link is gone from the copy
    assert_git_layout_sane(dest)  # nothing under `.git` is a shape Eris cannot reason about
    assert_no_repo_escapes(dest)  # ... and the copy is ONE self-contained repository
    assert_no_nested_repositories(dest)  # ... with no OTHER repository inside it
    drop_git_repo_escapes(dest)  # alternates + per-worktree config never reach a worker
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


@dataclass(frozen=True)
class ConfigRewrite:
    """What :func:`rewrite_git_config` did to the copy's ``.git/config``."""

    rewritten: bool
    #: The relpath of a SYMLINK that was replaced by the rewritten regular
    #: file (``.git/config``), or None. Recorded in
    #: ``SnapshotSanitization.dropped_symlinks``: the link is no longer in the
    #: copy, and the run must be able to see that it was there.
    replaced_symlink: str | None = None
    #: Fully-qualified names of the entries KEPT and DROPPED, in file order
    #: (``core.filemode``, ``diff.external``, ``diff.evil.textconv``). Reported
    #: for tests and operators; not a ledger record.
    kept: tuple[str, ...] = ()
    dropped: tuple[str, ...] = ()


# ------------------------------------------------------- the git config parser
#
# A faithful port of git's `config.c` (`git_parse_source` / `get_base_var` /
# `get_extended_base_var` / `get_value` / `parse_value`), byte for byte, because
# every previous version of this control was a LINE-oriented approximation and
# every previous version was bypassed. git's real grammar is not line-oriented:
# measured 2026-08-24 on git 2.50.1, `[core] filemode = true` and
# `[core]filemode=true` are both a section header AND a variable on ONE line,
# `[core][user] name = x` puts the variable in `user`, a value continues across
# lines with a trailing backslash, `\r\n` collapses to `\n`, a leading UTF-8 BOM
# is skipped, and a `#`/`;` outside quotes starts a comment mid-value.
#
# Fail-closed direction: this parser decides only what to KEEP. If it
# mis-parses in the direction of "this is not an allowlisted section", the entry
# is dropped, which is safe. If it cannot parse the file at all it RAISES and
# the copy is refused, which is also safe - git would refuse to open such a
# repository anyway (measured: a bad escape and an unterminated quote are both
# `fatal: bad config line`).

_CONFIG_SPACE = frozenset(b" \t\n\v\f\r")
_CONFIG_KEYCHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
_CONFIG_ALPHA = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_EOF = -1


class GitConfigParseError(SanitizeError):
    """The copy's ``.git/config`` is not a config file git would accept."""


@dataclass(frozen=True)
class GitConfigEntry:
    """One ``section[.subsection].key = value`` entry, exactly as git sees it.

    ``section`` and ``key`` are lower-cased (git does); ``subsection`` keeps its
    case in the ``[section "sub"]`` form and is lower-cased in the deprecated
    ``[section.sub]`` form, again as git does. ``value is None`` is a bare key,
    which git reads as boolean true."""

    section: bytes
    subsection: bytes | None
    key: bytes
    value: bytes | None

    @property
    def name(self) -> str:
        parts = [self.section, *([] if self.subsection is None else [self.subsection]), self.key]
        return b".".join(parts).decode("utf-8", errors="replace")


class _ConfigReader:
    """git's ``get_next_char``: a UTF-8 BOM is skipped, ``\\r\\n`` becomes
    ``\\n``, a lone ``\\r`` stays (git's ``ungetc`` of the peeked byte is a
    one-byte look-ahead here), and EOF is reported as :data:`_EOF`."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
        self._i = 0

    def next(self) -> int:
        if self._i >= len(self._raw):
            return _EOF
        c = self._raw[self._i]
        self._i += 1
        if c == 0x0D and self._i < len(self._raw) and self._raw[self._i] == 0x0A:
            self._i += 1
            return 0x0A
        return c


def _skip_to_end_of_line(reader: _ConfigReader) -> None:
    while True:
        c = reader.next()
        if c in (_EOF, 0x0A):
            return


def _read_section(reader: _ConfigReader) -> tuple[bytes, bytes | None]:
    """git's ``get_base_var`` (+ ``get_extended_base_var``), called just after
    the ``[``. Returns ``(section, subsection)``."""
    name = bytearray()
    while True:
        c = reader.next()
        if c == _EOF:
            raise GitConfigParseError("unterminated section header")
        if c == 0x5D:  # ]
            base = bytes(name)
            head, dot, tail = base.partition(b".")
            return head, (tail if dot else None)
        if c in _CONFIG_SPACE:
            return _read_extended_section(reader, bytes(name), c)
        if c not in _CONFIG_KEYCHARS and c != 0x2E:  # keychar or '.'
            raise GitConfigParseError("invalid character in a section header")
        name.append(c | 0x20 if c in _CONFIG_ALPHA else c)  # tolower, ASCII only


def _read_extended_section(
    reader: _ConfigReader, section: bytes, c: int
) -> tuple[bytes, bytes | None]:
    """git's ``get_extended_base_var``: ``[section "subsection"]``. The
    subsection keeps its case and only ``\\`` + newline is an error inside it."""
    while c in _CONFIG_SPACE:
        if c == 0x0A:
            raise GitConfigParseError("newline inside a section header")
        c = reader.next()
    if c != 0x22:  # "
        raise GitConfigParseError("expected a quoted subsection name")
    sub = bytearray()
    while True:
        c = reader.next()
        if c in (_EOF, 0x0A):
            raise GitConfigParseError("unterminated subsection name")
        if c == 0x22:
            break
        if c == 0x5C:  # backslash: the next char is taken literally
            c = reader.next()
            if c in (_EOF, 0x0A):
                raise GitConfigParseError("unterminated subsection name")
        sub.append(c)
    if reader.next() != 0x5D:
        raise GitConfigParseError("expected `]` after a subsection name")
    return section, bytes(sub)


def _read_value(reader: _ConfigReader) -> bytes:
    """git's ``parse_value``: quotes toggle, ``\\`` escapes ``\\n``/``\\t``/
    ``\\b``/``\\\\``/``\\"`` and continues the line, ``#``/``;`` outside quotes
    start a comment, and unquoted leading/trailing whitespace is stripped."""
    value = bytearray()
    quote = False
    comment = False
    space = 0
    while True:
        c = reader.next()
        if c in (_EOF, 0x0A):
            if quote:
                raise GitConfigParseError("missing closing quote in a value")
            return bytes(value)
        if comment:
            continue
        if c in _CONFIG_SPACE and not quote:
            if value:
                space += 1
            continue
        if not quote and c in (0x3B, 0x23):  # ; #
            comment = True
            continue
        value += b" " * space
        space = 0
        if c == 0x5C:  # backslash
            c = reader.next()
            if c in (0x0A, _EOF):
                continue  # a value continued on the next line (git reads EOF as one)
            escaped = {0x74: 0x09, 0x62: 0x08, 0x6E: 0x0A, 0x5C: 0x5C, 0x22: 0x22}.get(c)
            if escaped is None:
                raise GitConfigParseError("bad escape in a value")
            value.append(escaped)
            continue
        if c == 0x22:
            quote = not quote
            continue
        value.append(c)


def _read_variable(reader: _ConfigReader, first: int) -> tuple[bytes, bytes | None]:
    """git's ``get_value``: the key (lower-cased), then either nothing (a bare
    key, boolean true) or ``= value``."""
    key = bytearray([first | 0x20])
    while True:
        c = reader.next()
        if c == _EOF or c not in _CONFIG_KEYCHARS:
            break
        key.append(c | 0x20 if c in _CONFIG_ALPHA else c)
    while c in (0x20, 0x09):
        c = reader.next()
    if c in (_EOF, 0x0A):
        return bytes(key), None
    if c != 0x3D:  # =
        raise GitConfigParseError("expected `=` after a key")
    return bytes(key), _read_value(reader)


def parse_git_config(raw: bytes) -> list[GitConfigEntry]:
    """Every entry git would read out of ``raw``, in file order. Raises
    :class:`GitConfigParseError` on anything git would call a bad config line."""
    reader = _ConfigReader(raw)
    section: bytes | None = None
    subsection: bytes | None = None
    entries: list[GitConfigEntry] = []
    while True:
        c = reader.next()
        if c == _EOF:
            return entries
        if c in _CONFIG_SPACE:
            continue
        if c in (0x23, 0x3B):  # # ;
            _skip_to_end_of_line(reader)
            continue
        if c == 0x5B:  # [
            section, subsection = _read_section(reader)
            continue
        if c not in _CONFIG_ALPHA:
            raise GitConfigParseError("a key must start with a letter")
        if section is None:
            raise GitConfigParseError("a key outside any section")
        key, value = _read_variable(reader, c)
        entries.append(GitConfigEntry(section, subsection, key, value))


def _quote_config_value(value: bytes, name: str) -> bytes:
    """Serialise a value so git reads back exactly these bytes. Always quoted:
    an unquoted value would have its whitespace stripped and a ``#`` in it would
    start a comment. A control character git cannot represent in a quoted value
    REFUSES the copy rather than being silently mangled."""
    out = bytearray(b'"')
    for byte in value:
        if byte == 0x5C:
            out += b"\\\\"
        elif byte == 0x22:
            out += b'\\"'
        elif byte == 0x09:
            out += b"\\t"
        elif byte == 0x0A:
            out += b"\\n"
        elif byte == 0x08:
            out += b"\\b"
        elif byte < 0x20 or byte == 0x7F:
            raise GitConfigParseError(
                f"{name}: value contains a control byte 0x{byte:02x} that git config "
                "cannot represent; refusing the copy"
            )
        else:
            out.append(byte)
    out += b'"'
    return bytes(out)


def _allowlisted(entry: GitConfigEntry) -> bool:
    """An entry survives only with NO subsection and either an allowlisted
    ``[core]`` key or a wholly allowlisted section. A subsection is always
    dropped: ``[core "x"] filemode`` is ``core.x.filemode``, which is not a key
    git acts on, and ``[extensions "x"] y`` makes a v1 repository refuse to
    open ("unknown repository extension")."""
    if entry.subsection is not None:
        return False
    section = entry.section.decode("ascii", errors="replace")
    if section in GIT_CONFIG_ALLOWED_SECTIONS:
        return True
    return section == "core" and entry.key.decode("ascii", errors="replace") in (
        GIT_CONFIG_ALLOWED_CORE_KEYS
    )


def allowlist_git_config(raw: bytes) -> tuple[bytes, tuple[str, ...], tuple[str, ...]]:
    """Rewrite a git config from the ALLOWLIST: parse it the way git does, keep
    only :data:`GIT_CONFIG_ALLOWED_CORE_KEYS` and
    :data:`GIT_CONFIG_ALLOWED_SECTIONS`, and RE-SERIALISE.

    Nothing is copied verbatim. The output is generated from the parsed
    ``(section, key, value)`` triples, with every value re-quoted, so a line
    that git would read differently from the way Eris read it cannot survive
    into the copy. Returns ``(bytes, kept_names, dropped_names)``."""
    entries = parse_git_config(raw)
    out = bytearray(GIT_CONFIG_HEADER.encode("ascii"))
    kept: list[str] = []
    dropped: list[str] = []
    current: bytes | None = None
    for entry in entries:
        if not _allowlisted(entry):
            dropped.append(entry.name)
            continue
        if entry.section != current:
            out += b"[" + entry.section + b"]\n"
            current = entry.section
        if entry.value is None:
            out += b"\t" + entry.key + b"\n"
        else:
            out += b"\t" + entry.key + b" = " + _quote_config_value(entry.value, entry.name) + b"\n"
        kept.append(entry.name)
    return bytes(out), tuple(kept), tuple(dropped)


def _read_config_symlink_target(copy_root: Path, cfg: Path, link_st: os.stat_result) -> bytes:
    """Bytes of the file a ``.git/config`` SYMLINK points at, refusing unless
    the target resolves to a regular file INSIDE the copy root.

    This is the only place a config that is not a regular file is read, and it
    is where the docstring promise ("the original is never opened for writing")
    is enforced for the replacement path: containment is decided on the
    REALPATH, and the open carries ``O_NOFOLLOW`` so a component swapped for a
    symlink between the resolve and the open fails instead of escaping. The
    caller re-``lstat``s the link before unlinking it (identity unchanged) and
    creates the replacement with ``O_CREAT | O_EXCL | O_NOFOLLOW``, so no
    pre-existing path - here or anywhere - is ever opened for writing."""
    rel = "/".join(GIT_CONFIG)
    try:
        target = cfg.resolve(strict=True)
    except (OSError, RuntimeError) as exc:  # dangling, or a symlink loop
        raise SanitizeError(
            f"{rel}: is a symlink that does not resolve ({exc}); refusing the copy"
        ) from exc
    root = Path(os.path.realpath(copy_root))
    if target == root or not _is_under(target, root):
        raise SanitizeError(
            f"{rel}: is a symlink resolving to {target}, OUTSIDE the copy root {root}; "
            "refusing the copy (the original is never written through)"
        )
    # O_NONBLOCK so a link to a FIFO fails the S_ISREG check below instead of
    # blocking the whole run on a reader; it is a no-op for a regular file.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(target, flags)
    except OSError as exc:  # ENXIO (a fifo with no writer), ELOOP, EACCES...
        raise SanitizeError(
            f"{rel}: is a symlink to {target}, which could not be read ({exc}); refusing the copy"
        ) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SanitizeError(
                f"{rel}: is a symlink to {target}, which is {_describe(st.st_mode)}, "
                "not a regular file; refusing the copy"
            )
        data = _read_all(fd)
    finally:
        os.close(fd)
    now = cfg.lstat()  # the link must not have moved under us before we unlink
    if not stat.S_ISLNK(now.st_mode) or (now.st_dev, now.st_ino) != (
        link_st.st_dev,
        link_st.st_ino,
    ):
        raise SanitizeError(f"{rel}: changed while it was being replaced; refusing the copy")
    return data


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1 << 16)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _describe(mode: int) -> str:
    for test, name in (
        (stat.S_ISLNK, "a symlink"),
        (stat.S_ISDIR, "a directory"),
        (stat.S_ISFIFO, "a fifo"),
        (stat.S_ISSOCK, "a socket"),
        (stat.S_ISCHR, "a character device"),
        (stat.S_ISBLK, "a block device"),
        (stat.S_ISREG, "a regular file"),
    ):
        if test(mode):
            return name
    return "of an unknown type"  # pragma: no cover - no other POSIX file type exists


def assert_git_layout_sane(copy_root: Path) -> None:
    """Refuse the copy unless every path in :data:`GIT_REQUIRED_KINDS` is the
    kind Eris assumes it is, or absent.

    This is the GENERAL form of the same finding five times over (an excluded
    `.git/index`, a missing semantic index check, missing index flag bits, the
    fsmonitor-valid bit, a symlinked `.git/config`): a path Eris reasons about
    is not the thing git actually reads. Every check is an ``lstat`` - a
    symlink is never followed - and every failure names the path, the reason
    and why Eris depends on that path."""
    root = Path(copy_root)
    for parts, kind, why in GIT_REQUIRED_KINDS:
        rel = "/".join(parts)
        try:
            st = root.joinpath(*parts).lstat()
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                continue  # absent (or under a non-directory parent): nothing to reason about
            raise SanitizeError(f"{rel}: cannot be checked in the copy ({exc}); refusing") from exc
        if not _KIND_TEST[kind](st.st_mode):
            raise SanitizeError(
                f"{rel}: is {_describe(st.st_mode)} in the copy, expected {_KIND_NAME[kind]} "
                f"or nothing; refusing the copy ({why})"
            )


def assert_no_repo_escapes(copy_root: Path) -> None:
    """Refuse the copy when it is not ONE self-contained repository.

    :data:`GIT_REFUSED_IF_PRESENT` names the structures whose presence means
    part of the repository lives somewhere Eris has not copied, has not
    rewritten and does not guard: a linked worktree (``.git/commondir``), a
    worktree HOST (``.git/worktrees/``) and submodule gitdirs
    (``.git/modules/``). A gitlink ``.git`` FILE is refused one step earlier by
    :func:`assert_git_layout_sane`, because a file where a directory belongs is
    a shape question.

    Refusing is the honest answer: verifying the half of the repository Eris
    can see, and reporting it as if it were the whole, is worse than saying no.
    """
    root = Path(copy_root)
    for parts, why in GIT_REFUSED_IF_PRESENT:
        rel = "/".join(parts)
        try:
            root.joinpath(*parts).lstat()
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                continue
            raise SanitizeError(f"{rel}: cannot be checked in the copy ({exc}); refusing") from exc
        raise SanitizeError(f"{rel}: is present in the copy; refusing the copy ({why})")


def assert_no_nested_repositories(copy_root: Path) -> None:
    """Refuse the copy when ANOTHER repository lives inside it: any ``.git``
    below the copy root, whatever its shape.

    M2c follow-up 5, advisor round. The config allowlist rewrites exactly ONE
    file - the copy's own ``.git/config``. A nested repository has its own, and
    Eris never sees it. Measured 2026-08-24 on git 2.50.1, with an outer repo
    whose ``sub/.git`` is a FILE reading ``gitdir: /elsewhere/ext/work/.git``
    and that EXTERNAL config carrying ``diff.external``:

    * ``sub`` NOT registered in the outer index -> nothing executed;
    * ``sub`` registered as a GITLINK (``update-index --add --cacheinfo
      160000,<sha>,sub``) -> ``git --no-optional-locks status --porcelain``,
      ``git diff HEAD`` and ``status --porcelain=v2`` ALL EXECUTED the external
      program.

    No ``.gitmodules`` was involved, and the gitdir was outside the copy
    entirely, so nothing Eris rewrites, deletes or hashes could have helped.
    The honest answer is to refuse: recursive sanitisation would mean rewriting
    a config tree of unbounded depth, some of it outside the snapshot, and
    getting it wrong is exactly this bug again.

    The root's own ``.git`` is not a nested repository and is skipped; a
    gitdir under it (``.git/modules/``) is refused by
    :func:`assert_no_repo_escapes`. The INDEX side of the same scope rule - a
    gitlink entry with no checked-out ``.git`` to find - is checked where git
    is already running, on the verification guard's baseline
    (``evidence.git_index_prober``): it is a superproject either way, but with
    nothing to execute it is a scope refusal rather than a containment one."""
    root = Path(copy_root)
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(dirpath)
        if base == root:
            # the copy's OWN `.git` is the repository being verified
            dirnames[:] = [d for d in dirnames if d != GIT_DIR]
            names = [f for f in filenames if f != GIT_DIR]
        else:
            names = list(filenames)
        for name in (*dirnames, *names):
            if name == GIT_DIR:
                rel = _rel(base / name, root).as_posix()
                raise SanitizeError(
                    f"{rel}: a NESTED repository is present in the copy; refusing the copy "
                    "(Eris does not copy submodule or worktree repositories - their `.git` "
                    "holds a config Eris never rewrites, and it may point outside the "
                    "snapshot entirely)"
                )


def drop_git_repo_escapes(copy_root: Path) -> tuple[str, ...]:
    """Delete every path in :data:`GIT_DROPPED_RELPATHS` from the COPY and
    return what was removed.

    ``.git/objects/info/alternates`` (and its ``http-`` twin) point git at
    another object store. Measured 2026-08-24 on git 2.50.1: planting one in a
    properly history-truncated snapshot makes ``git cat-file -e`` of a commit
    the snapshot deliberately does NOT contain go from failing to succeeding -
    the corpus answer the truncation removed becomes readable again.
    ``.git/config.worktree`` is a second config file, with the same arbitrary
    execution risk as ``.git/config``, read when ``extensions.worktreeConfig``
    is set (which the config rewrite also drops).

    Called only AFTER :func:`assert_git_layout_sane`, so each path is a regular
    file or absent and an ``unlink`` cannot be the wrong operation."""
    root = Path(copy_root)
    removed: list[str] = []
    for parts in GIT_DROPPED_RELPATHS:
        rel = "/".join(parts)
        try:
            root.joinpath(*parts).unlink()
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                continue
            raise SanitizeError(f"{rel}: could not be removed from the copy ({exc})") from exc
        removed.append(rel)
    return tuple(removed)


def rewrite_git_config(copy_root: Path) -> ConfigRewrite:
    """Rewrite the COPY's ``.git/config`` from an ALLOWLIST.

    **The original is never opened for writing here** - the argument is the
    copy's root, and every path used is under it.

    A repository-supplied config is arbitrary code execution, not a
    misconfiguration. Measured 2026-08-24 on git 2.50.1, against the ALLOWLISTED
    verification command ``git --no-optional-locks diff HEAD``:

    * ``[diff] external = /tmp/evil.sh`` in the copy's ``.git/config`` EXECUTED
      ``evil.sh``;
    * ``[diff "evil"] textconv = /tmp/evil.sh`` plus ``f.txt diff=evil`` in a
      TRACKED ``.gitattributes`` (tree content, which sanitisation does not
      touch) EXECUTED it too;
    * a planted ``.git/objects/info/alternates`` made a commit the
      history-truncated snapshot deliberately removed reachable again.

    So the previous model - neutralise the keys we happen to know about
    (``core.fsmonitor``, ``core.untrackedCache``) - was the wrong shape. This
    keeps only :data:`GIT_CONFIG_ALLOWED_CORE_KEYS` and
    :data:`GIT_CONFIG_ALLOWED_SECTIONS` and drops EVERYTHING else: every
    ``diff.*``, ``filter.*``, ``merge.*``, ``gpg.*``, ``credential.*``,
    ``url.*``, ``http.*``, ``uploadpack.*``, ``include.*``, ``includeIf.*``,
    ``alias.*``, ``remote.*``, ``branch.*``, ``user.*``, and every ``core.*``
    that is not on the list (``worktree``, ``hooksPath``, ``fsmonitor``,
    ``untrackedCache``, ``pager``, ``editor``, ``sshCommand``, ``askPass``,
    ``alternateRefsCommand``, ``sharedRepository``, ...). With no driver
    DEFINED, a ``.gitattributes`` naming ``diff=evil`` or ``filter=x`` is inert
    - which is measured, not assumed
    (``test_verify_real_git.py::test_a_repository_textconv_driver_cannot_execute_
    in_the_verification_copy``).

    Because the file is re-serialised from parsed entries rather than filtered
    line by line, a line git would read differently from the way Eris read it
    cannot survive. A config Eris cannot parse REFUSES the copy
    (:class:`GitConfigParseError`); git refuses to open such a repository too.

    The control FAILS CLOSED on shape as well. A ``.git/config`` that exists but
    is not a regular file used to be skipped silently while git followed it
    happily. Now an in-copy symlink to a regular file is READ, UNLINKED and
    REPLACED by a regular file holding the rewritten bytes (never written
    through, and recorded in ``dropped_symlinks``); every other shape - a
    symlink escaping the copy, a dangling one, a fifo, a device, a directory -
    RAISES :class:`SanitizeError`. A link that escapes or dangles in the
    ORIGINAL is dropped by the copier before this runs, which legitimately
    leaves no config at all; that case still proceeds.

    Bytes in, bytes out: the file is never decoded, so a non-UTF-8 config is
    parsed and re-quoted byte-faithfully.
    """
    rel = "/".join(GIT_CONFIG)
    cfg = Path(copy_root).joinpath(*GIT_CONFIG)
    try:
        st = cfg.lstat()  # never stat(): a symlink must not be followed
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return ConfigRewrite(False)  # no repository, or a gitlink
        raise SanitizeError(f"{rel}: cannot be checked in the copy ({exc}); refusing") from exc
    replaced: str | None = None
    if stat.S_ISLNK(st.st_mode):
        raw = _read_config_symlink_target(copy_root, cfg, st)
        mode = 0o644  # a fresh regular file: the LINK's mode says nothing
        os.unlink(cfg)  # unlink never follows: the target keeps its bytes
        replaced = rel
    elif not stat.S_ISREG(st.st_mode):
        raise SanitizeError(
            f"{rel}: is {_describe(st.st_mode)} in the copy, not a regular file; "
            "refusing the copy (git would still read it)"
        )
    else:
        raw = cfg.read_bytes()
        mode = stat.S_IMODE(st.st_mode)
    try:
        out, kept, dropped = allowlist_git_config(raw)
    except GitConfigParseError as exc:
        raise GitConfigParseError(f"{rel}: {exc}; refusing the copy") from exc
    # O_EXCL for the replacement (there is nothing at the path), O_NOFOLLOW
    # everywhere: no pre-existing file and no symlink is ever opened for
    # writing, so the write cannot leave the copy.
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_EXCL if replaced is not None else os.O_TRUNC
    if not mode & stat.S_IWUSR:  # a read-only config in the copy is still ours
        cfg.chmod(mode | stat.S_IWUSR)
    fd = os.open(cfg, flags, mode | stat.S_IWUSR)
    try:
        os.write(fd, out)
    finally:
        os.close(fd)
    cfg.chmod(mode)  # the copy keeps the original's file mode
    return ConfigRewrite(True, replaced, kept, dropped)


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
as it is - and differs from a raw ``cp -a`` in exactly four ways, all inherited
from :func:`sanitize_snapshot` and all deliberate. The WORKING TREE is copied
verbatim; every deviation is inside ``.git``, and every one of them exists
because git treats part of ``.git`` as executable configuration:

1. ``.git/hooks`` is not copied. Our allowlist runs ``git``, and a repository
   hook would execute on the first ``git`` invocation.
2. The copy's ``.git/config`` is NOT the original's file. It is rewritten from
   an ALLOWLIST (:func:`rewrite_git_config`): only the keys the repository
   FORMAT needs survive, and every ``diff.*``/``filter.*``/``alias.*``/
   ``remote.*``/``include.*`` and every path-or-command ``core.*`` is dropped,
   because a repository-supplied config otherwise makes git execute a
   repository-supplied program (measured, three ways, 2026-08-24). The
   ORIGINAL's config is never opened for writing, and the rewrite happens while
   the copy is being built - before any verification command, and before the
   guard takes its baseline.
3. ``.git/objects/info/alternates``, ``.git/objects/info/http-alternates`` and
   ``.git/config.worktree`` are deleted (:func:`drop_git_repo_escapes`), and a
   copy that is not ONE self-contained repository is REFUSED: a gitlink ``.git``
   FILE, ``.git/commondir``, ``.git/worktrees/`` or ``.git/modules/``
   (:func:`assert_no_repo_escapes`).
4. A symlink that is absolute, dangling, or resolves outside the tree is
   dropped and recorded in ``dropped_symlinks``; links that stay inside are
   copied with their target string intact - except an in-copy ``.git/config``
   link, which is replaced by the rewritten regular file (item 2 must not be
   bypassable by an alias) and recorded there too. Any other non-regular
   ``.git`` path Eris depends on refuses the copy
   (:func:`assert_git_layout_sane`).

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
