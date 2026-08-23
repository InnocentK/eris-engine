"""Contamination tripwire (E1 accept-and-scan decision): DETECT, never prevent.

Workers on this host can read outside the snapshot (E1). Every run is
therefore scanned for strings that could only come from outside the
snapshot: the source repository's path (from key.json + ``Path.home()``),
``athena-assistant``, the answer-key locations (``eval/corpus/``,
``key.json``), the vendors' memory stores under ``~`` and the answer key's
own fix-hunk lines / extra strings. Patterns are DERIVED AT RUN TIME; the
fix hunks never live in this repository and never reach the ledger: the
:class:`~eris.schemas.ScanResult` carries pattern sha256s and counts ONLY.

Distinctiveness: a pattern is whitespace-folded and kept only when it is at
least :data:`MIN_PATTERN_CHARS` long (the fixed markers are exempt - they
are short by construction) AND does not occur in the pre-fix snapshot tree
AND does not occur in the harness's own recorded paths (``known_texts``:
the snapshot and run directories Eris itself writes into ``run.started`` and
every ``Invocation.cwd``; a pattern those necessarily contain cannot
discriminate). Dropped patterns are counted, never listed.

Coverage: every blob, every event payload (canonical JSON), the rendered
evidence pack and any reused cache entry (``extra_texts``). A truncated
stdout or an empty-stdout TIMEOUT makes the scan ``scan_incomplete`` (the
scorer treats it as contaminated for defect/ABSTAIN categories). The scan
runs inside the run BEFORE finalize; ``eval/score.py`` re-scans read-only.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from eris.schemas import ScanHit, ScanResult, canonical_bytes, sha256_hex
from eris.writer import RunWriter

MIN_PATTERN_CHARS = 12
# Fixed markers: exempt from the length floor (short by construction), still
# subject to the pre-fix-tree and known-texts rules.
BUILTIN_MARKERS: tuple[str, ...] = ("athena-assistant", "eval/corpus/", "key.json")
VENDOR_MEMORY_RELPATHS: tuple[str, ...] = (
    ".claude/projects",
    ".codex/sessions",
    ".gemini/antigravity-cli/brain",
)
MAX_SCAN_FILE_BYTES = 64 << 20


def fold(text: str) -> str:
    """Whitespace-fold: every run of whitespace becomes one space; trimmed."""
    return " ".join(text.split())


@dataclass(frozen=True)
class Pattern:
    sha256: str  # of the folded text (utf-8) - the only thing that reaches the ledger
    folded: str


@dataclass(frozen=True)
class PatternSet:
    patterns: tuple[Pattern, ...]
    dropped_nondistinctive: int
    dropped_reasons: Mapping[str, int]

    @property
    def patterns_sha256(self) -> str:
        return sha256_hex("\n".join(sorted(p.sha256 for p in self.patterns)).encode("utf-8"))

    @property
    def count(self) -> int:
        return len(self.patterns)


def _iter_tree_texts(root: Path) -> Iterable[str]:
    """Folded text of every regular file under ``root`` except ``.git``
    (symlinks not followed, special files never opened)."""
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if d != ".git" and not (Path(dirpath) / d).is_symlink()
        )
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                st = p.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SCAN_FILE_BYTES:
                continue
            yield fold(p.read_bytes().decode("utf-8", errors="replace"))


def build_patterns(
    *,
    snapshot_root: Path | None,
    home: Path,
    source_repo: str | None = None,
    fix_hunk_lines: Sequence[str] = (),
    extra_strings: Sequence[str] = (),
    policy_patterns: Sequence[str] = (),
    known_texts: Sequence[str] = (),
) -> PatternSet:
    """Derive the pattern set for one run. ``must_mention`` strings are NOT
    patterns (a correct answer must be allowed to say them)."""
    candidates: list[tuple[str, bool]] = []  # (text, exempt_from_length_floor)
    if source_repo:
        candidates.append((source_repo, False))
    candidates.extend((m, True) for m in BUILTIN_MARKERS)
    candidates.extend((str(Path(home) / rel), False) for rel in VENDOR_MEMORY_RELPATHS)
    candidates.extend((s, False) for s in fix_hunk_lines)
    candidates.extend((s, False) for s in extra_strings)
    candidates.extend((s, False) for s in policy_patterns)

    reasons: dict[str, int] = {
        "too_short": 0,
        "duplicate": 0,
        "in_known_texts": 0,
        "in_pre_fix_tree": 0,
    }
    folded_known = [fold(t) for t in known_texts]
    seen: set[str] = set()
    survivors: list[Pattern] = []
    for raw, exempt in candidates:
        text = fold(raw)
        if not text or (not exempt and len(text) < MIN_PATTERN_CHARS):
            reasons["too_short"] += 1
            continue
        if text in seen:
            reasons["duplicate"] += 1
            continue
        seen.add(text)
        if any(text in k for k in folded_known):
            reasons["in_known_texts"] += 1
            continue
        survivors.append(Pattern(sha256_hex(text.encode("utf-8")), text))
    if snapshot_root is not None and survivors:
        pending = list(survivors)
        for file_text in _iter_tree_texts(Path(snapshot_root)):
            if not pending:
                break
            pending = [p for p in pending if p.folded not in file_text]
        in_tree = {p.sha256 for p in survivors} - {p.sha256 for p in pending}
        reasons["in_pre_fix_tree"] += len(in_tree)
        survivors = [p for p in survivors if p.sha256 not in in_tree]
    dropped = reasons["too_short"] + reasons["in_known_texts"] + reasons["in_pre_fix_tree"]
    return PatternSet(tuple(survivors), dropped, reasons)


# --------------------------------------------------------------------------- scanning


def scan_text(text: str, patterns: PatternSet) -> dict[str, int]:
    """{pattern sha256: non-overlapping occurrence count} over the folded text."""
    folded = fold(text)
    hits: dict[str, int] = {}
    for p in patterns.patterns:
        n = folded.count(p.folded)
        if n:
            hits[p.sha256] = n
    return hits


@dataclass
class _Tally:
    hits: list[ScanHit]
    incomplete: bool = False
    blobs: int = 0
    events: int = 0

    def add(self, where: str, counts: Mapping[str, int]) -> None:
        for sha, n in sorted(counts.items()):
            self.hits.append(ScanHit(pattern_sha256=sha, where=where, count=n))


def scan_run(
    *,
    events_path: Path,
    blobs_dir: Path,
    patterns: PatternSet,
    run_id: str,
    extra_texts: Mapping[str, str] | None = None,
) -> ScanResult:
    """Scan a run directory's ledger + blobs (+ ``extra_texts`` such as
    ``{"pack": rendered_pack, "cache:<sha>": entry_json}``). Read-only."""
    tally = _Tally([])
    if blobs_dir.is_dir():
        for blob in sorted(blobs_dir.iterdir()):
            if blob.name.startswith(".") or blob.is_symlink() or not blob.is_file():
                continue
            tally.blobs += 1
            data = blob.read_bytes()
            tally.add(
                f"blob:{blob.name}", scan_text(data.decode("utf-8", errors="replace"), patterns)
            )
    if events_path.is_file():
        for index, line in enumerate(events_path.read_bytes().splitlines()):
            if not line.strip():
                continue
            tally.events += 1
            where = f"line:{index}"
            try:
                event = json.loads(line)
            except ValueError:
                tally.add(where, scan_text(line.decode("utf-8", errors="replace"), patterns))
                continue
            payload = event.get("payload") if isinstance(event, dict) else None
            if isinstance(event, dict) and isinstance(event.get("seq"), int):
                where = f"event:{event['seq']}"
            if isinstance(payload, dict):
                if event.get("kind") == "invocation.finished":
                    if (
                        payload.get("stdout_truncated") is True
                        or payload.get("stderr_truncated") is True
                        or payload.get("output_file_truncated") is True
                        or (
                            payload.get("status") == "timeout"
                            and payload.get("stdout_sha256") is None
                        )
                    ):
                        tally.incomplete = True
                text = canonical_bytes(payload).decode("utf-8")
            else:
                text = line.decode("utf-8", errors="replace")
            tally.add(where, scan_text(text, patterns))
    for label, text in sorted((extra_texts or {}).items()):
        tally.add(label, scan_text(text, patterns))
    return ScanResult(
        scan_id=f"scan-{run_id}-{patterns.patterns_sha256[:12]}",
        run_id=run_id,
        patterns_sha256=patterns.patterns_sha256,
        pattern_count=patterns.count,
        patterns_dropped_nondistinctive=patterns.dropped_nondistinctive,
        hits=tally.hits,
        contaminated=bool(tally.hits),
        scan_incomplete=tally.incomplete,
        scanned_blobs=tally.blobs,
        scanned_events=tally.events,
    )


def scan_and_record(
    writer: RunWriter, patterns: PatternSet, *, extra_texts: Mapping[str, str] | None = None
) -> ScanResult:
    """Scan the open run (before finalize) and append ``scan.result``. The
    event carries the :class:`ScanResult` only: hashes and counts."""
    result = scan_run(
        events_path=writer.events_path,
        blobs_dir=writer.blobs_dir,
        patterns=patterns,
        run_id=writer.run_id,
        extra_texts=extra_texts,
    )
    writer.append("scan.result", result)
    return result
