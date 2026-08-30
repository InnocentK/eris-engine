"""Fixed-width text blocks.

Deliberately small and complete: every branch is reachable, every input
that can occur is handled, and nothing is left for a caller to get wrong.
"""

from __future__ import annotations


def wrap(text: str, width: int) -> list[str]:
    """Split ``text`` into lines of at most ``width`` characters.

    Words longer than ``width`` are placed on a line of their own rather
    than split, so a caller never receives a fragment that is not a word.
    """
    if width < 1:
        raise ValueError(f"width must be at least 1, got {width}")
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for word in text.split():
        # +1 for the space that would join this word to the current line
        if current and length + 1 + len(word) > width:
            lines.append(" ".join(current))
            current, length = [], 0
        current.append(word)
        length += len(word) + (1 if length else 0)
    if current:
        lines.append(" ".join(current))
    return lines


def indent(lines: list[str], spaces: int) -> list[str]:
    """Prefix every non-empty line with ``spaces`` spaces.

    Empty lines are left empty rather than filled with whitespace, so the
    result has no trailing spaces on a blank line.
    """
    if spaces < 0:
        raise ValueError(f"spaces must not be negative, got {spaces}")
    pad = " " * spaces
    return [pad + line if line else line for line in lines]
