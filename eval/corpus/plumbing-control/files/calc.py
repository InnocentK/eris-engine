"""A deliberately boring two-function module: the plumbing control's payload.

There is no defect here and nothing to find. The point of this task is to
exercise the harness end to end (pack -> propose -> critique -> verify ->
adjudicate -> summarize -> scan), not to score a model.
"""

from __future__ import annotations


def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b


def mean(values: list[float]) -> float:
    """Return the arithmetic mean of a non-empty list."""
    if not values:
        raise ValueError("mean() requires at least one value")
    return sum(values) / len(values)
