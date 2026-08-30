"""Two small arithmetic helpers."""

from __future__ import annotations


def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b


def mean(values: list[float]) -> float:
    """Return the arithmetic mean of a non-empty list."""
    if not values:
        raise ValueError("mean() requires at least one value")
    return sum(values) / len(values)
