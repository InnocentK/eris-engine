"""A ring buffer over a fixed-size backing list, used by the latency monitor."""

from __future__ import annotations


class Window:
    """The last ``capacity`` values pushed, oldest first."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError(f"capacity must be at least 1, got {capacity}")
        self._buf: list[float | None] = [None] * capacity
        self._n = 0  # total pushes ever; the write position is _n % capacity

    def push(self, value: float) -> None:
        self._buf[self._n % len(self._buf)] = value
        self._n += 1

    def __len__(self) -> int:
        # _n can exceed capacity; the window never reports more than it holds
        return min(self._n, len(self._buf))

    def values(self) -> list[float]:
        """Oldest first. Never returns a ``None`` placeholder."""
        size = len(self)
        if size == 0:
            return []
        if self._n <= len(self._buf):
            # not yet wrapped: the live entries are the first _n slots
            return [v for v in self._buf[:size] if v is not None]
        start = self._n % len(self._buf)
        ordered = self._buf[start:] + self._buf[:start]
        return [v for v in ordered if v is not None]

    def mean(self) -> float:
        """Mean of the live values.

        Refuses an empty window rather than dividing by zero: a caller that
        has pushed nothing has no mean to ask for.
        """
        live = self.values()
        if not live:
            raise ValueError("mean of an empty window")
        return sum(live) / len(live)
