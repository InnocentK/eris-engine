# window

`Window(capacity)` keeps the last `capacity` values pushed, oldest first.
Used by the latency monitor to report a rolling mean.

* `push(value)` - record a value, overwriting the oldest once full.
* `values()` - the live values, oldest first.
* `mean()` - the mean of the live values; raises on an empty window.
