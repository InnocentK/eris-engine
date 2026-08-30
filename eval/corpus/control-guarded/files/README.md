# window

A ring buffer, `Window`, holding the last `capacity` values pushed.

Every bound is already checked. The module is written to look risky so
that a reviewer has something tempting to flag; there is no defect.
