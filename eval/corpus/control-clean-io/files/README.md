# textblock

Fixed-width text layout for the report writer.

* `wrap(text, width)` - split text into lines of at most `width` characters.
  A word longer than `width` gets a line of its own; it is never split.
* `indent(lines, spaces)` - prefix each non-empty line. Blank lines stay blank.

Both raise `ValueError` on a nonsensical argument rather than returning
something a caller would have to check.
