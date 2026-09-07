# Service handbook - excerpt: review archive recovery targets

(Excerpt of the agreed and published targets the handbook carries for the
review archive; reproduced here verbatim so the drill plan's references
resolve inside this repository.)

## Recovery targets, review archive

* **Recovery point**: at most **24 hours** of data loss. The archive is
  backed up nightly; losing more than one night's data is a target breach.
* **Recovery time**: restored and verified within **4 hours** of starting
  the restore, measured from invoking `ops/restore.sh` to its verification
  steps completing.
* Owner: the archive on-call rotation. Reviewed annually alongside archive
  growth, and exercised by the quarterly restore drill (DRILL.md).
