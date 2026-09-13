# Restore drill: quarterly recovery test for the review archive

## Goal

Prove, once a quarter, that the review archive can actually be restored from
backup - not that backups exist, but that the restore path completes and
verifies on real backup data. The archive's recovery targets are already
agreed and published in the service handbook: at most 24 hours of data loss,
restored within 4 hours of starting; what a drill can and cannot say about
that 4-hour target is bounded under "Success criteria" below.

## Why a drill at all

The archive has never been restored in anger. Backups have run nightly for a
year and their job exits zero, which proves the job ran, not that the output
restores. The last time we relied on an untested restore path elsewhere, it
failed on a schema-version mismatch that ten minutes of drilling would have
caught. A quarterly cadence was chosen over monthly because the archive's
schema changes at most a few times a year and each drill costs about half an
engineer-day; over yearly because a year is long enough for the restore
procedure and the people who know it to drift apart.

## Method

1. On the first Tuesday of the quarter, the on-call engineer recreates the
   isolated `drill` project from its change-controlled template
   (`ops/templates/drill-standing-config.yaml`, applied by one platform
   command; `ops/drill-project.md` describes what it pins), selects the
   most recent nightly backup BY THE STORE'S OWN LISTING
   - never a hand-picked good one - and passes its id to the restore script
   (`RESTORE_BACKUP_ID`), which refuses to run without an explicit backup id
   precisely because restores overwrite their target. The drill project has no network route to
   production and its own credentials: write authority inside the drill
   project itself (the restore target), and outside it exactly one grant -
   READ on the backup store. Backups live in that store, not in the
   production project, so the drill fetches its input without any production
   access. Nothing in
   this plan reads from or writes to the production archive.
2. Restore uses the same script operators would use in an incident
   (`ops/restore.sh`), unmodified. If the script needs a change to work in
   the drill project, that change is the drill's first finding.
3. Verify the restored copy three ways, in increasing depth:
   * the restore tool's own integrity check passes;
   * row counts per table match the counts the backup job recorded at dump
     time (the job already writes these into the backup manifest);
   * fifty records sampled uniformly at random compare byte-identical
     against the manifest's per-record checksums.
4. Record two times, plus the age of the backup used, in the drill log
   alongside both results from "Success criteria": the
   restore-and-verify window (invoking
   `ops/restore.sh` to the end of step 3 - the same window the handbook's
   4-hour target is defined over, and the one the success criterion below
   bounds) and, separately, total drill time from step 1, so recreation
   overhead stays visible without muddying the target's window.

## Success criteria

The drill reports TWO results, judged independently so one failure cannot
mask the other:

* **Restore-path result** - PASS when all three verifications pass and the
  restore-and-verify window (as logged in step 4, the handbook target's own
  window) completes within 2 hours in the drill project. Drill hardware
  differs from production's, so drill wall-clock cannot prove the published
  4-hour target directly; requiring half the target on drill hardware is
  the margin held in its place, and the measured time is logged every
  quarter so the margin's adequacy is reviewed against archive growth
  rather than assumed.
* **Recovery-point result** - PASS when the backup used was under 24 hours
  old at drill time. A stale backup fails THIS result only; the restore
  still proceeds and the restore-path result is judged on its own merits.

The drill as a whole passes only when both results pass IN THE SAME
EXECUTION. A failure of either kind files an incident-priority ticket the
same day, and after the fix the drill is re-run IN FULL, in the same
quarter, both results judged afresh from that single execution - a
whole-drill pass stitched from different runs' halves is a pass no actual
drill achieved, and freshness in particular is a property of the backup at
the time it is judged, not a step that can be re-run on its own.

## Cost and schedule

The drill project is recreated on demand from a standing configuration (the
same isolated-project pattern the schema rehearsals use) and torn down after
each drill, so standing cost is zero. Compute for one restore plus verification is under $15 at current
archive size, re-checked annually against archive growth. Engineer time is
the real cost: budgeted at half a day, tracked in the drill log so the
budget claim is checked against reality each quarter.

## Rollback

There is nothing to roll back. The drill touches only the disposable drill
project; tearing it down is the normal end of a drill, whether passed or
failed. Production configuration is not read, and production data is not
touched.

## Residual risks, accepted with reasons

* Sampling fifty records verifies integrity statistically, not exhaustively.
  A full byte-for-byte comparison would roughly double drill compute and adds
  little: the failure modes we have actually seen (truncated dumps, schema
  mismatch, wrong credentials) all fail the first two checks loudly.
* The drill project's hardware differs from production's, so drill timing
  approximates an incident restore rather than reproducing it. The 2-hour
  criterion above is the stated margin for that; we accept the hardware
  delta rather than maintain a production-identical standby nobody else
  needs.
* A backup could be corrupted in a way that also corrupted its manifest.
  The manifest is built by the dump job from the same point-in-time
  snapshot as the dump but never from the dump file itself, so a dump-side
  corruption still fails the comparison;
  simultaneous corruption of both by the same fault is possible and accepted
  as beyond what a drill can rule out.
