#!/usr/bin/env bash
# Restore the review archive from the most recent nightly backup into the
# project named by ARCHIVE_PROJECT. This is the script operators use in an
# incident; the quarterly drill (docs/HANDBOOK-EXCERPT-recovery-targets.md,
# DRILL.md) runs it UNMODIFIED against the drill project. It needs read
# access to the backup store and write access to the target project only.
set -euo pipefail

: "${ARCHIVE_PROJECT:?set ARCHIVE_PROJECT to the project to restore into}"
STORE=${BACKUP_STORE:-archive-backups}

# 1. Most recent nightly backup - by the store's own listing, never hand-picked.
BACKUP=$(archivectl backups list --store "$STORE" --kind nightly --newest 1 --format id)
echo "restoring $BACKUP into $ARCHIVE_PROJECT"

# 2. Restore, then the restore tool's own integrity check.
archivectl restore --store "$STORE" --backup "$BACKUP" --into "$ARCHIVE_PROJECT"
archivectl verify --project "$ARCHIVE_PROJECT"

# 3. Row counts per table against the manifest the DUMP JOB wrote from the
#    live tables at dump time (see ops/backup-manifest.sample.json). The
#    manifest travels beside the dump, not inside it.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
archivectl manifest fetch --store "$STORE" --backup "$BACKUP" --out "$WORK/manifest.json"
archivectl rowcounts --project "$ARCHIVE_PROJECT" --compare "$WORK/manifest.json"

# 4. Fifty records sampled uniformly at random, byte-compared against the
#    manifest's per-record checksums. Exit non-zero on any mismatch.
archivectl sample-verify --project "$ARCHIVE_PROJECT" \
    --manifest "$WORK/manifest.json" --samples 50

echo "restore of $BACKUP into $ARCHIVE_PROJECT verified"
