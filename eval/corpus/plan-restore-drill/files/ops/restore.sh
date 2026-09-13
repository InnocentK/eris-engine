#!/usr/bin/env bash
# Restore the review archive from the backup named by RESTORE_BACKUP_ID into
# the project named by ARCHIVE_PROJECT - both explicit, because a restore
# overwrites its target. This is the script operators use in an incident; the
# quarterly drill (DRILL.md) runs it UNMODIFIED, passing the most recent
# nightly backup's id per its own selection rule. It needs read access to the
# backup store and write access to the target project, nothing else.
set -euo pipefail

: "${ARCHIVE_PROJECT:?set ARCHIVE_PROJECT to the project to restore into}"
STORE=${BACKUP_STORE:-archive-backups}

# 1. The backup to restore - REQUIRED, never defaulted. A restore overwrites
#    its target, and an incident may need an OLDER backup (the newest one can
#    be the corrupted one), so the script fails fast rather than guessing a
#    destructive payload. The caller selects; the drill's rule is the store's
#    own newest-nightly listing (see DRILL.md step 1).
BACKUP=${RESTORE_BACKUP_ID:?set RESTORE_BACKUP_ID to the id of the backup to restore}
echo "restoring $BACKUP into $ARCHIVE_PROJECT"

# 2. Restore, then the restore tool's own integrity check.
archivectl restore --store "$STORE" --backup "$BACKUP" --into "$ARCHIVE_PROJECT"
archivectl verify --project "$ARCHIVE_PROJECT"

# 3. Row counts per table against the manifest the dump job built from the
#    same point-in-time snapshot as the dump - never from the dump file
#    (see ops/backup-manifest.sample.json and ops/nightly-dump.sh). The
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
