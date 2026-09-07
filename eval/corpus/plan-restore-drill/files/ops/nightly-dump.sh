#!/usr/bin/env bash
# Nightly dump of the review archive. Writes the backup AND the manifest the
# restore drill compares against. The manifest's row counts and per-record
# checksums are computed FROM THE LIVE TABLES, before and independently of
# the dump file, so a corruption introduced by dumping cannot also corrupt
# the manifest (the drill's residual-risk note relies on exactly this).
set -euo pipefail
STORE=${BACKUP_STORE:-archive-backups}
ID="archive-$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 0. One point-in-time transaction snapshot, so the manifest and the dump
#    describe the SAME state - concurrent writes cannot make a valid dump
#    disagree with its own manifest. The manifest still never reads the
#    dump file.
SNAP=$(archivectl snapshot export)
WORK=$(mktemp -d)

# 1. Counts and checksums from the tables as of the snapshot.
archivectl manifest build --snapshot "$SNAP" --out "$WORK/$ID".manifest.json

# 2. The dump, from the same snapshot.
archivectl dump --snapshot "$SNAP" --out "$WORK/$ID".dump

# 3. Both uploaded beside each other; the manifest is never derived from the dump.
archivectl backups put --store "$STORE" --kind nightly --id "$ID" \
    --dump "$WORK/$ID".dump --manifest "$WORK/$ID".manifest.json
