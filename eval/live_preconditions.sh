#!/usr/bin/env bash
# Live-run preconditions. Prints PASS/FAIL per check and EXITS NON-ZERO if any
# failed, so it cannot be misread by an operator skimming output.
set -uo pipefail
PY=${PY:-.venv/bin/python}
POLICY=${POLICY:-policies/default.yaml}
ENVFILE=${ENVFILE:-.env}
# Split, because they are stopped by DIFFERENT mechanisms. A standalone `run`
# passes campaign_id=None, so `stop_file_paths` gives it ONLY the global
# `<runs_dir>/STOP`; a per-run STOP file is never read for it. Printing
# `touch <runs>/b-s0/STOP` as a way to halt S0 named a file nothing looks at.
CAMPAIGN_IDS=${CAMPAIGN_IDS:-"b-s1 b-s3"}
SINGLE_RUN_IDS=${SINGLE_RUN_IDS:-"b-s0"}
IDS="$CAMPAIGN_IDS $SINGLE_RUN_IDS"
fail=0
chk() { if [ "$1" -eq 0 ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; fail=1; fi; }

# preflight EXITS 0 even when it reports problems: a missing env-file and a
# grok worker with no XAI_API_KEY come back as WARN with status 0. Checking the
# exit code alone passed a doctor that was telling us the run would fail. The
# WARN lines that matter for a live run are the ones about workers this campaign
# uses; every non-OK line is surfaced and any worker WARN fails the gate.
"$PY" eval/run.py preflight --policy "$POLICY" --env-file "$ENVFILE" >/tmp/pf.out 2>&1
pf_rc=$?
grep -vE "^(OK|doctor:)" /tmp/pf.out || true
# Scoped to the workers this campaign actually spawns - the CLI panel and the
# judge. `openai-api` is an api-transport worker with no key configured and it
# WARNs every time; failing the gate on it would block a run for a worker that
# is never called, which is a false alarm and trains an operator to ignore the
# gate.
USED=$("$PY" -c "import sys; sys.path.insert(0,'src')
from pathlib import Path
from eris.policy import load_policy
from eris.schemas import Transport
p = load_policy(Path('$POLICY')).policy
print('|'.join(n for n, w in p.workers.items() if w.transport is Transport.CLI))")
[ "$pf_rc" -eq 0 ] && ! grep -qE "^(FAIL|ERROR)" /tmp/pf.out \
    && ! grep -qE "^WARN worker\.($USED)\b" /tmp/pf.out
chk $? "preflight: exit 0, no FAIL/ERROR, no WARN for a worker this run uses ($USED)"

"$PY" - "$POLICY" <<'PY' >/tmp/pins.out 2>&1
import sys
sys.path.insert(0, "src")
from pathlib import Path
from eris.policy import UNPINNED, load_policy
from eris.schemas import Transport

# A STALE pin does not raise: `load_policy` downgrades that worker to UNPINNED,
# and `launch.py` then refuses it - mid-campaign, after money has been spent on
# earlier cells. So the check is "is any CLI worker UNPINNED after loading",
# which catches never-pinned and gone-stale alike. Comparing the file's own
# hashes would MISS the stale case entirely, because the loader has already
# thrown the mismatched value away.
bad = []
for name, w in sorted(load_policy(Path(sys.argv[1])).policy.workers.items()):
    if w.transport is not Transport.CLI:
        print(f"{name}: {w.transport.value} transport, no executable to pin"); continue
    if getattr(w, "executable_sha256", UNPINNED) == UNPINNED:
        print(f"{name}: UNPINNED - never pinned, or the binary changed since. "
              f"Run `eris policy pin` and re-check"); bad.append(name)
    else:
        print(f"{name}: pinned")
sys.exit(1 if bad else 0)
PY
chk $? "no CLI worker is UNPINNED (a stale pin refuses at launch, mid-campaign)"

[ -f "$ENVFILE" ] && grep -q '^XAI_API_KEY=' "$ENVFILE"
chk $? "$ENVFILE exists and carries XAI_API_KEY (grok refuses at launch without it)"

# Resolved ABSOLUTE and shell-QUOTED. A runs_dir containing a space is valid
# (`runs_dir: "my runs"`), and an unquoted relative path turned the stop command
# into `touch my runs/<id>/STOP` - which creates a file called `my`, fails on
# the rest, and leaves the campaign running while the operator believes it is
# halted. A relative path also only works from the repo root.
RUNS=$("$PY" -c "import sys; sys.path.insert(0,'src')
from pathlib import Path
from eris.policy import load_policy
print(load_policy(Path('$POLICY')).policy.runs_dir)")
RUNS_Q=$("$PY" -c "import shlex, sys; from pathlib import Path
print(shlex.quote(str(Path(sys.argv[1]).resolve())))" "$RUNS" 2>/dev/null)
[ -n "$RUNS" ]
chk $? "runs_dir resolved from the policy: ${RUNS:-<unresolved>}"

# Snapshots are GENERATED and gitignored, so a clean checkout has none and every
# run refuses with "snapshot ... is not a directory" - after the campaign has
# started. Nothing in the earlier gate looked at them.
"$PY" - <<'PY' >/tmp/snap.out 2>&1
import sys
sys.path.insert(0, ".")
from pathlib import Path
from eval.make_control_snapshot import corpus_task_dirs, snapshot_matches_files
bad = []
for d in corpus_task_dirs(Path("eval/corpus")):
    state = snapshot_matches_files(d)
    if state is None:
        print(f"{d.name}: NO SNAPSHOT - run `python eval/make_control_snapshot.py eval/corpus --all`")
        bad.append(d.name)
    elif state is False:
        print(f"{d.name}: STALE - snapshot does not match files/; rebuild")
        bad.append(d.name)
    else:
        print(f"{d.name}: fresh")
sys.exit(1 if bad else 0)
PY
chk $? "every corpus snapshot is built and matches its files/"

collided=""
for id in $IDS; do [ -e "$RUNS/$id" ] && collided="$collided $id"; done
[ -z "$collided" ]
chk $? "run ids free${collided:+ (COLLIDES:$collided)}"

echo
if [ "$fail" -ne 0 ]; then echo "PRECONDITIONS FAILED - do not start any run"; exit 1; fi
echo "preconditions passed."
echo
echo "To halt a CAMPAIGN mid-flight, run EXACTLY one of these. The path is"
echo "absolute and quoted, so it works from any directory and survives a"
echo "runs_dir containing spaces:"
for id in $CAMPAIGN_IDS; do
  echo "    touch $("$PY" -c "import shlex, sys; from pathlib import Path
print(shlex.quote(str(Path(sys.argv[1]).resolve() / sys.argv[2] / 'STOP')))" "$RUNS" "$id")"
done
echo
GLOBAL=$("$PY" -c "import shlex, sys; from pathlib import Path
print(shlex.quote(str(Path(sys.argv[1]).resolve() / 'STOP')))" "$RUNS")
echo "A STANDALONE run ($SINGLE_RUN_IDS) is NOT stopped that way: it passes"
echo "campaign_id=None, so it reads only the global stop file. To halt one:"
echo "    Ctrl-C  (it is a single cell; the in-flight call finishes first)"
echo "    or  touch $GLOBAL   <- GLOBAL: halts every run using this runs dir"
echo
echo "Do not use $GLOBAL to stop a campaign - it stops everything else too."
