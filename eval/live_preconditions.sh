#!/usr/bin/env bash
# Live-run preconditions. Prints PASS/FAIL per check and EXITS NON-ZERO if any
# failed, so it cannot be misread by an operator skimming output.
set -uo pipefail
PY=${PY:-.venv/bin/python}
POLICY=${POLICY:-policies/default.yaml}
ENVFILE=${ENVFILE:-.env}
IDS=${IDS:-"b-s0 b-s1 b-s3"}
fail=0
chk() { if [ "$1" -eq 0 ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; fail=1; fi; }

"$PY" eval/run.py preflight --policy "$POLICY" --env-file "$ENVFILE" >/tmp/pf.out 2>&1
chk $? "preflight"

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

RUNS=$("$PY" -c "import sys; sys.path.insert(0,'src')
from pathlib import Path
from eris.policy import load_policy
print(load_policy(Path('$POLICY')).policy.runs_dir)")
[ -n "$RUNS" ]
chk $? "runs_dir resolved from the policy: ${RUNS:-<unresolved>}"

collided=""
for id in $IDS; do [ -e "$RUNS/$id" ] && collided="$collided $id"; done
[ -z "$collided" ]
chk $? "run ids free${collided:+ (COLLIDES:$collided)}"

echo
if [ "$fail" -ne 0 ]; then echo "PRECONDITIONS FAILED - do not start any run"; exit 1; fi
echo "preconditions passed; runs_dir=$RUNS  STOP file for campaign X = $RUNS/X/STOP"
