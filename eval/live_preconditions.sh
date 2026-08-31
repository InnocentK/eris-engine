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
# `${VAR-default}`, NOT `${VAR:-default}`: the colon form substitutes the default
# for an EMPTY value too, so `SINGLE_RUN_IDS=''` silently became "b-s0" again and
# the scoped re-check this script PRINTS could not do what it said. Found by
# running the printed command instead of trusting it (2026-08-31).
CAMPAIGN_IDS=${CAMPAIGN_IDS-"b-s1 b-s3"}
SINGLE_RUN_IDS=${SINGLE_RUN_IDS-"b-s0"}
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

# Calls the REAL launch-time gate, `launch.preflight_executable`, once per CLI
# worker - it resolves the pinned path, hashes the realpath and compares with
# the pin, which is exactly what refuses a cell mid-campaign after money has
# been spent on earlier ones. It is called rather than re-implemented because
# the version this replaced re-implemented it WRONG: it asserted that a stale
# pin makes `load_policy` downgrade the worker to UNPINNED, so it only tested
# `executable_sha256 == UNPINNED`. `_merge_pins` copies pins.yaml's sha256
# verbatim and NOTHING hashes the binary at load time, so a stale pin loads as
# pinned=True. Five deliberately corrupted pins all passed that check
# (2026-08-31), while the binaries had genuinely changed under it.
"$PY" - "$POLICY" <<'PY' >/tmp/pins.out 2>&1
import sys
sys.path.insert(0, "src")
from pathlib import Path
from eris.launch import LaunchRefused, preflight_executable
from eris.policy import load_policy
from eris.schemas import Transport

bad = []
for name, w in sorted(load_policy(Path(sys.argv[1])).policy.workers.items()):
    if w.transport is not Transport.CLI:
        print(f"{name}: {w.transport.value} transport, no executable to pin")
        continue
    try:
        digest, real = preflight_executable(w)
    except (LaunchRefused, FileNotFoundError) as exc:
        print(f"{name}: WOULD BE REFUSED AT LAUNCH - {type(exc).__name__}: {exc}")
        bad.append(name)
        continue
    print(f"{name}: launchable, {real} sha256 {digest[:12]}...")
sys.exit(1 if bad else 0)
PY
chk $? "every CLI worker passes the launch-time pin check (stale pin = refusal mid-campaign)"

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
        print(f"{d.name}: NO SNAPSHOT - run `.venv/bin/python eval/make_control_snapshot.py eval/corpus --all`")
        bad.append(d.name)
    elif state is False:
        print(f"{d.name}: STALE - snapshot does not match files/; rebuild")
        bad.append(d.name)
    else:
        print(f"{d.name}: fresh")
sys.exit(1 if bad else 0)
PY
chk $? "every corpus snapshot is built and matches its files/"

# A collision is a real refusal (`RunExists`, exit 2), so it stays a FAIL. But
# once a run in the default list COMPLETES, this check can never pass again,
# and an operator who must ignore a FAIL every time has been trained to ignore
# the gate - the same failure the openai-api scoping above exists to avoid. So
# a collision reports WHY (finalized vs resumable) and prints the exact scoped
# re-check for the ids actually about to start.
# The RESUME SYNTAX DIFFERS BY RUN KIND, so the collided ids are tracked in two
# lists rather than one. `run` takes `--resume <RUN_ID>` (a value); `campaign`
# declares `--resume` as store_true, so `campaign ... --resume b-s1` puts the
# bare id where the `campaign_command` positional is expected and argparse
# exits 2 with "invalid choice: 'b-s1' (choose from 'status')". An earlier
# version of this block printed the run form for EVERY collided id - the same
# defect the B3 panel raised as finding 2, reintroduced here ten lines after
# the STOP commands were split by exactly this distinction.
coll_camp="" ; coll_single="" ; free_camp="" ; free_single=""
for id in $CAMPAIGN_IDS; do
    if [ -e "$RUNS/$id" ]; then coll_camp="$coll_camp $id"; else free_camp="$free_camp $id"; fi
done
for id in $SINGLE_RUN_IDS; do
    if [ -e "$RUNS/$id" ]; then coll_single="$coll_single $id"; else free_single="$free_single $id"; fi
done
collided="$coll_camp$coll_single"
[ -z "$collided" ]
chk $? "run ids free${collided:+ (COLLIDES:$collided)}"
if [ -n "$collided" ]; then
    for id in $coll_camp; do
        if [ -e "$RUNS/$id/manifest.json" ]; then
            echo "        $id (campaign): FINALIZED. Its id cannot be reused; nothing to do."
        else
            echo "        $id (campaign): unfinalized - finish it by re-running the SAME command"
            echo "            with a bare --resume (it takes no value), repeating --arms and"
            echo "            --repeats, which otherwise default to all five arms at 2 repeats."
        fi
    done
    for id in $coll_single; do
        if [ -e "$RUNS/$id/manifest.json" ]; then
            echo "        $id (standalone): FINALIZED. Its id cannot be reused; nothing to do."
        else
            echo "        $id (standalone): unfinalized - finish it with \`--resume $id\`, which"
            echo "            takes the run id as its value and supplies it (drop --run-id)."
        fi
    done
    echo "        Re-check only what you are about to start:"
    echo "        CAMPAIGN_IDS='$(echo $free_camp)' SINGLE_RUN_IDS='$(echo $free_single)' bash eval/live_preconditions.sh"
fi

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
# Only printed when there IS a standalone run to stop: with SINGLE_RUN_IDS
# empty the block rendered "A STANDALONE run () is NOT stopped that way",
# which is operational text that says nothing, and text that says nothing in a
# stop procedure is text an operator learns to skip.
if [ -n "$SINGLE_RUN_IDS" ]; then
    echo "A STANDALONE run ($SINGLE_RUN_IDS) is NOT stopped that way: it passes"
    echo "campaign_id=None, so it reads only the global stop file. To halt one:"
    echo "    Ctrl-C  (it is a single cell; the in-flight call finishes first)"
    echo "    or  touch $GLOBAL   <- GLOBAL: halts every run using this runs dir"
    echo
fi
echo "Do not use $GLOBAL to stop a campaign - it stops everything else too."
