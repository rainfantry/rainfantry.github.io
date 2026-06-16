# Chapter 11 — Campaign Management: The Long War

**VADER-RCE Field Manual**
**Prerequisite**: Ch05-06 (Fuzzing Theory, Crash Triage), Ch08 (Target Reversing), Ch10 (Harness Construction)
**Drill**: DRILLS/11_campaign_ops/

---

## Why You Need This

You built a harness. You ran WinAFL. A few crashes showed up in the
output directory after a few hours. You triaged them, maybe found a
P2. Felt good for about thirty seconds.

Now what?

A few hours of fuzzing is a reconnaissance patrol. It tells you the
target is alive and your harness works. It does NOT find the deep bugs —
the heap overflow in a rarely-reached parser branch, the UAF that only
triggers when three nested container formats are stacked in a specific
order, the integer wrap that requires a precise combination of width,
height, and channel count.

Those bugs hide behind COVERAGE WALLS. The fuzzer needs to evolve its
corpus through millions of generations to crawl past the validation
checks, past the early-exit branches, into the dark code that nobody
tests. That takes days. Weeks. Sometimes months.

This is a siege, not a raid.

The TOCTOU campaign was a series of targeted strikes — 14 versions,
manually aimed, each testing a specific hypothesis. Effective for logic
bugs. But memory corruption hunting is fundamentally different. You're
not testing hypotheses. You're letting the machine explore a space too
large for any human to reason about. Your job shifts from operator to
LOGISTICS COMMANDER. You're managing infrastructure, monitoring health
metrics, making resource allocation decisions, and rotating campaigns
based on coverage data.

This chapter teaches you to run a sustained fuzzing operation. Not a
single session — a CAMPAIGN. Multiple fuzzers, multiple targets, weeks
of continuous operation, with structured assessment cycles that tell you
when to continue, when to pivot, and when to declare a target exhausted.

---

## Campaign Architecture

### The Forward Operating Base

RunPod is your FOB. GPU instances on demand, hourly billing, persistent
network storage. You're not paying for hardware — you're renting
firepower.

The critical architectural decision: separate your FUZZING instances
from your COLLECTION instance.

```
┌──────────────────────────────────────────────────────┐
│                   MASTER NODE                        │
│              (crash collector + dashboard)            │
│                                                      │
│   /campaigns/                                        │
│     ├── mpengine_zip/                                │
│     │   ├── crashes/          ← synced from workers  │
│     │   ├── corpus/           ← shared corpus        │
│     │   ├── coverage_log/     ← coverage snapshots   │
│     │   └── CAMPAIGN_LOG.md   ← weekly assessments   │
│     ├── mpengine_ole/                                │
│     └── mpengine_pe/                                 │
│                                                      │
│   /tools/                                            │
│     ├── crash_triage.py                              │
│     ├── coverage_plot.sh                             │
│     └── campaign_monitor.sh                          │
└────────────┬─────────────┬───────────────────────────┘
             │             │
     ┌───────┘             └───────┐
     │                             │
┌────┴─────┐  ┌──────────┐  ┌─────┴────┐
│ WORKER 1 │  │ WORKER 2 │  │ WORKER N │
│ WinAFL   │  │ WinAFL   │  │ WinAFL   │
│ strategy: │  │ strategy: │  │ strategy: │
│ determin. │  │ havoc    │  │ splice   │
│           │  │          │  │          │
│ seed: A   │  │ seed: B  │  │ seed: C  │
└───────────┘  └──────────┘  └──────────┘
```

The master node is cheap — it doesn't fuzz, it just collects. Give it
persistent storage. Workers are disposable — spot instances, cheapest
GPU available (fuzzing is CPU-bound anyway, the GPU doesn't matter for
WinAFL). Workers die? Restart them. The master holds the state.

### Storage Layout

Every campaign gets its own directory tree. No exceptions. When you're
running three campaigns against different format parsers simultaneously,
you WILL lose track of which crashes came from where if you dump them
all in one directory.

```
/campaigns/<campaign_name>/
  ├── config/
  │   ├── winafl_args.txt        # exact command line for reproduction
  │   ├── seeds/                 # original seed files (never mutated)
  │   └── dictionary.txt         # format-specific tokens
  ├── corpus/                    # evolved inputs (grows over time)
  ├── crashes/                   # crash-triggering inputs
  │   ├── raw/                   # as dumped by WinAFL
  │   ├── deduped/               # after stack-hash dedup
  │   └── triaged/               # after !exploitable classification
  ├── coverage_log/              # periodic coverage snapshots
  ├── worker_logs/               # per-worker stdout/stderr
  └── CAMPAIGN_LOG.md            # human-written weekly assessments
```

### Initialisation Script

Deploy this on the master node. It sets up the directory tree for a
new campaign and copies in your base configuration.

```bash
#!/bin/bash
# campaign_init.sh — initialise a new fuzzing campaign
# Usage: ./campaign_init.sh <campaign_name> <seed_dir> [dictionary]

set -euo pipefail

CAMPAIGN_NAME="${1:?Usage: campaign_init.sh <name> <seed_dir> [dict]}"
SEED_DIR="${2:?Provide path to seed files}"
DICT="${3:-}"

BASE="/campaigns"
CDIR="$BASE/$CAMPAIGN_NAME"

if [ -d "$CDIR" ]; then
    echo "[!] Campaign $CAMPAIGN_NAME already exists at $CDIR"
    echo "    Delete it or pick a different name."
    exit 1
fi

echo "[*] Creating campaign: $CAMPAIGN_NAME"

mkdir -p "$CDIR"/{config/seeds,corpus,crashes/{raw,deduped,triaged},coverage_log,worker_logs}

# Copy seed files
cp "$SEED_DIR"/* "$CDIR/config/seeds/"
SEED_COUNT=$(ls -1 "$CDIR/config/seeds/" | wc -l)
echo "[+] Copied $SEED_COUNT seed files"

# Copy seeds into corpus as starting population
cp "$CDIR/config/seeds/"* "$CDIR/corpus/"

# Copy dictionary if provided
if [ -n "$DICT" ] && [ -f "$DICT" ]; then
    cp "$DICT" "$CDIR/config/dictionary.txt"
    echo "[+] Dictionary copied"
fi

# Write initial campaign log
cat > "$CDIR/CAMPAIGN_LOG.md" << EOF
# Campaign: $CAMPAIGN_NAME

**Created**: $(date +%Y-%m-%d)
**Target**: mpengine.dll
**Seeds**: $SEED_COUNT files from $SEED_DIR
**Dictionary**: ${DICT:-none}

---

## Weekly Assessments

EOF

echo "[+] Campaign initialised at $CDIR"
echo "[*] Next: configure winafl_args.txt, then deploy workers"
```

---

## Launching A Campaign

### WinAFL Command Line Anatomy

Every flag matters. Get one wrong and you're wasting cycles — the
fuzzer runs but finds nothing, or crashes itself, or instruments the
wrong module.

Here's the full WinAFL launch command for an mpengine campaign, broken
down piece by piece:

```
afl-fuzz.exe ^
    -D C:\DynamoRIO\bin64 ^
    -t 30000 ^
    -i C:\campaigns\mpengine_zip\corpus ^
    -o C:\campaigns\mpengine_zip\crashes\raw ^
    -target_module mpengine.dll ^
    -target_method ScanBuffer ^
    -nargs 3 ^
    -fuzz_iterations 5000 ^
    -coverage_module mpengine.dll ^
    -persistence_mode in_app ^
    -- harness.exe @@
```

Now flag by flag:

**`-D C:\DynamoRIO\bin64`** — Path to DynamoRIO. This is the
instrumentation engine. It injects coverage tracking into the target
binary at runtime. If this path is wrong, WinAFL exits immediately
with a useless error about "unable to find instrumentation library."
Verify the path before your first launch. Always.

**`-t 30000`** — Timeout in milliseconds per execution. If a single
test case takes longer than this, WinAFL kills it and moves on. For
mpengine, 30 seconds is generous. Most scans complete in under 5
seconds. You want the timeout high enough to avoid false hangs on
complex files, low enough that a genuine infinite loop doesn't eat
your entire timeslice. Start at 30000. Drop to 10000 once you know
your harness is stable.

**`-i C:\campaigns\mpengine_zip\corpus`** — Input directory. Your
seed corpus. The fuzzer reads every file in here, mutates them, and
tests the mutations. Quality of seeds = quality of initial coverage.
Garbage in, garbage out. Curate your seeds — one representative file
per major code path in the parser.

**`-o C:\campaigns\mpengine_zip\crashes\raw`** — Output directory.
Where WinAFL dumps crash-triggering inputs, hang-triggering inputs,
and the queue of evolved corpus entries. After a campaign, this is
where your gold is buried (under a pile of gravel — see Ch06).

**`-target_module mpengine.dll`** — The DLL to instrument. WinAFL
instruments ONLY this module for coverage. Everything else runs
uninstrumented = fast.

**`-target_method ScanBuffer`** — The function WinAFL calls in the
fuzzing loop. This is your harness entry point — the function that
accepts a mutated input buffer and passes it to the parser. Get this
wrong and the fuzzer never reaches the parsing code.

**`-nargs 3`** — Number of arguments to the target method. WinAFL
needs to know this so it can save and restore the stack correctly
between iterations. Count your function parameters. Get it wrong
and you'll get random crashes from stack corruption — not from bugs
in the target.

**`-fuzz_iterations 5000`** — How many mutations to test before
restarting the target process. Higher = more throughput (process
startup is expensive). Lower = cleaner state (no accumulated heap
pollution between iterations). 5000 is a solid default for persistent
mode. If you see stability dropping below 90%, reduce this — state
is leaking between iterations.

**`-coverage_module mpengine.dll`** — Which module to track for
coverage feedback. Set this to ONLY the module you care about.
If you instrument everything, the coverage map fills with noise from
ntdll, kernel32, and every other loaded DLL. You want the fuzzer
evolving inputs based on NEW PATHS IN THE PARSER, not new paths in
the Windows loader.

**`-persistence_mode in_app`** — Use persistent mode. The harness
calls the target function in a loop without restarting the process.
10-100x faster than fork mode. Non-negotiable for serious campaigns.

**`-- harness.exe @@`** — The harness executable. `@@` is replaced
by the path to the current test file. Your harness reads this file
and feeds it to ScanBuffer.

### Recommended Starting Configuration For mpengine

```
Target module:      mpengine.dll
Target method:      ScanBuffer (or your harness wrapper)
Coverage module:    mpengine.dll ONLY
Timeout:            30000ms (initial), 10000ms (tuned)
Fuzz iterations:    5000 (reduce if stability < 90%)
Persistence mode:   in_app
Seeds:              5-20 curated files per format family
Dictionary:         format-specific (zip_tokens.txt, ole_tokens.txt)
```

### Worker Deployment Script

Deploy on each worker instance. Takes the campaign name and a worker
ID, syncs the corpus from master, and launches WinAFL.

```bash
#!/bin/bash
# worker_launch.sh — start a WinAFL worker for an existing campaign
# Usage: ./worker_launch.sh <campaign_name> <worker_id> <strategy>

set -euo pipefail

CAMPAIGN="${1:?Usage: worker_launch.sh <campaign> <worker_id> <strategy>}"
WORKER_ID="${2:?Provide worker ID (1, 2, ...)}"
STRATEGY="${3:-havoc}"  # deterministic | havoc | splice

MASTER="master.internal"  # adjust to your master node's address
BASE="/campaigns/$CAMPAIGN"
WORKER_DIR="$BASE/workers/worker_$WORKER_ID"
LOG="$BASE/worker_logs/worker_${WORKER_ID}.log"

mkdir -p "$WORKER_DIR" "$BASE/worker_logs"

# Sync corpus from master
echo "[*] Syncing corpus from master..."
rsync -az "$MASTER:$BASE/corpus/" "$WORKER_DIR/corpus/"

# Sync dictionary if present
if ssh "$MASTER" "test -f $BASE/config/dictionary.txt"; then
    rsync -az "$MASTER:$BASE/config/dictionary.txt" "$WORKER_DIR/dictionary.txt"
    DICT_FLAG="-x $WORKER_DIR/dictionary.txt"
else
    DICT_FLAG=""
fi

echo "[*] Starting worker $WORKER_ID (strategy: $STRATEGY)"

# Launch WinAFL
# Adjust paths to match your DynamoRIO + harness location
afl-fuzz.exe \
    -D /opt/dynamorio/bin64 \
    -t 30000 \
    -i "$WORKER_DIR/corpus" \
    -o "$WORKER_DIR/output" \
    -target_module mpengine.dll \
    -target_method ScanBuffer \
    -nargs 3 \
    -fuzz_iterations 5000 \
    -coverage_module mpengine.dll \
    -persistence_mode in_app \
    $DICT_FLAG \
    -- /opt/harness/harness.exe @@ \
    2>&1 | tee "$LOG"
```

---

## Monitoring Campaign Health

You've launched. Fuzzers are running. Now you WATCH. A campaign without
monitoring is a fire without a sentry — you'll wake up to find it
burned itself out six hours ago and you wasted an entire night of
compute.

### The Five Vital Signs

#### 1. exec/sec — The Heartbeat

This is your single most important metric. It tells you how many test
cases the fuzzer processes per second.

```
exec/sec benchmarks (mpengine + persistent mode):
  > 500    Excellent. Harness is tight. Parser is fast.
  200-500  Good. Normal for complex parsers.
  100-200  Acceptable. Look for optimisation opportunities.
  50-100   Concerning. Something is dragging. Investigate.
  < 50     ABORT. Fix the harness. You're wasting compute.
```

If exec/sec drops during a campaign (was 300, now 150), something
changed. Common causes:
- **Memory leak**: harness or target leaking. RSS growing. Check
  with `ps aux | grep harness` — if RSS is climbing, you've got a
  leak. Restart workers periodically or fix the leak.
- **Corpus bloat**: corpus grew so large that file I/O is the
  bottleneck. Minimise the corpus (`afl-cmin`).
- **Disk pressure**: output directory is huge and filesystem is
  struggling. Rotate old crash artifacts.

#### 2. Unique Crashes — The Body Count

New unique crash hashes per time period. This is what you're here for.

```
crash_rate benchmarks:
  First 24h:   0-20 unique crashes (initial exploration)
  Day 2-7:     0-5 per day (if the target has bugs)
  Week 2+:     0-2 per day (diminishing returns)
  After 1M+    0 new crashes for a week = target is hardening
  execs:       Consider pivoting.
```

Track unique crashes over time. If the rate spikes — something
changed in the corpus that opened a new parser branch. Good. If
it flatlines — the fuzzer has explored what it can reach with
current seeds.

#### 3. Coverage Growth — Territory Gained

New basic blocks discovered over time. This is your MAP of how much
of the target's code the fuzzer has explored.

Coverage always follows the same curve: steep initial growth as the
fuzzer discovers the obvious paths, then a long tail of diminishing
returns as it tries to push past validation checks into deeper code.

```
coverage_growth benchmarks:
  Hour 1:      Hundreds of new blocks (initial seed exploration)
  Hour 2-12:   Dozens per hour (mutation finding new branches)
  Day 2-7:     Singles per hour (deep exploration)
  Week 2+:     Plateau. Flat line. The fuzzer is stuck.
```

When coverage plateaus, the fuzzer is spinning its wheels. It's
mutating inputs but every mutation hits code it's already seen. Time
to intervene — new seeds, new dictionary entries, or a new target
entirely.

#### 4. Stability — State Discipline

The percentage of iterations where the fuzzer's coverage trace matches
the expected path. Below 100% means the target's behaviour changes
between executions even with the same input.

```
stability benchmarks:
  > 98%    Rock solid. Harness is clean.
  95-98%   Good. Minor non-determinism (threading, ASLR jitter).
  90-95%   Watch it. Some state leaking between iterations.
  < 90%    PROBLEM. State pollution is corrupting your coverage
           map. The fuzzer is making decisions based on phantom
           paths. Reduce -fuzz_iterations or fix your harness.
```

Stability below 90% means your coverage data is LYING. The fuzzer
thinks it found new paths but it's actually seeing noise from leaked
state between iterations. Every decision based on that coverage data
is suspect. This is like running a recon patrol with a broken compass —
you think you're heading north but you're walking in circles.

Fix: reduce `-fuzz_iterations` so the process restarts more often,
clearing accumulated state. Or fix the harness to properly reset
state between calls.

#### 5. Memory Usage — Slow Bleed

If the harness process RSS grows over time, something is leaking.
Either the harness isn't freeing buffers, or the target itself leaks
(mpengine is a big C++ codebase — leaks are common in error paths).

```
memory benchmarks:
  Stable RSS:    Normal. Process allocates on startup, holds steady.
  Slow growth:   Leak. Will OOM-kill eventually. Set up periodic
                 worker restarts (every 6-12 hours).
  Fast growth:   Severe leak. Will OOM-kill in hours. Fix the
                 harness or add explicit cleanup between iterations.
```

A slow leak that takes 24 hours to OOM-kill is manageable with
periodic restarts. A fast leak that kills the fuzzer every 2 hours
is EATING YOUR THROUGHPUT. Every restart is dead time — process
startup, DynamoRIO initialisation, first-pass coverage mapping.
At 2-hour restart intervals, you might lose 15-20% of effective
fuzzing time. Fix the leak.

### The Monitor Script

Run this on the master node. Pulls health metrics from all workers
every 60 seconds, logs to a dashboard file, and alerts on anomalies.

```bash
#!/bin/bash
# campaign_monitor.sh — live monitoring of fuzzer health
# Usage: ./campaign_monitor.sh <campaign_name>
# Run in tmux/screen. Ctrl+C to stop.

set -euo pipefail

CAMPAIGN="${1:?Usage: campaign_monitor.sh <campaign_name>}"
BASE="/campaigns/$CAMPAIGN"
DASHBOARD="$BASE/DASHBOARD.txt"
ALERT_LOG="$BASE/alerts.log"
INTERVAL=60

# Worker list — adjust to match your deployment
WORKERS=(worker_1 worker_2 worker_3)

alert() {
    local msg="[$(date '+%Y-%m-%d %H:%M')] ALERT: $1"
    echo "$msg" >> "$ALERT_LOG"
    echo "$msg"  # also print to console
}

while true; do
    echo "=== Campaign: $CAMPAIGN — $(date '+%Y-%m-%d %H:%M:%S') ===" > "$DASHBOARD"
    echo "" >> "$DASHBOARD"

    TOTAL_CRASHES=0
    TOTAL_EXECS=0

    for WORKER in "${WORKERS[@]}"; do
        WDIR="$BASE/workers/$WORKER/output"

        # Parse WinAFL fuzzer_stats file
        STATS_FILE="$WDIR/fuzzer_stats"
        if [ ! -f "$STATS_FILE" ]; then
            echo "  $WORKER: NO STATS FILE (not running?)" >> "$DASHBOARD"
            alert "$WORKER: fuzzer_stats not found — worker may be dead"
            continue
        fi

        EXEC_SEC=$(grep "execs_per_sec" "$STATS_FILE" | awk '{print $3}')
        TOTAL_EX=$(grep "execs_done" "$STATS_FILE" | awk '{print $3}')
        UNIQ_CRASH=$(grep "unique_crashes" "$STATS_FILE" | awk '{print $3}')
        STABILITY=$(grep "stability" "$STATS_FILE" | awk '{print $3}' | tr -d '%')
        LAST_CRASH=$(grep "last_crash" "$STATS_FILE" | awk '{print $3}')

        # Format last crash time
        if [ "$LAST_CRASH" != "0" ] 2>/dev/null; then
            LAST_CRASH_AGO=$(( ($(date +%s) - LAST_CRASH) / 3600 ))h
        else
            LAST_CRASH_AGO="never"
        fi

        printf "  %-12s | exec/s: %-6s | execs: %-12s | crashes: %-4s | stab: %s%% | last_crash: %s\n" \
            "$WORKER" "$EXEC_SEC" "$TOTAL_EX" "$UNIQ_CRASH" "$STABILITY" "$LAST_CRASH_AGO" \
            >> "$DASHBOARD"

        TOTAL_CRASHES=$((TOTAL_CRASHES + UNIQ_CRASH))
        TOTAL_EXECS=$((TOTAL_EXECS + TOTAL_EX))

        # Alert thresholds
        if [ "${EXEC_SEC%.*}" -lt 50 ] 2>/dev/null; then
            alert "$WORKER: exec/sec=$EXEC_SEC — below minimum threshold"
        fi
        if [ "${STABILITY%.*}" -lt 90 ] 2>/dev/null; then
            alert "$WORKER: stability=${STABILITY}% — state pollution likely"
        fi
    done

    echo "" >> "$DASHBOARD"
    echo "  TOTALS: $TOTAL_EXECS total execs | $TOTAL_CRASHES unique crashes" >> "$DASHBOARD"
    echo "  Updated: $(date '+%H:%M:%S')" >> "$DASHBOARD"

    cat "$DASHBOARD"
    echo ""
    sleep "$INTERVAL"
done
```

### Crash Collection Script

Run periodically on the master node. Syncs crashes from all workers,
dedups them, and adds them to the campaign's crash archive.

```bash
#!/bin/bash
# crash_collect.sh — pull crashes from workers and dedup
# Usage: ./crash_collect.sh <campaign_name>

set -euo pipefail

CAMPAIGN="${1:?Usage: crash_collect.sh <campaign_name>}"
BASE="/campaigns/$CAMPAIGN"
RAW="$BASE/crashes/raw"
DEDUPED="$BASE/crashes/deduped"

WORKERS=(worker_1 worker_2 worker_3)
MASTER="master.internal"

BEFORE=$(ls -1 "$DEDUPED" 2>/dev/null | wc -l)

echo "[*] Collecting crashes from ${#WORKERS[@]} workers..."

for WORKER in "${WORKERS[@]}"; do
    WDIR="$BASE/workers/$WORKER/output/crashes"
    if [ -d "$WDIR" ]; then
        # Copy with worker prefix to avoid filename collisions
        for f in "$WDIR"/*; do
            [ -f "$f" ] || continue
            BASENAME=$(basename "$f")
            cp -n "$f" "$RAW/${WORKER}_${BASENAME}"
        done
    fi
done

RAW_COUNT=$(ls -1 "$RAW" 2>/dev/null | wc -l)
echo "[+] Raw crashes: $RAW_COUNT"

# Dedup by file hash (quick pass — full stack-hash dedup is in triage)
echo "[*] Deduplicating by file hash..."
for f in "$RAW"/*; do
    [ -f "$f" ] || continue
    HASH=$(sha256sum "$f" | awk '{print $1}' | head -c 16)
    if [ ! -f "$DEDUPED/crash_${HASH}" ]; then
        cp "$f" "$DEDUPED/crash_${HASH}"
    fi
done

AFTER=$(ls -1 "$DEDUPED" 2>/dev/null | wc -l)
NEW=$((AFTER - BEFORE))

echo "[+] Deduped crashes: $AFTER total ($NEW new this collection)"
echo "[*] Full triage (stack-hash dedup + !exploitable) pending manual run"
```

---

## The Weekly Assessment Cycle

Campaigns don't manage themselves. Every week you pull data, assess
progress, and make a decision: continue, adjust, or kill.

This is not bureaucracy. This is BATTLE RHYTHM. Without structured
assessment, you'll discover three weeks in that your fuzzer died on
day 4 and you've been paying for idle instances. Or worse — it kept
running but hit a coverage plateau on day 2 and spent 19 days
generating the same mutations against the same code paths. Burning
money to learn nothing.

### The Monday Ritual

Every Monday morning. Non-negotiable. 30 minutes. Here's the protocol:

**1. Pull crash artifacts.**
Run `crash_collect.sh`. Check the new crash count. Run a quick dedup.

**2. Check coverage stats.**
Pull the coverage log from each worker. Compare total basic blocks
covered this week vs last week. Plot if you've got enough data.

**3. Check exec/sec trend.**
If throughput is declining, investigate. Memory leak? Corpus bloat?
Disk pressure? Worker that silently died?

**4. Log everything.**
Write a `CAMPAIGN_LOG.md` entry. Date, numbers, observations, decision.

**5. Make the decision.**

```
                        ┌─────────────────┐
                        │  New crashes     │
                        │  this week?      │
                        └──────┬──────────┘
                               │
                    ┌──── YES ─┤── NO ─────┐
                    │          │            │
               ┌────┴────┐    │    ┌───────┴──────┐
               │ TRIAGE  │    │    │  Coverage     │
               │ them.   │    │    │  still        │
               │ Any P1? │    │    │  growing?     │
               └────┬────┘    │    └──────┬────────┘
                    │         │           │
              YES ──┤         │    YES ───┤── NO ──────┐
               │    │         │     │     │            │
          ┌────┴──┐ │         │  ┌──┴──┐  │   ┌────────┴───┐
          │EXPLOIT│ │         │  │CONT-│  │   │  PLATEAU.  │
          │ DEV.  │ │         │  │INUE │  │   │  Refresh   │
          │ NOW.  │ │         │  │     │  │   │  or pivot. │
          └───────┘ │         │  └─────┘  │   └────────────┘
                    │         │           │
              NO ───┘         │           │
               │              │           │
          ┌────┴────┐         │           │
          │Log them.│         │           │
          │Continue.│         │           │
          └─────────┘         │           │
```

### Pivot Decision Tree — Expanded

**Crashes + P1 found**: STOP fuzzing this campaign. Shift to exploit
development. You have what you came for. Every hour spent fuzzing
after a P1 is an hour NOT spent turning that P1 into a working exploit.

**Crashes but no P1**: Log them. Continue the campaign. P2s and P3s
have value — they indicate bug-dense code regions. Continued fuzzing
near those paths may eventually hit a P1.

**No crashes, coverage growing**: CONTINUE. The fuzzer is still
exploring new code. It hasn't found bugs YET but it's reaching code
that hasn't been tested. Bugs may be deeper. Patience.

**No crashes, coverage plateau**: INTERVENTION needed. Options:

1. **Seed refresh**: Add new seed files. Different file variants,
   edge cases, malformed headers. Give the fuzzer new starting points
   to evolve from.
2. **Dictionary update**: Add new format-specific tokens. Maybe the
   parser has keywords the fuzzer hasn't discovered by random mutation.
3. **Strategy rotation**: Switch workers from deterministic to havoc,
   or add a splice worker that combines existing corpus entries.
4. **Target pivot**: This parser may be hardened. Move to a different
   format handler within mpengine. OLE, PE, PDF, ZIP, RAR, CAB —
   mpengine parses dozens of formats. If ZIP is dry, try OLE.

**No crashes after 1 billion+ iterations across all workers**: This
target is done. Either it's genuinely robust (unlikely for a parser
this complex) or your seeds/harness aren't reaching the vulnerable
code. Either way, continued investment has negative ROI. KILL the
campaign and redeploy resources.

### Kill Criteria — When To Walk Away

Not every campaign produces gold. Knowing when to STOP is as
important as knowing when to start. Sunk cost fallacy kills campaigns
— "I've been running this for three weeks, I can't quit now." Yes you
can. Walk away.

Hard kill criteria:

- **1 billion total executions, zero unique crashes.** Target is either
  hardened or your harness isn't reaching the right code. Either way,
  more iterations won't help.

- **Coverage plateau for 7+ days with no new crashes.** The fuzzer has
  explored everything it can reach. Without new seeds or structural
  changes, it will spin forever.

- **P1 crash found.** Kill the campaign. Shift to exploit development.
  This sounds counterintuitive — why stop when you're winning? Because
  one exploitable crash is enough. Finding a second P1 while the first
  goes unexploited is WASTE.

- **Budget exceeded.** Set a dollar limit before the campaign starts.
  RunPod charges by the hour. A three-worker campaign at $0.50/hr/worker
  runs $1,080/month. Know your limit. Hit it? Assess results and decide
  if more money is justified.

---

## Scaling Up

### Parallel Fuzzing Strategy

One fuzzer finds bugs. Three fuzzers find bugs FASTER. But only if
they're doing different things. Three identical fuzzers with the same
seeds and same strategy just triple your cost for marginal extra
coverage.

Effective parallel deployment uses STRATEGY DIVERSITY:

```
Worker 1: Deterministic mutations
  - Walks through each byte position systematically
  - Flips bits, inserts values, overwrites with interesting constants
  - Slow but thorough
  - Best for: finding bugs near the surface of the input

Worker 2: Havoc mode
  - Random mutations — splices, inserts, deletes, bit flips
  - Fast, high throughput
  - Best for: finding bugs in unexpected combinations

Worker 3: Splice mode
  - Combines fragments from different corpus entries
  - Creates chimera inputs that mix features from multiple files
  - Best for: hitting code paths that require specific combinations
```

You can also diversify by SEED SET. Give each worker a different
subset of seeds. Worker 1 gets minimal ZIP files. Worker 2 gets
nested ZIPs. Worker 3 gets ZIPs with encryption headers. Each
explores a different region of the parser's code from the start.

### Corpus Sharing

Workers that find new coverage share their discoveries. Without
sharing, each worker independently rediscovers the same paths.
With sharing, one worker's breakthrough immediately benefits all
others.

AFL supports this natively via the `-S` (secondary) and `-M` (master)
flags, sharing through a common output directory. For WinAFL across
multiple instances:

```bash
#!/bin/bash
# corpus_sync.sh — bidirectional corpus sync between workers
# Run on master node via cron: */30 * * * * /path/to/corpus_sync.sh <campaign>

CAMPAIGN="${1:?}"
BASE="/campaigns/$CAMPAIGN"
SHARED="$BASE/corpus"
WORKERS=(worker_1 worker_2 worker_3)

echo "[$(date)] Corpus sync for $CAMPAIGN"

for WORKER in "${WORKERS[@]}"; do
    WQUEUE="$BASE/workers/$WORKER/output/queue"

    # Pull new entries from worker's queue to shared corpus
    if [ -d "$WQUEUE" ]; then
        NEW=0
        for f in "$WQUEUE"/*; do
            [ -f "$f" ] || continue
            HASH=$(sha256sum "$f" | awk '{print $1}' | head -c 16)
            if [ ! -f "$SHARED/corpus_${HASH}" ]; then
                cp "$f" "$SHARED/corpus_${HASH}"
                NEW=$((NEW + 1))
            fi
        done
        [ $NEW -gt 0 ] && echo "  $WORKER → shared: $NEW new entries"
    fi

    # Push shared corpus entries back to worker
    PUSH=0
    for f in "$SHARED"/*; do
        [ -f "$f" ] || continue
        BASENAME=$(basename "$f")
        if [ ! -f "$WQUEUE/$BASENAME" ]; then
            cp "$f" "$WQUEUE/$BASENAME"
            PUSH=$((PUSH + 1))
        fi
    done
    [ $PUSH -gt 0 ] && echo "  shared → $WORKER: $PUSH new entries"
done

echo "[$(date)] Sync complete. Shared corpus: $(ls -1 "$SHARED" | wc -l) entries"
```

### Budget Management

RunPod pricing fluctuates. Spot instances are 50-70% cheaper than
on-demand but can be interrupted. For fuzzing, interruption is
annoying but not catastrophic — the corpus and crashes are on
persistent storage. The worker restarts and picks up where it left
off (minus the in-progress iteration).

```
Cost optimization strategies:

1. Use spot instances for workers. Always.
   On-demand = $0.50-1.00/hr per worker
   Spot      = $0.15-0.40/hr per worker
   Savings   = 50-70%

2. Run workers in off-peak hours (US nighttime = AU daytime).
   Spot prices drop when US demand decreases.

3. Use the cheapest GPU tier. Fuzzing is CPU-bound.
   RTX 3090 spot: ~$0.30/hr
   RTX 4090 spot: ~$0.50/hr
   CPU-only:      ~$0.10/hr (if available)
   The GPU does NOTHING for WinAFL. You're paying for CPU + RAM.

4. Right-size RAM. mpengine loads ~500MB. Harness + DynamoRIO adds
   ~300MB. 4GB total is plenty per worker. Don't pay for 48GB.

5. Set hard budget limits. Write it in CAMPAIGN_LOG.md before launch:
   "Budget: $200. Kill at $200 regardless of results."
```

### Diminishing Returns

More workers doesn't always mean more coverage. The relationship
is logarithmic, not linear.

```
Workers  vs  Coverage (approximate, after 7 days)
   1         100% (baseline)
   2         130-150%
   4         160-180%
   8         175-195%
  16         185-200%
```

Going from 1 to 3 workers nearly doubles your coverage. Going from
8 to 16 adds maybe 10%. The extra workers are rediscovering paths
that other workers already found. Unless you're diversifying strategy
and seeds aggressively, more than 4-5 workers hits diminishing returns
fast.

Rule of thumb: **3 workers with diverse strategies beats 8 identical
workers.** Spend your budget on intelligence, not brute force.

---

## Campaign Log Format

The campaign log is your war diary. Without it, you'll forget what you
tried, what worked, and why you made each decision. Two months into a
campaign, you WILL NOT remember whether you refreshed seeds on week 3
or week 4, and whether it helped. The log remembers.

### Weekly Entry Format

```markdown
### Week N — YYYY-MM-DD

| Metric               | Value          | Trend    |
|----------------------|----------------|----------|
| exec/sec (avg)       | 287            | stable   |
| Total executions     | 847,293,000    | +112M    |
| Unique crashes       | 14             | +3       |
| New coverage blocks  | 2,847          | +12      |
| Corpus size          | 1,204 entries  | +89      |
| Stability            | 96.2%          | -0.3%    |
| Cost this week       | $38.40         |          |
| Cost total           | $154.20        |          |

**Workers**: 3 active (w1: deterministic, w2: havoc, w3: splice)

**New crashes**:
- crash_a3f2: read AV in ParseZIPLocalHeader+0x3f2 → P3 (non-controllable)
- crash_b7e1: write AV in ScanBuffer+0x1a3 → P2 (partially controlled)
- crash_c901: heap overflow in DecompressLZMA+0x88 → P1 (controlled length)

**Coverage notes**: +12 new blocks, all in LZMA decompression path.
Corpus evolved past a CRC validation check that was blocking progress.

**Decision**: TRIAGE P1 crash_c901 immediately. Continue campaign for
remaining parsers. Add LZMA-heavy seeds to worker 3.
```

### Example CAMPAIGN_LOG.md

Here's what a multi-week log looks like in practice:

```markdown
# Campaign: mpengine_zip

**Created**: 2026-06-01
**Target**: mpengine.dll — ZIP/archive format parsers
**Seeds**: 12 files (minimal ZIP, nested ZIP, encrypted ZIP, ZIP64, etc.)
**Dictionary**: zip_tokens.txt (47 entries)
**Budget**: $250 max

---

## Weekly Assessments

### Week 1 — 2026-06-01

| Metric               | Value          | Trend     |
|----------------------|----------------|-----------|
| exec/sec (avg)       | 312            | baseline  |
| Total executions     | 189,043,000    | baseline  |
| Unique crashes       | 7              | baseline  |
| New coverage blocks  | 4,231          | baseline  |
| Corpus size          | 487 entries    | baseline  |
| Stability            | 97.1%          | baseline  |
| Cost this week       | $31.20         |           |
| Cost total           | $31.20         |           |

**Workers**: 3 active (spot instances, RTX 3090)

**New crashes**: 7 unique. 5x read AV (P3), 1x null deref (discard),
1x write AV in DecompressDeflate (P2 — investigating).

**Coverage notes**: Steep growth — expected for first week. Fuzzer
explored most top-level ZIP parsing paths.

**Decision**: CONTINUE. Good throughput. P2 crash warrants closer look.

---

### Week 2 — 2026-06-08

| Metric               | Value          | Trend     |
|----------------------|----------------|-----------|
| exec/sec (avg)       | 298            | -4.5%     |
| Total executions     | 369,417,000    | +180M     |
| Unique crashes       | 11             | +4        |
| New coverage blocks  | 4,502          | +271      |
| Corpus size          | 834 entries    | +347      |
| Stability            | 96.8%          | -0.3%     |
| Cost this week       | $33.60         |           |
| Cost total           | $64.80         |           |

**New crashes**: 4 new. 2x read AV (P3), 1x assertion (discard),
1x heap overflow in ParseZIP64ExtendedInfo (P2).

**Coverage notes**: Growth slowing as expected. +271 blocks, mostly
in ZIP64 extension parsing. Good — fuzzer pushed past the standard
ZIP header code into extended format handling.

**Decision**: CONTINUE. Coverage still growing. Two P2 crashes in
the pipeline. Add ZIP64-heavy seeds to worker 3.

---

### Week 3 — 2026-06-15

| Metric               | Value          | Trend     |
|----------------------|----------------|-----------|
| exec/sec (avg)       | 287            | -3.7%     |
| Total executions     | 547,293,000    | +178M     |
| Unique crashes       | 14             | +3        |
| New coverage blocks  | 4,514          | +12       |
| Corpus size          | 1,204 entries  | +370      |
| Stability            | 96.2%          | -0.6%     |
| Cost this week       | $38.40         |           |
| Cost total           | $103.20        |           |

**New crashes**: 3 new. 1x P1 (crash_c901 — heap overflow in
DecompressLZMA with controlled length field), 2x P3.

**Coverage notes**: +12 blocks. PLATEAU. Coverage has flatlined.
BUT — the P1 crash makes this irrelevant.

**Decision**: STOP CAMPAIGN. P1 found. Shift to exploit development
for crash_c901. Budget remaining: $146.80 — reallocate to next
campaign (mpengine_ole) after exploit work completes.
```

### Graphing Coverage Over Time

Visual coverage trends reveal plateaus faster than reading numbers.
Quick and dirty gnuplot one-liner:

```bash
#!/bin/bash
# coverage_plot.sh — plot coverage growth over time
# Reads coverage_log/ directory for timestamped block counts

CAMPAIGN="${1:?Usage: coverage_plot.sh <campaign_name>}"
BASE="/campaigns/$CAMPAIGN"
LOG_DIR="$BASE/coverage_log"
OUTPUT="$BASE/coverage_growth.png"

# Expects files named YYYYMMDD_HHMM.txt containing one number: block count
# Generate these with a cron job that runs:
#   grep "total_blocks" fuzzer_stats | awk '{print $3}' > coverage_log/$(date +%Y%m%d_%H%M).txt

# Build data file
DATA=$(mktemp)
for f in "$LOG_DIR"/*.txt; do
    [ -f "$f" ] || continue
    BASENAME=$(basename "$f" .txt)
    DATE="${BASENAME:0:8}"
    TIME="${BASENAME:9:4}"
    BLOCKS=$(cat "$f")
    echo "$DATE $TIME $BLOCKS"
done | sort > "$DATA"

# Plot
gnuplot << GNUPLOT
set terminal png size 1200,600
set output "$OUTPUT"
set title "Coverage Growth — $CAMPAIGN"
set xlabel "Date"
set ylabel "Basic Blocks Covered"
set xdata time
set timefmt "%Y%m%d"
set format x "%m/%d"
set grid
plot "$DATA" using 1:3 with linespoints title "Coverage" lw 2 pt 7 ps 0.8
GNUPLOT

rm "$DATA"
echo "[+] Coverage plot saved to $OUTPUT"
```

---

## When Things Go Wrong

Every campaign hits problems. The question isn't IF something breaks —
it's WHEN, and whether you notice before it wastes a week of compute.

### Fuzzer Dies Silently

WinAFL doesn't always crash loudly. Sometimes it just stops. The
process is still alive but it's stuck on a hang, a deadlock, or an
unhandled exception in DynamoRIO itself. From outside, it looks
like it's running. exec/sec is zero but nobody's watching.

**Fix: Watchdog cron job.**

```bash
#!/bin/bash
# watchdog.sh — detect and restart dead fuzzers
# cron: */5 * * * * /path/to/watchdog.sh <campaign_name>

CAMPAIGN="${1:?}"
BASE="/campaigns/$CAMPAIGN"
WORKERS=(worker_1 worker_2 worker_3)

for WORKER in "${WORKERS[@]}"; do
    STATS="$BASE/workers/$WORKER/output/fuzzer_stats"
    PID_FILE="$BASE/workers/$WORKER/winafl.pid"

    if [ ! -f "$STATS" ]; then
        echo "[WATCHDOG] $WORKER: no stats file — starting"
        # Re-launch worker (adjust command to your deployment)
        nohup /opt/scripts/worker_launch.sh "$CAMPAIGN" "${WORKER##*_}" \
            >> "$BASE/worker_logs/$WORKER.log" 2>&1 &
        echo $! > "$PID_FILE"
        continue
    fi

    # Check if fuzzer_stats was updated recently (within 5 minutes)
    STATS_AGE=$(( $(date +%s) - $(stat -c %Y "$STATS") ))

    if [ "$STATS_AGE" -gt 300 ]; then
        echo "[WATCHDOG] $WORKER: stats stale for ${STATS_AGE}s — restarting"

        # Kill the stuck process
        if [ -f "$PID_FILE" ]; then
            kill -9 "$(cat "$PID_FILE")" 2>/dev/null
        fi

        # Re-launch
        nohup /opt/scripts/worker_launch.sh "$CAMPAIGN" "${WORKER##*_}" \
            >> "$BASE/worker_logs/$WORKER.log" 2>&1 &
        echo $! > "$PID_FILE"
    fi
done
```

### Disk Full

Crash artifacts and corpus entries accumulate. A productive campaign
might generate 100GB+ of data over weeks. The disk fills silently,
the fuzzer can't write new crashes, and you lose findings.

**Fix: Crash rotation + corpus pruning.**

```bash
#!/bin/bash
# disk_maintenance.sh — prune old data, minimize corpus
# Run weekly after crash collection

CAMPAIGN="${1:?}"
BASE="/campaigns/$CAMPAIGN"

echo "[*] Disk maintenance for $CAMPAIGN"

# 1. Remove duplicate raw crashes (already deduped to crashes/deduped/)
echo "[*] Clearing raw crash staging area..."
BEFORE=$(du -sh "$BASE/crashes/raw" | awk '{print $1}')
rm -f "$BASE/crashes/raw"/*
echo "    Freed: $BEFORE"

# 2. Minimize corpus with afl-cmin
echo "[*] Minimizing corpus..."
CORPUS="$BASE/corpus"
CORPUS_MIN="${CORPUS}_min"
BEFORE_COUNT=$(ls -1 "$CORPUS" | wc -l)

# afl-cmin keeps the minimal set that achieves same coverage
afl-cmin -i "$CORPUS" -o "$CORPUS_MIN" \
    -t 30000 \
    -- /opt/harness/harness.exe @@

AFTER_COUNT=$(ls -1 "$CORPUS_MIN" | wc -l)
echo "    Corpus: $BEFORE_COUNT → $AFTER_COUNT entries"

# Swap
rm -rf "${CORPUS}_old"
mv "$CORPUS" "${CORPUS}_old"
mv "$CORPUS_MIN" "$CORPUS"
echo "    Old corpus backed up as ${CORPUS}_old"

# 3. Compress old worker logs
echo "[*] Compressing old logs..."
find "$BASE/worker_logs" -name "*.log" -mtime +7 -exec gzip {} \;

# 4. Report disk usage
echo "[*] Current disk usage:"
du -sh "$BASE"/*
echo ""
du -sh "$BASE"
```

### Target Hangs

Some inputs trigger infinite loops or exponential-time paths in the
parser. The fuzzer waits for the timeout, kills the iteration, and
marks it as a hang. A few hangs are normal. Hundreds of hangs mean
the fuzzer is SPENDING MORE TIME WAITING THAN FUZZING.

**Diagnosis**: Check the `hangs/` directory in the output. If it's
growing fast, you have a parser path that's easy to trigger and hard
to escape.

**Fix options**:

1. **Lower the timeout.** If most normal executions complete in 2
   seconds, drop `-t` from 30000 to 5000. Hangs get killed faster,
   less wasted time.

2. **Blacklist the hanging input.** Some fuzzers support excluding
   specific corpus entries. Remove the parent of the hanging mutations
   from the corpus.

3. **Fix the harness.** If the hang is in your harness code (not the
   target), that's your bug to fix. Add a timer thread that kills the
   scan call if it exceeds a threshold.

### No Crashes After 1 Billion Iterations

You've been running for weeks. Coverage plateaued. Crash count is
zero. The fuzzer is alive, healthy, burning money, and finding nothing.

This is the worst outcome. Not because the target is unbreakable —
but because the SILENCE gives you no information about WHY.

**Diagnostic checklist:**

1. **Is the harness actually reaching the parser?**
   Add instrumentation to verify. Log when the target function is
   called and what it returns. A harness that calls the wrong function
   or passes data in the wrong format will run forever without crashes
   because IT'S NOT TESTING ANYTHING.

2. **Are your seeds valid?**
   If the seeds fail validation immediately, every mutation also fails
   validation immediately. The fuzzer only sees the error-handling
   path — never the actual parsing code. Verify seeds by running them
   through the harness manually and checking that they reach the
   parser, not just the error handler.

3. **Is the coverage module correct?**
   If you're instrumenting the wrong module, the fuzzer's coverage map
   doesn't reflect the actual parser. It makes mutation decisions
   based on irrelevant data. Verify that `-coverage_module` matches
   the DLL that contains the parsing code.

4. **Is the target genuinely hardened?**
   Some parsers have been fuzzed to death by the vendor's own security
   team. Microsoft runs their own fuzzing campaigns against mpengine.
   The bugs that remain are DEEP — behind multiple validation gates,
   in rarely-exercised code paths, triggered by specific input
   combinations. If the easy bugs are already patched, you need
   SMARTER seeds, not more iterations.

5. **Try a different approach.**
   - Grammar-based fuzzing: instead of blind mutation, generate inputs
     that conform to the file format grammar but with boundary values
   - Different format entirely: pivot from ZIP to OLE, PE, PDF
   - Hybrid approach: use reversing (Ch08) to identify specific
     validation checks, then craft seeds that pass those checks and
     reach deeper code

The rule: if 1 billion iterations found nothing, MORE ITERATIONS WON'T
HELP. Change something fundamental — seeds, approach, or target.

---

## Putting It All Together — A Campaign From Start To Finish

Here's the complete workflow. From zero to results.

```
DAY 0: PREPARATION
├── Choose target format (ZIP, OLE, PE, etc.)
├── Curate 10-20 seed files (diverse, valid, different features)
├── Build format dictionary (magic bytes, keywords, constants)
├── Run campaign_init.sh to set up directory tree
├── Write WinAFL command line in config/winafl_args.txt
├── Set budget limit in CAMPAIGN_LOG.md
└── Deploy 3 workers with diverse strategies

DAY 1-3: INITIAL ASSESSMENT
├── Verify exec/sec is above 200
├── Verify stability is above 95%
├── Check that coverage is growing (steep curve expected)
├── Confirm crashes/ directory structure is working
└── Set up monitoring cron (watchdog + corpus sync)

WEEK 1 ASSESSMENT
├── Pull crashes, run crash_collect.sh
├── Dedup and quick-triage any finds
├── Log stats to CAMPAIGN_LOG.md
├── Decision: continue (expected)
└── Note: most campaigns produce first crashes in week 1

WEEK 2-4 ASSESSMENTS (weekly)
├── Same Monday ritual
├── Track coverage growth trend
├── Watch for plateau
├── Pivot seeds/strategy if growth stalls
├── Kill if budget exceeded
└── STOP if P1 crash found → shift to exploit dev

POST-CAMPAIGN
├── Final crash triage (full stack-hash dedup + !exploitable)
├── Archive campaign data (compress, push to persistent storage)
├── Write post-mortem in CAMPAIGN_LOG.md:
│   total cost, total execs, bugs found, lessons learned
└── Redeploy resources to next campaign
```

---

## Doctrine Alignment

The 0x1security compass says: search for knowledge, not bugs.

A campaign IS knowledge-gathering. Even a campaign that finds zero
crashes teaches you:
- Which code paths the fuzzer covered (and which it couldn't reach)
- Which validation checks are strong (coverage blockers)
- Where the parser's complexity lives (slow paths, deep nesting)
- What input features correlate with new coverage

A "failed" campaign that maps 50% of mpengine's ZIP parser and
identifies three coverage walls is NOT a waste. Those coverage walls
are your next research targets. Each one is a validation check that,
if bypassed with smarter seeds, opens up a new territory of code.

The siege analogy is exact: you're surrounding the fortress, probing
every wall for weakness, and documenting every result. Even the walls
that held are intelligence. When you come back with better tools or
a different approach, you know exactly where to hit.

The crashes are the goal but the KNOWLEDGE is the weapon.

---

## Key Terms (Add to Glossary)

| Term | Definition |
|------|-----------|
| **Campaign** | A sustained, structured fuzzing operation with defined goals, budget, and assessment cycles |
| **Forward operating base (FOB)** | The infrastructure — cloud instances, storage, tooling — from which a campaign is run |
| **Master-worker topology** | Architecture where one node collects results and others execute fuzzing |
| **Corpus sync** | Sharing evolved inputs between parallel fuzzer instances for broader coverage |
| **Coverage plateau** | Period where the fuzzer discovers no new basic blocks; indicates exhaustion of reachable code |
| **Kill criteria** | Pre-defined conditions under which a campaign is terminated regardless of results |
| **Campaign log** | Structured record of weekly assessments, metrics, decisions, and rationale |
| **exec/sec** | Executions per second — primary throughput metric for fuzzer health |
| **Stability (fuzzer)** | Percentage of iterations with deterministic coverage traces; measures state cleanliness |
| **Corpus minimisation** | Reducing corpus to smallest input set that achieves equivalent coverage (`afl-cmin`) |
| **Spot instance** | Cloud compute rented at reduced price with risk of interruption; ideal for fuzzing workers |
| **Diminishing returns** | The logarithmic relationship between worker count and coverage gain |
| **Seed refresh** | Adding new initial inputs to restart exploration from different parser entry points |
| **Watchdog** | Automated process that detects dead/stuck fuzzers and restarts them |
| **Battle rhythm** | Regular assessment cycle (weekly) that imposes structure on long-running operations |

---

## Summary — Key Takeaways

- **Fuzzing is a siege, not a raid.** Hours of fuzzing is recon. Days is patrolling. Weeks is a real campaign. The deep bugs — the ones worth exploiting — hide behind coverage walls that take millions of corpus generations to bypass.

- **Architecture matters.** Master-worker topology with persistent storage on the master. Workers are disposable. Crashes and corpus survive worker death.

- **Know your command line.** Every WinAFL flag has a purpose. Wrong `-nargs` = false crashes. Wrong `-coverage_module` = blind fuzzer. Wrong `-fuzz_iterations` = state pollution. Get the fundamentals right before you scale.

- **Five vital signs: exec/sec, unique crashes, coverage growth, stability, memory usage.** Monitor all five. Any one of them going wrong wastes your entire campaign. exec/sec below 50 = abort. Stability below 90% = fix harness. Memory growing = restart workers or fix leak.

- **The Monday ritual is non-negotiable.** Pull data. Check metrics. Log everything. Make one decision: continue, adjust, or kill. Without structured assessment, campaigns drift into expensive noise.

- **Parallel workers need strategy diversity.** Three identical fuzzers waste money. Three workers with different strategies (deterministic, havoc, splice) and different seed sets explore three different regions of the input space simultaneously.

- **Budget is a weapon, not a safety net.** Set hard limits before launch. Track cost weekly. Spot instances for workers. Cheapest GPU tier (fuzzing is CPU-bound). Don't pay for RAM you won't use.

- **Know when to walk away.** 1 billion iterations with zero crashes = change something fundamental. Coverage plateau for 7 days = refresh or pivot. P1 found = stop fuzzing, start exploiting. Sunk cost fallacy is the enemy.

- **Every campaign is intelligence.** Even zero-crash campaigns map code, identify coverage walls, and reveal parser structure. "Failed" campaigns make the next campaign smarter.

- **Log everything.** The campaign log is your institutional memory. In month two, you won't remember what you tried in week three. The log remembers. Metrics, decisions, rationale — all of it, every week.

---

## Drill 11 — Campaign Ops

Go to `DRILLS/11_campaign_ops/`. A simulated campaign environment is
waiting — a vulnerable target with a harness, seed files, and a
three-instance deployment script.

Your mission:
1. Initialise a campaign using `campaign_init.sh`
2. Deploy three workers with different strategies (deterministic, havoc, splice)
3. Run `campaign_monitor.sh` and verify all five vital signs
4. Run for 1 hour. Pull crashes with `crash_collect.sh`
5. Write a Week 1 assessment entry in CAMPAIGN_LOG.md
6. Make a decision: continue, pivot seeds, or kill
7. Set up the watchdog cron job and verify it detects a killed worker

This drill is about OPERATIONS, not exploitation. You're practising
the logistics of sustained campaign management. The fuzzer finds the
bugs. You keep the fuzzer alive, healthy, and pointed at the right
target. That's the job.
