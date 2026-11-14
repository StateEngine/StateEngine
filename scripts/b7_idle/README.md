# B7 idle measurement (one-shot diagnostic)

Sprint item B7: an idle host with zero or one attached session must stay quiet —
CPU under 0.1% of one core and at most 1 wakeup/s with no session, at most
2 wakeups/s with one session. This package measures that budget from
**outside** the host process; it changes no product code. It is a one-shot
diagnostic: the hosted workflow that runs it is deleted after the verdict.

## What is measured

`probe.py` drives an installed `se` binary in a throwaway data home:

1. fresh home + project, one saved claude agent, a local deterministic
   provider endpoint (`mock_anthropic.py`) on a loopback port;
2. `se up` (the product's detached runtime), then for one-session trials
   `se launch <agent> --new --task ... --detach` for one real headless
   Claude Code session;
3. after a settle window, `sampler.py` (a separate process) reads the
   host pid's OS accounting for the measurement window and never talks
   to the host;
4. per-trial receipts plus an aggregate `receipt.json` in the
   budgets.json measurement shape, with PASS/MISS verdicts per label.

Counters (repeated in every receipt):

- `cpu_percent_one_core` — 100 * delta(user+system CPU seconds) / wall
  seconds, summed over the pid's threads. One core busy the whole window is 100.
- `wakeups_per_second` (Linux) — delta of `voluntary_ctxt_switches` over all
  threads / wall seconds: the rate at which the host's threads wake out of
  waits (timer, futex, poll).
- `wakeups_per_second` (macOS) — delta of `ri_pkg_idle_wkups_expired` from
  libproc rusage / wall seconds, with a best-effort `sudo -n dtrace
  sched:sched_switch` count reported as a cross-check when available.

The measured pid is the runtime host only. The claude provider process is a
child of the host (verified in the `process_witness` section of each receipt);
its CPU and wakeups are deliberately excluded — the budget is the host's idle
cost, not the session's working cost.

## Provider disclosure

Hosted runners carry no fleet provider credentials, so the one-session trial
runs a **real Claude Code session** (real CLI process, real harness binding,
capture and mail) whose single setup turn is answered by the local
deterministic mock endpoint (`ANTHROPIC_API_KEY` + `ANTHROPIC_BASE_URL`
point at it; the harness passes both through to claude). The model's identity
is irrelevant to the host idle budget. A full real-LLM qualification would
need a fleet credential secret on the runner; that is a follow-up, not a
change to this measurement's meaning.

The build profile is dev: idle cost is wait-mechanism dominated, and the
profile changes no mechanism the verdict is about.

## Run locally

```sh
python3 scripts/b7_idle/probe.py --se PATH_TO_SE --out NEW_DIR
    [--claude-bin PATH] [--model M] [--task TEXT]
    [--trials-no-session 2] [--trials-one-session 3]
    [--settle 300] [--measure 600]
```

`--out` must not exist. Each trial gets `trial.json` (evidence: status dumps,
mock request log, process witness, cleanup readback); the aggregate is
`receipt.json`. The probe needs `curl` (mock health check) and `claude`
(Claude Code) on PATH; `--claude-bin` pins the executable.

## Hosted workflow

`.github/workflows/5e-b7-idle-20261114.yml` runs the same probe on
ubuntu-24.04 and macos-15 with the repo toolchain and pinned
`@anthropic-ai/claude-code@2.1.322`, building `se` from the pushed bytes.
It is a push-triggered one-shot (paths: this workflow file and this
directory); the lead pushes a branch carrying it. Windows is measured in the
native VM slot, not here: hosted Windows refuses the job-breakaway spawn the
provider needs (tracked separately).
