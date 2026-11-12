# Nightly Rust proof

This Linux scheduler runs the existing independent `journeys/run.mjs` judge with
its `rust-v1` command map. It adds no product assertions and does not replace the
judge's verdicts or thresholds. Product and judge Git revisions, map and file
hashes, native release identity, raw output and every first failure are retained.

Install `nightly.py`, `lifecycle.py`, `native.py`, `secode.py` and `report.py` together, and use the supplied user service and
timer. The service runs outside managed agent trees; fixture environment isolation
does not change ancestry or bypass owner guards. The adapter refuses a fleet or
session environment. It checks for 34 GiB available before building or starting a
judge. One five-hour deadline covers build, assembly and all probes, below the six-hour
service ceiling. Its lock serializes all invocations, and each judge still owns fixture
cleanup. A timeout retains its evidence and requires inspection of native custody.

Use dedicated bare mirrors for the product and judge: the scheduler adds retained
worktrees to them. It never checks out or updates a contributor's working tree.
An optional `product_fetch_refspec` fetches into that dedicated mirror from its
maintainer-configured origin before pinning tonight's source.

The configuration names absolute `state`, `product_git`, `judge_git`, `node` and
`auth_home` paths, trusted `product_ref` and `judge_ref` revisions, an array of
`prerequisite_paths`, and `probes`, for example:

```json
{
  "state": "/srv/proof/results",
  "product_git": "/srv/proof/product.git",
  "product_ref": "main",
  "product_fetch_refspec": "+refs/heads/main:refs/heads/main",
  "judge_git": "/srv/proof/judge.git",
  "judge_ref": "REVIEWED_JUDGE_COMMIT",
  "node": "/opt/judge-runtime/bin/node",
  "auth_home": "/srv/proof/native-login",
  "prerequisite_paths": ["/opt/judge-runtime/bin", "/opt/native-clis/bin"],
  "probes": [["codex", "first-hour"], ["claude", "wave-2"]]
}
```

Python 3.11 or later and the judge's Node 24 or later are required. The native CLIs
must already be installed and signed in. Only the independent
judge reads the login files to make private copies without refresh tokens; an optional
`credential_sources` object maps a provider to an absolute plain credential file
passed as `--credential-source`, for account profiles outside the usual login layout.
The judge refuses source symlinks and
checks the original inode and digest and removes the private copies after closure.
No native provider command uses the normal login home. Source and artifact trees
are retained, without credentials; cleanup of old evidence is a separate operator
operation. Native release builds use a private temporary directory on the result
filesystem, rather than a RAM-backed system temporary directory.

For a Linux SE Code harness probe, add `["secode", "secode"]` to `probes`
and configure its separately supplied native package and local model:

```json
{
  "secode": {
    "package": "/srv/proof/secode-package",
    "manifest_sha256": "REVIEWED_RELEASE_MANIFEST_SHA256",
    "base_url": "http://127.0.0.1:18020/v1",
    "model": "LOCAL_MODEL_ID"
  }
}
```

The reviewed judge must support `--surface secode --only secode --secode-input
FILE`. The scheduler verifies the pinned package manifest and native CLI, server
and terminal executable bytes, then retains `secode-input.json` and its SHA256 in
`run.json`. It checks those bytes again immediately before and after the judge.
This first scope accepts a credential-free loopback HTTP OpenAI-compatible model
only; it passes no login home or credential source to the SE Code judge. The judge
owns the isolated provider profile, fixtures and behavioral assertions.

The independent receipt uses `scope.mode: "secode-harness"` with selected journeys
`[1,2,3,4]`: Launch, Work, Mail and Resume. It echoes `secode_input_sha256` and a
`secode` object containing the input's package facts except its root path, plus the
provider facts. Ordinary required-budget and per-row cleanup checks still apply.
A missing or mismatched input, package/model echo or post-run verification keeps
the SE Code cells UNKNOWN. They have their own scoped grid; Windows and macOS are
NOT RUN for this Linux-only scope.

Each attempt has `run.json`, `grid.md`, `budgets.json`, a combined `report.json` and
`report.md`, plus the judge's original receipts. `latest.json` points to one
attempt's grid and budgets, including a failed attempt. The directory is a local
spool: there is no publisher, service identity, remote command or credential helper.
An outside reader publishes the grid. `latest.json` is bound at startup, before
builds or probes. It and both pointed-to files expose completion and overall
outcome, including interruptions and unavailable receipts. Service finalization
uses the service manager's invocation identity and a separate mapping per service;
it cannot mark another active attempt failed. A late finalizer cannot replace a
newer attempt. No managed identities enter the judge; operators may configure
`forbidden_environment_prefixes` and `forbidden_environment_names` for their setup. `--report DIRECTORY` regenerates reports
without running the product; `--prepared-build DIRECTORY` accepts a native release
only when its source matches the selected product revision, and the trusted
assembler verifies its inventory and hashes.

The original five journeys and the five sequential stock Codex first-hour checks
have different meanings, especially row four. They are separate scoped grids.
Windows and macOS are `NOT RUN` until native receipts exist. A journey cell is PASS
when its behavior passed and its cleanup is clean in a matching scoped receipt.
A completed judge exit of one can reflect budget misses; it does not turn passed
journeys red. Missing/crashed surfaces stay UNKNOWN in the planned scope, or
INTERRUPTED when that attempt was interrupted. They never drop out behind another
surface's passing rows. NOT RUN is reserved for a platform or journey outside the
plan. Completed observed rows remain visible even if later work is interrupted.
The overall attempt separately records completion, judge failures and interruption.
Service finalization retains the manager's exit facts and recognizes the producer's
expected completed-verdict exit; an unexpected exit still marks interruption.

An optional `native_receipts` array plans externally observed native cells, for example
`[{"platform":"win32","surface":"claude","selection":"wave-2","path":"/srv/proof/native-observation"}]`.
The native observer supplies `native-receipt.json`, `credential-closure.json`,
`results.json` and `budgets.json` in that directory. Import copies them into this
attempt without executing remote code. The observer must bind the product commit,
judge commit and complete judge file inventory to this attempt, name the native
archive hash and both result hashes, and witness transport and fixture credential
closure. A missing, unreadable, interrupted or mismatched observation stays UNKNOWN;
the observation must be from this UTC night and can be consumed by only one attempt,
so an earlier result cannot fill a new cell. Regenerating a report checks those bindings
again. Native budget probes retain their platform beside their measurements.
`--native-receipts-only` imports these observations without a local build or judge;
local probes are outside that attempt's plan. The native VM's ownership and lifetime
remain with its existing controller.

An observed zero remains zero. Budget measurements retain numbers, limits and
probe verdicts, using PASS, MISS or NOT MEASURED. A witnessed miss remains a miss
when other probes are missing; missing coverage is named separately and prevents a
whole-budget pass. Raw samples stay in the original judge receipts. Budget misses
never change journey cells. Missing embedded B1/B2, handover B8, FULL-write and
Codex-budget probes are named gaps.

Each invocation records load averages and observed concurrent Cargo/Rust driver
trees before and after the judge, beside its budget probes. Test commands count
as drivers; child compilers do not count as additional builds. The census names
its sequential observation and language limits and retains unreadable PIDs, so
an incomplete census is not an assertion that the box was idle. Endpoint snapshots
provide load context, not a claim about contention during every individual sample.
