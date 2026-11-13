# Nightly Rust proof

This Linux scheduler runs the existing independent `journeys/run.mjs` judge with
its `rust-v1` command map. It adds no product assertions and does not replace the
judge's verdicts or thresholds. Product and judge Git revisions, map and file
hashes, native release identity, raw output and every first failure are retained.

Install `nightly.py`, `lifecycle.py`, `native.py`, `report.py`, `remote_journey.py`,
`remote_credentials.py`, `remote_process.py`, `remote_recovery.py` and `remote_report.py` together, and use the supplied user service and
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
  "probes": [["codex", "first-hour"], ["claude", "wave-2"]],
  "remote": {"destination": "remote-proof", "surface": "claude"}
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
other unmeasured probes are named gaps. Codex first-hour receipts include the
existing CLI, write, process, memory and idle probes. Historical behavior-only
first-hour receipts remain readable and explicitly name their missing budgets.
The reporter pins nine required first-hour probes: CLI version, contextual reads,
running-host writes, standalone process count, no-session idle and RSS,
one-session process count, RSS and idle. Each required probe must contain a
passing measurement before the invocation can pass; a producer cannot shorten
this set. Current CLI latency receipts also require the complete verb/cohort set,
successful raw samples, and a matching nearest-rank p95 within the reported limit.

Each invocation records load averages and observed concurrent Cargo/Rust driver
trees before and after the judge, beside its budget probes. Test commands count
as drivers; child compilers do not count as additional builds. The census names
its sequential observation and language limits and retains unreadable PIDs, so
an incomplete census is not an assertion that the box was idle. Endpoint snapshots
provide load context, not a claim about contention during every individual sample.

Every local nightly plans a separate remote row. A missing `remote.destination`,
an unavailable SSH account or a failed provider login fails that row; it never
quietly removes remote coverage. Native-receipt-only attempts retain their own
platform scope and do not plan this Linux journey.

This journey requires `se` built with `--features remote`. The nightly's pinned
release builder selects that feature from `scripts/release/inputs.json` and uses
the distribution profile. A supplied `--prepared-build` must carry the same
feature in its release metadata. Use a release image for the native transfer;
the larger debug image was not qualified for the SSH bootstrap deadline.

`remote.destination` is an existing SSH alias for a disposable Linux account
registered by an administrator with `scripts/ci/installation_account.py`. The
alias must permit batch SSH, file transfer and loopback forwarding. A loopback
connection to a separate OS account exercises the transport without claiming a
second physical machine. The runner checks the native account registration,
holds a destination-wide fixture lock, stages the selected native `se` and
provider executables, and creates a fresh project for each attempt. Its launch
uses SSH and the public `se launch` command. It does not grant an agent remote
launch authority. Set `remote.provider_executable` when the provider's native
Linux executable is outside `prerequisite_paths`; script wrappers are refused.
The destination also requires Python 3.11 or later.

Remote runs currently use the Claude surface and require an explicit absolute
`automation_tokens.claude` file outside the login user's native home directory.
Provision a dedicated long-lived automation token there with mode 600; the runner
never reads or copies the operator's login files. The file contains the raw token,
not a JSON credential store. For example:

```json
"automation_tokens": {"claude": "/srv/proof/automation/claude-token"}
```

The runner sends the token over SSH stdin to a fixed wrapper, which places it in
`CLAUDE_CODE_OAUTH_TOKEN` before executing `se`. The host retains this provider
credential in memory. Claude and SE Code children inherit its supported login
environment; Codex uses its own allow-list and does not receive this token.
The token is absent from argv,
command metadata and the recovery journal. Destination scans before and after the
journey require `.claude/.credentials.json` and `.codex/auth.json` to be absent;
incumbent files are refused and never replaced. Source inode and digest are checked
again after process and runtime closure.

SIGTERM and SIGINT enter bounded cleanup. A private recovery journal in the source
user's state directory records ownership before starting a runtime; the next run,
under the same destination lock, retries only that attempt's cleanup before doing
new work. Set `remote.recovery_directory` to keep that journal elsewhere. Unproven
stops retain a leftover record and fail the run. Recovery records whether the old
token source changed or is unavailable, but its inode/digest comparison cannot block
process cleanup after rotation. The destination credential-file scan still runs.
The dedicated destination account
must not be used for ordinary work. Codex remote automation-token coverage is not
part of this probe.
The runner retains source and destination project data and executable copies for
inspection; the operator's existing evidence-retention policy owns their removal.

`remote-journey/remote.json` and both raw command pipes retain each observation.
The remote grid requires an actual provisional assistant reply, a durable commit
receipt for the sent message, a provisional assistant response to that message,
and the original session/lifecycle after reconnect. Assistant-reply durability is
not asserted. Cleanup
checks the public stop receipt and reads the stopped PID back through a separate
SSH process. Attach includes explicit connection setup through the first watch
snapshot; pending echo runs from process invocation to observed provisional
stderr; reconnect includes the resumed snapshot and original-session readback.
Live output uses `remote watch --measure`'s producer-to-stdout-flush clock estimate,
retaining its `unqualified` label and source clock bracket. Each measured value
carries `n=1`; unavailable values carry `n=0`. These are single-attempt samples, not p95 or
budget certifications. Missing clock evidence stays NOT MEASURED and fails the
overall attempt without erasing otherwise witnessed remote behavior.
Windows remote journeys and physical-machine qualification
are outside this Linux scope.
