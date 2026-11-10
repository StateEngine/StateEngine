# Serial self-hosted Linux CI

This adapter uses the ordinary GitHub runner for scheduling and status. It reuses
the approved networkless rootless containers and the existing `Cohort` consumers;
there is no polling job on a hosted Linux machine. One listener admits one job at
a time, and the full chain executes six stages serially inside one disposable container.
Compiled tests stay inside that container; no test archive crosses the host.

Pull requests and pushes retain default-feature tests. Scheduled runs on `main`
and manual runs of `main` compile and run all features, including documentation
and custom harnesses. The bound run records its feature mode and logs the actual
commands; a missing or failed stage still fails the complete check.

The listener runs as the locked `stateengine-ci` account. Both container hooks and
`ACTIONS_RUNNER_REQUIRE_JOB_CONTAINER=true` are mandatory service environment,
not workflow options. Without them a changed workflow could execute on the host.
The root-owned hook admits only four literal operation markers: changes, route,
linux and check. It does not execute a repository shell on the host. It rejects
container actions, candidate volumes, container options and service containers.
Runner directories, credentials, sockets and environment are never mounted in a
candidate container. A temporary repository read token stages an opaque source
archive through the GitHub API, verifies approved policy, and is not persisted or
passed into a container. Downloads use a credential-free approved archive redirect.
An incomplete response or a connection/read timeout retries the full idempotent
GET up to three times with a short backoff. Partial bytes are discarded; exhausted
retries refuse the job, and the response-size and credential-free redirect bounds
remain unchanged.

Change detection and route selection run on hosted runners. Only the complete
Linux workload uses the box; its preparation verifies the pinned policy before
staging candidate bytes. A changed or missing policy file downloads no candidate
archive and returns an unavailable outcome, selecting the complete hosted chain.
API failures and unreadable policy do not become an assertion of policy drift;
a failed preparation also selects hosted. The `linux` operation runs existing
formatting, Linux Clippy, test compilation/docs, both nextest/custom harness
partitions and Windows MSVC-target Clippy. Windows checking uses the prepared
public SDK and cross-checking tool inside the same networkless container.
The hook emits a separate Windows outcome; the final reader permits skipping the
hosted Windows job only when the complete box run and that outcome both passed. The final
required-status consumer always runs on hosted.

An infrastructure refusal before or between stages prints its reason and selects
the complete hosted Linux chain. An observed compile, test or workload resource
failure remains red, including when later admission or cleanup is unavailable.
Cancellation does not select fallback. Native outcomes, logs and exact source
binding are retained under the configured private controller state directory.
The legacy fixed metadata and check operation markers remain available to the
adapter, but this workflow does not schedule them on the box.

The full run has an 18 GiB memory cap, eight CPU cores and a 30-minute outside
deadline. Container admission requires 24 GiB available for the full run, preserving
6 GiB after its bounded allocation. The existing CI lock serializes
against other CI work. This adapter adds no guest-admission fence or guest lock;
guests use their own memory admission. Persistent container records still retain
exact process custody after a controller crash, and reconciliation must join known
native tasks before another container runs. Keep the dedicated App dispatcher
stopped during this cutover.

The adapter follows the pinned runner v2.338.2 protocol: `prepare_job` receives
`args.container`. Cleanup after failed preparation may have null state and only
reconciles previously recorded native custody under the CI lock.

Root installation:

1. Install a pinned official Linux x64 runner archive and verify its published
   SHA-256. Own its binaries and parent directory as root; disable self-update.
   Give the worker only its private work, diagnostics and registration-state files.
2. Install the reviewed `hook.js` and `hook.py` below the same root-owned adapter
   tree. Install `hook.py` as `/usr/local/libexec/stateengine-ci-hook`, root:root
   0755, and grant only `stateengine-ci ALL=(stateengine-ci-controller) NOPASSWD:
   /usr/local/libexec/stateengine-ci-hook` in a checked sudoers drop-in. The existing
   controller-to-worker fixed engine delegation remains unchanged.
3. Fill `self-hosted.json` from the example, root:root 0644, using the existing
   CI lock and approved image/cache. Make its new `state` directory
   controller-owned 0700. The controller needs no access to runner registration
   credentials or runner workspace; the small worker shim handles file commands.
4. Register one repository runner with label `stateengine-box`, disable update,
   and select the configured private work directory. Supply the short-lived
   registration token through `ACTIONS_RUNNER_INPUT_TOKEN` in the registration
   process environment, never argv, logs or a checked-in file. Return the binary
   directory to root ownership after registration.
5. Install the supplied service unit without enabling it until the
   approved policy and real container canaries pass. The hook itself executes
   as the separate locked controller through its exact sudo door.

The maintainer supplies the workflow change. `LINUX_CI_RUNNER` holds the JSON
runner selector, for example `["self-hosted","Linux","X64","stateengine-box"]`.
Clearing that one variable restores the complete hosted path. Disable the old
App route variable as part of cutover. Box preparation or infrastructure refusal
selects hosted automatically; known test red never becomes fallback success. An
offline runner remains queued until the maintainer clears the selector; an
already stranded run may need a re-run after that change. Busy work queues on the
box instead of overflowing to hosted. GitHub expires an unstarted self-hosted
job after 24 hours; the job execution timeout does not shorten that queue limit.
The sole required status remains `check`; it requires Windows-target Clippy
from the box or the complete hosted fallback.
The workflow allows hosted fmt/Clippy/archive/tests for an explicit hosted route,
a failed routing observation, or an unavailable box workload, even with the box
selector set. It always places `check` on hosted.
That final job checks out the event's trusted base revision for a pull request
(the selected main revision otherwise), never the candidate's status consumer,
and invokes it with isolated Python. It uses no candidate local actions or Python
startup imports. The maintainer owns this workflow invocation and reviews any
change to it along with the paired adapter; the required status is not a claim
that arbitrary replacement workflow definitions have been authenticated.

Before activation, independently exercise a real required check, a genuine test
failure, workflow/container rejection, cancellation with a surviving container,
free-memory refusal and exact cleanup. Syntax checks and isolated hook
requests do not qualify these deployed effects. Native Windows runtime and macOS qualification remain separate; a successful
MSVC-target cross-check makes no claim about native runtime behavior.
