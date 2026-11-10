# Serial self-hosted Linux CI

This adapter uses the ordinary GitHub runner for scheduling and status. It reuses
the approved networkless rootless containers and the existing `Cohort` consumers;
there is no polling job on a hosted Linux machine. One listener admits one job at
a time, and the full Linux chain executes its five container stages serially.

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

`changes` requests full checks conservatively, and `route` selects the box when
the pinned policy matches. A changed or missing policy file selects the complete
hosted path automatically. These two operations use fixed metadata only: a policy
mismatch downloads no candidate archive, creates no workload container and refuses
`linux` or `check` execution on the box. API failures and unreadable policy do not
become an assertion of policy drift. The
`linux` operation runs existing fmt, Clippy, archive/doc and both nextest/custom
harness partitions; `check` runs the existing required-status consumer inside an
isolated container. A real compile/test/resource failure remains red. CI policy
or dependency changes run on hosted until an approved image/report refresh; they
do not execute new host commands. Native outcomes, logs and exact source binding are
retained under the configured private controller state directory.

Every container admission preserves 34 GiB available after its bounded memory
allocation and keeps the existing resource caps. The existing CI lock serializes
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
App route variable as part of cutover. In box mode infrastructure loss stays red
or queued until the operator selects hosted; known test red never becomes fallback
success. Required Windows Clippy and the sole `check` status are unchanged.
The workflow must allow hosted fmt/Clippy/archive/tests when `linux-route` emits
`hosted` even with the box selector set, and place `check` on hosted for that route.

Before activation, independently exercise a real required check, a genuine test
failure, workflow/container rejection, cancellation with a surviving container,
free-memory refusal and exact cleanup. Syntax checks and isolated hook
requests do not qualify these deployed effects. Windows and macOS do not execute
this Linux-only adapter and remain native qualification lanes.
