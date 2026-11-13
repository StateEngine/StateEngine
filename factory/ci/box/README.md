# Linux CI shadow

These maintainer tools run Linux checks in a disposable rootless Podman container.
They do not register a GitHub runner, dispatch workflows, or update the required
`check` status. Windows and macOS jobs continue through their existing workflows.

Installation fixtures take the product's real account-wide lock. Nextest serializes
them in `installation-custody`; they refuse outside an administrator-registered
dedicated test account. The container image registers only its disposable user.
For a VM test user, run `scripts/ci/installation_account.py provision --identity
NATIVE_UID_OR_SID --profile NATIVE_PROFILE` as administrator, then run the tests as
that user. Never register an ordinary developer account or override the product lock.

Run `provision.py` as administrator to prepare the locked, dedicated account and
its root-owned seccomp policy. Run `build.py --help` for the trusted image builder.
Its source must already be merged on local `main`; it fetches public dependencies
before any PR code runs and records the immutable image ID and approved workflow
hashes. Review those inputs before using the resulting `image.json`.
Supply the public Rust 1.97.1 toolchain and rustup 1.29.1 executable explicitly;
the image uses the proxy to honor toolchain-qualified release commands offline.

Run `canary.py check --image IMAGE_ID --output NEW_DIRECTORY` to exercise the actual
machine boundary. A reviewer must independently run the canaries before a PR
shadow. Failed attempts remain in their original output directories.

Run `controller.py --help` for the shadow entrypoint, including its approved
dependency snapshot. Supply the existing hosted
run, attempt, PR number, actual checkout merge SHA, approved image report, and an
executable credential helper. The helper prints a repository read token; it runs
only in the outside controller. Forks, stale attempts, moved PRs and changed
workflow/tool definitions refuse. A new approved image is needed when dependencies
or CI policy change. Missing dependencies fail offline without adding network access.

Jobs run serially in one fresh container and private cache, using the hosted
commands, shipping features, two test partitions and CI profile. Compiled tests
stay in place, followed by Windows MSVC-target Clippy against the prepared public
SDK. No test archive is exported between stages. Logs, binding and outcomes
remain outside; candidate output cannot authorize success. Output overflow,
deadline or cancellation fails and removes the exact owned container. Conmon
enforces the job deadline if the controller disappears; a later run refuses while
an earlier container is still active.

This is a Linux-only fleet adapter. It cannot replace the hosted required path
until an automatic dispatcher and its hosted fallback have separately been approved
and exercised. No shared writable PR cache or privileged socket is exposed.


## Required-status cutover (disabled until maintainer deployment)

`dispatch.py` polls only the pinned repository/workflow. The hosted `scripts/ci/box.py`
reader selects one App-owned offer within 90 seconds, then waits at most 25 minutes.
Only an exact same-attempt `linux-box` job starting can acknowledge an offer; an
unused reservation expires after 30 seconds. Forks, unsupported events, changed
approved policy, busy guests, unavailable capacity and infrastructure loss use the
complete hosted Linux chain. A known compile/test/resource/output/deadline failure
is red. Both Windows Clippy and Linux outcomes remain required by `check.py`.
Windows Clippy runs for applicable drafts too; the informational Windows archive
and smoke run only on the nightly schedule and on manual runs.

The controller has no inbound port, runner registration, candidate host command or
worker-mounted credential. It uses the same networkless rootless container engine,
eight Cargo workers, four test threads per shard and one container
(maximum cap 18 GiB/8 CPUs, with a 30-minute outside deadline). The nextest installation group remains serial.
The serial profile is 18 GiB/8 CPUs. The paired profile used when both runner
slots are configured is 16 GiB/4 CPUs/4 workers, so the pair's caps sum to
34 GiB; admission also requires 6 GiB to remain available after a container is
admitted, so a box runs a paired pair only when it can keep that margin.
Dependency archives are maintainer-approved compiled dependencies, with every
workspace crate removed; they are streamed and unpacked only inside the container.
The hosted polling minutes remain billable and must be included in cost comparisons.

### Maintainer deployment

Do not start this service or enable `BOX_CI_ENABLED` when installing a review candidate.
These steps are an explicit maintainer deployment, not a script invoked by a candidate.

1. Create the dedicated **StateEngine Box CI** App, installed only on this repository,
   with Actions read, Checks write, Contents read, Pull requests read and Metadata read.
   No repository/Actions/workflow write, organization, administration or billing scope.
   Store its key root-only at `/etc/stateengine-ci/app-key.pem`; the service receives
   only its systemd credential copy. Do not reuse a seat App or daily credential.
2. Keep the existing locked `stateengine-ci` worker. Create a separate locked account
   `stateengine-ci-controller` with home `/var/lib/stateengine-ci-controller`, shell
   `/usr/sbin/nologin`, no supplementary groups and no password/login. Its private state
   directory is mode 0700. Create `/var/lib/stateengine-ci-jobs` owned by that controller,
   group `stateengine-ci`, mode **2750**; only the controller writes records and the worker
   reads them. This directory is separate from App key and private result storage.
3. Install the reviewed tree's `factory/ci/box/` and `scripts/ci/box_result.py` preserving
   those relative paths below root-owned `/usr/local/lib/stateengine-box-ci`; no installed
   code or ancestor may be writable by either account. Install `worker-engine.py` as
   `/usr/local/libexec/stateengine-ci-engine` and `idle.py` as
   `/usr/local/libexec/stateengine-ci-idle`, root:root 0755. Grant the controller only
   `sudo -u stateengine-ci /usr/local/libexec/stateengine-ci-engine` (its fixed Podman door).
   Grant existing guest-controller users only the argument-free idle door. Sudoers must
   spell the idle command with `""` to prohibit arguments; no worker shell or generic
   Python/env/sudo delegation is granted to the new controller.
4. With both guests stopped, apply `guest-owner-ci-fence.patch` to
   the administrator-selected shared `guest_owner.py` using `patch --fuzz=0 --dry-run` first, then
   `patch --fuzz=0`; both deployed VM controllers already call its `before_boot`.
   Review the complete resulting file, restart any old lifecycle controller before its
   next boot, and exercise **both** readers. Missing helper, unreadable engine, any
   persistent record/object or live recorded process/cgroup refuses admission. Install
   this fence before the dispatcher and retain it through disable/rollback until
   outside inventory and exact native closure are empty. No guest-owner/v1 wire change.
5. Give the controller traverse-only ACLs on the two VM state directories and read
   access to their existing `run.lock` files (flock works on read-only descriptors), plus
   read access to the shared guest publisher state file. Give it only traverse/read access
   to the existing shadow CI lock and its ancestors, not listing or credential access;
   use that exact lock as `ci_lock`. Do not grant VM control-script execution, VM directory
   writes or credential reads. No missing lock file is recreated.
6. Build/approve the image with `build.py` on merged trusted source. Its policy covers
   the workflow/actions, nextest config, all Cargo manifests/lock/toolchain and CI tools.
   Install the immutable image report and dependency snapshot root-owned, not writable
   by either account. Fill `/etc/stateengine-ci/dispatch.json` from `dispatch.example.json`
   with the numeric repository/workflow/App/installation IDs, pinned report/cache paths
   and SHA256, both absolute guest lock paths and the absolute shared publisher state
   path. `config_at` refuses incomplete old shadow reports. Install the service unit
   without enabling or starting it. Set repository variables `BOX_CI_APP_ID` and
   `BOX_CI_ENABLED=false`. Branch protection continues to require only `check`.
7. After review, publish the workflow, deploy the approved controller and run the real
   consumer witnesses below before setting `BOX_CI_ENABLED=true`. Disabling that variable
   restores hosted execution. Do not remove the persistent fence to roll back routing.

The root-owned engine door does a pre-create acknowledgement: it reports its native
PID and waits. The controller fsyncs that process pin before permitting creation. A
crash before acknowledgement gives EOF; a crash afterward leaves the pin and persistent
intent. Records retain creation, Conmon and container pins and the original cgroup even
when later inspect output shows exited state. Restart reconciliation removes only exact
known IDs, joins native closure and clears their records; unknown objects or unreadable
state retain the fence. A check-creation tombstone prevents a duplicate offer after a
lost API reply. Terminal reports are persisted before publication and retried unchanged;
a known red result cannot become unavailable on retry.

Before enablement, verify through the actual hosted consumer: success, genuine test red,
controller absence/busy-VM fallback, fork rejection before execution, stale/wrong-App/
wrong-SHA/duplicate output, unused queued-offer expiry and cancellation. Kill a controller
while a bounded real container survives and prove both guest admission readers refuse,
including when engine reads fail; reconciliation must join all native tasks before either
reader permits boot. Unit tests and isolated process checks do not qualify these deployed
App/workflow effects. Preserve any original failures and do not call fallback work box success.

For the optional guest-fence patch integration checks, set
`STATEENGINE_GUEST_OWNER_SOURCE` to the existing administrator-owned publisher source.
The tests apply the patch only to a disposable copy; an unset path skips that integration.
