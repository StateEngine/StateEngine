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

Run `canary.py check --image IMAGE_ID --output NEW_DIRECTORY` to exercise the actual
machine boundary. A reviewer must independently run the canaries before a PR
shadow. Failed attempts remain in their original output directories.

Run `controller.py --help` for the shadow entrypoint. Supply the existing hosted
run, attempt, PR number, actual checkout merge SHA, approved image report, and an
executable credential helper. The helper prints a repository read token; it runs
only in the outside controller. Forks, stale attempts, moved PRs and changed
workflow/tool definitions refuse. A new approved image is needed when dependencies
or CI policy change. Missing dependencies fail offline without adding network access.

Jobs run serially, each in its own namespace and private cache, using the hosted
commands, shipping features, two test partitions and CI profile. The single archive
is passed as bounded opaque bytes between containers. Logs, binding and outcomes
remain outside; candidate output cannot authorize success. Output overflow,
deadline or cancellation fails and removes the exact owned container. Conmon
enforces the job deadline if the controller disappears; a later run refuses while
an earlier container is still active.

This is a Linux-only fleet adapter. It cannot replace the hosted required path
until an automatic dispatcher and its hosted fallback have separately been approved
and exercised. No shared writable PR cache or privileged socket is exposed.
