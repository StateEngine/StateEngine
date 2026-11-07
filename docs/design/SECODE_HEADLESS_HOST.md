# Draft SE Code headless host path

Rust currently supports embedded SE Code only. Extend managed launch with an SE Code subprocess harness: the runtime owns its process and streams; SE Code owns its session and input queue. Implementation awaits approval and the open contract checks below.

## Binary lookup and launch

Resolve explicit `providers.secode.command`, then the bundle manifest, then absolute PATH entries. Pin the native image and probe service/resident capabilities before disturbing an incumbent. Missing/incompatible software gets an installation remedy; retain the user's credentials and saved permission profile.

Choose a private service directory under the state home automatically. Authenticate an existing service, or bootstrap one and verify its generation. Provision session, capability, workspace and context before literal argv: `run --service SERVICE --session SESSION --stdin --jsonl --resident`. Persist both session identities. Read back model/permissions and establish the session consumer before reporting ready.

## Detached lifetime and streams

The launch command returns after runtime custody is accepted. Reuse its detached bootstrap: Linux user-manager startup or the reported session-only bound; Windows native job breakaway, refusing if unavailable. The client stays in the runtime's managed scope. Its service has a separate lifetime and may serve other sessions.

The runtime owns all host pipe ends after launcher exit. Write the complete prompt, then close stdin; resident operation must survive EOF. Evented readers drain stdout JSONL and stderr into bounded, protected diagnostics, recording clipping/failure. JSONL supplies activity; canonical saved turns supply history. CLI/desktop disconnect leaves pipes open. After runtime failure, reconcile recorded client/service identities before reconnecting or replacing them; anonymous pipes cannot be reopened from metadata.

## Takeover and shutdown

Reuse explicit takeover. Persist displaced service generation, session, execution and native client birth before effects. Interrupt that execution; verify settled service state, saved interruption/capture and client exit before replacement. Changed or unreadable identities keep takeover pending.

Stop holds input, requests exact execution interruption and documented client shutdown, drains capture/output, then witnesses scope exit through the existing coordinator. Native escalation closes only the client scope; separate service execution still needs proof. Incomplete closure remains pending. Service shutdown requires exclusive ownership, settled dependent sessions and an outside exit witness.

## Durable reads and shared plans

Extend provider/profile selection in `process_plan` and `stop_plan`; add one `Harness` to `LaunchCoordinator`. Reuse reservation, checkpoints, commits, native observation, takeover, stop and release. Persist the provider binding for service generation, session and execution; PID/name alone conveys no authority.

Status/resume join durable engine records with authenticated canonical SE Code reads. Distinguish absent, unreadable and stale generations. Reopen the saved conversation after settled shutdown; reconcile uncertain writes with original keys. Retain the service's sole input queue and the host's existing store/capture path.

## Fleet and desktop boundaries

Migration supplies imported agent/session mappings and binary overrides. Fresh installs get bundle discovery and automatic service/session setup. Desktop and CLI share managed launch/stop operations, independent of runtime lifetime.

**Open pending the CLI contract:** service bootstrap/ownership, resident EOF behavior, post-launch pipe lifetime, canonical durable reads and requested client/service shutdown. These are proposed requirements, not established SE Code capabilities. Acceptance on fresh Linux/Windows: exit the launcher, complete work/mail, read durably, take over, stop and resume with outside process witnesses. macOS needs separate qualification.

Source seams: [launch planning](../../crates/se-core/src/ops/process_plan.rs), [stop planning](../../crates/se-core/src/ops/stop_plan.rs), [launch coordination](../../crates/se-host/src/process/launch.rs), [harness contract](../../crates/se-host/src/harness.rs), [runtime startup](../../crates/se/src/runtime/host.rs).
