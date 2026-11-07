# Draft SE Code headless host path

Rust currently supports embedded SE Code only. Add a managed subprocess harness: the runtime owns client custody and streams; SE Code owns its session and queue. Implementation needs approval and the qualifications below.

## Binary lookup and launch

Resolve explicit `providers.secode.command`, then the bundle manifest, then absolute PATH entries. Pin/probe the native image before disturbing an incumbent. Preserve user credentials and saved permissions; missing/incompatible software gets an installation remedy.

Create an independently supervised private service under the state home, separate from client custody. Authenticate only the service matching this home's durable creation/ownership record and generation; refuse foreign/unproved services. Provision session, capability, workspace and context before literal argv: `run --service SERVICE --session SESSION --stdin --jsonl --resident`. Persist both session identities and verify profile/consumer readiness.

## Detached lifetime and streams

The launch command returns after runtime custody is accepted. Reuse detached bootstrap: Linux user-manager startup or the reported session-only bound; Windows native job breakaway, refusing if unavailable. The client stays in its managed scope; the private service serves only this runtime's seats.

The runtime owns host pipe ends after launcher exit. Write one bounded UTF-8 prompt, close stdin, never replay it at idle/reconnect. Drain stdout JSONL and stderr into protected bounded diagnostics. CLI/desktop disconnect leaves readers running. If a reader dies, resident stdout closure retires that stream without replay; other output failures remain errors. Recover results through canonical service reads, never reopen anonymous pipes. Independently observe client exit; runtime death may also close its native scope and requires reconciliation, not an assumed live client.

## Takeover and shutdown

Reuse explicit takeover. Persist service generation, session, execution and client birth; fence the old exact client and its mail/input owner before interruption. Require exact-client absence, settled service execution and saved interruption/capture before replacement. Changed/unreadable identity or an unproved fence keeps takeover pending.

Stop holds input and requests native client cancellation: SIGINT/TERM on Linux; Ctrl+C/Break through an independent Windows console/group. Qualify that Windows control path; current headless `CREATE_NO_WINDOW` is insufficient. Drain output; witness client exit and authenticated service execution outcome. Report forced termination separately. `se down` settles seats, stops the private service and witnesses exit before runtime retirement. `se uninstall` performs the same retirement before removing binaries, preserving state. Incomplete closure blocks successful down/removal and retains cleanup custody.

## Durable reads and shared plans

Extend provider/profile selection in `process_plan` and `stop_plan`; add one `Harness` to `LaunchCoordinator`. Reuse reservations, checkpoints, commits, observation, takeover, stop and release. Persist service/session/execution bindings; PID/name alone conveys no authority.

Status/resume join engine records with authenticated service reads of active executions, messages/tool outcomes and pending permissions. Preserve absent/unreadable/stale distinctions, saved conversations and original retry keys. Reuse existing store/capture.

Committed mail wakes the host; it offers a session-bound notice through authenticated SE Code service control, and SE Code's sole queue wakes the resident seat at a safe boundary, preserving notice identity for retries.

## Fleet and desktop boundaries

Migration supplies imported agent/session mappings and binary overrides. Fresh installs get bundle discovery and automatic service/session setup. Desktop and CLI share managed launch/stop operations, independent of runtime lifetime.

**Qualification pending:** SE Code's `docs/resident-headless.md` defines client input/output, supervision and shutdown; its manual Node qualification remains on hold. Private-service bootstrap, native-notice control and Windows cancellation need adapter qualification. Separate Rust acceptance on fresh Linux/Windows must exercise launcher exit and runtime/reader death independently, later real mail, durable results, zero initial-input replay, fenced takeover, native requested shutdown, resume and down/uninstall with no owned process remaining. Neither qualification substitutes for the other; macOS remains separate.

Source seams: [launch planning](../../crates/se-core/src/ops/process_plan.rs), [stop planning](../../crates/se-core/src/ops/stop_plan.rs), [launch coordination](../../crates/se-host/src/process/launch.rs), [harness contract](../../crates/se-host/src/harness.rs), [runtime startup](../../crates/se/src/runtime/host.rs).
