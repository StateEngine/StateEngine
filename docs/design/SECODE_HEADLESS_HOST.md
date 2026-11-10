# Draft SE Code headless host path

The managed SE Code subprocess harness keeps the standalone runtime as the sole StateEngine owner: SE Code must not activate an embedded owner.

This Windows follow-up removes the temporary headless launch refusal so the shared nightly journey can exercise the existing service path. Private profile-directory protection remains required. The preserved `PermissionDenied` failure must be resolved before this follow-up is ready; enabling admission alone does not qualify Windows. Retained process reconciliation and cleanup remain available.

**No real-model request has run on any platform yet.** The Linux attempt stopped at the supported account importer before submitting a request. Real-model qualification belongs to the Windows follow-up once the importer accepts the account; the shared nightly journey will judge Windows enablement. Synthetic service replies prove protocol behavior, not model execution. macOS runtime remains unqualified.

## Binary lookup and launch

Resolve explicit `providers.secode.command`, then the bundle manifest, then absolute PATH entries. Pin/probe the native image, including external-host support, before disturbing an incumbent. Preserve credentials/permissions; missing capabilities get an installation remedy.

Coordinator-owned preparation reserves durable service/session/input identities before bootstrap or provisioning, retaining native cleanup custody immediately after creation. Reconcile uncertain effects against those originals before retrying; never create a second service or resubmit uncertain input. Create only a private, independently supervised service under the state home, outside client custody; authenticate its recorded ownership/generation and refuse foreign/unproved services. Provision capability, workspace and context before literal argv: `run --service SERVICE --session SESSION --stdin --jsonl --resident`. Before readiness, read back the exact session binding, actual saved model/effective permissions and live bound mail consumer, alongside keyed input acceptance.

## Detached lifetime and streams

Return after runtime custody acceptance. Reuse detached bootstrap: Linux user-manager startup or the reported session-only bound. The Windows follow-up must qualify native job breakaway before enabling launch. The client stays in its managed scope; the private service serves only this runtime's seats.

The runtime owns host pipe ends after launcher exit. Send one bounded UTF-8 prompt with its original input key, close stdin, and require durable queue-acceptance readback before readiness. If keyed admission/readback is unavailable or uncertain, report pending/no-replay; a completed pipe write proves neither acceptance nor permission to retry. Drain JSONL/stderr into protected bounded diagnostics. Lost stdout retires only that stream: keep a healthy resident/service running and use canonical reads; other output errors remain errors. Observe client exit independently. After runtime failure, reconcile identity/state; stop/relaunch only when reconciliation requires it, with the existing client/input-owner fence and dependent-session settlement, preserving uncertain input without replay.

## Takeover and shutdown

Reuse explicit takeover. Persist service generation, session, execution and client birth; fence the old exact client and its mail/input owner before interruption. Require exact-client absence, settled service execution and saved interruption/capture before replacement. Changed/unreadable identity or an unproved fence keeps takeover pending.

Stop holds input and requests native client cancellation: SIGINT/TERM on Linux. Windows enablement must qualify Ctrl+C/Break through an independent console/group; `CREATE_NO_WINDOW` needs a qualified cancellation path. Drain output; witness client exit and authenticated service execution outcome. Report forced termination separately. `se down` settles seats, stops the private service and witnesses exit before runtime retirement. `se uninstall` performs the same retirement before removing binaries, preserving state. Incomplete closure blocks successful down/removal and retains cleanup custody.

## Durable reads and shared plans

Extend provider/profile selection in `process_plan` and `stop_plan`; add one `Harness` to `LaunchCoordinator` for configuration/attach, keeping native preparation effects in the coordinator. Reuse reservations, checkpoints, commits, observation, takeover, stop and release. Persist service/session/execution bindings; PID/name alone conveys no authority.

Status/resume join engine records with authenticated active-execution, message/tool-outcome and permission reads. Preserve absent/unreadable/stale distinctions and original retry keys; reuse existing store/capture.

Committed mail wakes the host; it offers a session-bound notice through authenticated SE Code service control, and SE Code's sole queue wakes the resident seat at a safe boundary, with original notice keys.

## Migration and desktop boundaries

Migration supplies imported agent/session mappings and binary overrides. Fresh installs get bundle discovery and automatic service/session setup. Desktop and CLI share managed launch/stop operations, independent of runtime lifetime.

**Qualification bounds:** Linux managed-service consumers have exercised synthetic loopback replies. Windows profile initialization failed with `PermissionDenied`; this does not establish the underlying directory-protection cause, and this Windows follow-up remains unqualified. Before enabling it, the shared nightly journey must exercise launcher exit and runtime/reader death independently, later mail, durable results, zero initial-input replay, fenced takeover, native shutdown, resume and down/uninstall with no owned process remaining. Real-model execution remains unproved on every platform.

Source seams: [launch planning](../../crates/se-core/src/ops/process_plan.rs), [stop planning](../../crates/se-core/src/ops/stop_plan.rs), [launch coordination](../../crates/se-host/src/process/launch.rs), [harness contract](../../crates/se-host/src/harness.rs), [runtime startup](../../crates/se/src/runtime/host.rs).
