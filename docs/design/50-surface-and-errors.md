# 50 — Surface, output contracts, errors and configuration

Deep design, 2026-10-30. Defines the `se` CLI, MCP tools, synchronous core dispatcher, JSON families, errors and configuration. [OPS.md](../OPS.md) lists the admitted operation rows; the source registry generates CLI, MCP and linked exposure from them. Counts come from those rows, with no phantom tools for disabled Atlas. Rust is the shipped product; the Node engine remains private factory software, with no factory cutover or import in this plan.

Crates: types and errors live in `se-types`; the registry, `Op` impls and dispatcher in `se-core` (`se_core::ops`); clap and renderers in the `se` binary; MCP framing in `se-host`. Nothing in `se-core` depends on clap at runtime except through the `clap::Args` derive on input structs (feature `cli`, on by default; SE Code builds with `default-features = false` and gets no clap).

---

## 1. The operation registry

### 1.1 Synchronous operation types (`se-core`; values in `se-types`)

```rust
pub trait Op: DeserializeOwned + JsonSchema + Validate + Send + 'static
    + OpCli // = clap::Args under feature "cli", empty marker otherwise
{
    const META: OpMeta;
    type Output: Serialize + JsonSchema + Render + ExitStatus + Send + 'static;
    type Then: Send + 'static;
    type Custody: Send + 'static;
    fn run<R: se_store::Snapshot>(self, cx: &mut Cx<'_, R>)
        -> Result<OpStep<Self::Output, Self::Then, Self::Custody>, SeError>;
}

pub struct OpMeta {
    pub name: &'static str,            // "message.send" — registry key, stable
    pub cli: CliExposure,
    pub mcp: McpExposure,
    pub auth: Auth,                    // Owner | Session | Either
    pub anonymous: bool,               // only meta.version / meta.help / meta.schema
    pub human_only: HumanPolicy,       // Always | Never | ConfigKey, per input variant
    pub effect: Effect,
    pub scope: Scope,                  // decides which global flags the op accepts
    pub runtime: RuntimeNeed,
    pub feature: Feature,              // Core | Atlas
    pub family: Family,                // output schema family + major
    pub since: ApiVersion,             // internal CLI/IPC introduction version
    pub journeys: &'static [Journey],
}

pub enum CliExposure {
    Leaf { path: &'static [&'static str], hidden: bool, select: Selector },
    RootFlag(&'static str),            // meta.version: "--version"
    None(Reason),
}
pub enum Selector { Always, Flag(&'static str) }
pub enum McpExposure { Tool { name: &'static str, title: &'static str, description: &'static str }, None(Reason) }
pub struct Reason(pub &'static str);   // non-empty, ≥ 12 bytes (const-checked)
pub enum Auth { Owner, Session, Either }
pub enum HumanPolicy { Never, Always, ConfigKey }
pub struct ConfigKeyMeta { pub human_only: bool /* security keys, including agent can-create */ }
pub enum Effect { Read, Write, Custody, Variant(&'static [(&'static str, Effect)]) }
pub enum Scope { None, Home, Project, ProjectOrAll, Session }
pub enum RuntimeNeed { None, HostForWrites, Host, HostAutoStart }
pub struct Family { pub name: &'static str, pub major: u16 }   // ("se.launch", 1)
```

`Cx` borrows the store Snapshot and verified Admission after project/feature policy resolves. It has no writer wait, future, runtime or native I/O
callback. `Validate::validate` enforces the same closed input and UTF-8 limits as
schema generation. Synchronous `dispatch` returns one of:

- `OpStep::Complete(output)` for an already measured read/result;
- `OpStep::Commit { batch, then }`, where `batch` is the store's closed AtomicBatch
  and `then` is a typed operation continuation containing owned values only;
- `OpStep::Custody(plan)` for native/file work admitted to the host or hostless CLI custody adapter.

`then` is not a closure and captures no SQL handle, transaction or lock. On the
host, planning and continuation each run in a finite blocking-pool job, admitted
through the host's bounded worker permits, waiting within the request deadline
as specified in [40 §4](40-host-runtime-and-harnesses.md#4-executor-blocking-and-native-thread-accounting). An owned/Arc reader enters each job;
the job opens and closes its finite Snapshot there. No SQL read or synchronous
continuation runs on the async executor. After planning releases its worker
permit and Snapshot, the async driver calls `WriterClient::submit` and awaits
CommitWait on the executor. It then admits a new blocking job for the typed
continuation with the actual CommitReceipt and a fresh Snapshot. No worker
permit or transaction spans the writer await. Submission is bounded admission,
not a blocking commit; core never waits. The hostless CLI calls synchronous
`DirectStore::append(batch, lease)` and passes its actual CommitReceipt to the
same typed continuation with a fresh finite read. It adds no queued writer or
future. `se-store` is **Async: futures only at the writer boundary**. Custody
continuations may produce another typed Commit step, driven by the adapter.

The frozen first-write seam is [se-core::commit](../../crates/se-core/src/commit.rs).
`Cx` borrows `se-store::Snapshot` and verified Admission, while AtomicBatch and
CommitReceipt also live in se-store. Dependencies are core -> store -> types;
there is no types -> store cycle. [The compile-only consumer](commit-bridge-consumer.rs)
exercises message.send and working_state.set through both routes. Its host route
uses Arc readers and bounded blocking jobs for planning and finish, releases the
permit around CommitWait, uses the supplied runtime Handle, and statically
requires a Send future. Its direct route
remains synchronous. Both resolve replayed payload IDs from the actual receipt
and a fresh finite read. No planner, transaction engine or fake store/receipt
implementation is supplied.

**Writer stamp (coordinator decision, 2026-10-30).** Every store commit records which writer made it: `WriterMode::Host { generation }` when the running host's writer committed it, `WriterMode::Direct` when the CLI committed with no host running. The store writes this onto the event row in the commit transaction and returns it in `Committed { receipt, wakes, writer }`. The typed continuation copies the actual CommitReceipt writer into the output; it never predicts that stamp before the writer completes. An `Op::run` cannot construct or override a `WriterMode`; the type has no public constructor outside `se-store`. Every output family that carries a store receipt includes `writer` (Appendix A.0 lists them), and it is a required stable field. An outside observer proves routing by comparing `writer.host_generation` with `se status` `$.runtime.generation` and with the event read back through `se history --event`, which carries the same object. No timing is involved. MCP, SE Code calls and hooks always commit through a host, so they always report `host`. A replayed receipt reports the writer of the original commit.

Owner-only selectors (`--all`, private-read previews) stay outside MCP schemas and refuse under session authority. For launch/stop/wake, CLI AGENT resolves to the same typed `target_agent_id` used by the MCP DTO; the creator-control check in §3.1 applies before `run`. A target is never an actor override.

### 1.2 The `ops!` list

One file, `se-core/src/ops/mod.rs`, holds the only list. Order is display order in `se help`.

```rust
ops! {
    meta.version         => MetaVersion,         meta.help        => MetaHelp,
    meta.schema          => MetaSchema,          identity.whoami  => Whoami,
    project.init         => ProjectInit,         project.remove   => ProjectRemove,
    project.status       => ProjectStatus,       doctor.inspect   => DoctorInspect,
    doctor.repair        => DoctorRepair,        doctor.bundle    => DoctorBundle,
    config.get           => ConfigGet,           config.set       => ConfigSet,
    config.list          => ConfigList,          runtime.up       => RuntimeUp,
    runtime.down         => RuntimeDown,         mcp.serve        => McpServe,
    mcp.token            => McpToken,            agent.list       => AgentList,
    agent.create         => AgentCreate,         agent.show       => AgentShow,
    agent.rename         => AgentRename,         agent.launch     => AgentLaunch,
    agent.stop           => AgentStop,           agent.wake       => AgentWake,
    continuity.resume    => Resume,              working_state.get => WorkingStateGet,
    working_state.set    => WorkingStateSet,     history.search   => HistorySearch,
    history.list         => HistoryList,         history.event_read => EventRead,
    message.send         => MsgSend,             message.inbox    => MsgInbox,
    message.list         => MsgList,             message.read     => MsgRead,
    message.ack          => MsgAck,              message.dismiss  => MsgDismiss,
    decision.propose     => DecisionPropose,     decision.list    => DecisionList,
    decision.show        => DecisionShow,        decision.ratify  => DecisionRatify,
    decision.reject      => DecisionReject,      decision.retract => DecisionRetract,
    decision.supersede   => DecisionSupersede,
    session.begin        => SessionBegin,        session.context  => SessionContext,
    session.turn         => SessionTurn,         session.end      => SessionEnd,
    hook.claude          => HookClaude,          store.restore    => StoreRestore,
    credential.rotate    => CredentialRotate,    installation.uninstall => Uninstall,
    store.import_node    => ImportNode,          store.forget     => Forget,
    #[cfg(feature = "atlas")] atlas.find => AtlasFind,
    #[cfg(feature = "atlas")] atlas.refs => AtlasRefs,
    #[cfg(feature = "atlas")] atlas.impact => AtlasImpact,
    #[cfg(feature = "atlas")] atlas.changes => AtlasChanges,
    #[cfg(feature = "atlas")] atlas.outline => AtlasOutline,
}
```

The `macro_rules!` expansion produces:

| Generated item | Signature | Use |
| --- | --- | --- |
| `enum AnyOp` | one variant per op, holding its input | the dispatcher's sum type |
| `enum AnyOutput` | one variant per op output | renderers, exit mapping |
| `static CATALOGUE` | `&'static [&'static OpMeta]` | help, schema, tools/list |
| `fn cli_command() -> clap::Command` | builder tree (§1.3) | `se` binary |
| `fn from_matches(&ArgMatches) -> Result<AnyOp, SeError>` | leaf → `AnyOp` | `se` binary |
| `fn tool_defs(&Principal, &Features) -> Vec<ToolDef>` | §1.4 | MCP `tools/list`, `Host::tools` |
| `fn decode_tool(name: &str, args: Value) -> Result<AnyOp, SeError>` | serde with `deny_unknown_fields` | MCP `tools/call` |
| `fn dispatch<R: Snapshot>(AnyOp, &mut Cx<'_, R>) -> Result<AnyStep, SeError>` | §1.5 | every surface |
| `fn schema_catalogue(Option<&str>) -> SchemaCatalogue` | §1.6 | `se schema`, MCP schemas |
| `const` assertions | §1.7 | compile-time mirror rules |

The internal typed host wrapper awaits the custody executor when needed, while calling this same synchronous dispatcher. The SE Code-facing `Host::call_tool` signature is exactly [secode-stateengine-api.rs](secode-stateengine-api.rs); its version/DTO boundary is indexed in section 10. There is no second authorization implementation.

### 1.3 Clap generation

Leaves are grouped by `path[0]` into subcommands (`msg` → `send`, `inbox`, …). Each leaf is `<T as clap::Args>::augment_args(Command::new(leaf))`, with doc comments as help (one source for CLI help and schema descriptions). Two shapes need care:

* **Shared leaf, selector flag.** `doctor`, `doctor --fix CHECK-ID`, `doctor --bundle [PATH]` are three ops on one leaf; the generator merges their args, puts the selector flags in one `ArgGroup` (`multiple(false)`), and `from_matches` picks the op whose `Selector::Flag` is present (else the `Always` one). Same for `history` / `history --event ID` and root `--version`.
* **Hidden.** `session *` and `hook claude` are `hide(true)`; `help --all` still lists them under "Integrations".

Global flags are attached per leaf according to `Scope`: `-p/--project` only for `Project`/`ProjectOrAll`; `--home` for everything except `None`; `--json`, `-q`, `--no-color`, `-h` everywhere. A global flag on an op that does not take it refuses `usage-unknown-flag` (no inert acceptance). Before clap runs, a static matcher checks argv against the rename table (§7.5) and returns `renamed`/`command-retired` without loading any handler.

### 1.4 MCP catalogue

`ToolDef { name, title, description, input_schema: Value, output_schema: Value, annotations: { read_only_hint, destructive_hint, idempotent_hint } }`. Input schema is `schemars` draft 2020-12 with inlined subschemas, `additionalProperties: false` on every object, and owner fields skipped. Output schema is the `Output` type's schema, wrapped so `structuredContent` is the same object the CLI prints with `--json`. `tool_defs` filters: op has `McpExposure::Tool`; principal is a bound session (anonymous MCP callers get an empty list plus a server instruction to launch through `se`); feature on; grant present (`stateengine_agent_create` only when the session holds `agent.create`). Annotations derive from `Effect` (`Read` → read-only; `Custody` → destructive for stop).

### 1.5 Dispatcher

The transport wrapper and synchronous dispatcher use the same admission order for CLI, MCP, IPC and linked calls:

1. Resolve the registered operation and its input branch through `Effect::Variant`, then feature, authority and HumanPolicy. Always covers ratify, reject, retract, supersede, remove, forget, restore, credential rotate, uninstall and doctor --fix. The agent.stop release branch is owner/Always/CLI-only; ordinary stop retains either/Never and MCP exposure. ConfigKey covers config.set of security keys, including agent.<A>.can-create. Verify the owner terminal/ancestry proof before effects (70); failure refuses with the same-user mistake/drift bound.
2. Resolve project from the bound session or §2.2. A conflicting owner selector refuses.
3. Validate the closed DTO, UTF-8 limits, revision preconditions and required request identity. Wrong identity kind, unknown fields or changed-body key reuse refuse before effects.
4. Inspect runtime requirements. Read-only/hostless store work stays synchronous. Writes route to the existing host writer when it owns the lease. A reader/direct connection finding a supported older schema releases its shared lease and uses private host bootstrap for automatic backed-up migration, then reopens the read; it does not ask the user to run se up or upgrade manually. For custody or hooks requiring a host, the adapter uses the **private runtime bootstrap**, waits up to ten seconds for readiness and retains the same request identity. There is no public `se daemon` command. Pending returns an explicit readiness/result handle, never a fabricated success.
5. Synchronous `dispatch` validates/plans and returns Complete, Commit { batch, then } or Custody. The host runs planning and each continuation in separate bounded blocking-pool jobs with owned/Arc readers; only the CommitWait is awaited on the executor between jobs (§1.1). Native custody work feeds actual facts through those synchronous steps; hostless file-only work uses the CLI custody adapter. Core does not submit or await commits, and no transaction spans an await.
6. Render achieved facts, including original writer on replay. Ordinary refusals return `se.error/v1` on the error channel **without appending a history event**. A prior commit or partial native effect remains an explicit receipt/pending fact, not a refusal erased from the record.

### 1.5.1 Request identity and bounded inputs

Every public mutation creates its request identity **before first send**. CLI
generates and prints one per invocation (stderr before transmission and in the
keyed result), and accepts `--key KEY` after an uncertain outcome. MCP mutation
schemas require `idempotency_key` (1–128 bytes); linked/IPC preserve that key.
The linked ToolCall identity must equal `arguments.idempotency_key`; a mismatch
refuses before effects. Decision domain KEY is distinct from this request key.

Timeout, lost ACK, reconnect and writer handoff retain the original request key.
For store-backed mutations, changed normalized operation/project/principal/body
with the same key returns `idempotency-key-reused`, with no second effect.
Store-backed custody retains its keyed effect plan and readback. File-only
general config set and uninstall use [40 §9.5](40-host-runtime-and-harnesses.md#95-owned-configuration-and-remove)
readback reconciliation, without a receipt journal or durable request ledger.

Restore's store-backed keyed replay, including its verbatim original receipt, is owned by [20 — restore](20-data-model.md).

Only captured turns/hooks and recipient read/ack/dismiss markers use the restricted natural-key path. Their source session/turn or recipient/message/marker identity must already exist before first send; changed content conflicts. Random keys cannot bypass those uniqueness rules. A marker retry returns its original event/writer. Native hook/header-helper stdout retains its consumed protocol; request keys are printed on stderr and retained in their private keyed result, never added as a fake provider header. Session begin/end, working-state, agent create/launch/stop/wake, decisions and owner repairs are keyed mutations, not natural-key exceptions. When a provider has no turn ID, its trusted capture adapter derives the stable identity from the pinned source incarnation/position before first send; a fresh random ID on retry is invalid. Read-only calls cannot provide a mutation identity to acquire authority.

`se-types::MESSAGE_BODY_MAX_BYTES = 32 * 1024` and `WORKING_STATE_MAX_BYTES = 16 * 1024` are the single shared DTO limits. Schema generation, CLI stdin parsing, MCP, linked/IPC admission and store validation use them on UTF-8 bytes before any effect. Oversize messages/working state refuse `input-too-large`, never truncate. Preview budgets only affect explicitly labelled read output.

### 1.6 `se schema`

`SchemaCatalogue { schema: "se.schema-catalogue/v1", api: "1.0", build, ops: [OpSchema], families: [FamilySchema], errors: [ErrorSchema] }`. `OpSchema` = name, CLI path(s), MCP name or reason, auth, anonymous, human_only, effect, scope, runtime, feature, since, per-config-key human policy, input schema, output family. `ErrorSchema` = code, class, exit, detail schema. With `OP`, one `OpSchema` plus the families it references. Anonymous, discloses no state.

### 1.7 Compile-time mirror rules

Expanded as `const _: () = { ... };` blocks using `const fn` byte comparison:

* Every `CliExposure::None(r)` and `McpExposure::None(r)` has `r.0.len() >= 12` (a reason, not a placeholder).
* Every MCP name starts with `stateengine_`, matches `[a-z0-9_]+`, and is unique; every registry name is unique; no two leaves share a path unless their selectors differ.
* `auth == Owner` ⇒ `mcp` is `None` (MCP is session-bound).
* `anonymous` ⇒ name ∈ {`meta.version`, `meta.help`, `meta.schema`}.
* `human_only == Always` or `ConfigKey` ⇒ `auth == Owner` and `mcp` is `None`; config.set checks its closed key metadata before effects.
* Catalogue and MCP counts are derived from registry rows and feature/auth filtering. Changing the allowlist updates OPS.md and the source registry together; no separately maintained count assertion supplies authority.

### 1.8 Version boundaries

`se schema` and MCP schemas derive from the current DTOs. Every JSON family has its own explicit `schema` major; a breaking wire change changes that major. This first build has no schema-freeze tool, committed schema snapshots or N-1 encoders. The statically linked Rust API requires exact Cargo/API identity, not minor/range negotiation; section 10 indexes the exact declarations. The internal CLI/IPC framing identity is separate from that public Rust API and from each JSON family. Existing consumed adapter families remain explicit in §4.3.

---

## 2. CLI grammar

### 2.1 Global flags

| Flag | Type | Default | Notes |
| --- | --- | --- | --- |
| `-p, --project PROJECT` | name or `prj_` id | §2.2 | project-scoped ops only |
| `--home DIR` | path | `SE_HOME`, else platform state dir | product state home; never a project |
| `--json` | bool | false | current family JSON on stdout, diagnostics on stderr |
| `--key KEY` | 1–128 bytes | generated before send | mutating leaves only; reuse after an uncertain result (§1.5.1) |
| `-q, --quiet` | bool | false | suppresses human success text; errors still print |
| `--no-color` | bool | false | also `NO_COLOR` |
| `-h, --help` | bool | | generated help, loads no handler |
| `-V, --version` | bool | | `meta.version`; accepts only `--json` |

Removed root flags (`--registry-root`, `--project-root`, `--repo-root`, `--root`, `--actor`, `--agent-id`) refuse `usage-unknown-flag` with the replacement.

### 2.2 Project resolution (owner calls)

1. `-p/--project`. 2. `SE_PROJECT`. 3. Canonical cwd lookup: canonicalize cwd (Windows: `GetFinalPathNameByHandleW`, case-folded drive; Unix: `realpath`), find the closest registered root that is an ancestor-or-self; exact path-component prefix, never substring. 4. `default_project` from config. 5. The sole registered project. 6. Else `project-required` listing the registered projects (up to 20, then a count).

An unreadable registration at step 3 or two registrations at the same canonical root refuse (`source-unreadable`, `selector-ambiguous`) instead of falling through. Lookup never creates. With `SE_SESSION` set, authority is that session: project and agent come only from the capability, owner-only ops refuse `owner-required`, and the owner credential is never consulted.

### 2.3 Bare `se`

Runs `project.status` with the next-step renderer. No store or no project: onboarding text, exit 0:

```
StateEngine 0.1.0 — no project here yet.
  An agent (Claude Code or Codex) works in a project: a folder StateEngine tracks.
  Start: se init            (adopts this folder; your files and Git history stay as they are)
  Then:  se launch <name>   (opens your first agent)
```

Initialization remains an explicit owner operation. Plain `se init`, with no
`--adopt`, is managed setup: it writes no repository files, and agents launched
by StateEngine receive their integration wiring through launch flags.
`se init --repo DIR` creates
the per-user store, FULL-publishes/reads back its schema/header and completes
owner/project/agent setup before an achieved `se.init/v1` receipt. A retry
preserves valid state and completes missing setup. The low-level embedded
prepare/open/activate never creates state implicitly. At each workspace's first
open, SE Code's pre-TUI repository trust decision (profile_trust.rs, SC-SEC-01)
is the hook where, only after trust accepts the workspace, its UI
owner/human-presence path invokes the bundled
`se --home HOME init --repo DIR` located by stateengine_package.rs, then
re-prepares. A declined workspace is never registered and init is not invoked.
Profile onboarding remains once per profile. The public GitHub
stub has no se and silently skips init, without a missing-executable message.
Managed Rust `init --repo` writes nothing inside DIR: no repository files,
settings, hooks or Git changes; store/setup files live only in the per-user state
home outside DIR (40), so repository-write consent is unnecessary. `se init --adopt`
for user-started Claude/Codex sessions still writes the integration files in
70 §3.2 and reports them in `repo.files_touched` and `integrations[]`.
It cannot run from an agent tree or convert a BoundSession into owner
authority. Workspace init time is a separate cost outside B2.

Only failed workspace setup or another non-init route requiring initialized
state presents setup-required (Refused): subject “StateEngine store”, reason
“not initialized for the selected state home”, next step “Run se --home HOME
init --repo DIR”, with the actual resolved home and selected workspace in
structured argv. Preserve the original init failure; do not auto-retry or claim
success. Bare `se` and `se status` instead render their normal not-set-up state
and exit 0 without creating a store (T10/G4). The refusal creates no empty DB,
host endpoint or agent. Existing unreadable/foreign/newer files retain their
own diagnosis; init cannot overwrite them.

### 2.4 Argument vocabulary

| Token | Type and bounds |
| --- | --- |
| `AGENT` | `ag_…` id, or display name (case-insensitive), or imported alias; resolved before dispatch |
| `NAME` | 1–64 chars, `[A-Za-z0-9][A-Za-z0-9 ._-]*`, unique per project case-insensitively |
| `PROVIDER` | `claude` \| `codex` |
| `MODEL` | ≤128 bytes, passed to the provider and validated at launch |
| `BODY`, `TEXT`, `STATEMENT` | UTF-8; `-` reads stdin. Message body ≤32 KiB, task ≤16 KiB, working state ≤16 KiB, statement ≤8 KiB, reason ≤2 KiB |
| `KIND` | `note` (default) \| `task` \| `question` \| `answer` \| `blocker` \| `done` \| `handoff` \| `finding`. Import maps `task-pointer`→`task`, `ruling-request`→`question` |
| `KEY` | decision key `[a-z0-9][a-z0-9._-]{0,127}` |
| `ID` | typed opaque id (`msg_`, `dec_`, `ev_`, `ses_`); imported legacy ids accepted as-is |
| `CURSOR` | opaque, project- and principal-bound |
| `REV` | positive entity revision, or `absent` |
| `QUERY` | 1–512 bytes |
| Paging | `--limit N` (1–100, default 20; search 1–50), `--cursor CURSOR` on every list op |

One closed input type per operation is shared by CLI, MCP, IPC and linked calls;
CLI flag names may select/rename those fields but cannot define different limits
or defaults. General lists use limit 1–100, default 20; search 1–50, default 20;
message previews default 400 characters; resume defaults 4 KiB and caps at 1 MiB.
The host has one shared permit for resume requests with budgets above 32 KiB,
acquired before allocating the larger packet and held through serialization and
packet delivery/release, including cancellation. Admission uses the existing
request deadline/cancellation path; it never allocates a second large packet
while waiting. With section 80's four total packets, the largest encoded output
allocation is 1,048,576 + 3 × 32,768 = 1,146,880 bytes. Hostless synchronous CLI
assembly has only its invocation's packet and does not start a host to acquire a
permit. CLI, MCP and linked calls through a host share that host-wide permit.
The public session.turn DTO accepts at most 128 KiB decoded UTF-8 content within
the existing 1 MiB encoded frame cap. These are se-types constants SESSION_TURN_MAX_CONTENT_BYTES, SESSION_TURN_MAX_METADATA_BYTES and SESSION_TURN_MAX_FRAME_BYTES. Non-content fields, keys and framing occupy
at most 256 KiB; worst-case six-byte JSON escaping of content uses 768 KiB, so both
fit without enlarging transport buffers. CLI/MCP/IPC share these constants and
reject before effects. Trusted host capture from pinned provider sources streams
up to the store's 1 MiB canonical turn cap into staging instead of carrying raw
turn text through this public JSON operation; its source identity/cursor remains
mandatory. The in-process SE Code capture adapter uses that trusted capture seam.
Other strings/arrays retain their DTO bounds.

### 2.5 Commands

Human examples are abridged. `Family` is the `--json` schema family (§4).

**Discovery, setup, configuration**

| Op | Command line | Human output | Family |
| --- | --- | --- | --- |
| meta.version | `se --version` | `stateengine 0.1.0 (commit a1b2c3d)` | `se.version/v1` |
| meta.help | `se help [PATH...] [--all]`; `se PATH --help` | usage, args, examples | `se.help/v1` |
| meta.schema | `se schema [OP]` | op table; with OP its schemas | `se.schema-catalogue/v1` |
| project.init | `se init [--repo DIR] [--name NAME] [--agent NAME] [--provider PROVIDER] [--model MODEL] [--launch] [--adopt]` — `--repo` default cwd; `--name` default dir name; `--agent` default `main`; `--provider` default `[launch] provider` (`claude`); without `--adopt`, managed setup writes no repository files; `--adopt` installs unmanaged-session integrations | `Adopted ~/src/app as "app" (existing Git repo, 214 commits kept).`<br>`Agent "main" (claude) is ready. Next: se launch main`<br>`Profile default: workspace-write, approval on-request, network off, bypass false. Enable network: se config set profiles.default.network true`<br>Final line for plain init: To let Claude Code or Codex sessions you start yourself use StateEngine, run `se init --adopt` (writes .mcp.json, .claude/settings.local.json, .codex/config.toml).<br>`--adopt` output lists each file actually written. | `se.init/v1` (`profile.schema = stateengine-init/v1`) |
| project.remove | `se remove [-p P \| --all] [--keep-integrations]` (human-only) | `Stopped 2 agents (witnessed). Removed integrations: .mcp.json entry. Kept: history, repo files. Reinstall later with se init.` | `se.remove/v1` |
| project.status | `se status [-p P \| --all]`; bare `se` | `app — runtime up (daemon 0.1.0) · 2 agents: main running (claude), rev stopped · 3 unread for you · next: se msg inbox` | `se.status/v1` |
| doctor.inspect | `se doctor [-p P]` | `✓ store  ✓ credential  ✗ claude hooks: entry edited by you  ! containment: uncontained (no systemd user manager)` + `fix:` lines | `se.diagnosis/v1` |
| doctor.repair | `se doctor --fix CHECK-ID [-p P]` (human-only; prints plan first) | `Plan: integration repair; agents ended 0, credentials rotated 0, events lost 0. Applied 1 check. Re-read: ok.` | `se.repair/v1` |
| doctor.bundle | `se doctor --bundle [PATH]` (default `./se-support-<utc>.zip`) | `Wrote se-support-20261030T1201Z.zip (412 KB, 31 files, no turn or message text, no secrets). Nothing was uploaded.` | `se.support-bundle/v1` |
| config.get | `se config get KEY [--origin]` (`-p P` only for `agent.<A>.*`) | `launch.provider = codex  (config.toml)` | `se.config-value/v1` |
| config.set | `se config set KEY VALUE` (`-p P` only for `agent.<A>.*`) | `launch.provider: claude → codex (config.toml; read back)` | `se.config-receipt/v1` |
| config.list | `se config list [--origin]` | aligned `key = value  (origin)` | `se.config-page/v1` |

**Runtime, agents, continuity**

When an initialized home is already down, `se down` exits 0 with
`Already down; no host was running.` Its `se.runtime-stop/v1` reply sets
`already_down: true`, `complete: true` and `stops: []`; this proves an existing
state and claims no stop effect. The optional `already_down` field is omitted
for an actual shutdown. A missing endpoint with a held lease, unresolved native
custody or unreadable prior-host identity still refuses.

`se up --foreground` keeps the original CLI process as the host and drains it
through the normal shutdown path on Linux SIGINT, SIGTERM or SIGHUP, or Windows
Ctrl-C, Ctrl-Break or console-close events. A verified existing
host gives an already-running conflict with `se status` and `se down` guidance;
foreground mode never takes that host over.

| Op | Command line | Human output | Family |
| --- | --- | --- | --- |
| runtime.up | `se up [--foreground]` | `StateEngine running (daemon, pid 4120, generation 7, 127.0.0.1:24731).` | `se.runtime-start/v1` |
| runtime.down | `se down` | `Stopped main and the daemon (witnessed). Resume the conversation: se launch main` | `se.runtime-stop/v1` |
| mcp.serve | `se mcp [--stdio]` (stdio is the only transport; flag is explicit for clients) | none (JSON-RPC on stdout) | MCP protocol |
| mcp.token | `se mcp token` | `{"Authorization":"Bearer sels-…"}` | header map (Claude `headersHelper` protocol; no `schema` key) |
| agent.list | `se agent list [-p P]` | table: name, id, provider/model, state, conversation, `resume:` command | `se.agent-page/v1` |
| agent.create | `se agent add NAME [--provider PROVIDER] [--model MODEL] [-p P]` | `Added agent "rev" (codex, profile default). Start it: se launch rev` | `se.agent-receipt/v1` |
| agent.show | `se agent show AGENT [-p P]` | identity, profile, lifecycle, conversation, last capture | `se.agent-status/v1` |
| agent.rename | `se agent rename AGENT NAME [-p P]` | `rev → reviewer (ag_01J…; history kept)` | `se.agent-receipt/v1` |
| agent.launch | `se launch AGENT [--new] [--provider PROVIDER] [--model MODEL] [--task TEXT] [--detach] [-p P]` — creates the first conversation if none ever existed, otherwise resumes the saved conversation unless `--new`; window by default, `--detach` = headless | `Started main (claude), first conversation ready.` or `Resumed main (claude) in a new window — conversation 7f3a…, ready in 1.9 s. Stop: se stop main`; when not contained it prints the achieved process-group bound and actual reason. | `se.launch/v1` |
| agent.stop | `se stop AGENT [--release] \| --all [-p P]` — `--release` is owner-human only, single-agent only, after a stop that could not be proved (StopUnproved) | `Stopped main (exit witnessed). Resume: se launch main`; release prints possible remaining members and `Ownership released without an exit witness; processes may remain.` | `se.stop/v1` (`receipt = seat-stop/v1`) |
| agent.wake | `se wake AGENT [-p P]` | `Offered 2 unread messages to main (delivered to its session; not yet read).` | `se.wake/v1` |
| continuity.resume | `se resume [--since CURSOR] [--budget BYTES] [--preview AGENT]` (`--budget` 1024–1048576, default 4096, max 1048576; `--preview` owner only) | sections: who you are, working state, unread, required reads, omissions, next cursor | `se.resume/v1` |
| working_state.get | `se working-state [--agent AGENT]` | text + `revision 12` or `no working state yet` | `se.working-state/v1` |
| working_state.set | `se working-state set TEXT --expect REV [--agent AGENT]` | `Saved revision 13.` | `se.working-state-receipt/v1` |
| history.search | `se search QUERY [--kind turn\|message\|decision]... [--since TIME] [--until TIME] [--agent AGENT] [--limit N] [--cursor C]` | hits: time, kind, who, snippet, `history --event` id | `se.search-page/v1` |
| history.list | `se history [--agent AGENT] [--session ID] [--kind KIND]... [--since CURSOR] [--limit N] [--cursor C]` | chronological turns/messages/decisions; opaque continuation | `se.history-page/v1` |
| history.event_read | `se history --event ID` | the event and provenance, with an opaque read cursor | `se.event/v1` |

**Messages and decisions**

| Op | Command line | Human output | Family |
| --- | --- | --- | --- |
| message.send | `se msg send TO BODY [--kind KIND] [--ref ID]... [--reply-to ID] [--key IDEMPOTENCY]` — `TO` is `AGENT` or `owner` | `Sent msg_01J… to rev (committed; delivery pending).` | `se.message-receipt/v1` |
| message.inbox | `se msg inbox [AGENT] [--full] [--limit N] [--preview-chars N] [--cursor C]` | unread list with 400-character previews; footer `3 of 7 unread shown — se msg inbox --cursor …` (exit 2) | `se.message-page/v1` |
| message.list | `se msg list [--to AGENT] [--from AGENT] [--kind KIND] [--all] [--full] [--limit N] [--preview-chars N] [--cursor C]`. `--all` includes read and dismissed messages. `--full` prints complete bodies instead of previews, within the fixed page body budget of 256 KiB: a body is never cut, each page holds at least one row, and the rest comes through `--cursor`. Listing never creates or changes read or delivered markers; only `msg read`, `ack` and `dismiss` do. The owner may list any message in the project. Under a session, only messages the agent sent or received are listed. | table with disposition column; with `--full`, each message in full under a header line | `se.message-page/v1` |
| message.read | `se msg read ID` | full message; `marked read` | `se.message-read/v1` |
| message.ack | `se msg ack ID` | `Acknowledged msg_… (read).` | `se.disposition-receipt/v1` |
| message.dismiss | `se msg dismiss ID` | `Dismissed msg_… (not marked read; still in history).` | `se.disposition-receipt/v1` |
| decision.propose | `se decide KEY STATEMENT [--supersedes ID] [--key IDEMPOTENCY]` | `Proposed dec_… "api.versioning" — pending your approval: se decision ratify dec_…` | `se.decision-receipt/v1` |
| decision.list | `se decision list [--id ID] [--pending] [--history] [--limit N] [--cursor C]` | key, state, author, statement head | `se.decision-page/v1` |
| decision.show | `se decision show ID` | statement, author, state, transitions | `se.decision/v1` |
| decision.ratify | `se decision ratify ID [--expect REV]` (human-only) | `Ratified dec_… (governing).` | `se.decision-receipt/v1` |
| decision.reject | `se decision reject ID --reason TEXT [--expect REV]` (human-only) | `Rejected dec_…; proposal kept.` | `se.decision-receipt/v1` |
| decision.retract | `se decision retract ID --reason TEXT [--expect REV]` (human-only) | `Retracted dec_…; history kept.` | `se.decision-receipt/v1` |
| decision.supersede | `se decision supersede ID WITH_ID [--expect REV]` (human-only) | `dec_B now governs "api.versioning" (replaces dec_A).` | `se.decision-receipt/v1` |

`revision` is the entity's counter: creation is 1, and each committed change to
that entity adds one. The store compares that counter, never a global event
sequence. `--expect` defaults to the entity revision read at command start; the
CLI re-reads and shows the statement before a human-only change.

Only a caller-explicit `--expect` enters the retry fingerprint. The default read
is not intent. A matching request key returns its original receipt before any
default read, incarnation check or entity CAS; a changed explicit expectation
with the same key is `idempotency-key-reused`.

A never-launched agent needs no resume reference: plain launch creates its first
conversation. The same rule serves init `--launch`, `agent add` followed by
launch, and MCP launch. An existing-but-missing reference refuses with
`resume-reference-missing`; an unverifiable existing conversation refuses with
`resume-reference-unverifiable`. Neither silently creates a replacement.

**Integrations, owner recovery and optional Atlas**

| Op | Command line | Human output | Family |
| --- | --- | --- | --- |
| session.begin | `se session begin --agent AGENT --source claude\|codex\|secode --provider-session ID [--incognito]` (hidden; stdout must be a pipe) | none | `se.session-begin/v1` |
| session.context | `se session context [--budget BYTES] [--since CURSOR]` (hidden; capability from `SE_SESSION` or stdin line 1) | none | `secode.session-context-v1` |
| session.turn | `se session turn` (hidden; stdin one `se.turn/v1` object with at most 128 KiB decoded content in a 1 MiB frame) | none | `se.turn-receipt/v1` |
| session.end | `se session end [--session ID] --reason REASON --expect-generation N` (hidden) | none | `se.session-end/v1` |
| hook.claude | `se hook claude session-start\|prompt\|stop\|stop-failure` (hidden; native stdin) | Claude hook stdout protocol | Claude hook protocol |
| store.restore | `se restore` (human-only) | prints newest valid automatic backup, events lost, affected agents/credentials; preserves corrupt source and reports verified restore | `se.restore/v1` |
| credential.rotate | `se credential rotate` (human-only) | prints credentials revoked and affected agents; independently verifies new credential and revocations | `se.credential-rotation/v1` |
| installation.uninstall | `se uninstall` (human-only) | first ordinary graceful down with exact stop witnesses and saved resume references; prints achieved facts; then removes owned install/integrations and restores managed PATH entries | `se.uninstall/v1` |
| store.import_node | `se import --from-node PATH` | six user-state families: read/imported/duplicate/unreadable/dropped; originals untouched | `se.import/v1` |
| store.forget | `se forget --event ID [--event ID]...` (human-only; prints exact erase plan first) | erased bodies/projections, WAL/cache readback, no resurrection; named residual copies | `se.erasure/v1` |
| atlas.find | `se atlas find QUERY [--kind symbol\|text\|path] [--in PATH] [--limit N]` | `src/store/tx.rs:41 fn commit (symbol, resolved)` | `se.code-hits/v1` |
| atlas.refs | `se atlas refs SYMBOL [--path PATH] [--limit N] [--cursor C]` | sites with enclosing symbol and `resolved`/`name-only` | `se.code-refs/v1` |
| atlas.impact | `se atlas impact SYMBOL [--path PATH] [--depth 1..3]` (default 2) | dependents by hop, tests, omitted frontier | `se.impact/v1` |
| atlas.changes | `se atlas changes --since CURSOR\|COMMIT\|TIME [--limit N]` | added/removed/signature/body changes | `se.code-changes/v1` |
| atlas.outline | `se atlas outline PATH` | symbol tree with lines | `se.outline/v1` |

`identity.whoami` has no CLI (OPS.md); in an agent shell `se status` shows the bound principal.

---

## 3. MCP tool set

Session-bound: no tool takes an actor/authority override or project selector. External HTTP uses the authenticated bearer; stdio uses verified per-call session metadata. The statically linked SE Code caller uses its generation-bound in-process `BoundSession`, **not a minted credential or bearer**. Invalid/revoked authority refuses without owner fallback. `target_agent_id` is only a creator-control destination (§3.1), never the authenticated actor. Every tool's auth is session. Common failures include `session-required`, `capability-invalid`, `input-unknown-field`, `usage-invalid-value`, `input-too-large`, `store-unreadable`, `store-busy`, `internal`; keyed mutations also require their caller-retained identity (§1.5.1) and return commit-outcome-unknown when a commit/reply cannot be resolved. That tool error preserves the original identity for retry, not a success/read claim.

| Tool | Description (verbatim) | Input | Output | Extra errors |
| --- | --- | --- | --- | --- |
| `stateengine_whoami` | "Who you are in StateEngine: your project, agent identity, session and what you are allowed to do." | — | `Principal`: project{id,name}, agent{id,name}, session{id,source,generation}, grants[], binding | — |
| `stateengine_status` | "Your project at a glance: runtime, your agent's state, unread messages, pending decisions and the suggested next step." | — | `Status` (session view) | `runtime-incompatible` |
| `stateengine_resume` | "Restore your context after a restart or compaction: working state, unread mail, required reads and what was left out. Pass `since` from the last result to get only what changed." | `since?` cursor, `byte_budget?` int 1024–1048576 (4096) | `Resume`: principal, status ready/needs_read/integrity_blocked, working_state, unread[], required_reads[], omissions[], next_cursor, complete | `cursor-invalid`, `cursor-expired` |
| `stateengine_working_state_set` | "Replace your working-state note (what you are doing, what is next). Send the revision you last read as `expect`, or \"absent\" for the first write." | `text` ≤16 KiB, `expect` int\|"absent", `idempotency_key` 1–128 | `WorkingStateReceipt`: revision, committed\|replayed, current_revision; conflicts use se.error/v1 | `revision-conflict` |
| `stateengine_search` | "Search your project's history (turns, messages, decisions) you are allowed to see. Results are pointers; read an event with stateengine_event_read before relying on it." | `query` 1–512, `kinds?` [turn,message,decision], `since?`/`until?` RFC 3339, `limit?` 1–50 (20), `char_budget?` 500–32000 (8000), `cursor?` | `Page<SearchHit>`: event_id, kind, at, who, snippet; window | `cursor-invalid` |
| `stateengine_event_read` | "Read one committed event back from the store by id, with its provenance." | `event_id` | `Read<HistoryEvent>` | `target-unknown`, `source-unreadable` |
| `stateengine_msg_send` | "Send a message to another agent in your project, or to `owner` (the human). The result says it was committed; it does not mean it was read." | `to` (name/id/`owner`), `body` ≤32 KiB, `kind?` (note), `refs?` ≤20 ids, `reply_to?`, `idempotency_key` 1–128 | `MessageReceipt`: message_id, event_id, state committed\|deduplicated, delivery pending\|offered\|not-running | `target-unknown`, `idempotency-key-reused` |
| `stateengine_msg_list` | "List messages you sent or received. Default: unread messages addressed to you, oldest first, with body previews. Set `full` to get complete bodies; listing never marks anything read (use stateengine_msg_read for that). `complete` tells you whether anything was left out." | `view?` unread\|all (unread), `box?` inbox\|sent (inbox), `from?`, `kind?`, `full?` bool (false), `limit?` 1–100 (20), `preview_chars?` 0–4000 (400; not allowed with `full`), `cursor?` | `se.message-page/v1` (A.5): id, from, to, kind, at, disposition, `body.text`, `body.complete` (true for every row when `full`); a page holds at most 256 KiB of bodies, with the rest via `cursor` | `cursor-invalid`, `usage-conflicting-flags` (`full` with `preview_chars`) |
| `stateengine_msg_read` | "Read one message in full and mark it read." | `id` | `MessageRead`: message, body_complete, marker{state committed\|already, at} | `target-unknown`, `not-recipient` |
| `stateengine_msg_ack` | "Acknowledge a message you have handled. This records that you read it; it is not a reply." | `id` (restricted natural marker key) | `DispositionReceipt` | `target-unknown`, `not-recipient` |
| `stateengine_msg_dismiss` | "Dismiss a message without marking it read. It stays in history." | `id` (restricted natural marker key) | `DispositionReceipt` | `target-unknown`, `not-recipient` |
| `stateengine_decision_propose` | "Propose a project decision for the human to approve. You cannot approve it yourself. `supersedes` proposes replacing an existing decision." | `key`, `statement` ≤8 KiB, `rationale?` ≤8 KiB, `supersedes?`, `idempotency_key` 1–128 | `DecisionReceipt`: id, state pending | `usage-invalid-value`, `target-unknown`, `idempotency-key-reused` |
| `stateengine_decision_list` | "List project decisions. Pass `id` for one decision; `pending` for proposals awaiting approval; `history` to include retracted and superseded ones." | `id?`, `pending?` bool, `history?` bool, `limit?` 1–100 (20), `cursor?` | `Page<Decision>` | `cursor-invalid` |
| `stateengine_agent_create` | "Create a new agent identity in your project (requires the agent-create permission). This does not start it." | `name`, `provider` claude\|codex, `model?`, `profile?` (saved, non-bypass), `idempotency_key` 1–128 | `AgentReceipt`: agent{id,name}, created\|existing | `grant-required`, `state-conflict`, `usage-invalid-value`, `configuration-invalid`, `bypass-not-opted-in` |
| `stateengine_agent_status` | "Your agent's lifecycle, conversation, capture and resume facts." | — | `Read<AgentStatus>` | — |
| `stateengine_agent_launch` | "Start or resume your own agent, or a directly created agent while you hold agent-create permission. Creates the first conversation if none ever existed; otherwise resumes by default. new explicitly starts fresh." | `target_agent_id?` Id, `new?` bool, `model?`, `task?` ≤16 KiB, `detach?` bool (true), `idempotency_key` 1–128 | `LaunchResult` | `runtime-not-running`, `agent-already-running`, `launch-in-flight`, `resume-reference-missing`, `resume-reference-unverifiable`, provider errors |
| `stateengine_agent_stop` | "Stop your own agent, or a directly created agent while you hold agent-create permission. Returns the exact command that resumes this conversation." | `target_agent_id?` Id, `idempotency_key` 1–128 | `StopReceipt` | `runtime-not-running`, `stop-unwitnessed` |
| `stateengine_agent_wake` | "Offer pending mail to a running agent you directly created while you hold agent-create permission. Does not launch it or mark mail read." | `target_agent_id` Id, `idempotency_key` 1–128 | `WakeReceipt` | `grant-required`, `owner-required`, `wake-not-running` |
| `stateengine_session_turn` | "Record one conversation turn for this session (used by integrations, not for notes)." | `role` user\|assistant, `content` ≤128 KiB, `occurred_at`, `provider_session_id`, `turn_id` (stable provider/source identity before first send), `event_id?`, `source` claude\|codex\|secode | `TurnReceipt`: captured\|duplicate\|suppressed, event_id | `capture-consent-missing`, `usage-invalid-value`, `state-conflict` |
| `stateengine_atlas_find` | "Find code by symbol name, text or path in your project. Each hit says whether it was resolved or matched by name only." | `query`, `kind?` symbol\|text\|path (symbol), `in?` path prefix, `limit?` 1–50 (20) | `Page<CodeHit>` + index_state | `feature-unavailable`, `atlas-index-absent`, `atlas-unreadable` |
| `stateengine_atlas_refs` | "Who uses this symbol: imports, calls and type references." | `symbol`, `path?`, `limit?`, `cursor?` | `Page<Reference>` | + `atlas-symbol-unknown`, `atlas-symbol-ambiguous` |
| `stateengine_atlas_impact` | "What could break if this symbol changes: dependents up to 3 hops, with tests that reference them." | `symbol`, `path?`, `depth?` 1–3 (2), `budget?` | `Impact` | + `atlas-symbol-unknown`, `atlas-symbol-ambiguous` |
| `stateengine_atlas_changes` | "Code changes since you last looked (or since a cursor/commit/time)." | `since?`, `limit?`, `cursor?` | `Page<CodeChange>` | + `cursor-invalid` |
| `stateengine_atlas_outline` | "The symbol outline of one file." | `path` root-relative, `budget?` | `Read<Outline>` | + `atlas-path-outside-root`, `atlas-path-unknown`, `atlas-language-unsupported`, `atlas-file-over-budget` |

Framing: success is `structuredContent` (the family object) plus one text block (the human rendering). A domain error is `isError: true`, `structuredContent` = `se.error/v1`, text = the human error with its `fix:` line; a remedy that is a tool call carries `remedy.tool {name, arguments}`. Protocol errors stay JSON-RPC: unknown tool and malformed frames `-32602`/`-32600`, unknown method `-32601`, unsupported protocol revision `-32022`. Schema-invalid arguments are tool errors (`isError`), so the model can correct them.

### 3.1 Creator control

Authenticated A must currently hold `agent.<A>.can-create`, and the same-project target must have immutable `created_by == A`. Launch/stop omit `target_agent_id` for self; wake requires it. Owner CLI resolves the ordinary AGENT selector to the same target. Grandchildren, other creators' helpers, imported unknown creators and `--all` are owner-only. Grant revocation removes this authority; rename/profile changes do not change creator. Control grants no private read, inbox or continuity access to the target. The generated catalogue contains 24 tools when Atlas is built and enabled, 19 without Atlas; actual per-session exposure additionally follows grants.

---

## 4. Output contracts

### 4.1 Envelope rules

Every top-level product JSON result printed by `--json`, returned as MCP `structuredContent` or exported by `se schema` carries `"schema": "<family>/v<major>"` as its first key. `Read<T>` serializes as `{"state":"present","value":…}` \| `{"state":"absent","checked":"…"}` \| `{"state":"unreadable","source":"…","reason":"…"}` \| `{"state":"unknown","what":"…"}`. `Page<T>` serializes as `{"items":[…],"window":{"from":C,"to":C,"limit":n,"complete":bool,"omitted":{"count":n|null,"reason":"limit|budget|unreadable|source-incomplete"}},"next":C|null}`. Receipts carry `event_id`, `state` (`committed`/`replayed`/`refused`/`pending`) and any delivery fact separately. Unknown output fields must be ignored by consumers; stable fields never change meaning within a major.

### 4.2 Families

| Family | Op(s) | Stability | Key consumer |
| --- | --- | --- | --- |
| `se.version/v1` | meta.version | **stable** | SE Code installer, J1 runner |
| `se.help/v1`, `se.schema-catalogue/v1` | meta.help, meta.schema | **stable** | API consumers |
| `se.principal/v1` | identity.whoami | **stable** | agents |
| `se.init/v1` (+ `stateengine-init/v1` profile) | project.init | **stable** | SE Code first-workspace-open repository trust hook (managed no-write setup), J2 |
| `se.remove/v1` | project.remove | stable | J5 runner |
| `se.status/v1` | project.status | **stable** | SE Code, CLI |
| `se.diagnosis/v1`, `se.repair/v1`, `se.support-bundle/v1` | doctor.* | evolving | humans |
| `se.config-value/v1`, `se.config-receipt/v1`, `se.config-page/v1` | config.* | stable | |
| `se.runtime-start/v1`, `se.runtime-stop/v1` | up/down | stable | SE Code handover |
| `se.agent-page/v1`, `se.agent-receipt/v1`, `se.agent-status/v1` | agent.* | **stable** | SE Code, CLI |
| `se.launch/v1` | agent.launch | **stable** | SE Code, CLI |
| `se.stop/v1` (`receipt: "seat-stop/v1"`, `resume.command`) | agent.stop | **stable** | CLI, J3 |
| `se.wake/v1` | agent.wake | stable | |
| `se.resume/v1` | continuity.resume | **stable** | agents, CLI |
| `se.working-state/v1`, `se.working-state-receipt/v1` | working_state.* | stable | |
| `se.search-page/v1`, `se.history-page/v1`, `se.event/v1` | history.* | **stable** (`se.event`) | J3/J4 runner |
| `se.message-receipt/v1`, `se.message-page/v1`, `se.message-read/v1`, `se.disposition-receipt/v1` | message.* | **stable** | SE Code, CLI |
| `se.decision-receipt/v1`, `se.decision-page/v1`, `se.decision/v1` | decision.* | **stable** | CLI |
| `se.session-begin/v1`, `se.turn-receipt/v1`, `se.session-end/v1`, input `se.turn/v1` | session.* | **stable** | SE Code, hooks |
| `secode.session-context-v1` (`contract` key, `schema_version: 1`; fields per contracts.md O8) | session.context | **frozen** | SE Code |
| `se.restore/v1`, `se.import/v1`, `se.erasure/v1` | store.* | stable | |
| `se.credential-rotation/v1`, `se.uninstall/v1` | credential.rotate, installation.uninstall | stable | J5 |
| `se.code-hits/v1`, `se.code-refs/v1`, `se.impact/v1`, `se.code-changes/v1`, `se.outline/v1` | atlas.* | evolving until Atlas leaves alpha | agents |
| `se.error/v1` | every error | **stable** | everyone |
| protocols: Claude hook stdout, `headersHelper` header map, MCP JSON-RPC, `sec1`/`selp-`/`sels-` tokens | hook, mcp token, mcp | **stable** | Claude, Codex |

"Stable" identifies an actually consumed wire contract; consumers ignore unknown optional fields. A meaning/type/removal change requires a family major. Atlas families may evolve before release, with explicit majors rather than silent semantic changes.

### 4.3 Exact library API; current JSON families

The statically linked SE Code API requires exact version identity as declared in section 10, independently of JSON family versions. There is no range/minor negotiation or N-1 encoder. CLI `--json` and MCP serve the current family. `secode.session-context-v1` keeps its existing `contract`/`schema_version` framing and frozen fields; the versioned adapter adds `schema` around product JSON without replacing its consumed fields. A new context version is opt-in by its actual consumer. Native hook/header/MCP frames retain their provider-defined framing. Stored `seat-stop/v1` resume references and imported IDs remain readable migration inputs; they never execute retired command names.

---

## 5. Exit codes

| Exit | Meaning | Classes / payload states |
| --- | --- | --- |
| 0 | complete — including measured absence and zero | success; `Read::Present`, `Read::Absent`; complete `Page`; paged `Page` whose only omission reason is `limit`/`budget` |
| 1 | failed or refused | `Refused`, `Unauthorized`, `Conflict`, `Unavailable`, `Internal`, `Cancelled` |
| 2 | incomplete | `Incomplete`; `msg inbox` when not every unread message is in the window, any row is unreadable, or (`--full`) a body stays truncated; `Page` omissions for `unreadable`/`source-incomplete`; doctor with an unmeasured check and no failed one; stop/remove with an unwitnessed effect |
| 3 | unreadable | `Unreadable`; `Read::Unreadable` |
| 4 | unknown target or commit outcome | `Unknown`; `Read::Unknown`; transient `commit-outcome-unknown` retains original request identity |
| 64 | usage | `Usage` (also `renamed`, `command-retired`) |
| 75 | deferred Windows uninstall | the installed process has authorized its helper and must exit before image removal; achieved `se.uninstall/v1` facts are retained, post-exit effects remain pending, and no success is claimed |

Rules: `ExitStatus::exit(&self)` on each output computes the code from payload facts, so a nonzero exit always comes with the full payload on stdout. Doctor: 0 all healthy, 1 any check failed, 2 none failed but some unmeasured. Native `se hook claude` exits 0 (Claude treats exit 2 as blocking; a failed capture is a recorded fact and a stderr line). Explicit `se hook claude stop --json` is the receipt mode for an outside caller: it performs the same authenticated natural-identity capture, emits the complete `se.hook-result/v1` envelope with any measured diagnostics, and uses the ordinary payload/error exit policy. Native stop and stop-failure keep empty stdout; session-start keeps provider framing. Neither mode permits `--project` or `--key` to replace the bound session or natural identity. `se mcp` exits 0 on EOF and 1 on a transport failure. Human errors go to stderr; with `--json` the `se.error/v1` object goes to stdout and the human text still goes to stderr.

---

## 6. Error catalog

### 6.1 Shape

The exact declarations are [error.rs](../../crates/se-types/src/error.rs) and its [catalogue](../../crates/se-types/src/error/catalog.rs). `SeError` wraps a validated `ErrorBody`/typed `Detail`, retry policy and optional source cause; code/class/exit derive from that detail. `codes!` generates closed code/detail pairs, messages and remedy text. `CommandResolver` maps a failure to a typed registered operation or a manual action; arbitrary diagnostic text is never executed. Wire output is `se.error/v1` with code, class, exit, message, typed detail, remedy and retry. Every ordinary refusal stays on the error channel and creates no refusal-history row. Human form:

```
error[agent-unknown]: no agent named "revewr" in project app (did you mean "reviewer"?)
  fix: se agent list -p app
```

In the tables below, `{x}` interpolates a detail field; `→` gives the remedy command; class abbreviations: U Usage, R Refused, A Unauthorized, K Unknown, X Unreadable, C Conflict, I Incomplete, V Unavailable, N Internal, Z Cancelled.

### 6.2 Canonical catalogue

The table below mirrors `crates/se-types/src/error/catalog.rs`; typed detail fields are required. Like-class failures share codes; `reason` retains the exact cause and `next_step` retains the legal remedy. Neither is inferred from an empty read. Typed remedy resolution selects an admitted command; it never executes detail text. Merged names are not aliases or extra codes.

#### Usage (14)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| atlas-symbol-ambiguous | U | symbol: String, candidates: Vec<String> | `{symbol}` names {candidates.len} symbols | add `--path` |
| command-retired | U | old: String, reason: String, workflow: String | `{old}` was retired: {reason} | {workflow} |
| cursor-invalid | U | reason: String | this cursor isn't valid here ({reason}) | rerun without `--since` |
| input-too-large | U | field: String, limit_bytes: u64, got_bytes: u64 | {field} is {got_bytes} bytes; limit {limit_bytes} | shorten or split it |
| input-unknown-field | U | op: String, field: String, next_step: String | `{field}` is not accepted by {op} | {next_step} |
| project-conflicts-session | U | flag_project: String, session_project: String | `-p {flag_project}` conflicts with this session's project {session_project} | drop `-p` |
| project-required | U | choices: Vec<ProjectChoice> | which project? none registered here | Use `se init` (none) or `se … -p NAME` |
| renamed | U | old: String, replacement: String | `{old}` was renamed | Use `{replacement}` (template; fill placeholders) |
| selector-ambiguous | U | kind: String, selector: String, matches: Vec<String> | {selector} matches {matches.len} {kind} entries: {matches} | Select an exact ID from {matches} |
| usage-conflicting-flags | U | flags: Vec<String> | {flags} cannot be used together | pick one |
| usage-invalid-value | U | argument: String, got: String, expected: String | {argument}: `{got}` is not {expected} | correct the value |
| usage-missing-argument | U | command: String, argument: String | `{command}` needs {argument} | Use `se help {command}` |
| usage-unknown-command | U | got: String, suggestion: Option<String> | unknown command `{got}` | Use `se help` |
| usage-unknown-flag | U | flag: String, command: String, reason: String | `{command}` does not accept {flag}: {reason} | Use `se help {command}` |

#### Unauthorized (9)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| capability-invalid | A | subject: String, reason: String, next_step: String | Session credential {subject}: {reason} | {next_step} |
| grant-required | A | grant: String, agent: AgentId | Session for {agent} lacks permission {grant} | Owner: `se config set agent.{agent}.can-create true` |
| human-terminal-required | A | op: String, reason: String | `{op}` needs you at an interactive terminal not started by an agent: {reason} | Open your own terminal outside an agent tree; this mistake/drift guard is not proof against a determined agent using your account |
| listener-admission-refused | A | reason: String | local server refused the request: {reason} | reconnect through `se mcp token`; non-loopback access is not supported |
| message-scope-denied | A | filter: String, agent: AgentId | as an agent, {agent} can list only messages it sent or received; `{filter}` names others' mail | Drop the filter, or the owner runs `se msg list` from their own terminal. |
| not-recipient | A | message: MessageId, recipient: String | only {recipient} can mark {message} read or dismissed | read it with `se msg read` as that agent, or leave it |
| os-user-mismatch | A | expected: String, actual: String | this StateEngine home belongs to {expected}, you are {actual} | use your own `SE_HOME` |
| owner-required | A | op: String | `{op}` is an owner command; agent sessions can't run it | Use an owner terminal; unsetting SE_SESSION alone does not establish authority |
| session-required | A | op: String | `{op}` acts as an agent and needs a launched session | Use `se launch AGENT` |

#### Refused (36)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| api-version-unsupported | R | client: String, host: String | client API {client} vs runtime {host} | upgrade the older side |
| atlas-file-over-budget | R | path: String, size: u64, budget: u64 | {path} ({size}) exceeds the per-file parse budget | none; the file stays text-searchable |
| atlas-index-absent | R | project: ProjectId | no code index for {project} yet | Set `enabled = true` under `[atlas]` in the selected config.toml, then `se down` and `se up` with the same --home; `se status` reports progress |
| atlas-language-unsupported | R | path: String, language: Option<String> | {language} files aren't parsed | text search: `--kind text` |
| atlas-path-outside-root | R | path: String, root: String | {path} is outside {root} | use a project-relative path |
| backup-failed | R | path: String, step: String, reason: String | Backup {path} failed at {step}: {reason} | Run `se doctor`; automatic backup or restore must verify before proceeding |
| bypass-not-opted-in | R | profile: String | full bypass is only allowed through a saved, named profile | add `bypass = true` under `[profiles.NAME]`, then → `se config set agent.A.profile NAME` |
| capture-consent-missing | R | session: SessionId | capture is off for this session | relaunch without `--incognito` |
| configuration-invalid | R | subject: String, reason: String, next_step: String | Configuration {subject}: {reason} | {next_step} |
| decision-state-invalid | R | subject: String, reason: String, next_step: String | Decision transition {subject}: {reason} | {next_step} |
| feature-unavailable | R | subject: String, reason: String, next_step: String | Feature {subject}: {reason} | {next_step} |
| forget-not-captured-record | R | event: EventId, kind: String | only captured turns and messages can be erased; {event} is a {kind} | pick a captured record |
| home-unsupported-location | R | home: String, kind: String | {home} is on a {kind} location; the store needs a local disk | set `SE_HOME` to a local folder |
| import-format-unsupported | R | path: String, found: String, supported: Vec<String> | {path} is format {found}; supported: {supported} | upgrade Node StateEngine first, then import |
| import-source-active | R | path: String, pid: Option<u32> | the old StateEngine is still running on {path} | stop it with the old `se down`, then retry |
| integration-failed | R | subject: String, reason: String, next_step: String | Integration {subject}: {reason} | {next_step} |
| job-breakaway-refused | R | parent: String | Windows won't let the agent outlive {parent} | Launch from a terminal outside {parent}'s job, or have that job permit explicit JOB_OBJECT_LIMIT_BREAKAWAY_OK; `se up` inside the same strict job does not help |
| launch-failed | R | subject: String, reason: String, next_step: String | Launch {subject}: {reason} | {next_step} |
| listener-unavailable | R | subject: String, reason: String, next_step: String | Listener {subject}: {reason} | {next_step} |
| project-removed | R | project: ProjectId, at: UnixMicros | project {project} was removed at {at} | re-adopt: → `se init --repo {root}` |
| provider-change-breaks-resume | R | agent: AgentId, saved: String, requested: String | {agent}'s conversation is a {saved} conversation | Use `se launch {agent} --new --provider {requested}` |
| provider-cli-not-found | R | provider: String, searched: Vec<String> | can't find the {provider} CLI | install it (`Cmd::Manual`), or → `se config set providers.{provider}.command PATH` |
| provider-incompatible | R | subject: String, reason: String, next_step: String | Provider {subject}: {reason} | {next_step} |
| recipient-other-project | R | to: String, project: ProjectId | {to} is in project {project} | send from that project |
| repair-refused | R | subject: String, reason: String, next_step: String | Repair {subject}: {reason} | {next_step} |
| repo-invalid | R | subject: String, reason: String, next_step: String | Repository {subject}: {reason} | {next_step} |
| resume-reference-missing | R | agent: AgentId | {agent}'s previously saved conversation reference is missing | Use `se launch {agent} --new` |
| runtime-incompatible | R | subject: String, reason: String, next_step: String | Runtime {subject}: {reason} | {next_step} |
| secret-to-terminal-refused | R | what: String | refusing to print {what} to a terminal | run it through a pipe (integrations only) |
| session-already-ended | R | session: SessionId, at: UnixMicros | session {session} ended at {at} | Use `se launch AGENT` |
| setup-required | R | subject: String, reason: String, next_step: String | Setup {subject}: {reason} | {next_step} |
| store-migration-failed | R | from: u64, to: u64, step: String, rollback_copy: String | upgrade {from}→{to} failed at {step}; old copy kept at {rollback_copy} | Use `se doctor` |
| store-read-only | R | path: String | {path} is read-only | fix permissions or `SE_HOME` |
| store-too-new | R | store_version: u64, supported: u64 | the store was written by a newer se (schema {store_version}) | Upgrade se; unsupported migration paths refuse without modifying the source store |
| wake-not-running | R | agent: AgentId | {agent} isn't running, so there is nothing to wake | Use `se launch {agent}` |
| window-unavailable | R | tried: Vec<String> | no terminal window could be opened ({tried}) | Use `se launch AGENT --detach`, or set `launch.terminal` |

#### Unknown (5)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| agent-unknown | K | selector: String, suggestion: Option<String> | no agent `{selector}` in {project} | Use `se agent list` |
| atlas-path-unknown | K | path: String | {path} isn't indexed | Use `se atlas find PATH --kind path` |
| atlas-symbol-unknown | K | symbol: String | no symbol `{symbol}` | Use `se atlas find {symbol}` |
| commit-outcome-unknown | K | operation: String, key: Option<String>, natural_events: Vec<EventId> | Commit outcome unknown for {operation}; original key {key}, natural events {natural_events} | Rerun the same command with --key K (CLI), substituting the original detail.key, or repeat the call with the same idempotency_key (MCP); natural capture/markers replay the original natural_events unchanged |
| target-unknown | K | subject: String, reason: String, next_step: String | Unknown target {subject}: {reason} | {next_step} |

#### Unreadable (6)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| atlas-source-unreadable | X | path: String, reason: String | Atlas can't read {path}: {reason} | restore read access to the file |
| atlas-unreadable | X | path: String, reason: String | can't read the index database atlas.db: {reason} | Run `se doctor`; only a diagnosed atlas.index repair may rebuild atlas.db; source-file unreadability is separate |
| resume-reference-unverifiable | X | agent: AgentId, conversation: String, reason: String | can't verify conversation {conversation}: {reason} | Use `se launch {agent} --new` (starts fresh, explicitly) |
| source-unreadable | X | subject: String, reason: String, next_step: String | Cannot read {subject}: {reason} | {next_step} |
| store-corrupt | X | path: String, check: String | the store failed its integrity check ({check}) | Run `se restore` in your own terminal; it prints loss/stop consequences, restores newest valid automatic backup and preserves the corrupt source; no salvage |
| store-unreadable | X | path: String, reason: String | can't read the store: {reason} | Use `se doctor` |

#### Conflict (6)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| agent-already-running | C | agent: AgentId, pid: u32, since: String | {agent} is already running (since {since}) | message it, or → `se stop {agent}` |
| idempotency-key-reused | C | key: String, original_event: EventId | key `{key}` was used for a different request | use a new key |
| integration-conflict | C | path: String, entry: String | you changed {entry} in {path}; StateEngine won't overwrite it | keep it, or delete the entry and → `se doctor --fix CHECK-ID` |
| launch-in-flight | C | agent: AgentId, launch_id: LaunchId | {agent} is already being launched | retry |
| revision-conflict | C | entity: String, expected: String, current: String | {entity} changed (you had revision {expected}, now {current}) | reread: → `se working-state` / `se decision show ID` |
| state-conflict | C | subject: String, reason: String, next_step: String | State conflict {subject}: {reason} | {next_step} |

#### Incomplete (10)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| atlas-indexing | I | indexed: u64, total: u64 | index is {indexed}/{total} files; results may be partial | retry later |
| atlas-parse-failed | I | path: String, language: String, reason: String | Atlas couldn't parse {path} ({language}): {reason} | results for this file use bounded text search; → `se doctor --bundle` to report the diagnostic |
| cursor-expired | I | oldest_available: Cursor | the cursor is older than retained history | rerun without `--since` |
| forget-incomplete | I | erased: Vec<String>, residual: Vec<String> | erased in the store; copies remain in {residual} | delete or let backups expire; provider transcripts belong to Claude/Codex |
| import-incomplete | I | families: Vec<ImportFamilyIssue> | import finished with rejected rows | rerun (idempotent); see the receipt |
| launch-readiness-timeout | I | agent: AgentId, waited_ms: u64, last_observed: String | {agent} started but wasn't ready after {waited_ms} ms | Use `se agent show {agent}` |
| remove-incomplete | I | stopped: Vec<String>, unwitnessed: Vec<String>, remaining: Vec<String> | removal partly done: {remaining} | Use `se remove -p P` (idempotent) |
| runtime-start-pending | I | waited_ms: u64 | the runtime is still starting after {waited_ms} ms | Use `se status` |
| stop-unwitnessed | I | scope: String, reason: String, remaining: Vec<String> | Stop of {scope} is unconfirmed: {reason}; named remaining {remaining} | Read `se status` and retry the same keyed stop; for an uncontained group after a stop that could not be proved (StopUnproved only), owner-human `se stop AGENT --release` relinquishes ownership without signalling or proving exit |
| transcript-truncated | I | path: String, offset: u64, size: u64 | {path} shrank below the read offset | captured turns stay; → `se status` |

#### Unavailable (9)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| atlas-resource-budget | V | resource: String, requested: u64, available: u64 | Atlas can't index right now: {resource} needs {requested}, {available} available | wait for memory pressure to ease, or use bounded text search → `se atlas find QUERY --kind text` |
| deadline-exceeded | V | op: String, deadline_ms: u64 | `{op}` didn't finish in {deadline_ms} ms | retry |
| ipc-unavailable | V | endpoint: String, reason: String | can't reach the runtime: {reason} | Use `se status` |
| runtime-handover-in-progress | V | generation: String | the runtime is changing hosts | retry (`WhenRuntimeReady`) |
| runtime-not-running | V | op: String, reason: String | `{op}` needs a ready runtime writer: {reason} | Reopen the current runtime generation and retry with the original request identity; use `se up` if no runtime is running |
| runtime-start-failed | V | reason: String, log: String | the runtime didn't start: {reason} | see {log}; → `se doctor` |
| store-busy | V | waited_ms: u64, reason: String, next_step: String | Store unavailable after {waited_ms} ms: {reason} | {next_step}; retry the same request identity |
| store-disk-full | V | path: String, free_bytes: Option<u64> | not enough disk space at {path} | free space and retry |
| store-migration-required | V | from: u64, to: u64 | Store {from} needs supported additive migration to {to} | Start `se up`: the sole owning host verifies a pre-migration backup and migrates automatically; an old running host requires `se down` first |

#### Internal (1)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| internal | N | report_id: String, location: String | StateEngine hit a bug ({report_id}) | Use `se doctor --bundle` and send it |

#### Cancelled (1)

| Code | Cl | Typed detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| cancelled | Z | op: String | `{op}` was interrupted | rerun; writes are all-or-nothing |

Total: **97 codes**. Warnings remain stderr-only: `w-legacy-env-present`, `w-provider-near-minimum`, `w-store-near-full`, `w-notify-degraded`.

`commit-outcome-unknown` is Class::Unknown (exit 4) with a transient
`Retry::AfterReread` policy; no new class is introduced. Its key is the original
caller request key, or null only for the restricted natural-event path, whose
original event IDs are retained. CLI prints the concrete retry argv with the same
`--key`; MCP repeats `idempotency_key`; natural capture/markers replay exactly
the original source/marker identities. An unknown outcome is not a definite
rollback, rejection, committed receipt or permission to start replacement work.
The adapter preserves the source checkpoint for natural captures even when no
event ID is yet assigned; that protected source identity is repeated unchanged.

Internal `store-backpressure` maps to `store-busy` with exact pressure cause and
release/checkpoint remedy; `store-writer-closed` maps to `runtime-not-running`
with closed-before-acceptance cause and current-generation reopen remedy;
`source-changed` maps to `state-conflict` with the exact source incarnation/prefix
cause and new-source review remedy. They retain their typed internal diagnostics
and never become successful empty reads. Section 20 lists the complete map.

`stop-unwitnessed.detail.reason` includes the observed population, enumeration completeness and scope/escape bound; structured partial-stop results retain the separate A.6 fields. Named `remaining` is not a complete census unless that observation says so.
`store-disk-full.detail.free_bytes = null` means free space was not measured;
zero is reserved for an actual zero-space observation. The store is the producer
of SQLITE_FULL rollback errors (20), with commit-outcome-unknown kept distinct.


Default BestAvailable containment is never a refusal. Launch succeeds uncontained when Linux delegation is unavailable, with the exact cause. Before window-child creation the selected terminal/broker's common-ancestor entry permission is probed; denied or unproved entry selects uncontained with `containment_cause: "no-delegation"`, even if a headless scoped creator could launch contained. A later failure of an already selected contained launch retains its native error, never retries weaker. Stop reports its actual cgroup/job/process-group bound and enumeration; setsid/double-fork escapes outside an uncontained group are named. A short or empty named list never proves an empty scope.

---

## 7. Configuration

### 7.1 Environment (six, nothing else read)

| Var | Meaning |
| --- | --- |
| `SE_HOME` | state home. Default: Windows `%LOCALAPPDATA%\StateEngine`; Linux `$XDG_STATE_HOME/stateengine` (else `~/.local/state/stateengine`); macOS `~/Library/Application Support/StateEngine` |
| `SE_PROJECT` | owner project selection (step 2 of §2.2) |
| `SE_SESSION` | the one opaque session capability given to launched agents; scrubbed from children StateEngine spawns that are not the agent |
| `SE_LOG` | log filter (`error`…`trace`, or `module=level,…`) |
| `NO_COLOR` | any non-empty value disables color |
| `SE_CONFIG` | user config file path (default `$SE_HOME/config.toml`) |

`CLAUDE_CONFIG_DIR` and `CODEX_HOME` are read only to locate provider transcripts; provider API keys are passed through to the provider untouched and never read. Old `STATEENGINE_*` variables are not read. Their presence triggers `w-legacy-env-present` and a doctor finding.

### 7.2 `config.toml` (user scope)

```toml
version = 1                       # required; other values refuse configuration-invalid
default_project = ""              # name or id; "" = none

[runtime]
listen_port = 24731               # example only; init chooses per-user hash in 20000–29999

[launch]
provider = "claude"               # claude | codex — default for init/agent add
terminal = ""                     # Linux/macOS terminal command; "" = detect

[providers.claude]
command = "claude"                # name on PATH or absolute path
model = ""                        # "" = provider default
profile = "default"

[providers.codex]
command = "codex"
model = ""
profile = "default"

[profiles.default]                # built in; may be overridden but never set bypass
sandbox = "workspace-write"       # read-only | workspace-write
network = false                   # command network access; opt in with true
# approval = "on-request"         # optional explicit policy; defaults described below

# [profiles.NAME]                 # user-defined; the ONLY place bypass can appear
# bypass = true                   # full permission/sandbox bypass, chosen by name
# [profiles.git-workspace]        # explicit dedicated-clone authoring permission
# sandbox = "workspace-write"
# git_write = true                # also permit this workspace's physical .git

[atlas]
enabled = false                   # opt-in in this file; no project settings layer
```

The agent saves its profile name. One resolver derives the effective sandbox,
approval, network and bypass policy from that named profile before launch or
resume; provider adapters consume the resolved policy without replacing its
values. Omitted sandbox/network keys default to workspace-write/false. Omitted
approval defaults to never for headless Codex and on-request for attended Codex
and Claude; an explicit profile approval value takes precedence. A read-only
profile stays read-only. `git_write = true` is allowed only in a separately named
workspace-write profile without bypass. It grants the existing provider sandbox
write access to this workspace's physical `.git` directory; linked metadata,
Git worktrees and shared common directories refuse and require a dedicated clone.
It does not enable network access or authorize paths outside the workspace.
Supported approval values are on-request, untrusted
and never, subject to the installed provider's capability checks. For Codex,
never denies escalation and is legal without bypass; any provider setting
that disables permissions or sandboxing requires the saved named bypass opt-in.
Only `[profiles.NAME] bypass = true`, explicitly selected for the agent, permits
full access; network true is a separate explicit choice, not a bypass opt-in.
If the installed provider cannot honor the complete resolved policy, refuse
provider-incompatible before work rather than widening writes or network.

Init and launch print and return the effective named profile, sandbox, approval,
network and bypass values, rather than a fixed sample default. Init resolves for
its requested launch mode, or the next default launch when not launching; each
actual launch resolves again. Init also prints the exact network opt-in command
for that profile: `se config set profiles.NAME.network true`. Profile/security
writes retain §7.3's human-only check; enabling network never widens write access.

`runtime.listen_port` is persisted at init from a deterministic per-user hash in
20000–29999, probing candidates in that range if occupied and naming exhaustion
instead of selecting the old Node port. The explicit remedy for a later collision
is `se config set runtime.listen_port N`. Listen address is the fixed loopback
constant; it is not configurable. Hash inputs/owner identity stay private.

Autostart on custody demand, default handback on SE Code exit, launch readiness
60 s, list default 20/max 100, search max 50, preview default 400, resume default
4 KiB/max 1 MiB, two automatic backups, 4 MiB log rotation with three files, and
the Atlas parse budget are constants with one owning module. No config knobs
control those fixed policies. Existing per-call limit/budget flags remain bounded
by the shared input DTO. SE_LOG and CLI/no-color environment choices remain the
explicit diagnostic/render overrides, not another settings layer.

Unknown keys refuse (`input-unknown-field`) on load, naming the line. Dotted names (`launch.provider`) are the `KEY` used by `se config`.

### 7.3 One configuration file and durable agent metadata

General settings live only in the selected `config.toml`; no project settings layer or repository config participates. This includes `capture.enabled` (bool, default true) and the keys above. General file values have exactly one source; saved agent metadata is not a project settings layer. `se config get/list --origin` names the selected file, environment/flag override or built-in default. `config set` of a general key validates the one file value, then uses the shared file-custody adapter for atomic replacement, sync and independent reread. It is a hostless CLI file write and never starts a runtime. Its retries use the canonical file-state reconciliation rule in [40 §9.5](40-host-runtime-and-harnesses.md#95-owned-configuration-and-remove), with no receipt journal. No general key is written to a store event, config head or Snapshot.config, and a receipt never invents an event/writer. Manual file edits take effect on next read or restart. The result distinguishes saved file readback from pending host application. It never writes a project override. General settings reject `-p` as inapplicable. Each ConfigKeyMeta marks human_only: true for profiles/permissions, capture/privacy policy, listener/security keys and agent.<A>.can-create; those writes require the same outside-agent-tree owner terminal check as other human-only actions. Non-security keys do not gain a blanket human-only requirement.

`agent.<AGENT>.profile`, `.model` and `.can-create` are explicit durable **agent record** updates exposed through `config get/set`, not another configuration source. Only these selectors accept owner project resolution (`-p` when needed); they update/read the canonical agent row with its revision and commit receipt. `.can-create` defaults false, profile/model are the saved identity's values. Flag choices for an invocation do not silently change those saved values. Grants are checked against the current record, not a stale config snapshot. `config list` lists file settings; `agent show` reports saved agent fields.

### 7.4 Precedence and application

For general settings: CLI flag > documented environment variable > selected `config.toml` > built-in default. Configuration is never read from cwd, the repository or the binary folder. A saved named profile is the only bypass opt-in, explicitly selected for that agent; neither default configuration nor doctor repair selects bypass. Atlas is compiled only into the standalone `se`; it is enabled by default and can be disabled with `atlas.enabled = false` in config.toml; a host without an installed Atlas controller reports it unavailable. Edit the selected config.toml and restart with `se down` then `se up` using the same --home; `config get/set` changes saved agent settings only. Its cold index is a transient child capped below the section 80 budget, never work that blocks host readiness.

### 7.5 Renamed-command refusal table

Static data in `se/src/renamed.rs`, matched on the first one or two argv tokens before clap. Output: `renamed` (exit 64), the literal template, no handler, no data access, no argument forwarding.

| Old | Use instead |
| --- | --- |
| `agents` | `se agent list` |
| `projects` | `se status --all` |
| `decision` (bare), `decisions` | `se decision list` |
| `pending` | `se decision list --pending` |
| `agent-rename` | `se agent rename AGENT NAME` |
| `seat create` / `seat launch` / `seat stop` / `seat wake` | `se agent add NAME` / `se launch AGENT` / `se stop AGENT` / `se wake AGENT` |
| `launch` / `stop` / `wake` with no agent | `se up` / `se down` / `se wake AGENT` (target never guessed) |
| `ratify` | `se decision ratify ID` |
| `ratifyall`, `ratify all` | run `se decision ratify ID` once per decision (no bulk approval) |
| `reject` / `retract` / `reverse` | `se decision reject ID` / `se decision retract ID` / `se decision supersede ID WITH_ID` |
| `rawlog-search` | `se search QUERY` |
| `floor-event` | `se history --event ID` (exit codes: 0 present/absent, 3 unreadable, 4 unknown) |
| `capture-status`, `context`, `init --status` | `se status` |
| `working-state-show` | `se working-state` |
| `working-state-set`, `seat-continuity-write` | `se working-state set TEXT --expect REV` |
| `packet` | `se resume --preview AGENT` |
| `decommission`, `init --remove` | `se remove --project P` |
| `plugin`, `hook-install`, `hook-uninstall` | `se doctor --fix` (repair setup), `se status` (inspect), `se remove` (remove with the project) |
| `verify-chain` | `se doctor` (inspect only) |
| `rebuild-index` | retired; on projection disagreement use owner-human `se restore`; no alpha replay/repair command |
| `hook-emit`, `capture-turn`, `msg deliver\|retry-delivery\|recover-delivery\|handoff\|unread-ids\|wake-backlog\|turn-outcome\|index-build` | `se doctor --fix` (reconfigures the native hook/mail integration) |
| MCP `stateengine_identity_whoami`, `_project_status`, `_context_packet`, `_working_state_get`, `_rawlog_search`, `_memory_recall`, `_floor_event`, `_seat_launch`, `_seat_stop`, `_seat_launch_status`, `_atlas_query` | `stateengine_whoami`, `_status`, `_resume`, `_resume`, `_search`, `_search`, `_event_read`, `_agent_launch`, `_agent_stop`, `_agent_status`, `_atlas_find` (MCP error `renamed`, arguments must be corrected) |
| MCP `stateengine_agent_rename`, `stateengine_tools` | owner CLI `se agent rename AGENT NAME`; native tools/list and direct calls |

`command-retired` (exit 64) with reason and current workflow: `process start|inspect|stop|list`, `process-start`, `process-stop`, `stateengine_process_start`, `stateengine_process_stop` (use managed `launch`/`stop` for agents; arbitrary process service removed), `backup` (automatic backups remain; use `restore` for recovery), `agent-alias`/`agent alias`/`stateengine_agent_alias` (use stable ids or rename), `floor`, `floor-serve`, `projection-drain`, `drain-outbox`, `capture-receipts`, `file-write`, `project-owner-assign`, `human-bootstrap`, `state`, `run`, `serve`, `server`, `start`, `refresh`, `substrate-*`, `brick*`, `memory-*`/`memories`/`stateengine_memory_suggest` (memories import as decisions), `mail-tunnel`/`stateengine_mail_tunnel`, `deps`, `msg complete|reconcile|treat`, `seat cut|move|prompt`, `doctor contradictions`, and every factory command (campaigns, reviews, gates, landings, census, remote compute, routing). Any other unknown token is `usage-unknown-command` with a spelling suggestion from the live registry only.

---

## 8. Hazard plans, recovery and supported outcomes

Every hazardous action prints a concrete plan **before effects**: affected IDs/paths, agents ended, credentials revoked/rotated, events lost (zero when measured zero), retained copies and the legal recovery command. Unknown/unreadable consequences refuse rather than print zero. Store-backed keyed replays do not duplicate a commit; file-only retries use section 40’s current-state reconciliation rule. Human presence means a verified owner at a TTY outside an agent process tree, as specified in 70; it is a mistake/drift guard, **not proof against a determined agent using that OS account**. Help, refusals and human decision receipts state that bound. No typed-ID confirmation is used.

| Action | Human check / plan | Consequences and boundary |
| --- | --- | --- |
| `se stop AGENT --release` | owner + human-presence; exact single agent and possible remaining members | release contract and limits: A.6; native mechanics: 30; durable marker: 20 |
| `se remove` | owner + human-presence; exact projects, integrations, agent instances, credentials | stop/revoke only the owned scope; preserve repository files, Git and history; partial witness remains incomplete |
| `se forget --event ID` | owner + human-presence; exact captured-record revisions and copies | erase store/projections plus WAL/cache readback and no-resurrection checks; name backups/provider transcripts that cannot be erased; never implicit in remove/import |
| `se import --from-node PATH` | owner; print supported user families, source quiescence, conflicts and counts | original read-only; import identities, agents/profiles, messages/marks, decisions, working state, turns/conversation refs only; no fleet, credentials or live process ownership |
| supported startup migration | sole owning host; print from/to, verified pre-migration backup, affected runtime and zero planned loss | automatic additive migration; if an old host runs, refuse with `run se down first`; too-new/unsupported paths refuse; no approval token/manual migration command |
| `se restore` | owner + human-presence; newest independently verified valid automatic backup, exact stop/revocation and loss range | preserve corrupt source unchanged; restore history only by this named operation; no salvage or implicit doctor restore; unresolved loss counts are labelled unknown and require diagnosis |
| `se credential rotate` | owner + human-presence; exact credentials and agent sessions invalidated | replace/read back machine credential and durable revocations; end/revoke named affected sessions; never a configuration repair |
| `se doctor --fix CHECK-ID` | owner + human-presence; one currently diagnosed supported check, old/new owned config, side effects | no broad repair sweep, history restore, credential rotation or weakening permissions; changed user edits refuse; reread after the single repair |
| `se uninstall` | owner + human-presence; owned install/integrations, agents/credentials, exact managed PATH entries | first ordinary graceful down: exact owned-agent stop witnesses and saved resume references, then print achieved stop facts; only afterward remove owned installation/integrations and restore managed PATH; unresolved stops prevent removal, user work/history remains |

Automatic backups run at start-of-day and clean shutdown, plus the verified backup before migration. A backup failure is surfaced; it cannot silently license migration/restore. Projection disagreement returns store-corrupt with the owner-human `se restore` remedy; alpha has no index-repair or event-log replay command. Doctor marks that check `repairable: false`; `--fix` refuses with `repair-refused` and the same restore remedy. Restoration selects the newest **valid**, re-opened backup, preserves the corrupt source and reports the actual lost interval. There is no public manual-backup operation or event-log salvage in this build.

History search is a bounded streamed scan with a byte/time window and continuation, not FTS. Forget matches those actual stores and caches rather than promising removal of a nonexistent FTS index. NORMAL durability may lose several recent ordinary commits on power loss or OS crash, not an application crash; decision ratify/reject/retract/supersede are all FULL. Section 20 defines the complete FULL set and 80 measures its real mixed workload.

`se down` stops all owned agents and runtime on each OS and renders one A.6 StopResult per agent, including unknown population and its reason, plus original-conversation resume argv. It cannot report success then say agents remain running. Failed/unknown stop witnesses report incomplete facts. Default SE Code exit with live agents instead transfers to detached `se up`; that daemon exits ten minutes after its last live agent. Embedded idle process measurements apply when no agent is live. Embedded session binding uses an in-process handle and adds no credential-issued/activated commits. Explicit owner init (including the per-workspace managed repository-trust-hook invocation) pays the fresh-schema FULL cost; the normal prompt embedded first bind atomically commits runtime.owner and the witnessed first session under FULL before starting the writer. Expiry of section 40's FIRST_BIND_WINDOW (10 s from activate returning Prepared, absolute deadline rechecked on resume), or definite first-bind refusal within that window, uses owner-only FULL admission. Status then reports ready; a later first bind takes the ordinary session-activation path like a second bind without an expiry failure to SE Code, with its actual extra cost reported. E2's prompt case includes that joint commit, native binding and complete continuity response; its late path has independent added-startup and bind-request-to-first-visible-assistant-response checks, each p95 ≤100 ms with its own n and over-count; activation and any fallback-owner-COMMIT race are inside the latter, while window-expiry fallback during user idle is off both clocks and recorded separately (80). Setup absence is a named refusal, not a fast successful E2 sample.

Install/uninstall scripts and SE Code's installer invoke this same `se uninstall` operation rather than reimplementing it. It never kills an agent without the ordinary stop witness. File-only retries follow section 40’s readback-reconciliation rule, without a separate persistent journal; file readbacks never claim an event/writer.

The product is complete only after real Claude and Codex pass all five journeys on clean Windows, Linux and macOS in standalone and embedded compositions. Windows/Linux is intermediate; the borrowed-Mac qualification runs before alpha release, without delaying the build. Atlas is compiled only into the standalone `se`; it is enabled by default and can be disabled with `atlas.enabled = false` in config.toml; a host without an installed Atlas controller reports it unavailable. Atlas is built after journeys/handover and never blocks a milestone; forget and live handover remain before alpha. Numerical budgets live only in section 80, size/build order in 95.

---

## Appendix A — Output schemas (judged families)

Exact field paths for the families the journey runner judges. `$` is the payload root and `[]` means "every element". "Always: yes" means the key is in every payload of that family (its value can still be `null` where the type allows). Any other value in that column names the case in which the key appears. Families may gain optional fields under the §1.8 version rules, and a judge must ignore keys it does not know. Key order does not matter, except that `schema` is serialized first.

### A.0 Shared shapes (section 00 vocabulary)

| Shape | JSON | Notes |
| --- | --- | --- |
| Id | string | Section 10 owns the text form: kind prefix + UUIDv7, e.g. `ag_0192f3a1-7c2e-7b4d-9a10-3e5f6a7b8c9d`. Prefixes: `prj_` project, `hu_` human, `ag_` agent, `ses_` session, `lch_` launch, `msg_` message, `dec_` decision, `ev_` event, `cred_` credential. Imported legacy ids keep their text. |
| Time | string | RFC 3339 UTC with microseconds, e.g. `2026-10-30T12:01:07.123456Z`. Used for display only; the store orders events. |
| Cursor | string | Opaque. Bound to store incarnation, project/principal and query; never a decoded sequence number or entity revision. |
| Revision | positive int | Per-entity counter: 1 at creation, incremented once per committed change to that entity. |
| Ref | object | `{id: Id, name: string}`. A message party also carries `kind: "agent" \| "owner"`. |
| Cmd | two sibling keys | `command`: string, the full line quoted for the current platform's shell. `argv`: string[], the exact tokens, starting with `"se"`. A judge runs `argv` verbatim. Wherever a row below says "+ Cmd", both keys sit in that object. When there is no command, both are null. |
| `Read<T>` | `{"state":"present","value":T}` \| `{"state":"absent","checked":string}` \| `{"state":"unreadable","source":string,"reason":string}` \| `{"state":"unknown","what":string}` | `checked` names what was consulted to establish the absence. |
| `Window` | `{"from":Cursor\|null,"to":Cursor\|null,"limit":int,"complete":bool,"omitted":{"count":int\|null,"reason":string\|null}}` | `complete: true` implies `omitted.count == 0` and `omitted.reason == null`. `count: null` means the number left out is unknown. `reason` is one of `limit`, `budget`, `unreadable`, `source-incomplete`. |
| List consistency | family metadata | Every list result, including mail, includes `consistency: "live-keyset"` alongside its canonical Page/Window. This is an operation-family label, not another completeness type; A.5 owns mail semantics. |
| `Page<T>` | `{"items":[T],"window":Window,"next":Cursor\|null}` | `next` is non-null exactly when following it can return more. Continuation advances a stable key without snapshot membership; all list families are labelled `consistency: "live-keyset"`. Complete means complete for the measured range, not an immutable historical list. |
| Receipt state | string | `committed`: a new event was appended. `replayed`: section 00's "already done" (same idempotency key and same body, so no new event). `pending`: committed, but the follow-up is not confirmed yet. `refused`: appears only inside bulk results; when a whole call is refused, the output is an `se.error/v1` payload instead. |
| Writer | object | `{"mode":"host","host_generation":string}` \| `{"mode":"direct"}`. Records who committed the event the receipt refers to. `host`: the running host's writer committed it, and `host_generation` is the decimal text of that host's generation (the same number as `se.status/v1` `$.runtime.generation`, e.g. `"7"`). `direct`: the CLI committed it with no host running, and the key `host_generation` is absent. The value is stored on the event row at commit, so a `replayed` receipt reports the original commit's writer. Families that carry `$.writer` (always present): `se.message-receipt/v1`, `se.message-read/v1`, `se.disposition-receipt/v1`, `se.decision-receipt/v1`, `se.working-state-receipt/v1`, `se.turn-receipt/v1`, `se.agent-receipt/v1`. See §1.1, "Writer stamp". |
| Witness | object | `{"state":"witnessed"\|"unwitnessed"\|"not-applicable","method":string\|null,"observed_at":Time\|null,"detail":string\|null}`. A result is `witnessed` only after a re-read from outside the writer (00 G8). `method` is one of `job-empty` (Windows), `pidfd-exit+cgroup-empty` (Linux), `pidfd-exit+cgroup-removed` (Linux original pinned object removed plus root exit), `start-identity-exit+cgroup-empty` and `start-identity-exit+cgroup-removed` (Linux without pidfds, preserving the native identity-recheck bound), `pidfd-exit+pgid-empty` (Linux, `uncontained`), `start-identity-exit+pgid-empty` (Linux without pidfd support: exit confirmed by re-reading the recorded start identity as gone or changed, at the bound section 30 states), `kqueue-exit+pgid-empty` (macOS), `readback` (files and config), `registry-reread`. |
| ProcessId | object | `{"pid":int,"started_at":Time,"exe":string,"machine_id":string}`. `started_at` is the OS birth time (00 G6). A pid alone never identifies a process. |

When measured for a request, `$.diagnostics.write_timings` carries required
finite non-negative `queue_ms`, `transaction_ms` and `commit_call_ms`, and
`durability: "normal" | "full"`. `checkpoint_ms` is optional: it is included
only when the writer actually ran a checkpoint and measured that call. No
checkpoint means the key is omitted, never a substituted zero. These transient
measurements do not change the immutable original receipt or writer on replay.

A completed write may carry optional `$.maintenance_pending: true` when its
known successful commit still needs checkpoint maintenance. The original
committed/replayed receipt and writer remain intact; this transient obligation
is not `commit-outcome-unknown`. Absence makes no claim about maintenance.

Public Page/Window encoders omit internal `Window.snapshot`/`WindowFields`
accounting. Only opaque cursors cross the CLI, MCP, IPC and linked boundaries;
store sequence numbers are neither public ordering fields nor revisions.

### A.1 `se.init/v1` — `se init`

Success requires the selected state home to contain the read-back initialized
schema/header and achieved project/owner/agent facts. A schema-only or partially
configured attempt is not a completed init receipt; its retry preserves valid
published state and finishes the missing work. No new output fields are added.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.init/v1"` | yes | family |
| `$.outcome` | `"created"` \| `"adopted"` \| `"already-present"` | yes | `created`: registered a folder that had no files and no Git repo. `adopted`: registered a folder with existing files and/or Git history, which init leaves untouched. `already-present`: the registration already existed; `$.changed` lists any missing pieces init restored. |
| `$.project.id` | Id | yes | stable project id |
| `$.project.name` | string | yes | display name |
| `$.project.root` | string | yes | canonical repository root, the path cwd lookup matches |
| `$.project.registered_at` | Time | yes | first registration time; a retry does not change it |
| `$.repo.root` | string | yes | equal to `project.root` |
| `$.repo.git` | object \| null | yes | null when the folder is not a Git repository |
| `$.repo.git.head` | string \| null | if `git` non-null | commit sha at init time; null on an unborn branch. Init never changes it. |
| `$.repo.git.branch` | string \| null | if `git` non-null | current branch; null when HEAD is detached |
| `$.repo.files_touched` | int | yes | number of files StateEngine wrote inside the repo; 0 for a managed setup |
| `$.owner.human_id` | Id | yes | the owner's (human's) identity |
| `$.owner.os_user` | string | yes | the OS account the owner proof is tied to |
| `$.home` | string | yes | state home used (`SE_HOME` or the platform default) |
| `$.agent.id` | Id | yes | first agent's id |
| `$.agent.name` | string | yes | first agent's name (default `main`) |
| `$.agent.outcome` | `"created"` \| `"existing"` | yes | `existing` on a retry; init never creates a duplicate |
| `$.agent.provider` | `"claude"` \| `"codex"` | yes | saved provider |
| `$.agent.model` | string \| null | yes | null means the provider's default |
| `$.agent.permission_profile.name` | string | yes | saved profile name (`default`) |
| `$.agent.permission_profile.sandbox` | `"read-only"` \| `"workspace-write"` \| `"bypass"` | yes | effective sandbox |
| `$.agent.permission_profile.approval` | string | yes | effective approval policy |
| `$.agent.permission_profile.network` | bool | yes | effective command network access; false by default |
| `$.agent.permission_profile.bypass` | bool | yes | false unless a named bypass profile was chosen |
| `$.profile` | object | yes | compatibility block for `stateengine-init/v1` decoders |
| `$.profile.schema` | `"stateengine-init/v1"` | yes | |
| `$.profile.project` | Id | yes | equal to `project.id` |
| `$.profile.repo_root` | string | yes | equal to `project.root` |
| `$.profile.registry_root` | string | yes | equal to `home` |
| `$.profile.keys_dir` | string | yes | folder that holds the machine credential |
| `$.profile.human_id` | Id | yes | equal to `owner.human_id` |
| `$.profile.agent_id` | Id | yes | equal to `agent.id` |
| `$.profile.native_server_port` | int | yes | selected per-user loopback port; init hash in 20000–29999, persisted as runtime.listen_port |
| `$.integrations[]` | array | yes | edits StateEngine owns outside the store; empty for managed launches |
| `$.integrations[].path` | string | yes | file edited |
| `$.integrations[].entry` | string | yes | the marked key or block |
| `$.integrations[].action` | `"written"` \| `"unchanged"` \| `"conflict-kept"` | yes | `conflict-kept`: you had edited the entry, so init kept your version and did not write it |
| `$.integrations[].witness` | Witness | yes | method `readback` |
| `$.changed` | string[] | yes | what this call changed; empty on a retry that changed nothing |
| `$.next` | `{text}` + Cmd | yes | the next step, normally `se launch main` |
| `$.launch` | object \| null | yes | with `--launch`, the full `se.launch/v1` payload (carrying its own `schema`); otherwise null |

```json
{"schema":"se.init/v1","idempotency_key":"request-init-v1-example","outcome":"adopted",
 "project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app","root":"C:\\Users\\ana\\src\\app","registered_at":"2026-10-30T12:00:01.000001Z"},
 "repo":{"root":"C:\\Users\\ana\\src\\app","git":{"head":"4f1c2e9a0b7d","branch":"main"},"files_touched":0},
 "owner":{"human_id":"hu_0192f3a0-1111-7aaa-8bbb-000000000002","os_user":"DESKTOP-1\\ana"},
 "home":"C:\\Users\\ana\\AppData\\Local\\StateEngine",
 "agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main","outcome":"created","provider":"claude","model":null,
          "permission_profile":{"name":"default","sandbox":"workspace-write","approval":"on-request","network":false,"bypass":false}},
 "profile":{"schema":"stateengine-init/v1","project":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","repo_root":"C:\\Users\\ana\\src\\app",
            "registry_root":"C:\\Users\\ana\\AppData\\Local\\StateEngine","keys_dir":"C:\\Users\\ana\\AppData\\Local\\StateEngine\\keys",
            "human_id":"hu_0192f3a0-1111-7aaa-8bbb-000000000002","agent_id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","native_server_port":24731},
 "integrations":[],"changed":["project registered","agent main created","machine credential created"],
 "next":{"text":"Open your first agent","command":"se launch main","argv":["se","launch","main"]},
 "launch":null}
```

For a default headless Codex launch, the effective permission profile instead
contains `"approval":"never","network":false,"bypass":false`: escalation is
denied, not bypassed. The Claude example above keeps its on-request policy.

### A.2 `AgentRow` and `se.agent-page/v1` — `se agent list`

`se.agent-page/v1` is `{schema, project: Ref}` plus the `Page<AgentRow>` keys `$.items[]`, `$.window` and `$.next`. `se.status/v1` reuses the same `AgentRow` in `$.agents.items[]`. In the table, "row" stands for `$.items[]`.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.agent-page/v1"` | yes | |
| `$.project` | Ref | yes | the project being listed |
| row`.id` | Id | yes | stable agent id |
| row`.name` | string | yes | display name |
| row`.role` | string \| null | yes | free-text label (imported or set); grants no authority |
| row`.provider` | `"claude"` \| `"codex"` | yes | saved provider |
| row`.model` | string \| null | yes | saved model; null means the provider's default |
| row`.profile` | string | yes | permission profile name |
| row`.session.state` | `"never-launched"` \| `"starting"` \| `"running"` \| `"stopping"` \| `"stopped"` \| `"lost"` \| `"unknown"` | yes | `lost`: recorded as running but not found on re-read. `unknown`: the process identity was unreadable. |
| row`.session.recorded_state` | `"prepared"` \| `"activated"` \| `"ended"` \| `"revoked"` \| null | yes | the immutable session projection; activation alone is not a fresh liveness observation |
| row`.session.process_state` | `Read<string>` | yes | the matching lifecycle projection, including `stop-unproved`; absent, unreadable and unknown remain distinct. An unrelated newer session's process is never substituted. |
| row`.session.liveness` | `Read<string>` | yes | fresh outside native observation (`live` or `exited`), or a named absent/unreadable/unknown result. A recorded PID or exited index alone is not a new native witness. |
| row`.session.session_id` | Id \| null | yes | current or most recent session |
| row`.session.launch_id` | Id \| null | yes | current or most recent launch |
| row`.session.surface` | `"window"` \| `"headless"` \| `"secode"` \| `"attended"` \| null | yes | how the agent runs or last ran |
| row`.session.process` | ProcessId \| null | yes | non-null while starting, running or stopping |
| row`.session.since` | Time \| null | yes | when the current state began |
| row`.session.observed_at` | Time \| null | yes | last observation of the process from outside |
| row`.session.containment` | `"cgroup"` \| `"job"` \| `"process-group"` \| `"uncontained"` \| null | yes | how the current or most recent launch is held. `cgroup`: Linux delegated cgroup v2 scope. `job`: Windows job. `process-group`: macOS tracked process group. `uncontained`: Linux with no systemd user manager or delegation; the agent runs in its own process group, launch still succeeds, and stop reaches only that group (70 §2.4). null when never launched. |
| row`.session.containment_cause` | string \| null | yes | the probe cause when `containment` is `uncontained`, otherwise null. One of `no-user-manager`, `no-delegation`, `cgroup-v2-absent`, `cgroup-unreadable`, `scope-create-failed`; the probe's full text is in the `custody.linux-cgroup` doctor check (A.10). Never null when uncontained. |
| row`.conversation.id` | string \| null | yes | the provider's conversation/thread id |
| row`.conversation.state` | `"saved"` \| `"none"` \| `"unverifiable"` | yes | whether a default launch can resume it |
| row`.resume.ready` | bool | yes | true exactly when `se launch NAME` will resume `conversation.id` |
| row`.resume.mode` | `"resume"` \| `"new"` \| `"running"` | yes | what the command does. `running`: the agent is already running, and the command is null. |
| row`.resume.reason` | string \| null | yes | why it is not ready |
| row`.resume` + Cmd | | yes | e.g. `se launch main` or `se launch main --new`; null while running |
| row`.unread` | int | yes | unread messages addressed to this agent |
| row`.last_activity_at` | Time \| null | yes | last captured turn or message |

```json
{"schema":"se.agent-page/v1","project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},
 "items":[{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main","role":null,"provider":"claude","model":null,"profile":"default",
   "session":{"state":"stopped","session_id":"ses_0192f3a2-0000-7000-8000-00000000000a","launch_id":"lch_0192f3a2-0000-7000-8000-00000000000b",
              "surface":"window","process":null,"since":"2026-10-30T12:20:00.000000Z","observed_at":"2026-10-30T12:20:00.004100Z",
              "containment":"job","containment_cause":null},
   "conversation":{"id":"7f3a9c1e-55b0-4d0a-9e61-2c1d0b9a8f77","state":"saved"},
   "resume":{"ready":true,"mode":"resume","reason":null,"command":"se launch main","argv":["se","launch","main"]},
   "unread":0,"last_activity_at":"2026-10-30T12:19:41.000000Z"}],
 "consistency":"live-keyset","window":{"from":null,"to":"c1.Zm9v","limit":20,"complete":true,"omitted":{"count":0,"reason":null}},"next":null}
```

`se.launch/v1` carries the same pair for the agent it launched, at `$.containment` and `$.containment_cause`, with the same values and the same rule: launch never refuses for containment, and an `uncontained` launch always names its cause. On Linux every LinuxUserManager agent-process launch, warm included, requests its own fresh delegated scope over direct user-manager D-Bus StartTransientUnit with a short-lived native creator; no shared first-launch scope or resident authority is reused. The creator waits for the correlated JobRemoved success and actual scope placement, then starts the authorized root and hands custody to the unchanged host. Scope acquisition has section 80's separate p95 ≤200 ms target; other launch paths keep ≤50 ms, with provider startup reported separately. Absent delegation or an unusable pre-probed terminal/broker origin selects an explicitly uncontained default with its actual cause before child creation.

`se.launch/v1` also requires `$.permission_profile` with the same five fields
and types as init's `$.agent.permission_profile`: name, sandbox, approval,
network and bypass. These are the actual resolved values used for this launch,
including read-only and named-profile choices. Human launch output prints them;
Codex approval never with bypass false is an ordinary sandboxed policy.

### A.3 `se.status/v1` — `se status`, bare `se`, `stateengine_status`

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.status/v1"` | yes | |
| `$.scope` | `"project"` \| `"all"` \| `"session"` \| `"none"` | yes | `none`: no project is selected or registered |
| `$.generated_at` | Time | yes | |
| `$.version` | string | yes | version of the se that produced the payload |
| `$.setup.state` | `"configured"` \| `"not-set-up"` \| `"unreadable"` | yes | `not-set-up`: no store in the home (a measured absence) |
| `$.setup.home` | string | yes | the home that was checked |
| `$.setup.reason` | string \| null | yes | set when `unreadable` |
| `$.runtime.state` | `"running"` \| `"starting"` \| `"draining"` \| `"stopped"` \| `"unknown"` | yes | from `runtime.lock`, the endpoint file and a re-read from outside |
| `$.runtime.host` | `"daemon"` \| `"secode"` \| null | yes | who owns the runtime |
| `$.runtime.process` | ProcessId \| null | yes | host process identity (pid + birth) while running, starting or draining |
| `$.runtime.detachment` | `"session-only"` \| `"windows-breakaway"` \| `"user-manager-unit"` | only when natively measured | Actual startup/recovery detachment, omitted when unobserved. For `session-only`, plain status says "Host: runs as a session process and stops when this login session ends". This does not claim a background service. |
| `$.runtime.generation` | int \| null | yes | current generation |
| `$.runtime.endpoint` | string \| null | yes | `127.0.0.1:PORT` |
| `$.runtime.version` | string \| null | yes | the host's se version |
| `$.runtime.observed_at` | Time \| null | yes | last observation from outside |
| `$.runtime.resources` | object | when a host answered and native counters are available | Host self-accounting (coordinator decision, 2026-10-30). `$.runtime` is this family's host block, so this is the requested `host.resources`. The values are kernel-sourced counters that the host reads about itself at `sampled_at`; they are never estimates. A failed resource observation leaves this key absent and names the reason in `resources_unavailable`, while the rest of status remains available. A file-only CLI reader cannot sample the host's own counters. Absence never means zero or proves no host is running. The journey runner measures StateEngine's own idle cost as the difference of two samples 60 s apart. |
| `$.runtime.resources_unavailable` | string | when hosted native self-accounting is unavailable | Names the failed observation or unsupported platform; absent when a sample succeeded or no host answered. |
| `$.runtime.resources.self_voluntary_switches` | int \| null | with `resources` | cumulative since host start when the OS supplies the split. Linux/macOS: `ru_nvcsw` from `getrusage(RUSAGE_SELF)`, which counts the host's own threads, exited ones included, and excludes child processes such as agents. Windows: null, because the OS does not separate voluntary and involuntary switches. An unavailable counter is never zero. |
| `$.runtime.resources.self_involuntary_switches` | int \| null | with `resources` | Linux/macOS: `ru_nivcsw` from the same call. Windows: null, because the OS does not separate it; this is an unavailable fact, not zero. |
| `$.runtime.resources.cpu_user_us` | int | with `resources` | cumulative user CPU in microseconds. Linux/macOS: `ru_utime`. Windows: `GetProcessTimes` user time. Children are excluded on every OS. |
| `$.runtime.resources.cpu_system_us` | int | with `resources` | cumulative kernel CPU in microseconds. Linux/macOS: `ru_stime`. Windows: `GetProcessTimes` kernel time. |
| `$.runtime.resources.rss_bytes` | int | with `resources` | current resident set at `sampled_at`, not the peak. Linux: `/proc/self/statm` resident pages × page size. macOS: `task_info(MACH_TASK_BASIC_INFO).resident_size`. Windows: `GetProcessMemoryInfo` `WorkingSetSize`. |
| `$.runtime.resources.sampled_at` | Time | with `resources` | when the host read the counters |
| `$.runtime.resources.method` | string | with `resources` | the OS source, one of `linux:getrusage(RUSAGE_SELF)+/proc/self/statm`, `macos:getrusage(RUSAGE_SELF)+task_info`, `windows:GetProcessTimes+thread-context-switches+GetProcessMemoryInfo` |

These counters cover the host process. When `$.runtime.host` is `daemon`, that process is StateEngine alone. When it is `secode`, the host is SE Code's server process, so the counters include SE Code's own work. A runner that needs StateEngine-only idle cost measures the standalone daemon, or diffs SE Code with and without the feature.
| `$.project` | `Read<ProjectView>` | yes | `absent` after removal or when no project is selected (see A.9) |
| `$.project.value.id`, `.name`, `.root`, `.registered_at` | Id, string, string, Time | when present | |
| `$.removal` | object \| null | yes | set when the selected registration was removed: `{project: Ref, root, removed_at, event_id}` |
| `$.principal` | object \| null | yes | session scope only: `{project: Ref, agent: Ref, session_id}` |
| `$.agents` | `Page<AgentRow>` \| null | yes | project and session scope; in session scope it lists only the caller |
| `$.inbox.owner_unread` | int \| null | yes | unread messages to the owner; null in session scope |
| `$.inbox.self_unread` | int \| null | yes | session scope: the caller's own unread count |
| `$.decisions.pending` | int \| null | yes | proposals waiting for the owner |
| `$.capture.state` | `"on"` \| `"off"` \| `"degraded"` \| `"unknown"` | yes | turn capture for the project |
| `$.capture.last_turn_at` | Time \| null | yes | |
| `$.atlas.state` | `"not-built"` \| `"disabled"` \| `"absent"` \| `"updating"` \| `"ready"` \| `"unreadable"` | yes | |
| `$.pending[]` | `{what, since, detail}` | yes | facts not yet confirmed (adoption in progress, undelivered notifications, stops without a witness) |
| `$.projects` | `Page<{id, name, root, agents_running: int, owner_unread: int}>` \| null | yes | set only with `--all` |
| `$.next` | `{text}` + Cmd | yes | suggested next step |

```json
{"schema":"se.status/v1","scope":"project","generated_at":"2026-10-30T12:05:00.000000Z","version":"0.1.0",
 "setup":{"state":"configured","home":"/home/ana/.local/state/stateengine","reason":null},
 "runtime":{"state":"running","host":"daemon","process":{"pid":4120,"started_at":"2026-10-30T12:02:11.250000Z","exe":"/home/ana/.local/bin/se","machine_id":"m-6a1f"},
            "generation":7,"endpoint":"127.0.0.1:24731","version":"0.1.0","observed_at":"2026-10-30T12:05:00.000000Z",
            "resources":{"self_voluntary_switches":1843,"self_involuntary_switches":12,"cpu_user_us":412000,"cpu_system_us":198000,
                         "rss_bytes":9437184,"sampled_at":"2026-10-30T12:05:00.000000Z","method":"linux:getrusage(RUSAGE_SELF)+/proc/self/statm"}},
 "project":{"state":"present","value":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app","root":"/home/ana/src/app","registered_at":"2026-10-30T12:00:01.000001Z"}},
 "removal":null,"principal":null,
 "agents":{"items":[{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main","role":null,"provider":"claude","model":null,"profile":"default",
   "session":{"state":"running","session_id":"ses_0192f3a2-0000-7000-8000-00000000000a","launch_id":"lch_0192f3a2-0000-7000-8000-00000000000b","surface":"headless",
              "process":{"pid":4188,"started_at":"2026-10-30T12:02:15.010000Z","exe":"/usr/local/bin/claude","machine_id":"m-6a1f"},
              "since":"2026-10-30T12:02:16.000000Z","observed_at":"2026-10-30T12:05:00.000000Z",
              "containment":"uncontained","containment_cause":"no-user-manager"},
   "conversation":{"id":"7f3a9c1e-55b0-4d0a-9e61-2c1d0b9a8f77","state":"saved"},
   "resume":{"ready":true,"mode":"running","reason":null,"command":null,"argv":null},"unread":0,"last_activity_at":"2026-10-30T12:04:51.000000Z"}],
   "consistency":"live-keyset","window":{"from":null,"to":"c1.YQ","limit":20,"complete":true,"omitted":{"count":0,"reason":null}},"next":null},
 "inbox":{"owner_unread":1,"self_unread":null},"decisions":{"pending":0},
 "capture":{"state":"on","last_turn_at":"2026-10-30T12:04:51.000000Z"},"atlas":{"state":"disabled"},
 "pending":[],"projects":null,
 "next":{"text":"You have 1 unread message","command":"se msg inbox","argv":["se","msg","inbox"]}}
```

### A.4 `se.message-receipt/v1` — `se msg send`, `stateengine_msg_send`

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.message-receipt/v1"` | yes | |
| `$.state` | `"committed"` \| `"replayed"` | yes | `replayed`: same idempotency key and same body, so no new event |
| `$.message_id` | Id | yes | |
| `$.event_id` | Id | yes | the append event; read it back with `se history --event` |
| `$.recorded_at` | Time | yes | commit time |
| `$.project` | Ref | yes | |
| `$.from` | Ref + kind | yes | the sender, taken from the caller's authority, never from input |
| `$.to` | Ref + kind | yes | the resolved recipient (`kind: "owner"` when sent to `owner`) |
| `$.kind` | message kind | yes | |
| `$.reply_to` | Id \| null | yes | |
| `$.refs` | Id[] | yes | |
| `$.idempotency_key` | string | yes | created before first send; replay retains the same key |
| `$.body.bytes` | int | yes | body size; the receipt does not echo the body |
| `$.body.sha256` | string | yes | hex digest of the stored body |
| `$.delivery.state` | `"pending"` \| `"offered"` \| `"not-running"` \| `"not-applicable"` | yes | provider notification delivery observed at send time; `not-applicable` for messages to `owner`. This immutable receipt is not recipient read or task completion. |
| `$.delivery.at` | Time \| null | yes | when it was offered |
| `$.writer.mode` | `"host"` \| `"direct"` | yes | who committed the message event (A.0 Writer) |
| `$.writer.host_generation` | string | when mode is `host` | generation of the host that committed it |

```json
{"schema":"se.message-receipt/v1","state":"committed","message_id":"msg_0192f3b0-0000-7000-8000-000000000101",
 "event_id":"ev_0192f3b0-0000-7000-8000-000000000102","recorded_at":"2026-10-30T12:06:00.120000Z",
 "project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},
 "from":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
 "to":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},
 "kind":"handoff","reply_to":null,"refs":[],"idempotency_key":"request-0192f3a8-0000-7000-8000-000000000049",
 "body":{"bytes":212,"sha256":"9b1e5a0c…"},"delivery":{"state":"pending","at":null},
 "writer":{"mode":"host","host_generation":"7"}}
```

### A.5 `se.message-page/v1` — `se msg inbox`, `se msg list`, `stateengine_msg_list`

`{schema, consistency, view, unread_total}` plus the `Page<MessageRow>` keys.

Mail is a live keyset in immutable sent order: each page reads current membership,
delivery/disposition and unread counts, and continuation advances the last sent
key. Concurrent arrivals or marker/supersession changes may alter later pages;
unchanged data concatenates without gaps. No first-page high-water pins later
membership or disposition as-of that earlier read. The Page/Window shape is
unchanged; [20 — bounded reads](20-data-model.md) owns the indexed reader/cursor.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.message-page/v1"` | yes | |
| `$.consistency` | `"live-keyset"` | yes | current-state keyset; no historical inbox snapshot |
| `$.view.op` | `"inbox"` \| `"list"` | yes | which operation produced it |
| `$.view.recipient` | Ref + kind \| null | yes | whose inbox (the caller, or an agent the owner is inspecting); null for an owner list with no recipient filter |
| `$.view.disposition` | `"unread"` \| `"all"` | yes | an inbox is always `unread` |
| `$.view.box` | `"inbox"` \| `"sent"` \| `"any"` | yes | |
| `$.view.filter` | `{to: Ref\|null, from: Ref\|null, kind: kind\|null}` | yes | filters applied |
| `$.view.inspection` | bool | yes | true when the owner reads an agent's inbox. Such reads never mark anything read. |
| `$.view.full` | bool | yes | true for `msg list --full` / `full: true` (and `msg inbox --full`): every readable row has `body.complete: true` |
| `$.view.scope` | `"project"` \| `"own"` | yes | `project`: the owner sees every message in the project. `own`: a session sees only messages it sent or received. |
| `$.unread_total` | int \| null | yes | unread messages matching the view, counted regardless of the window; null when a source was unreadable |
| `$.items[].id` | Id | yes | message id |
| `$.items[].event_id` | Id | yes | append event |
| `$.items[].from`, `.to` | Ref + kind | yes | |
| `$.items[].kind` | message kind | yes | |
| `$.items[].sent_at` | Time | yes | time it was recorded |
| `$.items[].reply_to` | Id \| null | yes | |
| `$.items[].refs` | Id[] | yes | |
| `$.items[].body.text` | string | yes | the full body when `complete`; otherwise a preview cut at a UTF-8 boundary |
| `$.items[].body.complete` | bool | yes | |
| `$.items[].body.bytes` | int | yes | size of the full body |
| `$.items[].body` + Cmd | | yes | body reference: `se msg read ID` when `complete` is false; null otherwise |
| `$.items[].delivery.state` | `"pending"` \| `"offered"` \| `"delivered"` \| `"not-applicable"` | yes | provider notification delivery only; `pending` means correlated provider input acceptance was not recorded, not that the recipient is still unread or has unfinished work |
| `$.items[].delivery.at` | Time \| null | yes | |
| `$.items[].disposition.state` | `"unread"` \| `"read"` \| `"dismissed"` | yes | the recipient's own marker |
| `$.items[].disposition.at` | Time \| null | yes | |
| `$.items[].unreadable` | null \| `{reason}` | yes | set for a row that exists but could not be decoded (its other fields are then null). Such rows also count in `window.omitted`. |
| `$.window`, `$.next` | Window, Cursor \| null | yes | see A.0. Inbox exits 2 when `unread_total` is null, or is larger than the number of unread items shown, or any row is unreadable. With `full`, a page holds at most 256 KiB of bodies, never cuts a body and holds at least one row. Rows that did not fit are reported as `omitted.reason: "budget"` and returned by following `next`. |

Markers are untouched: producing this family (inbox, list, `--full` or not, owner or session) never creates or changes a delivered, read or dismissed marker. `disposition` and `delivery` report the stored state as it was when the page was read. Observing history is not the recipient reading it; only `se.message-read/v1` and `se.disposition-receipt/v1` write markers.

Plain output names `delivery` **Notification delivery** and shows **Recipient state**
separately. A recipient can resume, read and reply without a correlated notification
input event, so `delivery.state: "pending"` and `disposition.state: "read"` can both be
true. Clients show the recipient marker as the read state; neither notification
delivery nor reading is a task-completion acknowledgment. A reply is separate mail.

```json
{"schema":"se.message-page/v1","consistency":"live-keyset",
 "view":{"op":"inbox","recipient":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},"disposition":"unread","box":"inbox",
         "filter":{"to":null,"from":null,"kind":null},"inspection":false,"full":false,"scope":"own"},
 "unread_total":3,
 "items":[{"id":"msg_0192f3b0-0000-7000-8000-000000000101","event_id":"ev_0192f3b0-0000-7000-8000-000000000102",
   "from":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
   "to":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},
   "kind":"handoff","sent_at":"2026-10-30T12:06:00.120000Z","reply_to":null,"refs":[],
   "body":{"text":"Please review src/store/tx.rs; the token is in NOTES","complete":false,"bytes":212,
           "command":"se msg read msg_0192f3b0-0000-7000-8000-000000000101","argv":["se","msg","read","msg_0192f3b0-0000-7000-8000-000000000101"]},
   "delivery":{"state":"offered","at":"2026-10-30T12:06:00.300000Z"},"disposition":{"state":"unread","at":null},"unreadable":null}],
 "window":{"from":null,"to":"c1.bTE","limit":1,"complete":false,"omitted":{"count":2,"reason":"limit"}},"next":"c1.bTE"}
```

This example exits 2: 3 messages are unread and 1 is shown.

### A.6 `se.stop/v1` — `se stop`, `stateengine_agent_stop`

A StopResult is the per-agent shape below. For a single target it sits at the
root, with `$.scope = "agent"` and `$.stops = null`. With `--all`, root per-target
fields are null and `$.stops[]` contains one StopResult per agent, including every
unknown/unwitnessed outcome. `se down` and uninstall carry that same array; an
error for one agent never drops its result or prevents independent stops.
`$.complete` is false if any entry lacks an exit witness. No arbitrary-process
stop family is introduced.

For the ordinary Linux scoped-creator path, the helper reports exec success or
the actual pre-exec failure while the root is still its child. A root outliving
that helper can later be witnessed exited while its wait status is unavailable.
Human output says "exited, status unavailable"; it never guesses exit 0 or
"crashed". A stop may be successfully witnessed with unavailable status;
requested termination and an unrequested exit of unknown cause stay distinct.
A removed original pinned cgroup plus independent root exit is an exit witness,
including on the first stop observation; a missing name without that native
object evidence is not. Render native ScopeObservation.exit_basis through
`pidfd-exit+cgroup-removed` or `start-identity-exit+cgroup-removed`, retaining
the pinned original scope identity in Witness.detail; an ObservedEmpty basis
keeps the corresponding cgroup-empty method. The Exited record retains this
same evidence through retry/recovery and already-released acknowledgment.

Human text follows `enumeration`: `complete` prints the count ("2 processes still running"); `best-effort` or `unavailable` with `population = populated` prints "processes still running in the agent's group; count unavailable" and lists whatever `remaining[]` names, labelled as partial. `population = unknown` prints its reason and all gathered facts; an empty diagnostic list never proves an empty scope.

Owner-human CLI `se stop AGENT --release` is single-target and legal only from
StopUnproved after an ordinary stop that could not be proved; `--all --release`
and MCP/agent release inputs refuse before effects. [30 — process ownership](30-process-ownership.md)
owns release mechanics; [20 — data model](20-data-model.md) owns the durable
marker and recovery. The command reports those facts in the result below.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.stop/v1"` | yes | |
| `$.receipt` | `"seat-stop/v1"` | yes | compatibility marker for stop-handle decoders |
| `$.scope` | `"agent"` \| `"all"` | yes | |
| `$.result` | `"stopped"` \| `"already-stopped"` \| `"unwitnessed"` \| `"ownership-released"` \| `"partial"` | yes | `partial` occurs only with `all` |
| `$.complete` | bool | yes | every target was witnessed gone or was already stopped |
| `$.event_id` | Id \| null | yes | the stop event; null for `already-stopped` |
| `$.target.project` | Ref | single target | |
| `$.target.agent` | Ref | single target | the agent stopped |
| `$.target.session_id` | Id \| null | single target | |
| `$.target.launch_id` | Id \| null | single target | |
| `$.target.provider` | provider | single target | |
| `$.target.process` | ProcessId \| null | single target | the exact instance stopped, re-checked before acting |
| `$.method` | `"graceful"` \| `"forced"` \| null | single target | null for `already-stopped` and `ownership-released` |
| `$.witness` | Witness | single target | outside confirmation that the recorded instance and owned job/cgroup/group are gone; exact pinned Linux scope removal plus root exit is valid and retained in detail, not ScopeUnreadable; uncontained process-group checks exclude setsid/double-fork escapes and name that bound |
| `$.population` | `"populated"` \| `"empty"` \| `"unknown"` | single target | the observed live-population state for the whole owned scope (Linux cgroup, Windows job, macOS tracked group, Linux uncontained group); `empty` also permits proved removal of the original pinned cgroup plus root exit, with that distinct basis in witness detail, never a fabricated population-file read |
| `$.population_reason` | string \| null | single target | required nonempty reason for unknown; null when known |
| `$.ownership_release` | object \| null | single target | non-null only for ownership-released: lifecycle, generation, resulting entity revision, exact scope, remaining diagnostics and release time; never an exit witness |
| `$.remaining[]` | `{pid, exe, started_at}` | single target | members still running that StateEngine could name; empty when `population = empty` |
| `$.enumeration` | `"complete"` \| `"best-effort"` \| `"unavailable"` | single target | whether `remaining[]` is the whole population. `best-effort`/`unavailable` with `populated` means "still running; count unavailable", never a count |
| `$.capture.flushed` | bool | single target | the transcript was caught up before the stop |
| `$.capture.last_event_id` | Id \| null | single target | last captured turn |
| `$.resume.state` | `"ready"` \| `"unavailable"` | single target | whether the command below resumes the same conversation |
| `$.resume.reason` | string \| null | single target | set when `unavailable` |
| `$.resume.conversation_id` | string \| null | single target | the provider conversation that will be resumed |
| `$.resume.provider`, `.model` | provider, string \| null | single target | kept so the resume uses the same provider and model |
| `$.resume` + Cmd | | single target | `se launch AGENT` (which resumes by default); `se launch AGENT --new` when `unavailable` |
| `$.stops[]` | array \| null | yes | one StopResult per agent for `all`: `{target, result, event_id, method, witness, population, population_reason, ownership_release, remaining, enumeration, capture, resume}` |

```json
{"schema":"se.stop/v1","idempotency_key":"request-stop-v1-example","receipt":"seat-stop/v1","scope":"agent","result":"stopped","complete":true,
 "event_id":"ev_0192f3c0-0000-7000-8000-000000000201",
 "target":{"project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},"agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
           "session_id":"ses_0192f3a2-0000-7000-8000-00000000000a","launch_id":"lch_0192f3a2-0000-7000-8000-00000000000b","provider":"claude",
           "process":{"pid":4188,"started_at":"2026-10-30T12:02:15.010000Z","exe":"/usr/local/bin/claude","machine_id":"m-6a1f"}},
 "method":"graceful",
 "witness":{"state":"witnessed","method":"pidfd-exit+cgroup-empty","observed_at":"2026-10-30T12:20:00.004100Z","detail":null},
 "population":"empty","population_reason":null,"ownership_release":null,"remaining":[],"enumeration":"complete",
 "capture":{"flushed":true,"last_event_id":"ev_0192f3bf-0000-7000-8000-0000000001ff"},
 "resume":{"state":"ready","reason":null,"conversation_id":"7f3a9c1e-55b0-4d0a-9e61-2c1d0b9a8f77","provider":"claude","model":null,
           "command":"se launch main","argv":["se","launch","main"]},
 "stops":null}
```

### A.7 `se.resume/v1` — `se resume`, `stateengine_resume` (top level)

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.resume/v1"` | yes | |
| `$.schema_version` | `1` | yes | compatibility with the old resume format (O7) |
| `$.resume_status` | `"ready"` \| `"needs_read"` \| `"integrity_blocked"` | yes | `needs_read`: `required_reads` is not empty. `integrity_blocked`: a source was unreadable, so the packet cannot be trusted as complete. |
| `$.principal.project`, `.agent` | Ref | yes | verified identity, never taken from input |
| `$.principal.session_id` | Id \| null | yes | null for `--preview` |
| `$.principal.preview` | bool | yes | owner preview: binds, acknowledges and launches nothing |
| `$.generated_at` | Time | yes | |
| `$.since` | Cursor \| null | yes | the cursor supplied |
| `$.complete` | bool | yes | every section fit in the budget and nothing was left out |
| `$.budget.limit_bytes`, `.used_bytes` | int, int | yes | the UTF-8 byte budget and how much was used |
| `$.working_state` | `Read<{text, revision: int, updated_at}>` | yes | |
| `$.unread` | `Page<MessageRow>` | yes | unread mail (previews) |
| `$.required_reads[]` | `{kind: "message"\|"decision"\|"event", id, why}` | yes | items to read before acting |
| `$.decisions.governing[]` | `{id, key, statement, ratified_at}` | yes | governing decisions, as many as fit the budget |
| `$.decisions.pending` | int | yes | |
| `$.recent_turns[]` | `{event_id, at, role, preview}` | yes | this agent's latest turns |
| `$.code_changes` | array (≤5) \| null | yes | Atlas enrichment; null when Atlas is off |
| `$.omissions[]` | `{section, count: int\|null, reason, tool}` + Cmd | yes | what was left out and how to retrieve it |
| `$.attention[]` | string[] | yes | warnings in plain language |
| `$.cursor` | Cursor | yes | pass as `since` next time |

```json
{"schema":"se.resume/v1","schema_version":1,"resume_status":"needs_read",
 "principal":{"project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},"agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},
              "session_id":"ses_0192f3c8-0000-7000-8000-00000000000e","preview":false},
 "generated_at":"2026-10-30T12:41:00.000000Z","since":null,"complete":false,"budget":{"limit_bytes":32768,"used_bytes":30114},
 "working_state":{"state":"present","value":{"text":"Reviewing tx.rs for main; next: reply with findings","revision":4,"updated_at":"2026-10-30T12:20:11.000000Z"}},
 "unread":{"items":[],"window":{"from":null,"to":null,"limit":20,"complete":true,"omitted":{"count":0,"reason":null}},"next":null},
 "required_reads":[{"kind":"message","id":"msg_0192f3b0-0000-7000-8000-000000000101","why":"handoff addressed to you, not yet acknowledged"}],
 "decisions":{"governing":[{"id":"dec_0192f3a9-0000-7000-8000-000000000050","key":"api.versioning","statement":"Breaking JSON changes bump the family major.","ratified_at":"2026-10-30T12:10:00.000000Z"}],"pending":0},
 "recent_turns":[{"event_id":"ev_0192f3bf-0000-7000-8000-0000000001ff","at":"2026-10-30T12:19:41.000000Z","role":"assistant","preview":"Found two issues in commit()…"}],
 "code_changes":null,
 "omissions":[{"section":"recent_turns","count":14,"reason":"budget","tool":"stateengine_search","command":"se search QUERY --agent rev","argv":["se","search","QUERY","--agent","rev"]}],
 "attention":["1 message needs reading before you act"],
 "cursor":"c1.cmVzdW1lLTQx"}
```

### A.8 `se.remove/v1` — `se remove`

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.remove/v1"` | yes | |
| `$.scope` | `"project"` \| `"all"` | yes | |
| `$.outcome` | `"removed"` \| `"absent"` \| `"partial"` | yes | `absent`: nothing was registered (an idempotent retry). `partial` exits 2. |
| `$.projects[]` | array | yes | one entry per project acted on |
| `$.projects[].project` | Ref + `root` | yes | |
| `$.projects[].outcome` | `"removed"` \| `"absent"` \| `"partial"` | yes | |
| `$.projects[].removed_at` | Time \| null | yes | |
| `$.projects[].event_id` | Id \| null | yes | the removal event; history is kept |
| `$.projects[].agents_stopped[]` | `{agent: Ref, prior_state, witness: Witness, process: ProcessId\|null}` | yes | agents that were running; `prior_state` uses the AgentRow session states |
| `$.projects[].processes_stopped[]` | `{lifecycle_id, process: ProcessId, witness: Witness}` | yes | owned provider/terminal helpers within the removed agent lifecycles |
| `$.projects[].processes_may_remain[]` | StopResult (A.6) | yes | one retained ownership-released result per released lifecycle, including unknown population/reason and partial diagnostics; these are warnings even when removal succeeds, never agents_stopped or exit witnesses |
| `$.projects[].credentials_revoked[]` | `{credential_id, kind: "session"\|"launch"\|"bearer", session_id\|null, state: "revoked"\|"already-revoked", at}` | yes | ids only, never secrets |
| `$.projects[].integrations[]` | `{path, entry, action: "reversed"\|"kept-by-flag"\|"conflict-kept"\|"absent", witness: Witness}` | yes | edits StateEngine owned outside the store. `conflict-kept`: you changed the entry, so remove left it and listed it in `remaining`. |
| `$.projects[].removed[]` | `{what, path\|null}` | yes | `what` is one of `registration`, `launch-files`, `session-pins`, `atlas-index`, `runtime-endpoint` |
| `$.projects[].kept[]` | `{what, path\|null, note}` | yes | `what` is one of `history`, `repo-files`, `git-history`, `provider-transcripts`, `backups` |
| `$.projects[].remaining[]` | `{what, reason}` + Cmd | yes | work still left to do; empty when `outcome` is `removed` |
| `$.runtime.action` | `"stopped"` \| `"left-running"` \| `"not-running"` | yes | `--all` stops the standalone runtime; SE Code's runtime is left running |
| `$.runtime.process` | ProcessId \| null | yes | the host that was stopped or left running |
| `$.runtime.witness` | Witness | yes | |
| `$.machine_credential.state` | `"kept"` \| `"removed"` | yes | removed only with `--all` |
| `$.machine_credential.witness` | Witness | yes | re-read confirming the file is gone |
| `$.next` | `{text}` + Cmd | yes | e.g. the uninstall step, or `se init` to come back |

```json
{"schema":"se.remove/v1","idempotency_key":"request-remove-v1-example","scope":"project","outcome":"removed",
 "projects":[{"project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app","root":"/home/ana/src/app"},
   "outcome":"removed","removed_at":"2026-10-30T12:59:10.000000Z","event_id":"ev_0192f3d0-0000-7000-8000-000000000301",
   "agents_stopped":[{"agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},"prior_state":"running",
     "witness":{"state":"witnessed","method":"pidfd-exit+cgroup-empty","observed_at":"2026-10-30T12:59:09.800000Z","detail":null},
     "process":{"pid":5120,"started_at":"2026-10-30T12:40:02.000000Z","exe":"/usr/local/bin/codex","machine_id":"m-6a1f"}}],
   "processes_stopped":[],"processes_may_remain":[],
   "credentials_revoked":[{"credential_id":"cred_0192f3a2-0000-7000-8000-0000000000c1","kind":"session","session_id":"ses_0192f3c8-0000-7000-8000-00000000000e","state":"revoked","at":"2026-10-30T12:59:09.900000Z"}],
   "integrations":[],
   "removed":[{"what":"registration","path":null},{"what":"launch-files","path":"/home/ana/.local/state/stateengine/launch/prj_0192f3a0"}],
   "kept":[{"what":"history","path":null,"note":"messages, decisions and turns stay in the store; se forget erases a record"},
           {"what":"repo-files","path":"/home/ana/src/app","note":"untouched"},{"what":"git-history","path":"/home/ana/src/app","note":"untouched"}],
   "remaining":[]}],
 "runtime":{"action":"left-running","process":{"pid":4120,"started_at":"2026-10-30T12:02:11.250000Z","exe":"/home/ana/.local/bin/se","machine_id":"m-6a1f"},
            "witness":{"state":"not-applicable","method":null,"observed_at":null,"detail":"other projects still registered"}},
 "machine_credential":{"state":"kept","witness":{"state":"not-applicable","method":null,"observed_at":null,"detail":null}},
 "next":{"text":"Come back later","command":"se init --repo /home/ana/src/app","argv":["se","init","--repo","/home/ana/src/app"]}}
```

### A.9 Post-remove status answer

After `se remove -p app`, `se status -p app --json` exits 0 (a measured absence) and prints:

```json
{"schema":"se.status/v1","scope":"project","generated_at":"2026-10-30T13:00:00.000000Z","version":"0.1.0",
 "setup":{"state":"configured","home":"/home/ana/.local/state/stateengine","reason":null},
 "runtime":{"state":"stopped","host":null,"process":null,"generation":null,"endpoint":null,"version":null,"observed_at":"2026-10-30T13:00:00.000000Z"},
 "project":{"state":"absent","checked":"registry: last registration of app was removed"},
 "removal":{"project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},"root":"/home/ana/src/app",
            "removed_at":"2026-10-30T12:59:10.000000Z","event_id":"ev_0192f3d0-0000-7000-8000-000000000301"},
 "principal":null,"agents":null,"inbox":{"owner_unread":null,"self_unread":null},"decisions":{"pending":null},
 "capture":{"state":"off","last_turn_at":null},"atlas":{"state":"absent"},"pending":[],"projects":null,
 "next":{"text":"Re-adopt this folder","command":"se init --repo /home/ana/src/app","argv":["se","init","--repo","/home/ana/src/app"]}}
```

After `se remove --all`, `se status --all` gives `$.scope = "all"` and an empty `$.projects.items` with `window.complete: true`. After an uninstall that also deleted the home, status gives `$.setup.state = "not-set-up"`, `$.project = {"state":"absent","checked":"no store in home"}` and `$.removal = null`. Status never answers a removed project with the `project-removed` error; that error is for operations that act on a project. A judge tells the three outcomes apart by `setup.state`, `project.state` and `removal`.

### A.10 `se.diagnosis/v1` — `se doctor`

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.diagnosis/v1"` | yes | |
| `$.generated_at` | Time | yes | |
| `$.scope.home` | string | yes | |
| `$.scope.project` | Ref \| null | yes | |
| `$.outcome` | `"healthy"` \| `"problems"` \| `"incomplete"` | yes | exits 0, 1 and 2 respectively (§5) |
| `$.summary.ok`, `.failed`, `.warning`, `.unmeasured`, `.skipped` | int | yes | number of checks in each state |
| `$.checks[].id` | string | yes | stable id (listed below) |
| `$.checks[].title` | string | yes | human label |
| `$.checks[].state` | `"ok"` \| `"failed"` \| `"warning"` \| `"unmeasured"` \| `"skipped"` \| `"not-applicable"` | yes | `unmeasured`: the check could not run. It is never reported as `ok`. |
| `$.checks[].measured_at` | Time \| null | yes | null unless the check was measured |
| `$.checks[].observed` | string \| null | yes | what was found |
| `$.checks[].expected` | string \| null | yes | what a healthy result looks like |
| `$.checks[].reason` | string \| null | yes | why the check failed, was unmeasured or was skipped |
| `$.checks[].code` | error code \| null | yes | the §6 code a command would raise for this problem |
| `$.checks[].fix` | `{text}` + Cmd \| null | yes | the fix; its command is null when the fix is manual |
| `$.checks[].repairable` | bool | yes | whether `se doctor --fix` can apply the fix |

Stable check ids:
- `binary.version`, `home.location`, `home.permissions`, `credential.machine`
- `store.open`, `store.schema`, `store.integrity`, `store.backups`, `disk.space`
- `config.user`, `env.legacy`
- `runtime.lock`, `runtime.endpoint`, `runtime.version`, `listener.loopback`
- `provider.claude`, `provider.codex`
- `custody.windows-job`, `custody.linux-cgroup`, `custody.macos-kqueue`: only the current OS's check is measured; the others report `not-applicable`. `custody.linux-cgroup` is `ok` when agents get a delegated cgroup v2 scope and `warning` (never `failed`) when they run `uncontained`; its `observed` names the containment and the full probe text, `code` is null (nothing refuses), and its manual fix enables a systemd user manager with delegation. It replaces the removed `cgroup-delegation-missing` refusal.
- `integration:<path>#<entry>`: one per owned edit.
- `capture:<agent-name>`: one per agent.
- `atlas.index`

New ids may be added. Existing ids keep their meaning. Provider checks use `se_host::MIN_CODEX_VERSION` (the sole minimum constant); the value below is an illustrative rendered observation, not a second configuration source.

```json
{"schema":"se.diagnosis/v1","generated_at":"2026-10-30T12:30:00.000000Z",
 "scope":{"home":"/home/ana/.local/state/stateengine","project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"}},
 "outcome":"problems","summary":{"ok":14,"failed":1,"warning":1,"unmeasured":0,"skipped":0},
 "checks":[
  {"id":"store.integrity","title":"Store integrity","state":"ok","measured_at":"2026-10-30T12:30:00.010000Z","observed":"ok","expected":"ok","reason":null,"code":null,"fix":null,"repairable":false},
  {"id":"provider.codex","title":"Codex CLI","state":"failed","measured_at":"2026-10-30T12:30:00.050000Z","observed":"codex 0.120.0","expected":">= 0.152.0",
   "reason":"too old","code":"provider-incompatible","fix":{"text":"Upgrade Codex","command":null,"argv":null},"repairable":false},
  {"id":"custody.linux-cgroup","title":"Agent process custody","state":"warning","measured_at":"2026-10-30T12:30:00.060000Z",
   "observed":"uncontained (no-user-manager: $XDG_RUNTIME_DIR/systemd/private absent); agents run in their own process group","expected":"a delegated cgroup v2 scope from the systemd user manager",
   "reason":"no systemd user manager for this user, so stop reaches only each agent's process group","code":null,"fix":{"text":"Run a systemd user manager with cgroup delegation (exact steps printed here); agents launch either way","command":null,"argv":null},"repairable":false}]}
```

This example exits 1. One check failed, and a failure outranks a warning.

### A.11 `DecisionRow`, `se.decision-receipt/v1` — `se decide`, `se decision ratify|reject|retract|supersede`, `stateengine_decision_propose`

`DecisionRow` is shared by the receipt, the page (A.12) and `se decision show`.

The canonical declaration is `se_types::{DecisionRow, DecisionReceipt}` in
`crates/se-types/src/surface/decision.rs`. The actual family serializer is
`se_core::ops::decision_receipt(DecisionReceipt)`, returning the existing core
`Envelope<DecisionReceipt>`; its `schema` is `se.decision-receipt/v1`. The
shared `WriteReceipt` is flattened into the top level, never a nested `commit`
object. The five `DecisionAction` spellings and five `DecisionState` spellings
are closed enums matching the tables below. These output declarations do not
register the unfinished FULL operations in `AnyOp`/`AnyOutput` or make them
executable; future operations consume these types rather than define another
receipt.

| Path (row = a `DecisionRow`) | Type | Always | Meaning |
| --- | --- | --- | --- |
| row`.id` | Id | yes | decision id (`dec_…`) |
| row`.key` | string | yes | decision key, e.g. `api.versioning` |
| row`.state` | `"pending"` \| `"ratified"` \| `"rejected"` \| `"retracted"` \| `"superseded"` | yes | current state. `pending` is a proposal waiting for the owner. |
| row`.governing` | bool | yes | true only when `ratified` and not later retracted or superseded |
| row`.revision` | int | yes | per-decision counter: 1 at creation, plus one per committed transition; pass it as `--expect` |
| row`.statement.text` | string | yes | the full statement when `complete`; otherwise a preview cut at a UTF-8 boundary |
| row`.statement.complete` | bool | yes | |
| row`.statement.bytes` | int | yes | size of the full statement |
| row`.statement` + Cmd | | yes | body reference `se decision show ID` when `complete` is false; null otherwise |
| row`.rationale` | string \| null | yes | the proposer's rationale (preview rules as for `statement`) |
| row`.proposed_by` | Ref + kind (`agent` \| `owner`) | yes | author, taken from authority |
| row`.proposed_at` | Time | yes | |
| row`.decided_by` | Ref + kind \| null | yes | the owner who ratified, rejected, retracted or superseded it; null while `pending` |
| row`.decided_at` | Time \| null | yes | time of the latest transition; null while `pending` |
| row`.reason` | string \| null | yes | reject/retract reason |
| row`.supersedes` | Id \| null | yes | decision this one replaces. On a proposal it is only a proposed link; it takes effect when the owner runs `decision supersede`. |
| row`.superseded_by` | Id \| null | yes | set once a replacement governs |
| row`.event_id` | Id | yes | event of the latest transition |

`se.decision-receipt/v1`:

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.decision-receipt/v1"` | yes | |
| `$.action` | `"propose"` \| `"ratify"` \| `"reject"` \| `"retract"` \| `"supersede"` | yes | |
| `$.state` | `"committed"` \| `"replayed"` | yes | receipt state (A.0) |
| `$.event_id` | Id | yes | the transition event |
| `$.recorded_at` | Time | yes | commit time |
| `$.project` | Ref | yes | |
| `$.idempotency_key` | string | yes | required for propose and every owner transition; generated/printed by CLI before first send |
| `$.authority.guard` | string \| null | yes | human transitions: `"owner-terminal-outside-agent-tree"`; proposal: null |
| `$.authority.limit` | string | yes | `"mistake/drift guard; not proof against a determined agent using the same OS account"` |
| `$.decision` | DecisionRow | yes | the decision read back after the commit. For `supersede`, this is the replacement, now governing. |
| `$.replaced` | DecisionRow \| null | yes | `supersede` only: the prior decision, now `superseded`; null otherwise |
| `$.writer.mode` | `"host"` \| `"direct"` | yes | A.0 Writer |
| `$.writer.host_generation` | string | when mode is `host` | |

When the replacement is pending, `decision supersede` approves it and retires
its predecessor in one FULL transaction. The receipt's `event_id` is the
replacement's actual ratification event; `replaced.event_id` identifies the
predecessor's separate retirement event in the same atomic operation. A stale
revision on either decision rolls back both transitions. Replaying the original
request key returns those original events and rows even after later transitions.

```json
{"schema":"se.decision-receipt/v1","authority":{"guard":null,"limit":"mistake/drift guard; not proof against a determined agent using the same OS account"},"action":"propose","state":"committed",
 "event_id":"ev_0192f3a8-0000-7000-8000-000000000049","recorded_at":"2026-10-30T12:08:00.000000Z",
 "project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},"idempotency_key":"request-0192f3a8-0000-7000-8000-000000000049",
 "decision":{"id":"dec_0192f3a9-0000-7000-8000-000000000050","key":"api.versioning","state":"pending","governing":false,"revision":1,
   "statement":{"text":"Breaking JSON changes bump the family major.","complete":true,"bytes":44,"command":null,"argv":null},
   "rationale":"Consumers pin majors.","proposed_by":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
   "proposed_at":"2026-10-30T12:08:00.000000Z","decided_by":null,"decided_at":null,"reason":null,
   "supersedes":null,"superseded_by":null,"event_id":"ev_0192f3a8-0000-7000-8000-000000000049"},
 "replaced":null,
 "writer":{"mode":"host","host_generation":"7"}}
```

The same decision after `se decision ratify dec_…` run in the owner's terminal with no host running (the request uses a fresh key):

```json
{"schema":"se.decision-receipt/v1","authority":{"guard":"owner-terminal-outside-agent-tree","limit":"mistake/drift guard; not proof against a determined agent using the same OS account"},"action":"ratify","state":"committed",
 "event_id":"ev_0192f3aa-0000-7000-8000-000000000051","recorded_at":"2026-10-30T12:10:00.000000Z",
 "project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},"idempotency_key":"request-0192f3aa-0000-7000-8000-000000000051",
 "decision":{"id":"dec_0192f3a9-0000-7000-8000-000000000050","key":"api.versioning","state":"ratified","governing":true,"revision":2,
   "statement":{"text":"Breaking JSON changes bump the family major.","complete":true,"bytes":44,"command":null,"argv":null},
   "rationale":"Consumers pin majors.","proposed_by":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
   "proposed_at":"2026-10-30T12:08:00.000000Z","decided_by":{"kind":"owner","id":"hu_0192f3a0-1111-7aaa-8bbb-000000000002","name":"ana"},
   "decided_at":"2026-10-30T12:10:00.000000Z","reason":null,"supersedes":null,"superseded_by":null,
   "event_id":"ev_0192f3aa-0000-7000-8000-000000000051"},
 "replaced":null,
 "writer":{"mode":"direct"}}
```

### A.12 `se.decision-page/v1` — `se decision list`, `stateengine_decision_list`; `se.decision/v1` — `se decision show`

`se.decision-page/v1` is `{schema, project, filter, consistency: "live-keyset"}` plus the `Page<DecisionRow>` keys. List ordering is by store order of the latest transition, oldest first.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.decision-page/v1"` | yes | |
| `$.project` | Ref | yes | |
| `$.filter.id` | Id \| null | yes | exact-id filter. With `id` alone, a complete empty page means the id is absent (OPS.md). |
| `$.filter.pending` | bool | yes | only `pending` proposals |
| `$.filter.history` | bool | yes | include `rejected`, `retracted` and `superseded`. Without it, the page holds governing and pending decisions. |
| `$.items[]` | DecisionRow | yes | A.11; statements are previews by default (`complete` says which) |
| `$.items[].unreadable` | null \| `{reason}` | yes | set for a row that exists but could not be decoded (its other fields are then null); also counted in `window.omitted` |
| `$.window`, `$.next` | Window, Cursor \| null | yes | A.0. An omission with reason `unreadable` exits 2. |

`se.decision/v1` (`se decision show ID`) is `{"schema":"se.decision/v1","decision":Read<DecisionDetail>}`. `DecisionDetail` is a `DecisionRow` whose `statement.complete` is always true, plus `transitions[]`: `{action, by: Ref + kind, at, event_id, reason}`, oldest first. An unknown id gives `{"state":"absent","checked":"decisions in project app"}`, exit 0. An undecodable row gives `unreadable`, exit 3. Detail uses only the exact-ID transition reader at one snapshot: up to 32 pages of 128 events and 1 MiB each, with a 250 ms deadline per page. Exhausting these bounds gives `unreadable`, never a partial success. Incoming committed supersede transitions appear in the replacement’s history without incrementing its own revision; a proposal’s intended predecessor alone is not an effective supersede transition.

```json
{"schema":"se.decision-page/v1","project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},
 "filter":{"id":null,"pending":false,"history":false},
 "items":[{"id":"dec_0192f3a9-0000-7000-8000-000000000050","key":"api.versioning","state":"ratified","governing":true,"revision":2,
   "statement":{"text":"Breaking JSON changes bump the family major.","complete":true,"bytes":44,"command":null,"argv":null},
   "rationale":"Consumers pin majors.","proposed_by":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
   "proposed_at":"2026-10-30T12:08:00.000000Z","decided_by":{"kind":"owner","id":"hu_0192f3a0-1111-7aaa-8bbb-000000000002","name":"ana"},
   "decided_at":"2026-10-30T12:10:00.000000Z","reason":null,"supersedes":null,"superseded_by":null,
   "event_id":"ev_0192f3aa-0000-7000-8000-000000000051","unreadable":null}],
 "consistency":"live-keyset","window":{"from":null,"to":"c1.ZDE","limit":20,"complete":true,"omitted":{"count":0,"reason":null}},"next":null}
```

### A.12.1 `se.config-value/v1` and `se.agent-status/v1` — independent readback

The published DTOs are `se_core::ops::{ConfigValueOutput, AgentStatusOutput}`
in `crates/se-core/src/ops/outputs.rs`. Their `into_envelope` methods add the
literal family `schema` first. These declarations do not add operations to the
executable catalogue: a runner must still refuse an unsupported command rather
than substitute fixture data for installed readback.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.config-value/v1"` | config value | family |
| `$.key` | string | config value | exact canonical setting key, including `agent.<A>.*` for saved agent metadata |
| `$.value` | `Read<JSON value>` | config value | present retains the setting's boolean, number, string, array or object type; a present JSON null is distinct from absent, unreadable and unknown |
| `$.origin` | string | when origin was requested and established | selected file, environment/flag override, built-in default or saved agent field; omitted otherwise |
| `$.schema` | `"se.agent-status/v1"` | agent status | family |
| `$.agent` | `Read<AgentRow>` | agent status | present value is exactly A.2's row, including nested session, conversation and resume objects |

Configuration values follow the existing redaction policy; no credential or
secret becomes a readback value. A judge accepts a value or agent fact only from
`state: "present"`, compares the native JSON type and exact value, and fails
closed on the other three Read states. Neither family carries an event or
writer stamp because these are reads. Optional timing diagnostics use the same
outer envelope as other outputs and are absent when there is no measured write.

### A.13 Other write receipts carrying `writer`

Every keyed write result also carries its original `$.idempotency_key`; natural capture/marker results carry `$.request_identity` with `kind: "natural"` and its source session/turn or recipient/message/marker fields. Each committed/replayed family below carries `$.schema`, `$.state` (`committed` \| `replayed`), `$.event_id` (Id), `$.recorded_at` and `$.writer` (A.0), together with the fields listed.

| Family | Additional fields (all always present) |
| --- | --- |
| `se.working-state-receipt/v1` (`se working-state set`, `stateengine_working_state_set`) | `$.agent` Ref; `$.revision` int (the new revision); `$.current_revision` int (equal to `revision`); `$.bytes` int. A conflict returns `se.error/v1` code `revision-conflict` with expected/current revisions on CLI, MCP and linked calls; it creates no event or writer stamp. |
| `se.turn-receipt/v1` (`se session turn`, `stateengine_session_turn`, hooks) | `$.result` `"captured"` \| `"duplicate"` \| `"suppressed"`; `$.session_id` Id; `$.turn_id` string \| null; `$.role`; `$.bytes` int. A `suppressed` turn appends no body, and its `event_id` is the suppression-count event. |
| `se.agent-receipt/v1` (`se agent add`, `se agent rename`, `stateengine_agent_create`) | `$.action` `"create"` \| `"rename"`; `$.outcome` `"created"` \| `"existing"` \| `"renamed"` \| `"unchanged"`; `$.agent` `{id, name, provider, model, profile}`; `$.previous_name` string \| null (rename only); `$.process_started` false (creating an agent never starts a process). |
| `se.disposition-receipt/v1` (`msg ack`, `msg dismiss`) | `$.message_id`; `$.disposition` `"read"` \| `"dismissed"`; `$.marker` `"new"` \| `"already"`; `$.by` Ref (the recipient). |
| `se.message-read/v1` (`msg read`) | `$.message` MessageRow (A.5, with `body.complete` true unless the body exceeds the hard cap); `$.marker` `"new"` \| `"already"`. `event_id` and `writer` refer to the read-marker event; on `already`, they refer to the original marker. |

```json
{"schema":"se.working-state-receipt/v1","idempotency_key":"working-state-0192f3b5-0000-7000-8000-000000000110","state":"committed","event_id":"ev_0192f3b5-0000-7000-8000-000000000110",
 "recorded_at":"2026-10-30T12:20:11.000000Z","agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},
 "revision":4,"current_revision":4,"bytes":52,"writer":{"mode":"host","host_generation":"7"}}
```

### A.13.1 Canonical `se.agent-receipt/v1` declaration

`se_types::AgentReceipt` in `crates/se-types/src/surface/agent.rs` is serialized
by `se_core::ops::agent_receipt` using the existing family Envelope. Agent add
uses `action: "create"`; rename reuses this same family. The shared declarations
of `Named`, `ActorRef`, `Writer`, `CommitState` and the saved Claude/Codex
`Provider` now live in `se-types`; their existing core names re-export the same
types and preserve their wire layouts.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.agent-receipt/v1"` | yes | family |
| `$.state` | `"committed"` \| `"replayed"` | yes | actual original write outcome |
| `$.event_id`, `$.recorded_at`, `$.idempotency_key`, `$.writer` | Id, Time, string, Writer | yes | flattened immutable write fields from A.0; replay retains the original event and writer |
| `$.action` | `"create"` \| `"rename"` | yes | selected operation |
| `$.outcome` | `"created"` \| `"existing"` \| `"renamed"` \| `"unchanged"` | yes | actual identity effect; not a launch result |
| `$.agent.id`, `$.agent.name` | Id, string | yes | saved agent identity |
| `$.agent.provider` | `"claude"` \| `"codex"` | yes | saved provider |
| `$.agent.model` | string \| null | yes | null selects the provider default |
| `$.agent.profile` | string | yes | saved named permission profile |
| `$.previous_name` | string \| null | yes | previous name for rename; null for create |
| `$.process_started` | false | yes | add/rename never launches a process |

Creation is a FULL store mutation. A judge requires the returned agent id and
saved metadata to agree with independent `se.agent-status/v1` readback. It
checks `process_started` is false; a creation receipt cannot substitute for a
process launch witness. These declarations alone add no executable operation.

### A.13.2 `se.config-receipt/v1` — store-backed agent metadata

`se_types::AgentConfigReceipt` in the same module is the store-backed branch
for `config set agent.<A>.model`, `.profile` and `.can-create`. Its actual family
serializer is `se_core::ops::agent_config_receipt`, returning the existing
`Envelope<AgentConfigReceipt>`. The general `config.toml` file-custody branch
has no store event or writer and cannot use this payload; section 40 §9.5 still
governs that separate branch.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.config-receipt/v1"` | yes | family |
| `$.storage` | `"agent-record"` | yes | closed discriminator for the store-backed branch |
| `$.state` | `"committed"` \| `"replayed"` | yes | original write outcome |
| `$.event_id`, `$.recorded_at`, `$.idempotency_key`, `$.writer` | Id, Time, string, Writer | yes | flattened immutable write fields; no nested `commit` object |
| `$.project`, `$.agent` | Ref, Ref | yes | exact admitted project and saved agent |
| `$.key` | string | yes | canonical `agent.<A>.model`, `.profile` or `.can-create` key |
| `$.previous` | `{value: JSON, source: "stored" \| "default"}` | yes | effective prior value and its measured source; the first can-create write has `{value:false,source:"default"}`, while a stored false or JSON null retains source stored |
| `$.value` | JSON value | yes | committed setting read back with its native type; `.can-create` is boolean, `.profile` is a string and `.model` is string or null |
| `$.revision` | int | yes | entity revision committed by this request |
| `$.current_revision` | int | yes | fresh readback revision; may be later on replay and never replaces the original committed revision |
| `$.authority.guard` | `"owner-terminal-outside-agent-tree"` \| null | yes | established human-presence guard for `.profile` permission selection and `.can-create`; null for the ordinary `.model` update |
| `$.authority.limit` | string | yes | the same mistake/drift-bound disclosure as A.11 |

Agent metadata changes are FULL store mutations. A judge requires the exact
key/value type and entity to agree with independent `se.config-value/v1`
readback and checks the committed/replayed event and writer. A failed or
unreadable resulting readback refuses rather than publishing a guessed success;
it does not become a null setting. An unknown or unreadable prior value refuses
rather than supplying a guessed receipt. The first can-create write reports
`previous: {value:false, source:"default"}`, matching the effective false from
`config get`. The source is established by the original committed first-write
facts (`Expected::Absent` and no cause); the store's absent grant remains an
absent storage fact. A later stored false or present JSON null has
`source:"stored"`. Replay reconstructs the effective prior value and source
from the original commit without substituting the current grant head.
Transient timings, when measured, use the existing optional outer diagnostics;
these DTO declarations add no timer, store write or executable command.

### A.14 `se.event/v1` and `se.history-page/v1` — `se history`, `stateengine_event_read`

The judged readback for anything a hook, integration or command recorded. Capture-only hook stdout stays empty; session-start retains its provider context framing (section 40); an outside judge reads the captured turn back through this family instead.

`se.event/v1` always carries:

| Path | Type | Meaning |
| --- | --- | --- |
| `$.schema` | `"se.event/v1"` | |
| `$.event_id` | Id | |
| `$.position` | Cursor | Opaque event position; numeric store order stays private. |
| `$.kind` | string | Event kind, e.g. `session.turn`, `message.sent`, `decision.ratified`. |
| `$.recorded_at` | Time | |
| `$.project` | Ref | |
| `$.actor` | Ref | Who caused it (agent, owner or integration principal). |
| `$.writer` | Writer (A.0) | Who committed it. |
| `$.read_at` | Cursor | Opaque read checkpoint, not an entity revision. |
| `$.payload` | object | Kind-specific, below. |

For `kind: "session.turn"`, `$.payload` always carries `session_id` Id; `turn_id` string \| null (the provider's id when it has one); `provider` `"claude"` \| `"codex"` \| `"secode"`; `provider_session` string \| null; `role` `"user"` \| `"assistant"`; `source` `"hook"` \| `"transcript"` \| `"app-server"` \| `"integration"`; `occurred_at` Time \| null; and `body` `{"text": string, "bytes": int, "sha256": string, "complete": bool}`. `complete: false` is retained only for explicitly identified legacy/partial capture with disclosed omissions. New trusted captures above the 1 MiB store cap refuse without advancing their source cursor; public session.turn rejects above 128 KiB before an effect. A suppressed turn has no `session.turn` event; its suppression-count event has `kind: "capture.suppressed"` and `payload.count`.

`se.history-page/v1` is a labelled live-keyset `Page<se.event/v1 without $.schema>` (A.0) plus `$.schema` and opaque `$.read_at`. Filters: `--session ID`, `--kind KIND` (repeatable), `--agent A`, `--since CURSOR`. Results preserve store chronological order without exposing its numeric sequence; `--cursor C` continues the same query.

The store query carries `session: Option<SessionId>` and exact
`kinds: Vec<EventKind>` alongside agent/since filters. The exact capture kind is
`session.turn` throughout store, wire and this appendix. The session+kind query
uses the turns projection’s scoped session/sequence index, then authoritative
event primary-key reads, within the byte/page budget. It adds neither a broad
event-kind index nor an event session/kind index to the hot insert path. Filtering
is applied before paging, never by reading a broad page and post-filtering. An empty
filtered page therefore has the declared completeness and continuation semantics. Runtime-private kinds remain excluded before reading.

**How an outside judge checks a captured turn (B9 and J3):** drive the real integration exactly as its provider does (Claude hooks/transcript, Codex app-server or SE Code direct capture; section 40), then run `se history --session SESSION_ID --kind session.turn --json` from outside the writer. The turn must appear once with the expected `role`, `body.sha256` and `writer`. Running the same hook again must not add a second row (the turn receipt says `duplicate`).

```json
{"schema":"se.event/v1","event_id":"ev_0192f3b5-0000-7000-8000-000000000120","position":"c1.ZXhhbXBsZS1ldmVudA","kind":"session.turn",
 "recorded_at":"2026-10-30T12:21:03.000000Z","project":{"id":"prj_0192f3a0-0000-7aaa-8bbb-000000000001","name":"demo"},
 "actor":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev","kind":"agent"},"writer":{"mode":"host","host_generation":"7"},
 "read_at":"c1.ZXhhbXBsZS1yZWFk","payload":{"session_id":"ses_0192f3b4-0000-7000-8000-000000000031","turn_id":"t-17","provider":"claude",
 "provider_session":"9f1c…","role":"assistant","source":"hook","occurred_at":"2026-10-30T12:21:02.881000Z",
 "body":{"text":"Done: built.txt written.","bytes":24,"sha256":"…","complete":true}}}
```

### A.15 Owner hazard results — repair, restore, rotate and uninstall

Each family has `schema`, `idempotency_key` (the original request key), `state`
(`committed` | `replayed` | `pending`), `complete` and the exact printed `plan`.
A normal refusal is `se.error/v1`, not a successful hazard result. `plan` contains
`targets[]` (typed IDs/owned paths), `agents_ended[]`, `credentials_rotated[]`,
`events_lost: Read<{after: Cursor, through: Cursor|null, count}>`, `retained_copies[]`, and
`authority_limit` stating the same-user mistake/drift boundary. Measured zero is
Present with count zero; unknown/unreadable is never zero. Printing the plan is
not a new durable phase or typed-ID confirmation. File-only results use the
section 40 readback rule: `committed` reports applied requested state and
`replayed` reports that the current state already matches, without claiming a
historical store commit or persisted receipt. Partial/unreadable effects remain
pending or refuse; they are never manufactured as successful original history.

Restore retry and the stored original receipt are owned by [20 — restore](20-data-model.md); the family fields below do not introduce file-state reconciliation.

| Family | Additional required fields | Witness and completion rule |
| --- | --- | --- |
| `se.repair/v1` | `check_id`, `applied[]`, `skipped[]`, `readbacks[]`, `remaining_checks[]` | exactly the one diagnosed CHECK-ID; no restore/rotation; complete only after owned config readback; user-edited conflicts remain visible |
| `se.restore/v1` | `recovery_event_id`, `backup {id, path, schema, through: Cursor, verified_at}`, `source {store_id: Id|null, incarnation: int|null}`, `target {store_id: Id, incarnation: int}`, `preserved_source {path, witness}`, `lost {after: Cursor, through: Cursor|null, count: Read<int>}`, `stops[]`, `revocations[]`, `restored_store {schema, through: Cursor, witness}` | first execution independently reopens the newest valid automatic backup and preserves corrupt source; RecoveryRecorded retains the complete original receipt payload before atomic publication; retry returns the stored original receipt verbatim, without reselection, reconstruction or fresh observations; no event salvage |
| `se.credential-rotation/v1` | `revoked[] {credential_id, session_id, witness}`, `new_credential {credential_id, witness}`, `stops[]` | no credential bytes; verify new protected credential and every named revocation/stop; partial effects remain pending/incomplete |
| `se.uninstall/v1` | `install_files[] {path, outcome, witness}`, `integrations[] {path, entry, outcome, witness}`, `stops[]: StopResult[]` (A.6, unknown included), `revocations[]`, `path {scope, before_entries, after_entries, witness}`, `preserved[]` | ordinary graceful down and saved resume references must be witnessed and printed first; scripts/SE Code installer invoke this one operation; only then owned install/integration/PATH entries removed/restored with fresh-shell PATH readback; preserved repositories, Git, history, backups and provider transcripts named; any unresolved obligation makes complete false |

Windows uninstall has two reporting points. Before returning 75, the native
parent retains the full achieved report: stops with original resume references,
PATH before/after with its native witness, preserved paths, recovery inventory
and the original request key. Plain output labels the remaining work "handoff
pending" and prints how to check the reported names; it does not instruct a retry
through an image that the helper is deleting. To wait for a final exit status,
start with the matching archive's `uninstall.ps1`.

That entry returns zero only after a matching helper success and outside absence
of its **own** installed image/record and the helper's reported staging names.
A mismatched reply image/record is a failure even if the claimed names are absent.
The final JSON is `se.uninstall-completion/v1` with `complete`, cleanup names and
witness, and `achieved` containing the original `se.uninstall/v1` snapshot. Its
pending entries describe the parent observation; the completion witness separately
resolves post-exit cleanup, without inventing earlier observations or dropping
achieved facts. PATH is witnessed only by the native parent, not by the script's
file-absence checks. Failed or missing helper replies, unreadable cleanup or a
bounded wait expiring produce a named nonzero result and archive recovery guidance.

Store-committing subresults carry their event/writer stamps from A.0. A file-only
readback has a Witness, never a manufactured event or writer. Secret header-helper
framing remains its native map; its private keyed result is not a new public tool.
