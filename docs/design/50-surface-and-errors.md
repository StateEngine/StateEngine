# 50 — Surface, output contracts, errors and configuration

Deep design, 2026-10-30. Governs the `se` CLI, the MCP tool set, the library dispatcher, JSON output families, exit codes, the error catalog and configuration. Authority order: `rust-se/docs/OPS.md` (the reviewed allowlist) over this file over `03-api.md`. OPS.md lists **59 operations** (its header count; the brief said 60) and **25 MCP tools** (20 core + 5 Atlas). This section adds no operation. Where it has to choose something OPS.md leaves open (flag spellings, defaults, limits, names of schema families and error codes) the choice is marked as a decision here, and a seat implements it as written.

Crates: types and errors live in `se-types`; the registry, `Op` impls and dispatcher in `se-core` (`se_core::ops`); clap and renderers in the `se` binary; MCP framing in `se-host`. Nothing in `se-core` depends on clap at runtime except through the `clap::Args` derive on input structs (feature `cli`, on by default; SE Code builds with `default-features = false` and gets no clap).

---

## 1. The operation registry

### 1.1 Core types (`se-types::op`)

```rust
pub trait Op: DeserializeOwned + JsonSchema + Validate + Send + 'static
    + OpCli // = clap::Args under feature "cli", empty marker otherwise
{
    const META: OpMeta;
    type Output: Serialize + JsonSchema + Render + ExitStatus + Send + 'static;
    fn run(self, cx: Cx<'_>) -> impl Future<Output = Result<Self::Output, SeError>> + Send;
}

pub struct OpMeta {
    pub name: &'static str,            // "message.send" — registry key, stable
    pub cli: CliExposure,
    pub mcp: McpExposure,
    pub auth: Auth,                    // Owner | Session | Either
    pub anonymous: bool,               // only meta.version / meta.help / meta.schema
    pub human_only: bool,              // interactive TTY outside any agent process tree
    pub effect: Effect,
    pub scope: Scope,                  // decides which global flags the op accepts
    pub runtime: RuntimeNeed,
    pub feature: Feature,              // Core | Atlas
    pub family: Family,                // output schema family + major
    pub since: ApiVersion,             // (1, 0) for every alpha op
    pub journeys: &'static [Journey],
}

pub enum CliExposure {
    Leaf { path: &'static [&'static str], hidden: bool, select: Selector },
    Many(&'static [CliLeaf]),          // process.control: inspect/stop
    RootFlag(&'static str),            // meta.version: "--version"
    None(Reason),
}
pub enum Selector { Always, Flag(&'static str), Fixed { field: &'static str, value: &'static str } }
pub enum McpExposure { Tool { name: &'static str, title: &'static str, description: &'static str }, None(Reason) }
pub struct Reason(pub &'static str);   // non-empty, ≥ 12 bytes (const-checked)
pub enum Auth { Owner, Session, Either }
pub enum Effect { Read, Write, Custody, Variant(&'static [(&'static str, Effect)]) }
pub enum Scope { None, Home, Project, ProjectOrAll, Session }
pub enum RuntimeNeed { None, HostForWrites, Host, HostAutoStart }
pub struct Family { pub name: &'static str, pub major: u16 }   // ("se.launch", 1)
```

`Cx` carries the verified `Authority` (built only by the host or the CLI bootstrap, never deserialized), the resolved `ProjectCtx` (from the session for bound calls, from §2.2 otherwise), the store handle (`StoreRead` always; `StoreWrite` routed through the host writer when a host holds `runtime.lock`, direct otherwise — one store function either way), an optional `HostLink` for custody, a `CancellationToken`, a `Clock`, and the `Features` set. `Validate::validate(&self) -> Result<(), SeError>` enforces bounds the JSON Schema also states (lengths, ranges, enum closure) so a library caller that skips schema validation gets the same refusal.

**Writer stamp (Prime decision, 2026-10-30).** Every store commit records which writer made it: `WriterMode::Host { generation }` when the running host's writer committed it, `WriterMode::Direct` when the CLI committed with no host running. The store writes this onto the event row in the commit transaction and returns it in `Committed { receipt, wakes, writer }`. The dispatcher, not the op, copies it into the output's `writer` field. An `Op::run` cannot construct or override a `WriterMode`; the type has no public constructor outside `se-store`. Every output family that carries a store receipt includes `writer` (Appendix A.0 lists them), and the freeze check treats it as a required stable field. An outside observer proves routing by comparing `writer.host_generation` with `se status` `$.runtime.generation` and with the event read back through `se history --event`, which carries the same object. No timing is involved. MCP and SE Code calls always commit through a host, so they always report `host`. A replayed receipt reports the writer of the original commit.

Owner-only selectors (an `AGENT` positional, `--all`) live in a flattened `OwnerSel<T>` field carrying `#[serde(skip)] #[schemars(skip)]`. They exist for the CLI and typed library callers and never appear in an MCP schema. A session call with a non-empty `OwnerSel` refuses `owner-required` before `run`.

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
    decision.supersede   => DecisionSupersede,   process.start    => ProcessStart,
    process.control      => ProcessControl,      process.list     => ProcessList,
    session.begin        => SessionBegin,        session.context  => SessionContext,
    session.turn         => SessionTurn,         session.end      => SessionEnd,
    hook.claude          => HookClaude,          store.backup     => StoreBackup,
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
| `async fn dispatch(AnyOp, Cx<'_>) -> Result<AnyOutput, SeError>` | §1.5 | every surface |
| `fn schema_catalogue(Option<&str>) -> SchemaCatalogue` | §1.6 | `se schema`, xtask |
| `const` assertions | §1.7 | compile-time mirror rules |

The typed library entry is `Host::call::<O: Op>(&self, &Authority, O) -> Result<O::Output, SeError>`; it goes through the same `dispatch` admission steps, monomorphised.

### 1.3 Clap generation

Leaves are grouped by `path[0]` into subcommands (`msg` → `send`, `inbox`, …). Each leaf is `<T as clap::Args>::augment_args(Command::new(leaf))`, with doc comments as help (one source for CLI help and schema descriptions). Three shapes need care:

* **Shared leaf, selector flag.** `doctor`, `doctor --fix`, `doctor --bundle [PATH]` are three ops on one leaf; the generator merges their args, puts the selector flags in one `ArgGroup` (`multiple(false)`), and `from_matches` picks the op whose `Selector::Flag` is present (else the `Always` one). Same for `history` / `history --event ID` and root `--version`.
* **Fixed field.** `process inspect` and `process stop` both decode `ProcessControl` with `action` fixed to `inspect` / `stop`.
* **Hidden.** `session *` and `hook claude` are `hide(true)`; `help --all` still lists them under "Integrations".

Global flags are attached per leaf according to `Scope`: `-p/--project` only for `Project`/`ProjectOrAll`; `--home` for everything except `None`; `--json`, `-q`, `--no-color`, `-h` everywhere. A global flag on an op that does not take it refuses `flag-not-applicable` (no inert acceptance). Before clap runs, a static matcher checks argv against the rename table (§7.5) and returns `renamed`/`command-retired` without loading any handler.

### 1.4 MCP catalogue

`ToolDef { name, title, description, input_schema: Value, output_schema: Value, annotations: { read_only_hint, destructive_hint, idempotent_hint } }`. Input schema is `schemars` draft 2020-12 with inlined subschemas, `additionalProperties: false` on every object, and owner fields skipped. Output schema is the `Output` type's schema, wrapped so `structuredContent` is the same object the CLI prints with `--json`. `tool_defs` filters: op has `McpExposure::Tool`; principal is a bound session (anonymous MCP callers get an empty list plus a server instruction to launch through `se`); feature on; grant present (`stateengine_agent_create` only when the session holds `agent.create`). Annotations derive from `Effect` (`Read` → read-only; `Custody` → destructive for stop).

### 1.5 Dispatcher

`dispatch` runs the same admission sequence for CLI, MCP and library:

1. Feature check → `feature-disabled` / `feature-not-built`.
2. Authority check against `auth`/`anonymous` → `owner-required`, `session-required`.
3. `human_only` → interactive TTY on stdin and stdout, and the process ancestry contains no launched agent lifecycle → else `human-terminal-required`.
4. Project resolution (§2.2) or session project; a conflicting `-p` → `project-conflicts-session`.
5. `Validate`.
6. Runtime need: `Host` → `HostLink` or `runtime-not-running`; `HostAutoStart` → start `se daemon --detach`, wait for the endpoint file (deadline 10 s) → `runtime-start-pending`; `HostForWrites` → route writes to the host writer if the lock is held.
7. `O::run(cx)`; on `Err`, authenticated refusals append `receipt.refused` per the data design.

### 1.6 `se schema`

`SchemaCatalogue { schema: "se.schema-catalogue/v1", api: "1.0", build, ops: [OpSchema], families: [FamilySchema], errors: [ErrorSchema] }`. `OpSchema` = name, CLI path(s), MCP name or reason, auth, anonymous, human_only, effect, scope, runtime, feature, since, input schema, output family. `ErrorSchema` = code, class, exit, detail schema. With `OP`, one `OpSchema` plus the families it references. Anonymous, discloses no state.

### 1.7 Compile-time mirror rules

Expanded as `const _: () = { ... };` blocks using `const fn` byte comparison:

* Every `CliExposure::None(r)` and `McpExposure::None(r)` has `r.0.len() >= 12` (a reason, not a placeholder).
* Every MCP name starts with `stateengine_`, matches `[a-z0-9_]+`, and is unique; every registry name is unique; no two leaves share a path unless their selectors differ.
* `auth == Owner` ⇒ `mcp` is `None` (MCP is session-bound).
* `anonymous` ⇒ name ∈ {`meta.version`, `meta.help`, `meta.schema`}.
* `human_only` ⇒ `auth == Owner` and `mcp` is `None`.
* `CATALOGUE.len() == 54 + 5 * cfg!(feature = "atlas")`; MCP tool count `== 20 + 5 * atlas`. Changing the allowlist means editing OPS.md and these constants in the same commit.

### 1.8 Schema freeze

`cargo xtask schema --check` regenerates `schemas/v1/ops.json`, `schemas/v1/<family>.json` and `schemas/v1/errors.json` and diffs them against the committed files. It is a CI build check, not a test suite. Allowed without a version bump: a new optional output field; a new optional input field with a default; a new op (bumps API minor); a new error code. Fails without a family major bump: removing or renaming a field, changing a type, making an input required, adding an output enum variant to a family that does not declare `open_enum` for that field, removing an input enum variant, changing exit mapping. A major bump keeps the N-1 encoder (§4.3). `xtask schema --write` updates the files; review sees the diff.

---

## 2. CLI grammar

### 2.1 Global flags

| Flag | Type | Default | Notes |
| --- | --- | --- | --- |
| `-p, --project PROJECT` | name or `prj_` id | §2.2 | project-scoped ops only |
| `--home DIR` | path | `SE_HOME`, else platform state dir | product state home; never a project |
| `--json[=vN]` | optional major | current major | JSON on stdout; `=vN` pins a family major still served (§4.3) |
| `-q, --quiet` | bool | false | suppresses human success text; errors still print |
| `--no-color` | bool | false | also `NO_COLOR`, `[output] color` |
| `-h, --help` | bool | | generated help, loads no handler |
| `-V, --version` | bool | | `meta.version`; accepts only `--json` |

Removed root flags (`--registry-root`, `--project-root`, `--repo-root`, `--root`, `--actor`, `--agent-id`) refuse `legacy-root-flag` with the replacement.

### 2.2 Project resolution (owner calls)

1. `-p/--project`. 2. `SE_PROJECT`. 3. Canonical cwd lookup: canonicalize cwd (Windows: `GetFinalPathNameByHandleW`, case-folded drive; Unix: `realpath`), find the closest registered root that is an ancestor-or-self; exact path-component prefix, never substring. 4. `default_project` from config. 5. The sole registered project. 6. Else `project-required` listing the registered projects (up to 20, then a count).

An unreadable registration at step 3 or two registrations at the same canonical root refuse (`registration-unreadable`, `cwd-registration-ambiguous`) instead of falling through. Lookup never creates. With `SE_SESSION` set, authority is that session: project and agent come only from the capability, owner-only ops refuse `owner-required`, and the owner credential is never consulted.

### 2.3 Bare `se`

Runs `project.status` with the next-step renderer. No store or no project: onboarding text, exit 0:

```
StateEngine 0.1.0 — no project here yet.
  An agent (Claude Code or Codex) works in a project: a folder StateEngine tracks.
  Start: se init            (adopts this folder; your files and Git history stay as they are)
  Then:  se launch <name>   (opens your first agent)
```

### 2.4 Argument vocabulary

| Token | Type and bounds |
| --- | --- |
| `AGENT` | `ag_…` id, or display name (case-insensitive), or imported alias; resolved before dispatch |
| `NAME` | 1–64 chars, `[A-Za-z0-9][A-Za-z0-9 ._-]*`, unique per project case-insensitively |
| `PROVIDER` | `claude` \| `codex` |
| `MODEL` | ≤128 bytes, passed to the provider and validated at launch |
| `BODY`, `TEXT`, `STATEMENT` | UTF-8; `-` reads stdin. Message body ≤64 KiB, task ≤16 KiB, working state ≤16 KiB, statement ≤8 KiB, reason ≤2 KiB |
| `KIND` | `note` (default) \| `task` \| `question` \| `answer` \| `blocker` \| `done` \| `handoff` \| `finding`. Import maps `task-pointer`→`task`, `ruling-request`→`question` |
| `KEY` | decision key `[a-z0-9][a-z0-9._-]{0,127}` |
| `ID` | typed opaque id (`msg_`, `dec_`, `ev_`, `obs_`, `ses_`); imported legacy ids accepted as-is |
| `CURSOR` | opaque, project- and principal-bound |
| `REV` | non-negative integer, or `absent` |
| `QUERY` | 1–512 bytes |
| Paging | `--limit N` (1–200, default 20), `--cursor CURSOR` on every list op |

### 2.5 Commands

Human examples are abridged. `Family` is the `--json` schema family (§4).

**Discovery, setup, configuration**

| Op | Command line | Human output | Family |
| --- | --- | --- | --- |
| meta.version | `se --version` | `stateengine 0.1.0 (commit a1b2c3d)` | `se.version/v1` |
| meta.help | `se help [PATH...] [--all]`; `se PATH --help` | usage, args, examples | `se.help/v1` |
| meta.schema | `se schema [OP]` | op table; with OP its schemas | `se.schema-catalogue/v1` |
| project.init | `se init [--repo DIR] [--name NAME] [--agent NAME] [--provider PROVIDER] [--model MODEL] [--launch]` — `--repo` default cwd; `--name` default dir name; `--agent` default `main`; `--provider` default `[launch] provider` (`claude`) | `Adopted ~/src/app as "app" (existing Git repo, 214 commits kept).`<br>`Agent "main" (claude) is ready. Next: se launch main` | `se.init/v1` (`profile.schema = stateengine-init/v1`) |
| project.remove | `se remove [-p P \| --all] [--keep-integrations]` (human-only) | `Stopped 2 agents (witnessed). Removed integrations: .mcp.json entry. Kept: history, repo files. Reinstall later with se init.` | `se.remove/v1` |
| project.status | `se status [-p P \| --all]`; bare `se` | `app — runtime up (daemon 0.1.0) · 2 agents: main running (claude), rev stopped · 3 unread for you · next: se msg inbox` | `se.status/v1` |
| doctor.inspect | `se doctor [-p P]` | `✓ store  ✓ credential  ✗ claude hooks: entry edited by you  ! containment: uncontained (no systemd user manager)` + `fix:` lines | `se.diagnosis/v1` |
| doctor.repair | `se doctor --fix [-p P]` | `Applied 1, skipped 1 (your edit kept), refused 0. Re-read: ok.` | `se.repair/v1` |
| doctor.bundle | `se doctor --bundle [PATH]` (default `./se-support-<utc>.zip`) | `Wrote se-support-20261030T1201Z.zip (412 KB, 31 files, no turn or message text, no secrets). Nothing was uploaded.` | `se.support-bundle/v1` |
| config.get | `se config get KEY [-p P] [--origin]` | `launch.provider = codex  (project app)` | `se.config-value/v1` |
| config.set | `se config set KEY VALUE [-p P]` | `launch.provider: claude → codex (project app)` | `se.config-receipt/v1` |
| config.list | `se config list [-p P] [--origin]` | aligned `key = value  (origin)` | `se.config-page/v1` |

**Runtime, agents, continuity**

| Op | Command line | Human output | Family |
| --- | --- | --- | --- |
| runtime.up | `se up [--foreground]` | `StateEngine running (daemon, pid 4120, generation 7, 127.0.0.1:3221).` | `se.runtime-start/v1` |
| runtime.down | `se down` | `Stopped the daemon (witnessed). Agents still running: main — stop them with se stop main.` | `se.runtime-stop/v1` |
| mcp.serve | `se mcp [--stdio]` (stdio is the only transport; flag is explicit for clients) | none (JSON-RPC on stdout) | MCP protocol |
| mcp.token | `se mcp token` | `{"Authorization":"Bearer sels-…"}` | header map (Claude `headersHelper` protocol; no `schema` key) |
| agent.list | `se agent list [-p P]` | table: name, id, provider/model, state, conversation, `resume:` command | `se.agent-page/v1` |
| agent.create | `se agent add NAME [--provider PROVIDER] [--model MODEL] [-p P]` | `Added agent "rev" (codex, profile default). Start it: se launch rev` | `se.agent-receipt/v1` |
| agent.show | `se agent show AGENT [-p P]` | identity, profile, lifecycle, conversation, last capture | `se.agent-status/v1` |
| agent.rename | `se agent rename AGENT NAME [-p P]` | `rev → reviewer (ag_01J…; history kept)` | `se.agent-receipt/v1` |
| agent.launch | `se launch AGENT [--new] [--provider PROVIDER] [--model MODEL] [--task TEXT] [--detach] [-p P]` — resumes the saved conversation unless `--new`; window by default, `--detach` = headless | `Resumed main (claude) in a new window — conversation 7f3a…, ready in 1.9 s. Stop: se stop main`; when not contained it adds `Uncontained: no systemd user manager (stop reaches only its process group).` | `se.launch/v1` |
| agent.stop | `se stop AGENT \| --all [-p P]` | `Stopped main (exit witnessed). Resume: se launch main` | `se.stop/v1` (`receipt = seat-stop/v1`) |
| agent.wake | `se wake AGENT [-p P]` | `Offered 2 unread messages to main (delivered to its session; not yet read).` | `se.wake/v1` |
| continuity.resume | `se resume [--since CURSOR] [--budget BYTES] [--preview AGENT]` (`--budget` 1024–1048576, default 32768; `--preview` owner only) | sections: who you are, working state, unread, required reads, omissions, next cursor | `se.resume/v1` |
| working_state.get | `se working-state [--agent AGENT]` | text + `revision 12` or `no working state yet` | `se.working-state/v1` |
| working_state.set | `se working-state set TEXT --expect REV [--agent AGENT]` | `Saved revision 13.` | `se.working-state-receipt/v1` |
| history.search | `se search QUERY [--kind turn\|message\|decision]... [--since TIME] [--until TIME] [--agent AGENT] [--limit N] [--cursor C]` | hits: time, kind, who, snippet, `history --event` id | `se.search-page/v1` |
| history.list | `se history [--agent AGENT] [--since CURSOR] [--limit N]` | chronological turns/messages/decisions | `se.history-page/v1` |
| history.event_read | `se history --event ID` | the event, provenance, `read from store at seq N` | `se.event/v1` |

**Messages and decisions**

| Op | Command line | Human output | Family |
| --- | --- | --- | --- |
| message.send | `se msg send TO BODY [--kind KIND] [--ref ID]... [--reply-to ID] [--key IDEMPOTENCY]` — `TO` is `AGENT` or `owner` | `Sent msg_01J… to rev (committed; delivery pending).` | `se.message-receipt/v1` |
| message.inbox | `se msg inbox [AGENT] [--full] [--limit N]` | unread list with 200-char previews; footer `3 of 7 unread shown — se msg inbox --cursor …` (exit 2) | `se.message-page/v1` |
| message.list | `se msg list [--to AGENT] [--from AGENT] [--kind KIND] [--all] [--full] [--limit N] [--cursor C]`. `--all` includes read and dismissed messages. `--full` prints complete bodies instead of previews, within the fixed page body budget of 256 KiB: a body is never cut, each page holds at least one row, and the rest comes through `--cursor`. Listing never creates or changes read or delivered markers; only `msg read`, `ack` and `dismiss` do. The owner may list any message in the project. Under a session, only messages the agent sent or received are listed. | table with disposition column; with `--full`, each message in full under a header line | `se.message-page/v1` |
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

`--expect` defaults to the revision read at command start; the CLI re-reads and shows the statement before a human-only change, so the default is not a blind overwrite.

**Process custody, integrations, data, Atlas**

| Op | Command line | Human output | Family |
| --- | --- | --- | --- |
| process.start | `se process start [--cwd DIR] [--env KEY=VALUE]... -- COMMAND ARGS...` | `Started obs_… (pid 9132, started 12:01:07Z).` | `se.process-receipt/v1` |
| process.control | `se process inspect --observation O`; `se process stop --observation O [--deadline MS]` (default 5000, max 30000) | `obs_…: running (identity rechecked)` / `stopped, 3 processes gone (witnessed)` | `se.process-observation/v1`, `se.process-stop/v1` |
| process.list | `se process list [-p P] [--limit N]` | instances with `observed running at T` / `unknown` | `se.process-page/v1` |
| session.begin | `se session begin --agent AGENT --source claude\|codex\|secode --provider-session ID [--incognito]` (hidden; stdout must be a pipe) | none | `se.session-begin/v1` |
| session.context | `se session context [--budget BYTES] [--since CURSOR]` (hidden; capability from `SE_SESSION` or stdin line 1) | none | `secode.session-context-v1` |
| session.turn | `se session turn` (hidden; stdin one `se.turn/v1` JSON object ≤1 MiB) | none | `se.turn-receipt/v1` |
| session.end | `se session end [--session ID] --reason REASON --expect-generation N` (hidden) | none | `se.session-end/v1` |
| hook.claude | `se hook claude session-start\|prompt\|stop\|stop-failure` (hidden; native stdin) | Claude hook stdout protocol | Claude hook protocol |
| store.backup | `se backup [PATH]` (default `$SE_HOME/backups/state-<utc>.db`) | `Backed up to …db (184 MB, schema 3, verified by re-open).` | `se.backup/v1` |
| store.import_node | `se import --from-node PATH` | per family: read/imported/duplicate/unreadable/dropped; originals untouched | `se.import/v1` |
| store.forget | `se forget --event ID [--event ID]...` (human-only; asks to type the first id) | erased bodies, index rows, file pages; named residual copies | `se.erasure/v1` |
| atlas.find | `se atlas find QUERY [--kind symbol\|text\|path] [--in PATH] [--limit N]` | `src/store/tx.rs:41 fn commit (symbol, resolved)` | `se.code-hits/v1` |
| atlas.refs | `se atlas refs SYMBOL [--path PATH] [--limit N] [--cursor C]` | sites with enclosing symbol and `resolved`/`name-only` | `se.code-refs/v1` |
| atlas.impact | `se atlas impact SYMBOL [--path PATH] [--depth 1..3]` (default 2) | dependents by hop, tests, omitted frontier | `se.impact/v1` |
| atlas.changes | `se atlas changes [--since CURSOR\|COMMIT\|TIME] [--limit N]` | added/removed/signature/body changes | `se.code-changes/v1` |
| atlas.outline | `se atlas outline PATH` | symbol tree with lines | `se.outline/v1` |

`identity.whoami` has no CLI (OPS.md); in an agent shell `se status` shows the bound principal.

---

## 3. MCP tool set

Session-bound: no tool takes `project_id`, `agent_id`, `actor`, or an authority field. The session comes from the HTTP bearer (`selp-`/`sels-`, one principal per connection) or, on stdio and in SE Code, per-call `_meta["stateengine.session-capability-v1"]` (`sec1.…`). Invalid or revoked → error, never a fallback. Every tool's auth is **session**. Common errors on every tool: `session-required`, `capability-invalid`, `capability-revoked`, `capability-expired`, `input-unknown-field`, `usage-invalid-value`, `input-too-large`, `store-unreadable`, `store-busy`, `internal`. The table lists the rest.

| Tool | Description (verbatim) | Input | Output | Extra errors |
| --- | --- | --- | --- | --- |
| `stateengine_whoami` | "Who you are in StateEngine: your project, agent identity, session and what you are allowed to do." | — | `Principal`: project{id,name}, agent{id,name}, session{id,source,generation}, grants[], binding | — |
| `stateengine_status` | "Your project at a glance: runtime, your agent's state, unread messages, pending decisions and the suggested next step." | — | `Status` (session view) | `runtime-version-mismatch` |
| `stateengine_resume` | "Restore your context after a restart or compaction: working state, unread mail, required reads and what was left out. Pass `since` from the last result to get only what changed." | `since?` cursor, `byte_budget?` int 1024–1048576 (32768) | `Resume`: principal, status ready/needs_read/integrity_blocked, working_state, unread[], required_reads[], omissions[], next_cursor, complete | `cursor-invalid`, `cursor-expired` |
| `stateengine_working_state_set` | "Replace your working-state note (what you are doing, what is next). Send the revision you last read as `expect`, or \"absent\" for the first write." | `text` ≤16 KiB, `expect` int\|"absent" | `WorkingStateReceipt`: revision, committed\|conflict, current_revision | `revision-conflict` |
| `stateengine_search` | "Search your project's history (turns, messages, decisions) you are allowed to see. Results are pointers; read an event with stateengine_event_read before relying on it." | `query` 1–512, `kinds?` [turn,message,decision], `since?`/`until?` RFC 3339, `limit?` 1–50 (20), `char_budget?` 500–32000 (8000), `cursor?` | `Page<SearchHit>`: event_id, kind, at, who, snippet; window | `cursor-invalid` |
| `stateengine_event_read` | "Read one committed event back from the store by id, with its provenance." | `event_id` | `Read<HistoryEvent>` | `event-unknown`, `event-unreadable` |
| `stateengine_msg_send` | "Send a message to another agent in your project, or to `owner` (the human). The result says it was committed; it does not mean it was read." | `to` (name/id/`owner`), `body` ≤64 KiB, `kind?` (note), `refs?` ≤20 ids, `reply_to?`, `idempotency_key?` ≤128 | `MessageReceipt`: message_id, event_id, state committed\|deduplicated, delivery pending\|offered\|not-running | `recipient-unknown`, `reply-target-unknown`, `idempotency-key-reused` |
| `stateengine_msg_list` | "List messages you sent or received. Default: unread messages addressed to you, oldest first, with body previews. Set `full` to get complete bodies; listing never marks anything read (use stateengine_msg_read for that). `complete` tells you whether anything was left out." | `view?` unread\|all (unread), `box?` inbox\|sent (inbox), `from?`, `kind?`, `full?` bool (false), `limit?` 1–100 (20), `preview_chars?` 0–4000 (400; not allowed with `full`), `cursor?` | `se.message-page/v1` (A.5): id, from, to, kind, at, disposition, `body.text`, `body.complete` (true for every row when `full`); a page holds at most 256 KiB of bodies, with the rest via `cursor` | `cursor-invalid`, `usage-conflicting-flags` (`full` with `preview_chars`) |
| `stateengine_msg_read` | "Read one message in full and mark it read." | `id` | `MessageRead`: message, body_complete, marker{state committed\|already, at} | `message-unknown`, `not-recipient` |
| `stateengine_msg_ack` | "Acknowledge a message you have handled. This records that you read it; it is not a reply." | `id`, `idempotency_key?` | `DispositionReceipt` | `message-unknown`, `not-recipient` |
| `stateengine_msg_dismiss` | "Dismiss a message without marking it read. It stays in history." | `id`, `idempotency_key?` | `DispositionReceipt` | `message-unknown`, `not-recipient` |
| `stateengine_decision_propose` | "Propose a project decision for the human to approve. You cannot approve it yourself. `supersedes` proposes replacing an existing decision." | `key`, `statement` ≤8 KiB, `rationale?` ≤8 KiB, `supersedes?`, `idempotency_key?` | `DecisionReceipt`: id, state pending | `decision-key-invalid`, `decision-unknown`, `idempotency-key-reused` |
| `stateengine_decision_list` | "List project decisions. Pass `id` for one decision; `pending` for proposals awaiting approval; `history` to include retracted and superseded ones." | `id?`, `pending?` bool, `history?` bool, `limit?` 1–100 (20), `cursor?` | `Page<Decision>` | `cursor-invalid` |
| `stateengine_agent_create` | "Create a new agent identity in your project (requires the agent-create permission). This does not start it." | `name`, `provider` claude\|codex, `model?`, `profile?` (saved, non-bypass) | `AgentReceipt`: agent{id,name}, created\|existing | `grant-required`, `agent-name-taken`, `agent-name-invalid`, `profile-unknown`, `bypass-not-opted-in` |
| `stateengine_agent_status` | "Your agent's lifecycle, conversation, capture and resume facts." | — | `Read<AgentStatus>` | — |
| `stateengine_agent_launch` | "Start or resume your agent's conversation through the runtime. Resumes by default; `new: true` starts a fresh conversation." | `new?` bool, `model?`, `task?` ≤16 KiB, `detach?` bool (true) | `LaunchResult` | `runtime-not-running`, `agent-already-running`, `launch-in-flight`, `resume-reference-missing`, `resume-reference-unverifiable`, provider errors |
| `stateengine_agent_stop` | "Stop your own agent process after the current turn. Returns the exact command that resumes this conversation." | — | `StopReceipt` | `runtime-not-running`, `stop-unwitnessed` |
| `stateengine_process_start` | "Start a process you own (literal argv, no shell). Returns an observation handle for stateengine_process_stop." | `argv` [1–256 strings], `cwd?` workspace-relative, `env?` map ≤32 keys | `ProcessReceipt` | `custody-unavailable-hostless`, `command-not-found`, `spawn-failed`, `cwd-outside-workspace`, `env-key-not-allowed` |
| `stateengine_process_stop` | "Inspect or stop a process you started, by observation handle. Stop re-checks identity and confirms the whole tree is gone." | `action` inspect\|stop, `observation`, `deadline_ms?` 0–30000 (5000) | `ProcessObservation` \| `ProcessStop` | `observation-unknown`, `observation-not-yours`, `process-identity-changed`, `process-identity-unreadable`, `stop-deadline-exceeded` |
| `stateengine_session_turn` | "Record one conversation turn for this session (used by integrations, not for notes)." | `role` user\|assistant, `content` ≤1 MiB, `occurred_at`, `provider_session_id`, `turn_id?`, `event_id?`, `source` claude\|codex\|secode | `TurnReceipt`: captured\|duplicate\|suppressed, event_id | `capture-consent-missing`, `turn-invalid`, `session-generation-mismatch` |
| `stateengine_atlas_find` | "Find code by symbol name, text or path in your project. Each hit says whether it was resolved or matched by name only." | `query`, `kind?` symbol\|text\|path (symbol), `in?` path prefix, `limit?` 1–50 (20) | `Page<CodeHit>` + index_state | `feature-disabled`, `atlas-index-absent`, `atlas-unreadable` |
| `stateengine_atlas_refs` | "Who uses this symbol: imports, calls and type references." | `symbol`, `path?`, `limit?`, `cursor?` | `Page<Reference>` | + `atlas-symbol-unknown`, `atlas-symbol-ambiguous` |
| `stateengine_atlas_impact` | "What could break if this symbol changes: dependents up to 3 hops, with tests that reference them." | `symbol`, `path?`, `depth?` 1–3 (2), `budget?` | `Impact` | + `atlas-symbol-unknown`, `atlas-symbol-ambiguous` |
| `stateengine_atlas_changes` | "Code changes since you last looked (or since a cursor/commit/time)." | `since?`, `limit?`, `cursor?` | `Page<CodeChange>` | + `cursor-invalid` |
| `stateengine_atlas_outline` | "The symbol outline of one file." | `path` root-relative, `budget?` | `Read<Outline>` | + `atlas-path-outside-root`, `atlas-path-unknown`, `atlas-language-unsupported`, `atlas-file-over-budget` |

Framing: success is `structuredContent` (the family object) plus one text block (the human rendering). A domain error is `isError: true`, `structuredContent` = `se.error/v1`, text = the human error with its `fix:` line; a remedy that is a tool call carries `remedy.tool {name, arguments}`. Protocol errors stay JSON-RPC: unknown tool and malformed frames `-32602`/`-32600`, unknown method `-32601`, unsupported protocol revision `-32022`. Schema-invalid arguments are tool errors (`isError`), so the model can correct them.

Open item, not decided here: OPS.md makes session `agent_launch`/`agent_stop` act on self only. Delegated launch of an agent the caller just created (an obvious J4 shape) needs an OPS.md amendment first.

---

## 4. Output contracts

### 4.1 Envelope rules

Every JSON object printed by `--json`, returned as MCP `structuredContent` or exported by `se schema` carries `"schema": "<family>/v<major>"` as its first key. `Read<T>` serializes as `{"state":"present","value":…}` \| `{"state":"absent","checked":"…"}` \| `{"state":"unreadable","source":"…","reason":"…"}` \| `{"state":"unknown","what":"…"}`. `Page<T>` serializes as `{"items":[…],"window":{"from":C,"to":C,"limit":n,"complete":bool,"omitted":{"count":n|null,"reason":"limit|budget|unreadable|source-incomplete"}},"next":C|null}`. Receipts carry `event_id`, `state` (`committed`/`replayed`/`refused`/`pending`) and any delivery fact separately. Unknown output fields must be ignored by consumers; stable fields never change meaning within a major.

### 4.2 Families

| Family | Op(s) | Stability | Key consumer |
| --- | --- | --- | --- |
| `se.version/v1` | meta.version | **stable** | SE Code installer, J1 runner |
| `se.help/v1`, `se.schema-catalogue/v1` | meta.help, meta.schema | **stable** | factory tooling |
| `se.principal/v1` | identity.whoami | **stable** | agents |
| `se.init/v1` (+ `stateengine-init/v1` profile) | project.init | **stable** | SE Code onboarding, J2 |
| `se.remove/v1` | project.remove | stable | J5 runner |
| `se.status/v1` | project.status | **stable** | SE Code, factory |
| `se.diagnosis/v1`, `se.repair/v1`, `se.support-bundle/v1` | doctor.* | evolving | humans |
| `se.config-value/v1`, `se.config-receipt/v1`, `se.config-page/v1` | config.* | stable | |
| `se.runtime-start/v1`, `se.runtime-stop/v1` | up/down | stable | SE Code handover |
| `se.agent-page/v1`, `se.agent-receipt/v1`, `se.agent-status/v1` | agent.* | **stable** | SE Code, factory |
| `se.launch/v1` | agent.launch | **stable** | SE Code, factory |
| `se.stop/v1` (`receipt: "seat-stop/v1"`, `resume.command`) | agent.stop | **stable** | factory, J3 |
| `se.wake/v1` | agent.wake | stable | |
| `se.resume/v1` | continuity.resume | **stable** | agents, factory |
| `se.working-state/v1`, `se.working-state-receipt/v1` | working_state.* | stable | |
| `se.search-page/v1`, `se.history-page/v1`, `se.event/v1` | history.* | **stable** (`se.event`) | J3/J4 runner |
| `se.message-receipt/v1`, `se.message-page/v1`, `se.message-read/v1`, `se.disposition-receipt/v1` | message.* | **stable** | SE Code, factory |
| `se.decision-receipt/v1`, `se.decision-page/v1`, `se.decision/v1` | decision.* | **stable** | factory |
| `se.process-receipt/v1`, `se.process-observation/v1`, `se.process-stop/v1`, `se.process-page/v1` | process.* | stable | |
| `se.session-begin/v1`, `se.turn-receipt/v1`, `se.session-end/v1`, input `se.turn/v1` | session.* | **stable** | SE Code, hooks |
| `secode.session-context-v1` (`contract` key, `schema_version: 1`; fields per contracts.md O8) | session.context | **frozen** | SE Code |
| `se.backup/v1`, `se.import/v1`, `se.erasure/v1` | store.* | stable | |
| `se.code-hits/v1`, `se.code-refs/v1`, `se.impact/v1`, `se.code-changes/v1`, `se.outline/v1` | atlas.* | evolving until Atlas leaves alpha | agents |
| `se.error/v1` | every error | **stable** | everyone |
| protocols: Claude hook stdout, `headersHelper` header map, MCP JSON-RPC, `sec1`/`selp-`/`sels-` tokens | hook, mcp token, mcp | **stable** | Claude, Codex |

"Stable" = covered by the freeze check and N/N-1. "Evolving" = freeze-checked, but a major bump needs no N-1 window during alpha.

### 4.3 N/N-1 policy

A breaking change bumps the family major. For one minor release after a bump the producer keeps the N-1 encoder: CLI `--json=vN-1`, library `Host::open` negotiated API range (SE Code pins its range, the host serves the DTO version it negotiated), MCP always serves N (agents read descriptions, not pinned decoders). `--json=v` older than N-1 refuses `json-version-unsupported` naming the served majors. `secode.session-context-v1` never changes in place; a v2 must be requested by the caller. Stored handles (old `seat-stop/v1` resume commands, imported ids) remain migration inputs: `se launch` accepts an imported conversation reference; it never executes an old command name.

---

## 5. Exit codes

| Exit | Meaning | Classes / payload states |
| --- | --- | --- |
| 0 | complete — including measured absence and zero | success; `Read::Present`, `Read::Absent`; complete `Page`; paged `Page` whose only omission reason is `limit`/`budget` |
| 1 | failed or refused | `Refused`, `Unauthorized`, `Conflict`, `Unavailable`, `Internal`, `Cancelled` |
| 2 | incomplete | `Incomplete`; `msg inbox` when not every unread message is in the window, any row is unreadable, or (`--full`) a body stays truncated; `Page` omissions for `unreadable`/`source-incomplete`; doctor with an unmeasured check and no failed one; stop/remove with an unwitnessed effect |
| 3 | unreadable | `Unreadable`; `Read::Unreadable` |
| 4 | unknown target | `Unknown`; `Read::Unknown` |
| 64 | usage | `Usage` (also `renamed`, `command-retired`) |

Rules: `ExitStatus::exit(&self)` on each output computes the code from payload facts, so a nonzero exit always comes with the full payload on stdout. Doctor: 0 all healthy, 1 any check failed, 2 none failed but some unmeasured. `se hook claude` always exits 0 (Claude treats exit 2 as blocking; a failed capture is a recorded fact and a stderr line). `se mcp` exits 0 on EOF and 1 on a transport failure. Human errors go to stderr; with `--json` the `se.error/v1` object goes to stdout and the human text still goes to stderr.

---

## 6. Error catalog

### 6.1 Shape

```rust
pub struct SeError { pub code: Code, pub retry: Retry, pub cause: Option<Box<dyn Error + Send + Sync>> }
#[non_exhaustive] pub enum Code { /* generated by codes! */ }
pub enum Class { Usage, Refused, Unauthorized, Unknown, Unreadable, Conflict, Incomplete, Unavailable, Internal, Cancelled }
pub enum Retry { Never, AfterReread, After(Duration), WhenRuntimeReady }
pub struct Remedy { pub text: String, pub command: Option<Cmd> }
pub enum Cmd { Se(Argv), Tool { name: &'static str, args: Value }, Manual }
impl Code { pub fn as_str(&self) -> &'static str; pub fn class(&self) -> Class;
            pub fn message(&self) -> String; pub fn remedy(&self, cx: &RenderCx) -> Remedy; }
```

One `codes!` table generates the enum, `as_str`, `class`, `message` and `remedy`; a row without class, template and remedy does not compile. `Cmd::Se` is built from a typed op input (`Argv::from_op(&AgentLaunch { agent, new: true, .. })`), so a remedy cannot name a command that is not in the registry. `Cmd::Manual` (only where the fix is outside the product, e.g. installing Claude Code) still has text. `se.error/v1` = `{schema, code, class, exit, message, detail, remedy{text, command[]|null, tool|null}, retry}`. Human form:

```
error[agent-unknown]: no agent named "revewr" in project app (did you mean "reviewer"?)
  fix: se agent list -p app
```

In the tables below, `{x}` interpolates a detail field; `→` gives the remedy command; class abbreviations: U Usage, R Refused, A Unauthorized, K Unknown, X Unreadable, C Conflict, I Incomplete, V Unavailable, N Internal, Z Cancelled.

### 6.2 Surface and input (18)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| usage-unknown-command | U | got, suggestion? | unknown command `{got}` | → `se help` |
| usage-unknown-flag | U | flag, command, suggestion? | `{command}` has no flag `{flag}` | → `se help {command}` |
| usage-missing-argument | U | command, argument | `{command}` needs {argument} | → `se help {command}` |
| usage-invalid-value | U | argument, got, expected | {argument}: `{got}` is not {expected} | correct the value |
| usage-conflicting-flags | U | flags[] | {flags} cannot be used together | pick one |
| flag-not-applicable | U | flag, command | `{flag}` has no meaning for `{command}` | drop the flag |
| input-unknown-field | U | op, field | `{field}` is not an input of {op} | → `se schema {op}` / tools/list |
| input-too-large | U | field, limit_bytes, got_bytes | {field} is {got_bytes} bytes; limit {limit_bytes} | shorten or split it |
| renamed | U | old, replacement | `{old}` was renamed | → `{replacement}` (template; fill placeholders) |
| command-retired | U | old, reason, workflow | `{old}` was retired: {reason} | {workflow} |
| legacy-root-flag | U | flag | `{flag}` was removed; projects come from the registry | → `se init --repo DIR` or `-p P` |
| feature-disabled | R | feature | {feature} is turned off | → `se config set {feature}.enabled true` |
| feature-not-built | R | feature | this build of se does not include {feature} | install the standard build from stateengine.ai |
| json-version-unsupported | U | family, requested, served[] | {family} v{requested} is not served (have {served}) | → `--json` |
| tool-unknown | U | name | no tool `{name}` | use tools/list |
| tool-not-available | A | name, reason | `{name}` is not available to this session ({reason}) | ask the owner, or use tools/list |
| secret-to-terminal-refused | R | what | refusing to print {what} to a terminal | run it through a pipe (integrations only) |
| stdin-required | U | what | {what} is read from stdin, which is a terminal | pipe the input |

### 6.3 Authority (14)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| owner-required | A | op | `{op}` is an owner command; agent sessions can't run it | run it in your own terminal (unset `SE_SESSION`) |
| human-terminal-required | A | op, reason (no-tty \| agent-process-tree) | `{op}` needs you at an interactive terminal not started by an agent | run `se {op}` in a terminal you opened |
| session-required | A | op | `{op}` acts as an agent and needs a launched session | → `se launch AGENT` |
| machine-credential-missing | R | path | no machine credential at {path} | → `se init` |
| machine-credential-unreadable | X | path, reason | can't read the machine credential: {reason} | → `se doctor` |
| os-user-mismatch | A | expected, actual | this StateEngine home belongs to {expected}, you are {actual} | use your own `SE_HOME` |
| capability-invalid | A | reason (malformed \| unknown \| bad-secret) | the session credential is not valid ({reason}) | relaunch: → `se launch AGENT` |
| capability-revoked | A | session, at, reason | session {session} was ended at {at} ({reason}) | → `se launch AGENT` |
| capability-expired | A | session, at | the session token expired at {at} | the helper renews it; if not → `se launch AGENT` |
| project-conflicts-session | U | flag_project, session_project | `-p {flag_project}` conflicts with this session's project {session_project} | drop `-p` |
| grant-required | A | grant | this session lacks permission `{grant}` | owner: → `se config set agent.{agent}.can-create true -p P` |
| not-recipient | A | message, recipient | only {recipient} can mark {message} read or dismissed | read it with `se msg read` as that agent, or leave it |
| self-approval-refused | A | decision | agents can propose decisions but not approve them | owner: → `se decision ratify {decision}` |
| listener-admission-refused | A | reason (host \| origin \| bearer-missing \| bearer-invalid \| second-principal) | local server refused the request: {reason} | reconnect through `se mcp token`; non-loopback access is not supported |

### 6.4 Project, home and configuration (16)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| project-required | U | choices[] {name,id,root} | which project? none registered here | → `se init` (none) or `se … -p NAME` |
| project-unknown | K | selector | no project `{selector}` | → `se status --all` |
| project-ambiguous | U | selector, matches[] | `{selector}` names {n} projects | use the id: `-p prj_…` |
| project-removed | R | project, at | project {project} was removed at {at} | re-adopt: → `se init --repo {root}` |
| registration-unreadable | X | path, reason | can't read project registrations: {reason} | → `se doctor` |
| cwd-registration-ambiguous | U | cwd, candidates[] | {cwd} is registered twice | → `-p P`, then `se doctor --fix` |
| home-unreadable | X | home, reason | can't read StateEngine home {home}: {reason} | → `se doctor` |
| home-unsupported-location | R | home, kind (network \| synced \| read-only) | {home} is on a {kind} location; the store needs a local disk | set `SE_HOME` to a local folder |
| config-unreadable | X | path, reason | can't read {path}: {reason} | fix permissions or → `se doctor` |
| config-invalid | R | path, line, column, problem | {path}:{line}:{column}: {problem} | edit the file |
| config-key-unknown | U | key, suggestion? | no setting `{key}` | → `se config list` |
| config-value-invalid | U | key, got, expected | {key}: `{got}` is not {expected} | → `se config get {key} --origin` |
| config-scope-invalid | U | key, scope | `{key}` is a {scope} setting | drop or add `-p` |
| config-version-unsupported | R | path, version, supported | {path} is format v{version}; this se reads v{supported} | upgrade se |
| profile-unknown | R | profile | no permission profile `{profile}` | → `se config list`; define `[profiles.{profile}]` |
| bypass-not-opted-in | R | profile | full bypass is only allowed through a saved, named profile | add `bypass = true` under `[profiles.NAME]`, then → `se config set agent.A.profile NAME` |

### 6.5 Init and remove (9)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| repo-not-found | R | path | {path} does not exist | → `se init --repo DIR` with an existing folder |
| repo-not-directory | R | path | {path} is not a folder | pick the repository folder |
| repo-inside-project | C | path, project, root | {path} is inside project {project} ({root}) | use it: → `se status -p {project}` |
| repo-name-mismatch | C | root, project, requested | {root} is already project {project} | rerun without `--name` |
| integration-conflict | C | path, entry | you changed {entry} in {path}; StateEngine won't overwrite it | keep it, or delete the entry and → `se doctor --fix` |
| integration-write-failed | R | path, reason | couldn't write {path}: {reason} | → `se doctor` |
| integration-readback-mismatch | R | path, entry | wrote {entry} in {path} but read back something else | → `se doctor --fix` |
| remove-target-required | U | choices[] | name the project to remove | → `se remove -p P` or `se remove --all` |
| remove-incomplete | I | stopped[], unwitnessed[], remaining[] | removal partly done: {remaining} | → `se remove -p P` (idempotent) |

### 6.6 Store (25)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| store-absent | R | home | no StateEngine data in {home} | → `se init` |
| store-unreadable | X | path, reason (permission \| io \| not-sqlite \| foreign-application-id) | can't read the store: {reason} | → `se doctor` |
| store-corrupt | X | path, check | the store failed its integrity check ({check}) | → `se doctor --fix` (restores from the newest good backup + salvage) |
| store-too-new | R | store_version, supported | the store was written by a newer se (schema {store_version}) | upgrade se |
| store-migration-required | V | from, to | the store needs a schema upgrade; ordinary start, status and auto-start never migrate | → `se down`, then `se doctor --fix` (explicit owner migration under the exclusive lease, verified backup first) |
| store-migration-failed | R | from, to, step, rollback_copy | upgrade {from}→{to} failed at {step}; old copy kept at {rollback_copy} | → `se doctor` |
| store-busy | V | waited_ms | the store stayed locked for {waited_ms} ms | retry (`Retry::After`) |
| store-disk-full | V | path, free_bytes | not enough disk space at {path} | free space and retry |
| store-read-only | R | path | {path} is read-only | fix permissions or `SE_HOME` |
| revision-conflict | C | entity, expected, current | {entity} changed (you had revision {expected}, now {current}) | reread: → `se working-state` / `se decision show ID` |
| idempotency-key-reused | C | key, original_event | key `{key}` was used for a different request | use a new key |
| event-unknown | K | event | no event {event} in this project | → `se search QUERY` |
| event-unreadable | X | event, reason | event {event} exists but can't be decoded: {reason} | → `se doctor` |
| cursor-invalid | U | reason (malformed \| other-project \| other-principal) | this cursor isn't valid here ({reason}) | rerun without `--since` |
| cursor-expired | I | oldest_available | the cursor is older than retained history | rerun without `--since` |
| backup-destination-exists | R | path | {path} already exists | choose another path |
| backup-failed | R | path, step, reason | backup failed at {step}: {reason} | → `se doctor` |
| backup-readback-mismatch | R | path | the backup at {path} didn't verify | → `se backup` to a new path |
| import-source-unreadable | X | path, reason | can't read Node state at {path}: {reason} | check the path |
| import-format-unsupported | R | path, found, supported[] | {path} is format {found}; supported: {supported} | upgrade Node StateEngine first, then import |
| import-source-active | R | path, pid? | the old StateEngine is still running on {path} | stop it with the old `se down`, then retry |
| import-incomplete | I | families[] {name, rejected, unreadable} | import finished with rejected rows | rerun (idempotent); see the receipt |
| forget-confirmation-required | R | events[] | erasure needs typed confirmation | rerun in a terminal and type the first id |
| forget-not-captured-record | R | event, kind | only captured turns and messages can be erased; {event} is a {kind} | pick a captured record |
| forget-incomplete | I | erased[], residual[] | erased in the store; copies remain in {residual} | delete or let backups expire; provider transcripts belong to Claude/Codex |

### 6.7 Runtime and listener (14)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| runtime-not-running | V | op | `{op}` needs the StateEngine runtime | → `se up` |
| runtime-start-failed | V | reason, log | the runtime didn't start: {reason} | see {log}; → `se doctor` |
| runtime-start-pending | I | waited_ms | the runtime is still starting after {waited_ms} ms | → `se status` |
| runtime-owned-elsewhere | R | host (secode \| daemon), pid, version | the runtime is hosted by {host} | quit SE Code to stop it |
| runtime-version-mismatch | R | running, this | runtime {running} is running; this se is {this} | → `se down`, then retry |
| legacy-runtime-running | R | pid? | the old Node StateEngine is running on this home | stop it with the old `se down` |
| runtime-handover-in-progress | V | generation | the runtime is changing hosts | retry (`WhenRuntimeReady`) |
| runtime-drain-timeout | I | deadline_ms, pending[] | shutdown didn't finish in time: {pending} | → `se down` |
| runtime-stop-unwitnessed | I | pid, reason | stop requested but exit not confirmed: {reason} | → `se status` |
| listener-port-in-use | R | port, holder? | port {port} is in use | → `se config set runtime.listen_port N` |
| listener-non-loopback | R | address | `{address}` is not loopback; only 127.0.0.1 is allowed | fix `runtime.listen_address` |
| ipc-unavailable | V | endpoint, reason | can't reach the runtime: {reason} | → `se status` |
| api-version-unsupported | R | client, host | client API {client} vs runtime {host} | upgrade the older side |
| custody-unavailable-hostless | V | op | this stdio server has no runtime; `{op}` can't act | → `se up` |

### 6.8 Agents, launch and providers (22)

Containment is never a refusal. On Linux a launch with no delegated cgroup succeeds uncontained and says so in `containment`/`containment_cause` (A.2); the former `cgroup-delegation-missing` refusal is removed and its facts live in the `custody.linux-cgroup` doctor check (A.10).

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| agent-unknown | K | selector, suggestion? | no agent `{selector}` in {project} | → `se agent list` |
| agent-ambiguous | U | selector, matches[] | `{selector}` matches {n} agents | use the id |
| agent-name-taken | C | name, agent | `{name}` is already agent {agent} | → `se launch {name}` or pick another name |
| agent-name-invalid | U | name, rule | `{name}`: {rule} | choose another name |
| provider-unsupported | U | got | `{got}` isn't a provider (claude, codex) | |
| provider-cli-not-found | R | provider, searched[] | can't find the {provider} CLI | install it (`Cmd::Manual`), or → `se config set providers.{provider}.command PATH` |
| provider-cli-too-old | R | provider, found, minimum | {provider} {found} is older than {minimum} | upgrade {provider} |
| provider-cli-unrecognized | R | provider, output | couldn't read the {provider} version | → `se doctor` |
| provider-protocol-unsupported | R | provider, version, needed | {provider} {version} lacks {needed} | upgrade {provider} |
| provider-change-breaks-resume | R | agent, saved, requested | {agent}'s conversation is a {saved} conversation | → `se launch {agent} --new --provider {requested}` |
| resume-reference-missing | R | agent | {agent} has no saved conversation to resume | → `se launch {agent} --new` |
| resume-reference-unverifiable | X | agent, conversation, reason | can't verify conversation {conversation}: {reason} | → `se launch {agent} --new` (starts fresh, explicitly) |
| agent-already-running | C | agent, pid, since | {agent} is already running (since {since}) | message it, or → `se stop {agent}` |
| launch-in-flight | C | agent, launch_id | {agent} is already being launched | retry |
| launch-readiness-timeout | I | agent, waited_ms, last_observed | {agent} started but wasn't ready after {waited_ms} ms | → `se agent show {agent}` |
| launch-failed | R | agent, provider, exit_code?, stderr_tail | {provider} exited during launch: {stderr_tail} | fix the provider error, then → `se launch {agent}` |
| window-unavailable | R | tried[] | no terminal window could be opened ({tried}) | → `se launch AGENT --detach`, or set `launch.terminal` |
| job-breakaway-refused | R | parent | Windows won't let the agent outlive {parent}: its job forbids breakaway | launch from a terminal outside {parent}'s job, or have that job permit breakaway (`JOB_OBJECT_LIMIT_BREAKAWAY_OK`). Running `se up` from inside the same job does not help: the host it starts is in that job too |
| codex-app-server-failed | R | phase, reason | Codex app-server failed at {phase}: {reason} | → `se doctor` |
| wake-not-running | R | agent | {agent} isn't running, so there is nothing to wake | → `se launch {agent}` |
| stop-unwitnessed | I | agent, pid, reason, population, remaining[], enumeration | stop sent but {agent}'s exit isn't confirmed: `enumeration = complete` → "{n} processes still running"; otherwise, when `population = populated` → "processes still running in the agent's group; count unavailable" | → `se agent show {agent}`, then `se stop {agent}` |
| stop-partial | I | stopped[], failed[] | stopped {n}; not confirmed: {failed} | → `se stop AGENT` for each |

### 6.9 Sessions, capture and hooks (9)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| session-unknown | K | session | no session {session} | → `se agent show AGENT` |
| session-binding-unproven | A | reason | a session id alone can't bind ({reason}) | launch through se, or → `se doctor --fix` for your integration |
| session-generation-mismatch | C | expected, current | session generation is {current}, not {expected} | reread and retry |
| session-already-ended | R | session, at | session {session} ended at {at} | → `se launch AGENT` |
| capture-consent-missing | R | session | capture is off for this session | relaunch without `--incognito` |
| turn-invalid | U | field, problem | turn {field}: {problem} | fix the integration (→ `se doctor`) |
| transcript-unreadable | X | path, reason | can't read the transcript {path}: {reason} | → `se doctor` |
| transcript-truncated | I | path, offset, size | {path} shrank below the read offset | captured turns stay; → `se status` |
| hook-payload-invalid | U | event, problem | Claude `{event}` payload: {problem} | → `se doctor` (hook exits 0 anyway) |

### 6.10 Messages and decisions (9)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| recipient-unknown | K | to, suggestion? | no agent `{to}` to send to | → `se agent list` |
| recipient-other-project | R | to, project | {to} is in project {project} | send from that project |
| message-unknown | K | id | no message {id} | → `se msg list --all` |
| reply-target-unknown | K | id | can't reply to {id}: not found | drop `--reply-to` |
| message-scope-denied | A | filter, agent | as an agent, {agent} can list only messages it sent or received; `{filter}` names others' mail | drop the filter, or the owner runs `se msg list` from their own terminal |
| decision-unknown | K | id | no decision {id} | → `se decision list` |
| decision-key-invalid | U | key | `{key}` isn't a valid decision key | use lowercase letters, digits, `.`, `_`, `-` |
| decision-state-invalid | R | id, state, action | can't {action} {id}: it is {state} | → `se decision show {id}` |
| supersede-invalid | R | prior, replacement, reason (same \| cycle \| prior-not-governing \| replacement-not-pending) | can't supersede: {reason} | → `se decision list --history` |

### 6.11 Process custody (10)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| observation-unknown | K | observation | no observation {observation} | → `se process list` |
| observation-not-yours | A | observation | {observation} belongs to another caller | use your own handle |
| bare-pid-refused | U | got | processes are selected by observation, not pid | → `se process list` |
| process-identity-changed | R | pid, expected_start, found_start | pid {pid} now belongs to a different process | nothing to stop; → `se process inspect --observation O` |
| process-identity-unreadable | X | pid, reason | can't read pid {pid}'s identity: {reason} | retry; → `se doctor` |
| command-not-found | R | program | `{program}` not found on PATH | give a full path |
| spawn-failed | R | program, reason | couldn't start {program}: {reason} | |
| cwd-outside-workspace | R | cwd, workspace | {cwd} is outside the project folder {workspace} | use a path inside the project |
| env-key-not-allowed | U | key | `{key}` can't be set for a managed process | drop it |
| stop-deadline-exceeded | I | observation, deadline_ms, population, remaining[], enumeration | after {deadline_ms} ms: `enumeration = complete` → "{n} processes still running"; otherwise, when `population = populated` → "processes still running in the observation's group; count unavailable" | retry with a longer `--deadline` |

`population` is `populated` \| `empty`, the kernel's own answer for the whole scope (Linux cgroup `populated`, Windows job active-process count, macOS tracked group, and for a Linux `uncontained` agent its process group, which does not cover descendants that left it). `remaining[]` lists `{pid, exe, started_at}` for each member StateEngine could name; `enumeration` (`complete` \| `best-effort` \| `unavailable`) says whether that list is the whole population. `{n}` is printed only when `enumeration = complete`; a populated scope with a shorter or empty list is never rendered as a count.

### 6.12 Atlas (12)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| atlas-index-absent | R | project | no code index for {project} yet | → `se config set atlas.enabled true -p P` (indexes in the background; `se status` shows progress) |
| atlas-indexing | I | indexed, total | index is {indexed}/{total} files; results may be partial | retry later |
| atlas-unreadable | X | path, reason | can't read the index database atlas.db: {reason} | → `se doctor --fix` (rebuilds the index). Only for atlas.db itself; an unreadable source file is `atlas-source-unreadable`. |
| atlas-path-outside-root | R | path, root | {path} is outside {root} | use a project-relative path |
| atlas-path-unknown | K | path | {path} isn't indexed | → `se atlas find PATH --kind path` |
| atlas-symbol-unknown | K | symbol | no symbol `{symbol}` | → `se atlas find {symbol}` |
| atlas-symbol-ambiguous | U | symbol, candidates[] | `{symbol}` names {n} symbols | add `--path` |
| atlas-language-unsupported | R | path, language? | {language} files aren't parsed | text search: `--kind text` |
| atlas-file-over-budget | R | path, size, budget | {path} ({size}) exceeds the per-file parse budget | none; the file stays text-searchable. Only for one oversized file; lack of memory or other machine resources is `atlas-resource-budget`. |
| atlas-resource-budget | V | resource, requested, available | Atlas can't index right now: {resource} needs {requested}, {available} available | wait for memory pressure to ease, or use bounded text search → `se atlas find QUERY --kind text` |
| atlas-parse-failed | I | path (root-relative), language, reason | Atlas couldn't parse {path} ({language}): {reason} | results for this file use bounded text search; → `se doctor --bundle` to report the diagnostic |
| atlas-source-unreadable | X | path (root-relative), reason | Atlas can't read {path}: {reason} | restore read access to the file |

### 6.13 Doctor and internal (7)

| Code | Cl | Detail | Message | Remedy |
| --- | --- | --- | --- | --- |
| repair-not-supported | R | check | `doctor --fix` can't repair {check} | follow the check's own fix line |
| repair-would-weaken-defaults | R | change | refusing to {change}: it weakens safety defaults | change it yourself by named profile |
| bundle-destination-invalid | U | path, reason | can't write the bundle to {path}: {reason} | → `se doctor --bundle PATH` |
| deadline-exceeded | V | op, deadline_ms | `{op}` didn't finish in {deadline_ms} ms | retry |
| cancelled | Z | op | `{op}` was interrupted | rerun; writes are all-or-nothing |
| task-failed | N | task, report_id | internal task {task} failed ({report_id}) | → `se doctor --bundle` and send it |
| internal | N | report_id, location | StateEngine hit a bug ({report_id}) | → `se doctor --bundle` and send it |

Total: 165 codes. Warnings (stderr only, not errors, codes `w-…`): `w-legacy-env-present` (a `STATEENGINE_*`/`SECODE_STATEENGINE_*` variable is set and ignored), `w-provider-near-minimum`, `w-store-near-full`, `w-notify-degraded`.

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
version = 1                       # required; other values refuse config-version-unsupported
default_project = ""              # name or id; "" = none

[runtime]
autostart = true                  # launch starts the standalone runtime when none runs
after_host_exit = "handover"      # handover | stop — SE Code exiting with live agents
listen_address = "127.0.0.1"      # loopback only; anything else refuses
listen_port = 3221                # written at init if 3221 is taken

[launch]
provider = "claude"               # claude | codex — default for init/agent add
window = "auto"                   # auto | window | headless
terminal = ""                     # Linux/macOS terminal command; "" = detect
ready_timeout_ms = 60000          # 5000–600000

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
approval = "on-request"           # on-request | untrusted | never (never needs bypass)

# [profiles.NAME]                 # user-defined; the ONLY place bypass can appear
# bypass = true                   # full permission/sandbox bypass, chosen by name

[resume]
byte_budget = 32768               # 1024–1048576

[messages]
inbox_limit = 20                  # 1–200
preview_chars = 200               # 0–4000

[store]
backups_kept = 2                  # automatic start/shutdown backups, 1–10

[log]
level = "info"                    # SE_LOG wins
max_file_mb = 4
files_kept = 3

[output]
color = "auto"                    # auto | always | never

[atlas]
enabled = false                   # default for projects without their own setting
max_file_kb = 512                 # per-file parse budget
```

Unknown keys refuse (`config-key-unknown`) on load, naming the line. Dotted names (`launch.provider`) are the `KEY` used by `se config`.

### 7.3 Project settings (stored in the store, `se config set KEY VALUE -p P`)

| Key | Type / default | Meaning |
| --- | --- | --- |
| `launch.provider`, `launch.window` | as user | per-project override |
| `profile` | profile name / `default` | default permission profile for new agents |
| `agent.<AGENT>.profile` | profile name | one agent's profile; a bypass profile must exist by name |
| `agent.<AGENT>.model` | string | saved model |
| `agent.<AGENT>.can-create` | bool / false | grants `agent.create` to that agent's sessions |
| `capture.enabled` | bool / true | turn capture; off makes sessions incognito |
| `resume.byte_budget`, `messages.inbox_limit` | as user | per-project override |
| `atlas.enabled` | bool / user value | enables indexing for this project |
| `atlas.exclude` | list of globs / `[]` | extra excludes beyond `.gitignore` |

User-only keys (`runtime.*`, `log.*`, `output.*`, `store.*`, `providers.*.command`, `profiles.*`) refuse `config-scope-invalid` with `-p`. `config set` validates, writes atomically, rereads and returns the readback in `se.config-receipt/v1`. `config get/list --origin` shows the winning source.

### 7.4 Precedence

CLI flag > `SE_*` env > project setting > user `config.toml` > built-in default. Configuration is never read from cwd, the repository or the binary's folder. Profiles resolve by name at launch; a profile with `bypass = true` is honoured only when selected by name for that agent (`agent.<A>.profile`), never as a default and never through `doctor --fix`.

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
| `process-start` / `process-stop` | `se process start -- COMMAND ARGS...` / `se process inspect\|stop --observation O` |
| `packet` | `se resume --preview AGENT` |
| `decommission`, `init --remove` | `se remove --project P` |
| `plugin`, `hook-install`, `hook-uninstall` | `se doctor --fix` (repair setup), `se status` (inspect), `se remove` (remove with the project) |
| `verify-chain`, `rebuild-index` | `se doctor`; `se doctor --fix` |
| `hook-emit`, `capture-turn`, `msg deliver\|retry-delivery\|recover-delivery\|handoff\|unread-ids\|wake-backlog\|turn-outcome\|index-build` | `se doctor --fix` (reconfigures the native hook/mail integration) |
| MCP `stateengine_identity_whoami`, `_project_status`, `_context_packet`, `_working_state_get`, `_rawlog_search`, `_memory_recall`, `_floor_event`, `_seat_launch`, `_seat_stop`, `_seat_launch_status`, `_atlas_query` | `stateengine_whoami`, `_status`, `_resume`, `_resume`, `_search`, `_search`, `_event_read`, `_agent_launch`, `_agent_stop`, `_agent_status`, `_atlas_find` (MCP error `renamed`, arguments must be corrected) |
| MCP `stateengine_agent_rename`, `stateengine_tools` | owner CLI `se agent rename AGENT NAME`; native tools/list and direct calls |

`command-retired` (exit 64) with reason and current workflow: `agent-alias`/`agent alias`/`stateengine_agent_alias` (use stable ids or rename), `floor`, `floor-serve`, `projection-drain`, `drain-outbox`, `capture-receipts`, `file-write`, `project-owner-assign`, `human-bootstrap`, `state`, `run`, `serve`, `server`, `start`, `refresh`, `substrate-*`, `brick*`, `memory-*`/`memories`/`stateengine_memory_suggest` (memories import as decisions), `mail-tunnel`/`stateengine_mail_tunnel`, `deps`, `msg complete|reconcile|treat`, `seat cut|move|prompt`, `doctor contradictions`, and every factory command (campaigns, reviews, gates, landings, census, remote compute, routing). Any other unknown token is `usage-unknown-command` with a spelling suggestion from the live registry only.

---

## 8. Choices made here that review should check

1. Message kinds closed at eight, with `owner` as a reserved recipient so agents can report to the human (J4 observability). OPS.md names a "kind" input but not its values.
2. `--json=vN` carries N-1 pinning instead of a new global flag.
3. Exit 2 for `msg inbox` is defined by unread coverage, not by body previews.
4. `se hook claude` always exits 0 because Claude treats exit 2 as blocking.
5. `agent.<A>.can-create` is the grant mechanism for `stateengine_agent_create`.
6. Session `agent_launch`/`agent_stop` are self-only per OPS.md; delegated launch needs an allowlist amendment.
7. Error-code total is 165, above the 80–120 target: splitting codes that need different remedies was preferred to merging codes whose fix lines would then be vague.

---

## Appendix A — Output schemas (judged families)

Exact field paths for the families the journey runner judges. `$` is the payload root and `[]` means "every element". "Always: yes" means the key is in every payload of that family (its value can still be `null` where the type allows). Any other value in that column names the case in which the key appears. Families may gain optional fields under the §1.8 freeze rules, and a judge must ignore keys it does not know. Key order does not matter, except that `schema` is serialized first.

### A.0 Shared shapes (section 00 vocabulary)

| Shape | JSON | Notes |
| --- | --- | --- |
| Id | string | Section 10 owns the text form: kind prefix + UUIDv7, e.g. `ag_0192f3a1-7c2e-7b4d-9a10-3e5f6a7b8c9d`. Prefixes: `prj_` project, `hu_` human, `ag_` agent, `ses_` session, `lch_` launch, `msg_` message, `dec_` decision, `ev_` event, `obs_` observation, `cred_` credential. Imported legacy ids keep their text. |
| Time | string | RFC 3339 UTC with microseconds, e.g. `2026-10-30T12:01:07.123456Z`. Used for display only; the store orders events. |
| Cursor | string | Opaque. Bound to its project and principal. |
| Ref | object | `{id: Id, name: string}`. A message party also carries `kind: "agent" \| "owner"`. |
| Cmd | two sibling keys | `command`: string, the full line quoted for the current platform's shell. `argv`: string[], the exact tokens, starting with `"se"`. A judge runs `argv` verbatim. Wherever a row below says "+ Cmd", both keys sit in that object. When there is no command, both are null. |
| `Read<T>` | `{"state":"present","value":T}` \| `{"state":"absent","checked":string}` \| `{"state":"unreadable","source":string,"reason":string}` \| `{"state":"unknown","what":string}` | `checked` names what was consulted to establish the absence. |
| `Window` | `{"from":Cursor\|null,"to":Cursor\|null,"limit":int,"complete":bool,"omitted":{"count":int\|null,"reason":string\|null}}` | `complete: true` implies `omitted.count == 0` and `omitted.reason == null`. `count: null` means the number left out is unknown. `reason` is one of `limit`, `budget`, `unreadable`, `source-incomplete`. |
| `Page<T>` | `{"items":[T],"window":Window,"next":Cursor\|null}` | `next` is non-null exactly when following it can return more. Pages concatenate to the full read (00 G5). |
| Receipt state | string | `committed`: a new event was appended. `replayed`: section 00's "already done" (same idempotency key and same body, so no new event). `pending`: committed, but the follow-up is not confirmed yet. `refused`: appears only inside bulk results; when a whole call is refused, the output is an `se.error/v1` payload instead. |
| Writer | object | `{"mode":"host","host_generation":string}` \| `{"mode":"direct"}`. Records who committed the event the receipt refers to. `host`: the running host's writer committed it, and `host_generation` is the decimal text of that host's generation (the same number as `se.status/v1` `$.runtime.generation`, e.g. `"7"`). `direct`: the CLI committed it with no host running, and the key `host_generation` is absent. The value is stored on the event row at commit, so a `replayed` receipt reports the original commit's writer. Families that carry `$.writer` (always present): `se.message-receipt/v1`, `se.message-read/v1`, `se.disposition-receipt/v1`, `se.decision-receipt/v1`, `se.working-state-receipt/v1`, `se.turn-receipt/v1`, `se.agent-receipt/v1`. See §1.1, "Writer stamp". |
| Witness | object | `{"state":"witnessed"\|"unwitnessed"\|"not-applicable","method":string\|null,"observed_at":Time\|null,"detail":string\|null}`. A result is `witnessed` only after a re-read from outside the writer (00 G8). `method` is one of `job-empty` (Windows), `pidfd-exit+cgroup-empty` (Linux), `pidfd-exit+pgid-empty` (Linux, `uncontained`), `start-identity-exit+pgid-empty` (Linux without pidfd support: exit confirmed by re-reading the recorded start identity as gone or changed, at the bound section 30 states), `kqueue-exit+pgid-empty` (macOS), `readback` (files and config), `registry-reread`. |
| ProcessId | object | `{"pid":int,"started_at":Time,"exe":string,"machine_id":string}`. `started_at` is the OS birth time (00 G6). A pid alone never identifies a process. |

### A.1 `se.init/v1` — `se init`

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
| `$.agent.permission_profile.bypass` | bool | yes | false unless a named bypass profile was chosen |
| `$.profile` | object | yes | compatibility block for `stateengine-init/v1` decoders |
| `$.profile.schema` | `"stateengine-init/v1"` | yes | |
| `$.profile.project` | Id | yes | equal to `project.id` |
| `$.profile.repo_root` | string | yes | equal to `project.root` |
| `$.profile.registry_root` | string | yes | equal to `home` |
| `$.profile.keys_dir` | string | yes | folder that holds the machine credential |
| `$.profile.human_id` | Id | yes | equal to `owner.human_id` |
| `$.profile.agent_id` | Id | yes | equal to `agent.id` |
| `$.profile.native_server_port` | int | yes | port of the loopback listener |
| `$.integrations[]` | array | yes | edits StateEngine owns outside the store; empty for managed launches |
| `$.integrations[].path` | string | yes | file edited |
| `$.integrations[].entry` | string | yes | the marked key or block |
| `$.integrations[].action` | `"written"` \| `"unchanged"` \| `"conflict-kept"` | yes | `conflict-kept`: you had edited the entry, so init kept your version and did not write it |
| `$.integrations[].witness` | Witness | yes | method `readback` |
| `$.changed` | string[] | yes | what this call changed; empty on a retry that changed nothing |
| `$.next` | `{text}` + Cmd | yes | the next step, normally `se launch main` |
| `$.launch` | object \| null | yes | with `--launch`, the full `se.launch/v1` payload (carrying its own `schema`); otherwise null |

```json
{"schema":"se.init/v1","outcome":"adopted",
 "project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app","root":"C:\\Users\\ana\\src\\app","registered_at":"2026-10-30T12:00:01.000001Z"},
 "repo":{"root":"C:\\Users\\ana\\src\\app","git":{"head":"4f1c2e9a0b7d","branch":"main"},"files_touched":0},
 "owner":{"human_id":"hu_0192f3a0-1111-7aaa-8bbb-000000000002","os_user":"DESKTOP-1\\ana"},
 "home":"C:\\Users\\ana\\AppData\\Local\\StateEngine",
 "agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main","outcome":"created","provider":"claude","model":null,
          "permission_profile":{"name":"default","sandbox":"workspace-write","approval":"on-request","bypass":false}},
 "profile":{"schema":"stateengine-init/v1","project":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","repo_root":"C:\\Users\\ana\\src\\app",
            "registry_root":"C:\\Users\\ana\\AppData\\Local\\StateEngine","keys_dir":"C:\\Users\\ana\\AppData\\Local\\StateEngine\\keys",
            "human_id":"hu_0192f3a0-1111-7aaa-8bbb-000000000002","agent_id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","native_server_port":3221},
 "integrations":[],"changed":["project registered","agent main created","machine credential created"],
 "next":{"text":"Open your first agent","command":"se launch main","argv":["se","launch","main"]},
 "launch":null}
```

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
 "window":{"from":null,"to":"c1.Zm9v","limit":20,"complete":true,"omitted":{"count":0,"reason":null}},"next":null}
```

`se.launch/v1` carries the same pair for the agent it launched, at `$.containment` and `$.containment_cause`, with the same values and the same rule: launch never refuses for containment, and an `uncontained` launch always names its cause. On Linux the host decides on the first launch it serves: it asks the systemd user manager for one delegated transient scope for agents (`systemd-run --user`, the pattern SE Code already uses) and places every later agent in it; when there is no user manager or no delegation it records the probe cause and every agent it launches is `uncontained` until the host restarts.

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
| `$.runtime.generation` | int \| null | yes | current generation |
| `$.runtime.endpoint` | string \| null | yes | `127.0.0.1:PORT` |
| `$.runtime.version` | string \| null | yes | the host's se version |
| `$.runtime.observed_at` | Time \| null | yes | last observation from outside |
| `$.runtime.resources` | object | only when a host answered | Host self-accounting (Prime decision, 2026-10-30). `$.runtime` is this family's host block, so this is the requested `host.resources`. The key is present whenever a running host answered the status call, and the key is absent otherwise: absent means no host, never zero. The values are kernel-sourced counters that the host reads about itself at `sampled_at`; they are never estimates. The journey runner measures StateEngine's own idle cost as the difference of two samples 60 s apart. |
| `$.runtime.resources.self_voluntary_switches` | int | with `resources` | cumulative since host start. Linux/macOS: `ru_nvcsw` from `getrusage(RUSAGE_SELF)`, which counts the host's own threads, exited ones included, and excludes child processes such as agents. Windows: the sum of `ContextSwitches` over the host process's live threads, which Windows does not split into voluntary and involuntary (switches of exited threads are not included). |
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
            "generation":7,"endpoint":"127.0.0.1:3221","version":"0.1.0","observed_at":"2026-10-30T12:05:00.000000Z",
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
   "window":{"from":null,"to":"c1.YQ","limit":20,"complete":true,"omitted":{"count":0,"reason":null}},"next":null},
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
| `$.idempotency_key` | string \| null | yes | as supplied |
| `$.body.bytes` | int | yes | body size; the receipt does not echo the body |
| `$.body.sha256` | string | yes | hex digest of the stored body |
| `$.delivery.state` | `"pending"` \| `"offered"` \| `"not-running"` \| `"not-applicable"` | yes | notification status when the call returned; `not-applicable` for messages to `owner`. Never a claim that the message was read. |
| `$.delivery.at` | Time \| null | yes | when it was offered |
| `$.writer.mode` | `"host"` \| `"direct"` | yes | who committed the message event (A.0 Writer) |
| `$.writer.host_generation` | string | when mode is `host` | generation of the host that committed it |

```json
{"schema":"se.message-receipt/v1","state":"committed","message_id":"msg_0192f3b0-0000-7000-8000-000000000101",
 "event_id":"ev_0192f3b0-0000-7000-8000-000000000102","recorded_at":"2026-10-30T12:06:00.120000Z",
 "project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},
 "from":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
 "to":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},
 "kind":"handoff","reply_to":null,"refs":[],"idempotency_key":null,
 "body":{"bytes":212,"sha256":"9b1e5a0c…"},"delivery":{"state":"pending","at":null},
 "writer":{"mode":"host","host_generation":"7"}}
```

### A.5 `se.message-page/v1` — `se msg inbox`, `se msg list`, `stateengine_msg_list`

`{schema, view, unread_total}` plus the `Page<MessageRow>` keys.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.message-page/v1"` | yes | |
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
| `$.items[].delivery.state` | `"pending"` \| `"offered"` \| `"delivered"` \| `"not-applicable"` | yes | notification only |
| `$.items[].delivery.at` | Time \| null | yes | |
| `$.items[].disposition.state` | `"unread"` \| `"read"` \| `"dismissed"` | yes | the recipient's own marker |
| `$.items[].disposition.at` | Time \| null | yes | |
| `$.items[].unreadable` | null \| `{reason}` | yes | set for a row that exists but could not be decoded (its other fields are then null). Such rows also count in `window.omitted`. |
| `$.window`, `$.next` | Window, Cursor \| null | yes | see A.0. Inbox exits 2 when `unread_total` is null, or is larger than the number of unread items shown, or any row is unreadable. With `full`, a page holds at most 256 KiB of bodies, never cuts a body and holds at least one row. Rows that did not fit are reported as `omitted.reason: "budget"` and returned by following `next`. |

Markers are untouched: producing this family (inbox, list, `--full` or not, owner or session) never creates or changes a delivered, read or dismissed marker. `disposition` and `delivery` report the stored state as it was when the page was read. Observing history is not the recipient reading it; only `se.message-read/v1` and `se.disposition-receipt/v1` write markers.

```json
{"schema":"se.message-page/v1",
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

For a single target, the per-target fields sit at the root, with `$.scope = "agent"` and `$.stops = null`. With `--all`, `$.scope = "all"`, the root-level per-target fields are null, and each element of `$.stops[]` carries the same per-target fields. `$.complete` is false if any entry lacks a witness. `se.process-stop/v1` (`se process stop`, `stateengine_process_stop`) carries the same `population`, `remaining[]` and `enumeration` fields for its observation.

Human text follows `enumeration`: `complete` prints the count ("2 processes still running"); `best-effort` or `unavailable` with `population = populated` prints "processes still running in the agent's group; count unavailable" and lists whatever `remaining[]` names, labelled as partial.

| Path | Type | Always | Meaning |
| --- | --- | --- | --- |
| `$.schema` | `"se.stop/v1"` | yes | |
| `$.receipt` | `"seat-stop/v1"` | yes | compatibility marker for stop-handle decoders |
| `$.scope` | `"agent"` \| `"all"` | yes | |
| `$.result` | `"stopped"` \| `"already-stopped"` \| `"unwitnessed"` \| `"partial"` | yes | `partial` occurs only with `all` |
| `$.complete` | bool | yes | every target was witnessed gone or was already stopped |
| `$.event_id` | Id \| null | yes | the stop event; null for `already-stopped` |
| `$.target.project` | Ref | single target | |
| `$.target.agent` | Ref | single target | the agent stopped |
| `$.target.session_id` | Id \| null | single target | |
| `$.target.launch_id` | Id \| null | single target | |
| `$.target.provider` | provider | single target | |
| `$.target.process` | ProcessId \| null | single target | the exact instance stopped, re-checked before acting |
| `$.method` | `"graceful"` \| `"forced"` \| null | single target | null for `already-stopped` |
| `$.witness` | Witness | single target | outside confirmation that the process and its descendants are gone |
| `$.population` | `"populated"` \| `"empty"` | single target | the kernel's answer for the agent's whole scope (Linux cgroup `populated`, Windows job, macOS tracked group, Linux `uncontained` process group); `empty` when witnessed |
| `$.remaining[]` | `{pid, exe, started_at}` | single target | members still running that StateEngine could name; empty when `population = empty` |
| `$.enumeration` | `"complete"` \| `"best-effort"` \| `"unavailable"` | single target | whether `remaining[]` is the whole population. `best-effort`/`unavailable` with `populated` means "still running; count unavailable", never a count |
| `$.capture.flushed` | bool | single target | the transcript was caught up before the stop |
| `$.capture.last_event_id` | Id \| null | single target | last captured turn |
| `$.resume.state` | `"ready"` \| `"unavailable"` | single target | whether the command below resumes the same conversation |
| `$.resume.reason` | string \| null | single target | set when `unavailable` |
| `$.resume.conversation_id` | string \| null | single target | the provider conversation that will be resumed |
| `$.resume.provider`, `.model` | provider, string \| null | single target | kept so the resume uses the same provider and model |
| `$.resume` + Cmd | | single target | `se launch AGENT` (which resumes by default); `se launch AGENT --new` when `unavailable` |
| `$.stops[]` | array \| null | yes | entries for the `all` scope: `{target, result, method, witness, population, remaining, enumeration, capture, resume}` |

```json
{"schema":"se.stop/v1","receipt":"seat-stop/v1","scope":"agent","result":"stopped","complete":true,
 "event_id":"ev_0192f3c0-0000-7000-8000-000000000201",
 "target":{"project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},"agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
           "session_id":"ses_0192f3a2-0000-7000-8000-00000000000a","launch_id":"lch_0192f3a2-0000-7000-8000-00000000000b","provider":"claude",
           "process":{"pid":4188,"started_at":"2026-10-30T12:02:15.010000Z","exe":"/usr/local/bin/claude","machine_id":"m-6a1f"}},
 "method":"graceful",
 "witness":{"state":"witnessed","method":"pidfd-exit+cgroup-empty","observed_at":"2026-10-30T12:20:00.004100Z","detail":null},
 "population":"empty","remaining":[],"enumeration":"complete",
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
| `$.projects[].processes_stopped[]` | `{observation_id, process: ProcessId, witness: Witness}` | yes | other processes StateEngine owned |
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
{"schema":"se.remove/v1","scope":"project","outcome":"removed",
 "projects":[{"project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app","root":"/home/ana/src/app"},
   "outcome":"removed","removed_at":"2026-10-30T12:59:10.000000Z","event_id":"ev_0192f3d0-0000-7000-8000-000000000301",
   "agents_stopped":[{"agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},"prior_state":"running",
     "witness":{"state":"witnessed","method":"pidfd-exit+cgroup-empty","observed_at":"2026-10-30T12:59:09.800000Z","detail":null},
     "process":{"pid":5120,"started_at":"2026-10-30T12:40:02.000000Z","exe":"/usr/local/bin/codex","machine_id":"m-6a1f"}}],
   "processes_stopped":[],
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
- `config.user`, `config.project`, `env.legacy`
- `runtime.lock`, `runtime.endpoint`, `runtime.version`, `listener.loopback`
- `provider.claude`, `provider.codex`
- `custody.windows-job`, `custody.linux-cgroup`, `custody.macos-kqueue`: only the current OS's check is measured; the others report `not-applicable`. `custody.linux-cgroup` is `ok` when agents get a delegated cgroup v2 scope and `warning` (never `failed`) when they run `uncontained`; its `observed` names the containment and the full probe text, `code` is null (nothing refuses), and its manual fix enables a systemd user manager with delegation. It replaces the removed `cgroup-delegation-missing` refusal.
- `integration:<path>#<entry>`: one per owned edit.
- `capture:<agent-name>`: one per agent.
- `atlas.index`

New ids may be added. Existing ids keep their meaning.

```json
{"schema":"se.diagnosis/v1","generated_at":"2026-10-30T12:30:00.000000Z",
 "scope":{"home":"/home/ana/.local/state/stateengine","project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"}},
 "outcome":"problems","summary":{"ok":14,"failed":1,"warning":1,"unmeasured":0,"skipped":0},
 "checks":[
  {"id":"store.integrity","title":"Store integrity","state":"ok","measured_at":"2026-10-30T12:30:00.010000Z","observed":"ok","expected":"ok","reason":null,"code":null,"fix":null,"repairable":false},
  {"id":"provider.codex","title":"Codex CLI","state":"failed","measured_at":"2026-10-30T12:30:00.050000Z","observed":"codex 0.120.0","expected":">= 0.166.0",
   "reason":"too old","code":"provider-cli-too-old","fix":{"text":"Upgrade Codex","command":null,"argv":null},"repairable":false},
  {"id":"custody.linux-cgroup","title":"Agent process custody","state":"warning","measured_at":"2026-10-30T12:30:00.060000Z",
   "observed":"uncontained (no-user-manager: $XDG_RUNTIME_DIR/systemd/private absent); agents run in their own process group","expected":"a delegated cgroup v2 scope from the systemd user manager",
   "reason":"no systemd user manager for this user, so stop reaches only each agent's process group","code":null,"fix":{"text":"Run a systemd user manager with cgroup delegation (exact steps printed here); agents launch either way","command":null,"argv":null},"repairable":false}]}
```

This example exits 1. One check failed, and a failure outranks a warning.

### A.11 `DecisionRow`, `se.decision-receipt/v1` — `se decide`, `se decision ratify|reject|retract|supersede`, `stateengine_decision_propose`

`DecisionRow` is shared by the receipt, the page (A.12) and `se decision show`.

| Path (row = a `DecisionRow`) | Type | Always | Meaning |
| --- | --- | --- | --- |
| row`.id` | Id | yes | decision id (`dec_…`) |
| row`.key` | string | yes | decision key, e.g. `api.versioning` |
| row`.state` | `"pending"` \| `"ratified"` \| `"rejected"` \| `"retracted"` \| `"superseded"` | yes | current state. `pending` is a proposal waiting for the owner. |
| row`.governing` | bool | yes | true only when `ratified` and not later retracted or superseded |
| row`.revision` | int | yes | changes on every transition; pass it as `--expect` |
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
| `$.idempotency_key` | string \| null | yes | as supplied (propose); null for owner transitions |
| `$.decision` | DecisionRow | yes | the decision read back after the commit. For `supersede`, this is the replacement, now governing. |
| `$.replaced` | DecisionRow \| null | yes | `supersede` only: the prior decision, now `superseded`; null otherwise |
| `$.writer.mode` | `"host"` \| `"direct"` | yes | A.0 Writer |
| `$.writer.host_generation` | string | when mode is `host` | |

```json
{"schema":"se.decision-receipt/v1","action":"propose","state":"committed",
 "event_id":"ev_0192f3a8-0000-7000-8000-000000000049","recorded_at":"2026-10-30T12:08:00.000000Z",
 "project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},"idempotency_key":null,
 "decision":{"id":"dec_0192f3a9-0000-7000-8000-000000000050","key":"api.versioning","state":"pending","governing":false,"revision":1,
   "statement":{"text":"Breaking JSON changes bump the family major.","complete":true,"bytes":44,"command":null,"argv":null},
   "rationale":"Consumers pin majors.","proposed_by":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
   "proposed_at":"2026-10-30T12:08:00.000000Z","decided_by":null,"decided_at":null,"reason":null,
   "supersedes":null,"superseded_by":null,"event_id":"ev_0192f3a8-0000-7000-8000-000000000049"},
 "replaced":null,
 "writer":{"mode":"host","host_generation":"7"}}
```

The same decision after `se decision ratify dec_…` run in the owner's terminal with no host running:

```json
{"schema":"se.decision-receipt/v1","action":"ratify","state":"committed",
 "event_id":"ev_0192f3aa-0000-7000-8000-000000000051","recorded_at":"2026-10-30T12:10:00.000000Z",
 "project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},"idempotency_key":null,
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

`se.decision-page/v1` is `{schema, project, filter}` plus the `Page<DecisionRow>` keys. List ordering is by store order of the latest transition, oldest first.

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

`se.decision/v1` (`se decision show ID`) is `{"schema":"se.decision/v1","decision":Read<DecisionDetail>}`. `DecisionDetail` is a `DecisionRow` whose `statement.complete` is always true, plus `transitions[]`: `{action, by: Ref + kind, at, event_id, reason}`, oldest first. An unknown id gives `{"state":"absent","checked":"decisions in project app"}`, exit 0. An undecodable row gives `unreadable`, exit 3.

```json
{"schema":"se.decision-page/v1","project":{"id":"prj_0192f3a0-1111-7aaa-8bbb-000000000001","name":"app"},
 "filter":{"id":null,"pending":false,"history":false},
 "items":[{"id":"dec_0192f3a9-0000-7000-8000-000000000050","key":"api.versioning","state":"ratified","governing":true,"revision":2,
   "statement":{"text":"Breaking JSON changes bump the family major.","complete":true,"bytes":44,"command":null,"argv":null},
   "rationale":"Consumers pin majors.","proposed_by":{"kind":"agent","id":"ag_0192f3a0-1111-7aaa-8bbb-000000000003","name":"main"},
   "proposed_at":"2026-10-30T12:08:00.000000Z","decided_by":{"kind":"owner","id":"hu_0192f3a0-1111-7aaa-8bbb-000000000002","name":"ana"},
   "decided_at":"2026-10-30T12:10:00.000000Z","reason":null,"supersedes":null,"superseded_by":null,
   "event_id":"ev_0192f3aa-0000-7000-8000-000000000051","unreadable":null}],
 "window":{"from":null,"to":"c1.ZDE","limit":20,"complete":true,"omitted":{"count":0,"reason":null}},"next":null}
```

### A.13 Other write receipts carrying `writer`

Each family below always carries `$.schema`, `$.state` (`committed` \| `replayed`, plus `conflict` for working state), `$.event_id` (Id \| null; null only for a working-state `conflict`), `$.recorded_at` and `$.writer` (A.0), together with the fields listed.

| Family | Additional fields (all always present) |
| --- | --- |
| `se.working-state-receipt/v1` (`se working-state set`, `stateengine_working_state_set`) | `$.agent` Ref; `$.revision` int \| null (the new revision; null on `conflict`); `$.current_revision` int \| null (the stored revision on `conflict`, otherwise equal to `revision`); `$.bytes` int. A `conflict` is returned with exit 1 and `se.error/v1` code `revision-conflict` on the CLI. MCP returns the receipt so the model can reread. |
| `se.turn-receipt/v1` (`se session turn`, `stateengine_session_turn`, hooks) | `$.result` `"captured"` \| `"duplicate"` \| `"suppressed"`; `$.session_id` Id; `$.turn_id` string \| null; `$.role`; `$.bytes` int. A `suppressed` turn appends no body, and its `event_id` is the suppression-count event. |
| `se.agent-receipt/v1` (`se agent add`, `se agent rename`, `stateengine_agent_create`) | `$.action` `"create"` \| `"rename"`; `$.outcome` `"created"` \| `"existing"` \| `"renamed"` \| `"unchanged"`; `$.agent` `{id, name, provider, model, profile}`; `$.previous_name` string \| null (rename only); `$.process_started` false (creating an agent never starts a process). |
| `se.disposition-receipt/v1` (`msg ack`, `msg dismiss`) | `$.message_id`; `$.disposition` `"read"` \| `"dismissed"`; `$.marker` `"new"` \| `"already"`; `$.by` Ref (the recipient). |
| `se.message-read/v1` (`msg read`) | `$.message` MessageRow (A.5, with `body.complete` true unless the body exceeds the hard cap); `$.marker` `"new"` \| `"already"`. `event_id` and `writer` refer to the read-marker event; on `already`, they refer to the original marker. |

```json
{"schema":"se.working-state-receipt/v1","state":"committed","event_id":"ev_0192f3b5-0000-7000-8000-000000000110",
 "recorded_at":"2026-10-30T12:20:11.000000Z","agent":{"id":"ag_0192f3a0-1111-7aaa-8bbb-000000000004","name":"rev"},
 "revision":4,"current_revision":4,"bytes":52,"writer":{"mode":"host","host_generation":"7"}}
```
