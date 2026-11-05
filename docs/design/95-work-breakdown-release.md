# 95 — Work breakdown: packaging and release

Reconciliation draft, 2026-10-30; branch base is main `3536238`. No implementation,
tests, signing, installer changes or publication are performed by this contribution.
Build units describe the Rust product release; the Node engine remains the private
factory library, with no fleet cutover or factory import in this plan. Desktop
remains deferred; this does not revive the historical Electron/Tauri experiment.

## Sources and scope

This revision applies the single `RECONCILIATION-DECISIONS-2026-10-30.md` list
beside the design handoff. Section **00** supplies product scope, **80** supplies
the single budget table, and **95** supplies the generated size table and build
order. The `secode-integration.md` planning note remains a source map in the release handoff directory (private evidence root).
Integration references below name its headings: **Payloads and entrypoints**,
**Choice of Rust integration**, **Changes SE Code would make**, and **Desktop
history and future requirements**. Its source/package observations are pinned
historical evidence, not a claim about current installed bytes. The accepted
section 10 exact statically linked API boundary is an integration dependency;
JSON families keep their own schema versions, without N-1 encoders or schema-freeze
tooling for this first release.

SE Code's current integration target is its Rust server in the SE Code repository,
branch `dev`, source `58e8a145f`: `secode-server` is the binary in
`crates/secode-product`, `secode.exe` is `crates/secode-cli` (including
`installation/`), and `secode-tui-r` is `crates/secode-tui-r`. The frozen TypeScript
predecessor is not the linked host. Library dependencies use caret ranges;
release lockfiles pin resolved bytes. The shared graph must resolve one bundled
SQLite linkage compatible with SE Code's rusqlite `0.40`, admit its axum `0.8.9`
or use hyper directly, and avoid an exact tokio pin; only se-host links tokio
within rust-se. These are input constraints, not new dependency infrastructure.

Three release variants must stay explicit:

| Variant | Contains | Runtime/build boundary |
| --- | --- | --- |
| Public SE Code | permissively licensed host API and unavailable stub | no proprietary se-types/store/core/proc/host/atlas dependency, source or `se` payload |
| Commercial SE Code | linked StateEngine host plus separately licensed native `se` payload/alias | embedded host uses default-features=false, secode+listener, no linked Atlas; one product host |
| Standalone StateEngine | native `se`, required notices and install/uninstall scripts | Atlas optional and enabled by default; user-history import, no fleet data; one daemon only when normal custody requires it |

The commercial package and standalone download use the same version/target-pinned
CLI bytes; the linked server has its separately recorded embedded feature graph.
No StateEngine Node/Postgres/npm/source checkout is needed on the recipient machine.
SE Code's independent optional JavaScript plugin runtime is a separate feature:
removing StateEngine's Node payload does not declare that feature removed.

Paths below are proposed implementation locations. **SE** means this rust-se repo;
**SC** means the SE Code repo, whose existing packager/installation files were
identified in the integration assessment. Site paths are owned by the download-site
maintainer. Estimates include handwritten release Rust/Python/PowerShell/config
changes, count shared helpers once, and exclude generated/vendor code, engine/API
implementation, tests and independent qualification tooling. These are ordered
build units, not mandatory separate landings or new gate infrastructure. Release
units are staged by the build-order milestone below, rather than waiting for all
earlier-numbered units to finish:

| Build stage | Release work available at that stage | Consumer milestone |
| --- | --- | --- |
| 0 | R01 input/feature split and runner wiring with the existing Rust action map | runner red against a stub on Windows/Linux, launched outside agent trees |
| 1 | minimal R03 standalone binary, R06 including se uninstall, unsigned R07 archive; R02 public separation proceeds independently | J1 from an unsigned archive, including install and delegating uninstall scripts |
| 2 | extend R03/R06/R07 for host and Claude headless custody | J2/J3/J5 with real Claude on Linux, then Windows |
| 3 | extend those same artifacts for Codex, attended/windowed flows, doctor plans and user-history import | all five journeys, both providers, Windows/Linux standalone |
| 4 | R05 embedded bundle plus live handover, forget and R04 signing; rerun R07 on signed bytes | B1/B2/B8 Windows/Linux and J1 from the signed download |
| 5 | macOS R03/R04 work in the borrowed-Mac compatibility campaign; final R08 | all five journeys on clean Windows/Linux/macOS, both providers, standalone and embedded SE Code |

Atlas implementation follows the journeys and live handover. It may be included
if ready and qualified, is enabled by default in included builds, and never holds
a milestone or release. An Atlas-free build reports NotBuilt rather than advertising tools.
Atlas is compiled only into the standalone `se`; it is enabled by default and can be disabled with `atlas.enabled = false` in config.toml; a host without an installed Atlas controller reports it unavailable.
Windows/Linux is an intermediate milestone; macOS qualification precedes alpha
shipping, while Windows/Linux development does not wait for borrowed hardware.

## Ordered build units

### R01 — Pin release variants, sources and offline inputs

**Files:** SE `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
`.cargo/config.toml`, `scripts/release/inputs.json`; SC existing build/payload pins
and private commercial build manifest.

**Depends on:** shared/API declarations and stage-appropriate product crates;
SC owner for its Rust/SQLite pins and release profile in the later linked graph;
licensed source/vendor access for the private job. Early standalone inputs do not
wait for SC packaging or credentials. No release helper opens se-store or user state.

**Clauses:** 00 §§3.1–3.2, 5.1/5.8, 7.1/7.2 (closed source, offline vendoring,
one SQLite linkage, panic=unwind); 80 §§3.1/3.3/4, B1/B2.

**Witness:** isolated builds resolve pinned offline inputs and record source,
version, target, toolchain, API/schema and feature sets in the existing manifests.
Build embedded and standalone graphs separately so optional features do not
unify into another advertised variant. Early J1 needs only the minimal standalone
graph, not a completed host, provider, embedded adapter or Atlas. Confirm unwind
behavior/profile and one compatible bundled SQLite library in the linked server; missing inputs fail
explicitly. Dependency metadata is not a runtime-budget measurement.

**Estimate:** 80–140 lines.

### R02 — Public SE Code export/stub and licensing separation

**Files:** SC public `Cargo.toml`/`Cargo.lock`, public host-API/stub crate,
private commercial workspace/adapter manifest, existing source-export/package
selection and notice lists. Reuse section 10's public API; no second DTO layer.

**Depends on:** R01; SC/public-API owners; commercial adapter owner. Proprietary
se-types and se-host remain private; public source carries only the permissive
contract/stub, not disabled imports of proprietary crates.

**Clauses:** 00 §§3.1, 7.1 and §7.2 item 4; integration **Choice of Rust integration**
and **Changes SE Code would make**; 80 B1/B2 baseline isolation.

**Witness:** build/package the public export in an environment where private
repositories and credentials are physically absent. No optional path/git
resolution, lockfile/package source, binary, debug/source archive or installer
payload pulls proprietary StateEngine into that graph. The public stub reports
unavailable without fabricated identity/context; normal SE Code still works.
Commercial packages identify StateEngine's separate license/notices rather than
relicensing it as MIT/Apache. Feature-off compilation alone does not prove this.

**Estimate:** 120–220 lines.

### R03 — Early native artifacts; macOS in its compatibility campaign

**Files:** SE `scripts/release/build.py`, existing CI release-job definition,
platform toolchain/config entries; SC existing native build/assembly jobs.

**Depends on:** R01 and the current stage's implemented `se`/core/store/proc;
add host/harnesses as their stages finish. Atlas, R04 signing and R05 commercial
bundling are not dependencies of the first unsigned standalone archive. Native
Windows/Linux tools are needed first; macOS SDK/hardware belongs to the borrowed-Mac
compatibility campaign. Reuse existing build capacity and release jobs, without
extra CI policy or new remote-execution machinery.

**Clauses:** 00 §§1.3, 3.1–3.2, 5.8/7.1; integration **Payloads and entrypoints**;
80 §§2.1–2.2/3.5/4, B3/B7.

**Witness:** each advertised target produces a real release binary with the
correct architecture, version, dynamic-library requirements and feature graph.
Build Windows/Linux x86_64 first; qualify macOS arm64/x86_64 in the compatibility
campaign and record the actual advertised architectures. All three OSes are
required before alpha ships; cross-compilation or omitting an OS from the download
index does not satisfy that obligation. Run on clean native machines without Rust,
Node, npm, a source checkout or build-tree environment. All required libraries/notices travel in the
artifact; build provenance alone cannot qualify another architecture/OS.

**Estimate:** 140–220 lines.

### R04 — Windows signing and macOS distribution trust

**Files:** SE `scripts/release/sign-windows.ps1` and `sign-macos.sh`; reuse SC's
existing signing/package finalization and truthful signing-manifest fields.

**Depends on:** R03 exact native bytes at stage 4; the operator's Windows signing
identity/provider and Apple Developer ID enrollment/access (00 §7.2 item 8); authorized release
credentials and platform verifier. No signing secret enters source or artifacts.

**Clauses:** 00 §§1.3/7.2; integration **Payloads and entrypoints** and package
signing source map; 80 §§2.1/3.5/5 (real Windows first-run samples retained).

**Witness:** independently verify each exact shipped Windows PE/installer under
Authenticode policy, expected publisher, SHA-256 digest and timestamp. Sign inner
binaries before inventory hashing, then finalize/sign the outer distributable and
verify again after download. Missing identity or failed verification remains
unsigned/failed and blocks a signed release, never becomes a claimed signature.
For macOS use the proper Developer ID identity for code versus installer, notarize
the supported distribution container and validate it on a quarantined fresh Mac.
Final package signing reuses this unit after R05/R07 assembly; it is not a rebuild.
Signing access never blocks unsigned stage-1 archives or their J1 install/uninstall
walk. macOS signing/notarization belongs to the borrowed-Mac campaign and remains
required for the final advertised Mac distribution before alpha.

**Estimate:** 100–180 lines. Signing service choice/access is a release dependency,
not a request to buy credentials or change today's package.

### R05 — Bundle native se inside commercial SE Code

**Files:** SC `scripts/release/{stateengine_payload,package}.py`,
`packages/stateengine/payload-pins.json`, existing payload/release manifests and
`crates/secode-cli/src/installation/{package,stateengine_package}.rs`.

**Depends on:** R01/R02/R03; completed in-process host adapter, both-direction live
handover and SC packager owner at stage 4. R04 signs the final assembled distribution.
Use the SC package's current version guard/inventory, not another selector.
Add a versioned native-payload variant; keep the legacy decoder for still-current
Node packages rather than relabelling their mandatory-Node schema as Rust.

**Clauses:** 00 §§1.1/2.1/3.2/7.1; integration **Payloads and entrypoints**,
**Choice of Rust integration**, **Changes SE Code would make**; 80 B1–B3/§3.3.

**Witness:** inspect the copied artifact from outside its assembler: the package
contains the native StateEngine entry, required notices and exact target/API/source
pins; linked host bytes match their build. The Rust variant replaces StateEngine's
Node/JS/Postgres payload inventory without requiring npm or an external checkout.
Missing/unlisted/linked/mismatched assets refuse. Install from the finished package:
the TUI/product uses one embedded host, not one CLI/daemon per tool or agent.
Closing SE Code with live agents hands custody to detached `se up`; that successor
exits 10 minutes after its last live agent. Ordinary `se down` stops agents on
every OS and prints observed stop facts with the original-conversation resume command.
Keep the private Node factory and its package/runtime independent of this product
release; no fleet migration or factory API conversion is needed.

**Estimate:** 160–260 lines.

### R06 — Install and uninstall; PATH ownership, upgrade and removal

**Files:** SC `crates/secode-cli/src/installation/{bundled,transition,package}.rs`
and existing installer/PATH handling; SE `scripts/release/install.{ps1,sh}` and
`uninstall.{ps1,sh}` for standalone user installation/removal. Wire the local-owner
`se uninstall` operation (`installation.uninstall`) registered in OPS by the
surface owner; it has no MCP tool. Uninstall scripts and SE Code's installer call
that operation; they contain no second stop, deletion or PATH-removal implementation.

**Depends on:** R03's minimal native entry for standalone stage 1; only commercial
installation waits for R05 and SC's installation owner/active-version guard at
stage 4. Both use platform user PATH APIs and ownership records. No runtime is
booted simply by installing or selecting the executable. The release scripts
are usable from the unsigned archive before J1 is claimed, including the registered
uninstall operation. With no running host it witnesses that absence; once launched
agents exist at stage 2, its same ordinary-down path stops them with the witness.

**Clauses:** 00 §§1.3/2.1/5.4/5.8; integration **Payloads and entrypoints**;
80 §§2.1/3.5/4, B3/B7.

**Witness:** fresh native login terminals resolve **both secode and se** after
commercial installation, without repository paths/environment setup. The se alias
selects the guarded installed package, preserves argv/stdio/exit code/cancellation,
and keeps that version alive during upgrade. Standalone install exposes se at
00 §5.4's user path. Collisions never overwrite an unrelated command; bundled and
standalone ownership must resolve upgrades/removal explicitly. Partial install
rolls back owned changes; removal preserves user code/history and unrelated aliases.
Measure the actual PATH-invoked command including selector/child overhead: all
six core reads retain section 80's sample counts and latency targets. Inner-binary
timing cannot hide a slow installed wrapper; optimize the existing guarded path if needed.

Uninstall prints the exact owned binaries, integration bindings and PATH edits
it will remove, with any live-agent consequence, then uses section 70's owner
human-presence/mistake-and-drift guard; no typed-ID prompt. `se uninstall` first
performs ordinary graceful down itself: stop owned agents with the outside stop
witness, save their original-conversation resume references, and print the achieved
stop facts. Only after that succeeds does it remove the installation. If down or
its witness is incomplete, it refuses with the named remaining obligation and
retains the installation; the user need not run a separate down command first.
It never kills agents without a stop witness or removes an in-use version.
Project `remove` and executable `uninstall`
are distinct: neither erases history, source, provider conversations, unrelated
aliases or independently installed commands; erasure remains explicit forget.
Remove only recorded install-owned PATH entries/bindings that still match their
owned bytes; user edits/conflicts refuse rather than overwrite. Standalone scripts
and SE Code's installer invoke the installed `se uninstall` and surface its receipt,
exit status and partial-failure facts. The operation owns the complete effect and
readbacks rather than reporting success before cleanup has happened.

From an external fresh terminal, J5 invokes `se uninstall` with live owned agents,
reads their achieved stop facts and saved resume references, verifies installed
command absence and restored PATH against its pre-install value, and checks unrelated
commands and preserved user history/source. Also exercise interrupted install/
uninstall and the bundled-versus-standalone collision case. Windows and Linux
qualify this early; macOS repeats it in the compatibility campaign before alpha.

**Estimate:** 240–380 lines.

### R07 — Standalone archives and stateengine.ai download staging

**Files:** SE `scripts/release/{assemble,publish}.py`, release manifest/notices and
standalone install/uninstall assets; stateengine.ai's existing downloads index/page,
versioned `/downloads/<version>/<target>/` objects and checksums.

**Depends on:** R01/R03 and standalone R06; site/release owner and existing upload
channel; license/notices inputs. No installer compiles code, fetches npm or needs a checkout.
Linux notices elect AFL-2.1 for the vendored libdbus library and ship its license and upstream attribution in every applicable standalone/commercial package.
R04/R05 are not needed for the early unsigned archive. R08 owns final release
promotion after signed-artifact consumer qualification.

**Clauses:** 00 §§1.3/5.4/5.8/7.1 (stateengine.ai, no telemetry);
integration **Payloads and entrypoints**; 80 B3/B7/§5 outside evidence.

**Witness:** at stage 1, stage an explicitly unsigned, target/version-pinned archive
with native `se`, notices, install/uninstall scripts and matching inventory; run
J1 from that real HTTPS download. It needs neither signing credentials nor a
commercial bundle. At stage 4, assemble signed packages using the same final native
CLI bytes pinned by commercial SE Code, with version/API, notices and truthful
platform trust metadata. Fetch staged objects via HTTPS from outside the publisher
and compare the downloaded/unpacked inventory/digests, not the source staging folder.
A clean machine installs and runs them without SE Code. Prepare a platform/arch/
version-specific download index and install instructions; atomically promote its
current-version pointer only after R08. Interrupted uploads leave the previous
working index, never a partly published release. No unsolicited update daemon or
telemetry is introduced.

**Estimate:** 120–200 lines of existing release/site integration.

### R08 — Qualify finished distributions, then promote

**Files:** no new product implementation planned. Use the existing independent
journey/budget runner, fresh native installation environments and release-owner
promotion path; defects return to the owning unit above.

**Depends on:** stage-appropriate R01–R07 outputs for intermediate checks; all
required release units, complete core/harness behavior and runner-owner probes
for final promotion; Windows/macOS/Linux access, signing identities and website/SC
release owners.
Absent hardware/credentials block their affected release, not this planning draft.

**Clauses:** 00 §§1.3–1.4/4/7.1; integration **Proposed budgets** and transition
boundary; 80 §§1–2/5, B1–B9 with the runtime/runner owners supplying their probes.

**Witness:** run the existing Rust-only journey/budget runner from a scheduler,
timer or non-agent shell outside agent process trees, so human-presence checks
are meaningful mistake/drift guards. Stage-1 J1 and stage-2 Claude J2/J3/J5 use
real unsigned downloads; stage 3 qualifies all five standalone journeys on
Windows/Linux with real Claude and Codex. These are intermediate results.
Before alpha promotion, walk all five journeys from real standalone and embedded
SE Code downloads on clean Windows, Linux and macOS with both providers, using
final signed/package bytes. Embedded qualification uses SE Code's Rust server,
exact linked API identity, first bind AND a real task with continuity/tools/mail,
and section 80's B1/B2 memory/startup methods. Embedded sessions use in-process
handles and mint no machine credentials. B3's zero persistent embedded-process
claim is measured while no agent is live; after SE Code exits with live agents,
count the detached successor and qualify both handover directions under B8,
including all retained crash phases. Qualify standalone B4, ordinary B9 write
paths and the separate FULL-mutation bound after real work, and core CLI
latency/idle with the same budget table.
Confirm public-package exclusion again, native trust/launch, upgrade/removal and
outside download/readback. Keep failed/outlier samples; missing probes are unknown,
not passes. Promote only the qualified package/index through the authorized release
owner; document the exact installed version and rollback-compatible predecessor.
Linked-code upgrades redeploy the product process; no dynamic Rust hot reload is claimed.

**Estimate:** 0 additional product lines; no new release observer/gate framework.

## Estimate and handoff boundaries

The per-unit estimates above feed the single generated size table in section 95;
R01–R07 sum to **960–1,600 handwritten lines** (lower bounds 80+120+140+100+160+240+120;
upper bounds 140+220+220+180+260+380+200). This file carries no second total table.
R06 counts installation effects and delegating scripts; the core registry/CLI
entry is counted once in 95-core-cli. R08 reuses the existing independent
runner and adds no product lines or new qualification framework. R03/R04 include
their macOS portion, scheduled in the borrowed-Mac campaign rather than counted
again as a second release implementation.

This excludes the engine, public API and harness implementations already assigned
elsewhere. Public-source separation is R02's early prerequisite, not a final
payload filter. Windows signing access, Apple enrollment and native hardware stay
named owner dependencies; this plan neither selects a paid provider nor claims
those resources exist. SC integration, packaging and site paths require their
owners' coordination before implementation. The historical desktop bridge and
SE Code 0.1 package maintenance remain outside this lane. The release ships the
Rust product while the Node repository retains its private factory engine.

Platform tool details follow primary documentation:
[Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool),
[Authenticode verification](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-verify-a-file-signature),
[Apple Developer ID](https://developer.apple.com/developer-id/) and
[notarization identity requirements](https://developer.apple.com/documentation/Security/resolving-common-notarization-issues).
These support R04's future witness, not evidence of a signed artifact today.
