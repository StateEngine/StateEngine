# 95 — Work breakdown: packaging and release

Planning draft, 2026-10-30; branch base is main `118044a`. No implementation,
tests, signing, installer changes or publication are performed by this contribution.
Build units describe the later Rust release, not a change to SE Code 0.1's current
bundled StateEngine. Desktop remains deferred; this does not revive the historical
Electron/Tauri packaging experiment.

## Sources and scope

Governing inputs are approved sections **00** and **80**, and Iris's
`secode-integration.md`, in `/mnt/nvme/stateengine/prime-handoff-20261030/`.
Integration references below name its headings: **Payloads and entrypoints**,
**Choice of Rust integration**, **Changes SE Code would make**, and **Desktop
history and future requirements**. Its source/package observations are pinned
historical evidence, not a claim about current installed bytes. The accepted
section 10 public API boundary is an additional integration dependency.

Three release variants must stay explicit:

| Variant | Contains | Runtime/build boundary |
| --- | --- | --- |
| Public SE Code | permissively licensed host API and unavailable stub | no proprietary se-types/store/core/proc/host/atlas dependency, source or `se` payload |
| Commercial SE Code | linked StateEngine host plus separately licensed native `se` payload/alias | embedded host uses default-features=false, secode+listener, Atlas off; one product host |
| Standalone StateEngine | native `se`, required notices and installer/package assets | Atlas/import included as specified in 00; one daemon only when normal custody requires it |

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
build units, not mandatory separate landings or new gate infrastructure.

## Ordered build units

### R01 — Pin release variants, sources and offline inputs

**Files:** SE `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`,
`.cargo/config.toml`, `scripts/release/inputs.json`; SC existing build/payload pins
and private commercial build manifest.

**Depends on:** se-types/API version and completed product crates; SC owner for
its Rust/SQLite pins and release profile; licensed source/vendor access for the
private job. No release helper opens se-store or user state.

**Clauses:** 00 §§3.1–3.2, 5.1/5.8, 7.1/7.2 (closed source, offline vendoring,
one SQLite linkage, panic=unwind); 80 §§3.1/3.3/4, B1/B2.

**Witness:** isolated builds resolve pinned offline inputs and record source,
version, target, toolchain, API/schema and feature sets in the existing manifests.
Build embedded and standalone graphs separately so standalone Atlas features
cannot unify into the embedded server. Confirm unwind behavior/profile and one
compatible bundled SQLite library in the linked server; missing inputs fail
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

### R03 — Native Windows, Linux and macOS build artifacts

**Files:** SE `scripts/release/build.py`, existing CI release-job definition,
platform toolchain/config entries; SC existing native build/assembly jobs.

**Depends on:** R01/R02; implemented `se`, core/store/host/proc and optional Atlas;
matching Windows SDK, Linux builder and macOS SDK/hardware. Reuse existing native
build capacity, not new remote-execution machinery.

**Clauses:** 00 §§1.3, 3.1–3.2, 5.8/7.1; integration **Payloads and entrypoints**;
80 §§2.1–2.2/3.5/4, B3/B7.

**Witness:** each advertised target produces a real release binary with the
correct architecture, version, dynamic-library requirements and feature graph.
Proposed initial matrix is Windows/Linux x86_64 and macOS arm64/x86_64; owners
confirm the advertised support set before publishing, and unqualified targets
stay unadvertised. Run on clean native machines without Rust, Node, npm, a source
checkout or build-tree environment. All required libraries/notices travel in the
artifact; build provenance alone cannot qualify another architecture/OS.

**Estimate:** 140–220 lines.

### R04 — Windows signing and macOS distribution trust

**Files:** SE `scripts/release/sign-windows.ps1` and `sign-macos.sh`; reuse SC's
existing signing/package finalization and truthful signing-manifest fields.

**Depends on:** R03 exact native bytes; Jimmy's Windows signing identity/provider
and Apple Developer ID enrollment/access (00 §7.2 item 8); authorized release
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

**Estimate:** 100–180 lines. Signing service choice/access is a release dependency,
not a request to buy credentials or change today's package.

### R05 — Bundle native se inside commercial SE Code

**Files:** SC `scripts/release/{stateengine_payload,package}.py`,
`packages/stateengine/payload-pins.json`, existing payload/release manifests and
`crates/secode-cli/src/installation/{package,stateengine_package}.rs`.

**Depends on:** R01–R04; completed in-process host adapter and SC packager owner.
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
the TUI/product uses one embedded host, not one CLI/daemon per tool or seat.
Keep today's Node package pins intact until the Rust variant is explicitly promoted.

**Estimate:** 160–260 lines.

### R06 — Install both commands on PATH; safe upgrade and removal

**Files:** SC `crates/secode-cli/src/installation/{bundled,transition,package}.rs`
and existing installer/PATH handling; SE `scripts/release/install.{ps1,sh}` for
standalone user installation.

**Depends on:** R05 and the native entry; SC installation owner/active-version
guard; platform user PATH APIs and ownership records. No runtime is booted simply
by installing or selecting the executable.

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
six core reads retain 30 samples and p95 strictly <20 ms. Inner-binary timing
cannot hide a slow installed wrapper; optimize the existing guarded path if needed.

**Estimate:** 200–320 lines.

### R07 — Standalone archives and stateengine.ai download staging

**Files:** SE `scripts/release/{assemble,publish}.py`, release manifest/notices and
standalone installer assets; stateengine.ai's existing downloads index/page,
versioned `/downloads/<version>/<target>/` objects and checksums.

**Depends on:** R01–R04/R06; site/release owner and existing upload channel;
license/notices inputs. No installer compiles code, fetches npm or needs a checkout.
R08 owns final release promotion after consumer qualification.

**Clauses:** 00 §§1.3/5.4/5.8/7.1 (stateengine.ai, no telemetry);
integration **Payloads and entrypoints**; 80 B3/B7/§5 outside evidence.

**Witness:** stage immutable per-target packages using the same final native CLI
bytes pinned by commercial SE Code, with matching version/API, notices and platform
trust metadata. Fetch staged objects via HTTPS from outside the publisher and
compare the downloaded/unpacked inventory/digests, not the source staging folder.
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

**Depends on:** R01–R07, complete core/harness behavior and runner-owner probes,
Windows/macOS/Linux access, signing identities and website/SC release owners.
Absent hardware/credentials block their affected release, not this planning draft.

**Clauses:** 00 §§1.3–1.4/4/7.1; integration **Proposed budgets** and transition
boundary; 80 §§1–2/5, B1–B7 (B8/B9 remain their existing runtime owners' obligations).

**Witness:** walk all five journeys from real bundled and standalone downloads on
three OSes, with Claude and Codex, using final signed/package bytes. Embedded A/B
includes first authenticated bind and real continuity/tools/mail: <=30,000,000
added bytes, <=100 ms, zero additional persistent StateEngine processes. Standalone
has one daemon, zero per-agent helpers, <=25,000,000 steady bytes after real work;
retain core CLI latency/idle observations using section 80's external methods.
Confirm public-package exclusion again, native trust/launch, upgrade/removal and
outside download/readback. Keep failed/outlier samples; missing probes are unknown,
not passes. Promote only the qualified package/index through the authorized release
owner; document the exact installed version and rollback-compatible predecessor.
Linked-code upgrades redeploy the product process; no dynamic Rust hot reload is claimed.

**Estimate:** 0 additional product lines; no new release observer/gate framework.

## Estimate and handoff boundaries

| Scope | Estimated handwritten lines |
| --- | ---: |
| R01–R07 release/product/config integration | 920–1,540 |
| R08 independent qualification tooling | excluded; reuse existing runner |

This excludes the engine, public API and harness implementations already assigned
elsewhere. Public-source separation is R02's early prerequisite, not a final
payload filter. Windows signing access, Apple enrollment and native hardware stay
named owner dependencies; this plan neither selects a paid provider nor claims
those resources exist. SC integration, packaging and site paths require their
owners' coordination before implementation. The historical desktop bridge and
SE Code 0.1 cutover remain outside this lane.

Platform tool details follow primary documentation:
[Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool),
[Authenticode verification](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-verify-a-file-signature),
[Apple Developer ID](https://developer.apple.com/developer-id/) and
[notarization identity requirements](https://developer.apple.com/documentation/Security/resolving-common-notarization-issues).
These support R04's future witness, not evidence of a signed artifact today.
