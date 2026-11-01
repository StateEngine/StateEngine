# macOS qualification: native fixtures first

Prepared against rust-se main `4fe8d76d43a00b4c699c24fb85d3c17c413b9e2a`.
No native Mac result is claimed. Counts below describe the cases in this source,
not observed passes. Use an ordinary signed-in user's Terminal, outside an agent
process tree; preserve failures and run the independent native checks first.

## 1. Clean Mac and source

Install [Xcode Command Line Tools](https://developer.apple.com/documentation/xcode/installing-the-command-line-tools/):
run `xcode-select --install`, complete the installer, then continue. Install
[rustup](https://rust-lang.org/tools/install/) if absent:

```sh
xcode-select -p
xcrun --find clang
git --version
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/se-rustup-init.sh
sh /tmp/se-rustup-init.sh -y --profile minimal
. "$HOME/.cargo/env"
```

Prime supplies a rust-se Git URL or Git bundle with `main`, and the independent
journey bundle. Set these two paths; the clone destination must be absent:

```sh
RUST_SE_GIT=/absolute/path/rust-se.bundle
JOURNEY_BUNDLE=/absolute/path/journey-bundle
MAC_SOURCE="$HOME/se-macos-qualification"
git clone --branch main "$RUST_SE_GIT" "$MAC_SOURCE"
cd "$MAC_SOURCE"
git rev-parse HEAD
git status --porcelain
rustup show active-toolchain
rustc -vV
sw_vers
uname -m
MAC_LOGS=$(mktemp -d "$HOME/se-macos-results.XXXXXX")
```

`rust-toolchain.toml` selects Rust **1.97.1**; stop if unavailable, do not change
the pin. `rustc -vV` must show a native Apple host (`aarch64-apple-darwin` or
`x86_64-apple-darwin`). Save those outputs and the exact source SHA in the result
directory. Do not substitute a Linux/Windows binary or a Rosetta run for the
other architecture's qualification. No Homebrew SQLite is needed for these
commands: the CLI's SQLite dependency builds its bundled C source with clang.

This helper keeps each real exit status beside its raw output; no pipe masks it:

```sh
mac_run() {
  mac_label=$1; shift
  if "$@" >"$MAC_LOGS/$mac_label.log" 2>&1; then
    mac_code=0
  else
    mac_code=$?
  fi
  cat "$MAC_LOGS/$mac_label.log"
  printf '%s\n' "$mac_code" >"$MAC_LOGS/$mac_label.exit"
  return "$mac_code"
}
```

## 2. Native Unix socket checks (independent of the CLI build)

```sh
mac_run runtime-paths env TMPDIR=/tmp cargo test --locked -p se-proc \
  --test unix_runtime_paths -j 2 -- --test-threads=1
mac_run socket-cleanup env TMPDIR=/tmp cargo test --locked -p se-proc \
  --test unix_socket_cleanup -j 2 -- --test-threads=1
```

Expected: **runtime paths 3 passed / 0 failed**; cleanup **5 passed / 0 failed /
1 ignored** (the separately privileged foreign-owner case). Any failure remains
a failure. `TMPDIR=/tmp` gives the cleanup fixture a short scratch path; no mode
or permission check is bypassed. The three path cases are default private
`state/run`, pure expected-path selection, and
`long_mac_home_uses_protected_temporary_leaf_and_a_short_live_socket`.
The last creates a 100-character home component, chooses a protected `se-<uid>`
temporary leaf, verifies the socket fits the native 104-byte limit, and performs
real bind/connect/write/read/close with socket absence afterward. It supplies a
short temporary root explicitly; it does not qualify every ambient `$TMPDIR`.

## 3. Build and applicable CLI cohort

```sh
mac_run cli-build cargo build --locked --release -p se --bin se -j 2
```

At the prepared main, expect **compile failure / 0 CLI cases executed**:
`crates/se/src/route/status.rs` calls `read_detachment`, but
`crates/se/src/runtime/host.rs` exports it only on Linux/Windows. This was
reproduced by macOS metadata checking on unchanged main `0abbfb44`; the same cfg
mismatch remains in the prepared source. Retain the build log and skip this
section's execution until a reviewed source fix builds; do not patch the Mac.

Once that blocker is fixed, run the non-host cohort below. Its source inventory
is **32 cases across 11 binaries, plus 1 ignored machine-identity child**; these
are expected case counts, not a prediction that unqualified Mac adapters pass.

```sh
mac_run cli-version ./target/release/se --version
mac_run cli-cohort env TMPDIR=/tmp cargo test --locked --release -p se -j 2 \
  --test agent_allocations --test cli_followups --test credential_native \
  --test decision_detail --test history_event --test install_home_custody \
  --test machine_identity --test project_root_absence --test project_roots \
  --test runtime_refusals --test uninstall_facts -- --test-threads=1
```

| Binary | Cases on macOS |
| --- | ---: |
| agent_allocations / cli_followups / credential_native | 1 / 4 / 3 |
| decision_detail / history_event / install_home_custody | 5 / 6 / 1 |
| machine_identity / project_root_absence / project_roots | 6 (+1 ignored) / 1 / 1 |
| runtime_refusals / uninstall_facts | 1 / 3 |

Do not run `cargo test -p se --all-targets` as the first Mac probe. `host_e3`,
`lost_reply`, `agent_allocation_routes` and `read_recovery` compile helpers using
`current_runtime_identity` / `NativeProcessRuntime::read_process`, which are
Linux/Windows-only. Filtering their test names does not prevent compilation of
those helpers. `endpoint_auto_recovery` and `unix_runtime_routing` are Linux-only;
`breakaway_refusal` and `runtime_image_remedy` are Windows-only (0 cases on Mac).
Detached bootstrap/process observation is also unimplemented on macOS:
`route/runtime.rs` returns "detached host startup is unavailable on this platform".
A cfg repair alone does not qualify `se up`, hosted writes or host retirement.

## 4. Journey 1 from the journey bundle

Install an independent [Node.js 24+ runtime](https://nodejs.org/en/download) for
the judge; verify `node --version`. J1 needs Git and a human Terminal, but no
provider sign-in or agent launch. Keep the runner outside a managed agent tree;
its environment check must pass without an authority bypass. Use the bundle's
reviewed `product.json` describing a **native Mac** standalone archive of the
same product SHA, not a hand-written installer wrapper or a bare copied binary:

```sh
MAC_J1_OUT="$MAC_LOGS/j1"
mac_run j1 sh "$JOURNEY_BUNDLE/journeys/run-macos.sh" \
  --implementation rust --distribution standalone --only 1 \
  --product "$JOURNEY_BUNDLE/product.json" --auth-home "$HOME" --out "$MAC_J1_OUT"
```

Expected qualification result: **1/1 selected journey**, with install/discovery,
30 installed `--version` samples (p95 strictly below 20 ms), saved init/status,
stopped runtime, public terminal uninstall, command/PATH removal and outside
process/fixture closure; `results.json` and `budgets.json` must agree. It does not
qualify journeys 2–5 or hosted B9. No runtime host is launched by standalone J1.

**Currently blocked before J1:** `scripts/release/inputs.json` supports only
Linux x86_64 and Windows x86_64; `build.py` refuses Apple targets, and `install.sh`
explicitly requires Linux x86_64 (also using GNU utilities). A native Mac archive
and installer are required in addition to the CLI cfg fix. Do not relabel the
Linux archive, edit its manifest or transplant a Mac binary into it. The existing
journey harness has a Mac terminal path (`/usr/bin/script -q /dev/null`); that path
itself still needs the native J1 walk. Give Prime the preserved blocker and
completed socket counts if no Mac archive is available.

## Off-Mac preparation: metadata only

With an authorized compute slot, the exact fixture metadata checks are:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
mac_run metadata-arm cargo check --locked --target aarch64-apple-darwin \
  -p se-proc -j 2 --test unix_runtime_paths --test unix_socket_cleanup
mac_run metadata-intel cargo check --locked --target x86_64-apple-darwin \
  -p se-proc -j 2 --test unix_runtime_paths --test unix_socket_cleanup
```

These execute **0 native cases**, link no runnable Mac product and cannot turn
any section above green. The runbook itself was checked without a workstation
build, fixture or native Mac execution.
