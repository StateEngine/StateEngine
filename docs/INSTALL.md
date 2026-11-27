# Installing, upgrading and removing StateEngine

StateEngine ships as one native `se` executable. Every install route below installs
the same verified release payload. Releases are **unsigned**: HTTPS delivers the
installer and its embedded checksum, and SHA-256 detects archive corruption or
substitution relative to that installer. A checksum is not a publisher signature.

Install Git and one signed-in provider first; see
[HARNESSES.md](HARNESSES.md#providers-and-sign-in).

## Supported platforms

| Your machine | TARGET | Archive ending |
| --- | --- | --- |
| Linux, Intel/AMD 64-bit (glibc) | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| Windows, Intel/AMD 64-bit | `x86_64-pc-windows-msvc` | `.zip` |
| macOS, Apple silicon | `aarch64-apple-darwin` | `.tar.gz` |
| macOS, Intel | `x86_64-apple-darwin` | `.tar.gz` |

Release archives are named `stateengine-VERSION-TARGET-unsigned` with the ending above.

## Install script

**Linux and macOS:**

```sh
curl --proto '=https' --proto-redir '=https' -fsSL https://github.com/StateEngine/StateEngine/releases/latest/download/install.sh | sh
```

**Windows PowerShell:**

```powershell
irm https://github.com/StateEngine/StateEngine/releases/latest/download/install.ps1 | iex
```

To finish the whole download before anything runs, so an interrupted transfer can
never execute a partial script, use these forms instead:

```sh
(se_installer=$(mktemp) || exit; trap 'rm -f "$se_installer"' 0; curl --proto '=https' --proto-redir '=https' -fsSL https://github.com/StateEngine/StateEngine/releases/latest/download/install.sh -o "$se_installer" && sh "$se_installer")
```

```powershell
& { $ErrorActionPreference = 'Stop'; $se_installer = irm https://github.com/StateEngine/StateEngine/releases/latest/download/install.ps1; iex $se_installer }
```

For a specific version, replace `latest/download` with `download/vVERSION`. Each
script embeds the exact versioned archive URL and its SHA-256 value, so resolving
`latest` cannot switch versions halfway through an installation.

The scripts reject unsupported platforms, unsafe archive paths or entry types,
download or checksum failures and version or target mismatches before installing.
Success requires reading back the installed command's absolute-path version and
cleaning up the download scratch. A failure preserves existing user data and
reports which step refused. If the installer itself refuses or is interrupted, the
verified extracted archive stays at the printed path so its recovery command still
works.

Run the installer as your normal user, without privilege elevation. Installation
neither starts a service nor configures a provider.

To put `se` on PATH, the installer saves a marked block in your login shell's startup
files (`~/.profile` and your bash or zsh files, or a fish `conf.d` file) on Linux and
macOS, or in your user PATH on Windows. Shells it can't edit safely, and links in
place of those files, get the exact line to add yourself instead. To change no
startup file or PATH at all, pass the opt-out flag; the installer then prints the line
to add:

```sh
curl --proto '=https' --proto-redir '=https' -fsSL https://github.com/StateEngine/StateEngine/releases/latest/download/install.sh | sh -s -- --no-modify-path
```

```powershell
& ([scriptblock]::Create((irm https://github.com/StateEngine/StateEngine/releases/latest/download/install.ps1))) -NoModifyPath
```

The extracted archive's installers take the same flags:
`sh ./install.sh --no-modify-path` or `.\install.ps1 -NoModifyPath`. Retrying an
interrupted upgrade keeps the PATH choice it started with. `se uninstall` removes only
the block it added and keeps a block you have edited, naming it in its report.

After it finishes, run the absolute `se --version` command the installer prints. Then
add the printed folder to PATH for the current terminal (see the PATH lines under the
manual install below) or open a fresh login terminal, which loads the installer's saved
PATH change, before running plain `se`.

## npm

```sh
npm install -g @stateengine/cli
se --version
npx @stateengine/cli --version      # temporary invocation without a global install
```

The package requires Node 18 or newer and selects the matching optional native
package for Linux x86_64 with glibc, Windows x64, or macOS arm64/x86_64. Keep
optional dependencies enabled. There is no install script, compiler or runtime
download: the configured npm registry supplies every package, even with
`--ignore-scripts`, and npm verifies package integrity during installation.

The launcher checks the platform, package version and executable presence, then
forwards the original arguments, stdio and exit result. It forwards termination
signals and waits for the native child to finish; on Windows the native child also
stops if its wrapper disappears. The platform packages contain the verified GitHub
Release payloads, including remote images and notices, and remain unsigned.
Unsupported platforms, missing optional packages and absent executables refuse with
a recovery step.

Update with `npm update -g @stateengine/cli` and remove with
`npm uninstall -g @stateengine/cli`. Package management does not start a service or
delete StateEngine history, configuration or provider login.

## Homebrew (upcoming)

A Homebrew formula is prepared for Linux x86_64 and macOS, but the tap is not
published yet. Use the install script or npm until it is announced.

## Manual archive install with checksum verification

Put the archive and its adjacent `.sha256` file in one folder and open a terminal
there. Replace `VERSION` with the downloaded version. Do not extract or install if
verification fails.

**Linux:**

```sh
archive="stateengine-VERSION-x86_64-unknown-linux-gnu-unsigned.tar.gz"
sha256sum -c "$archive.sha256" && tar -xzf "$archive" && cd "${archive%.tar.gz}"
```

**Windows PowerShell:**

```powershell
$archive = "stateengine-VERSION-x86_64-pc-windows-msvc-unsigned.zip"
$expected = ((Get-Content -LiteralPath "$archive.sha256" -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or $actual -ne $expected) { throw "Archive checksum mismatch; do not install." }
Expand-Archive -LiteralPath $archive -DestinationPath . -ErrorAction Stop
Set-Location -LiteralPath ([IO.Path]::GetFileNameWithoutExtension($archive))
```

**macOS** (use `x86_64-apple-darwin` on Intel Macs):

```sh
archive="stateengine-VERSION-aarch64-apple-darwin-unsigned.tar.gz"
shasum -a 256 -c "$archive.sha256" && tar -xzf "$archive" && cd "${archive%.tar.gz}"
```

A browser marks downloaded files as quarantined, and macOS may refuse to run the
unsigned `se` from such an archive. After the checksum passes, clear the mark from the
extracted folder before installing: `xattr -dr com.apple.quarantine .` The script
install above downloads with `curl`, which does not set the mark.

Then, from the extracted folder, install as your normal user.

**Linux and macOS, sh/bash/zsh:**

```sh
sh ./install.sh
export PATH="$HOME/.local/bin:$PATH"
se --version
```

**Windows PowerShell:**

```powershell
.\install.ps1
$env:Path = "$env:LOCALAPPDATA\StateEngine\bin;$env:Path"
se --version
```

Each installer also prints an absolute `se --version` command that works
immediately, before PATH changes. The PATH line above adds StateEngine to the
current terminal; future login terminals load the installer's saved change. In
**fish**, use `set -gx PATH "$HOME/.local/bin" $PATH`. A successful version check
prints `stateengine` and a version number. If `se` is not found, run that printed
command; do not continue with an unverified installation. Keep the extracted
archive for upgrades and removal.

## State homes

The state home holds StateEngine's settings, history and saved conversations. It is
separate from your repositories.

| OS | Default state home |
| --- | --- |
| Linux | `~/.local/state/stateengine` (or `$XDG_STATE_HOME/stateengine` when set) |
| Windows | `%LOCALAPPDATA%\StateEngine` |
| macOS | `~/Library/Application Support/StateEngine` |

`se init` prints the actual path. If you choose a custom home with `--home` or
`SE_HOME`, keep using it: commands without it select the default home instead.

## Upgrade

Standalone and npm installations upgrade differently; use the route you installed with.

**npm:** run `npm update -g @stateengine/cli`.

**Standalone (install script or archive):** if you have started a runtime, first run
`se --home HOME down` for every running data home. As the same OS owner, run the new
release's install script, or the archive's `install.sh` (Linux and macOS) or
`install.ps1` (Windows). For a custom installation data home, set `SE_HOME` to its
original absolute path before running the installer.

The installer replaces a stopped installation whose recorded files and native
ownership still match, preserving history, conversations, identity, credentials,
configuration and repository files. A live runtime or changed or foreign
installation files cause a refusal with its reason; resolve it before retrying.
After a successful installation, run `se --home HOME up` for each home.

Older binaries refuse data written with a newer unsupported schema. If trying an
older release leaves it unable to start or uninstall, run the current installer
again with the same installation data home; recovery does not require the older
binary to open or alter the newer data. Ordinary compatible uninstall followed by
installation also works: in your own terminal, run the installed
`se --home INSTALL_HOME uninstall`, or on Windows the matching old release
archive's `uninstall.ps1`, and wait for it to finish before installing. Use each
home's original path throughout; an old Windows host keeps the pipe name chosen by
its executable until restarted.

## Uninstall

**npm:** run `npm uninstall -g @stateengine/cli`. Package removal does not delete
StateEngine history, configuration or provider login.

**Standalone:** for one default Linux installation, remove the program from a
terminal you opened yourself. `se down` is only needed if you started a runtime
(with `se launch` or `se up`):

```sh
se down
se --home "$HOME/.local/state/stateengine" uninstall
```

If you set `XDG_STATE_HOME`, use `"$XDG_STATE_HOME/stateengine"` instead. On
Windows, run `se down` if a runtime is running, then the extracted archive's
`uninstall.ps1` in PowerShell and wait for its final successful completion.

For unattended removal, add `--yes` to `se uninstall`. This confirms removal
without a terminal; OS ownership, managed-session and agent ancestry checks still
apply.

The installation home is the directory containing `standalone-install.json`: the
path selected during installation, which may differ from a custom data home used
later. Removal keeps history, conversations, identity, credentials, configuration,
provider login and repository files.

## Build from source

The Rust workspace provides one `se` binary and libraries linked by the SE Code
application. To build an unsigned archive from a clean, committed source checkout,
install Git, Python 3.11+, and rustup with the toolchain pinned in
`rust-toolchain.toml` (currently Rust 1.97.1), plus the `rust-docs` component (added
below). Use a native machine matching the target:

- Linux needs a C compiler/linker and binutils.
- Windows needs Visual Studio Build Tools with the MSVC C++ workload and Windows SDK.
- macOS needs Xcode Command Line Tools.

SQLite's C source is bundled. The build downloads lockfile-pinned Cargo inputs
unless `--offline` is selected with an already populated cache.

For example, on Linux x86_64, choose new output paths outside the source tree:

```sh
rustup component add rust-docs
python3 scripts/release/build.py --target x86_64-unknown-linux-gnu --out /absolute/path/new-build
python3 scripts/release/assemble.py --build /absolute/path/new-build \
  --remote-build /absolute/path/windows-build \
  --remote-build /absolute/path/macos-arm-build \
  --remote-build /absolute/path/macos-intel-build \
  --out /absolute/path/new-archive
```

The release builder removes symbol tables and debug sections with the pinned
compiler's `rust-objcopy`, then checks the resulting executable and hashes those
final bytes. Linux keeps a separate `.debug` file; an emitted Windows PDB is
retained when available. Assembly writes retained diagnostics beside the archive
in its `.symbols` directory, bound to the source commit and executable hash. These
files stay out of the installer payload. macOS archives are stripped too; a
separate native symbol bundle is not produced by this build.

Build each companion on its matching native platform from the same commit and
release inputs. Remote-enabled archives include every supported destination's
executable and notices; assembly refuses missing or mismatched companion builds.
Use the matching target from the platform table for other native builds. Building
or cross-checking a target does not qualify its runtime behavior on that OS.

To bundle the native runtime inside another application's package, add
`--payload-out /absolute/path/new-payload` to the assembly command. This publishes
the same verified executable, build receipt and original license and notice bytes,
with an exact file inventory in `native-payload.json`. The assembly result reports
the manifest digest, version and source commit for the consumer's pin. The
directory includes remote bootstrap images when the archive does. The consumer
remains responsible for exercising its installed launcher on each native platform.
The payload output path must be absolute and new. Assembly prepares the archive,
checksum, payload and diagnostics before publishing their final paths; a refused
publication rolls back its newly published paths so the same command can retry.

Release maintainers: tagged releases, npm packages and the Homebrew formula are
produced by the tools described in `scripts/release/`.
