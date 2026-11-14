# Tagged standalone releases

`build.py` compiles on each supported native platform using the pinned compiler,
lockfile and distribution profile. `release_assets.py` assembles the four matching
builds and generates the downloadable installers; it does not compile again.

Before a release, set the workspace package version and tag that exact clean
commit as `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-prerelease`. Build output
directories are named by their target triples under one directory:

```sh
python -B scripts/release/build.py --target TARGET --out /new/builds/TARGET
python -B scripts/release/release_assets.py --builds /new/builds --out /new/assets --tag v0.0.1
```

The second command requires every target in `inputs.json`, built from the tagged
commit. It uses the existing assembler to verify build inventories, release
inputs, native formats and companion images before publishing any output. The
output contains four full archives, separate diagnostic archives where available,
archive checksum sidecars, `release.json`, `SHA256SUMS`, `install.sh` and
`install.ps1`. The last two embed exact versioned GitHub Release URLs and archive
SHA-256 values. Resolving `latest` for the script cannot select a different
version for its archive halfway through an installation.

Once those assets have been published and qualified, users can install with:

```sh
(se_installer=$(mktemp) || exit; trap 'rm -f "$se_installer"' 0; curl -fsSL https://github.com/StateEngine/StateEngine/releases/latest/download/install.sh -o "$se_installer" && sh "$se_installer")
```

```powershell
& { $ErrorActionPreference = 'Stop'; $se_installer = irm https://github.com/StateEngine/StateEngine/releases/latest/download/install.ps1; iex $se_installer }
```

The project domain can redirect `/install.sh` and `/install.ps1` to those URLs.
For a specific version, replace `latest/download` with `download/vVERSION`.
Both commands finish the script download successfully before executing it;
an interrupted transfer cannot become a successful empty shell invocation.
Do not mark an incomplete or unqualified release as latest. Stage all assets on
a draft first; expose it as a prerelease for native installation checks, then
promote the qualified stable release. An intentional prerelease remains a
prerelease and does not replace stable `latest`.

These are explicitly unsigned releases. HTTPS delivers the installer and its
embedded checksum; SHA-256 detects archive corruption or substitution relative
to that installer, and is not a separate publisher signature.

The download scripts reject unsupported platforms, unsafe archive paths/types,
download or checksum failures and version/target mismatches before handoff. The
standalone installer retains native file ownership, replacement and interrupted
installation recovery. Success requires an installed absolute-path version
readback and download scratch cleanup. A failure preserves existing user data
and reports which step refused. After installer handoff, a refusal or interruption
preserves the verified extracted archive at the printed path, so the standalone
installer's exact recovery command and flag remain usable. Failures before
handoff and completed successful installations clean only their owned scratch.

Installation neither starts a service nor configures a provider. Use the normal
user account, without privilege elevation. Removal belongs to `se uninstall`.
