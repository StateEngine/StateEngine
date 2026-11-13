# StateEngine CLI

```sh
npm install -g @stateengine/cli
se --version
```

For a temporary invocation:

```sh
npx @stateengine/cli --version
```

The package requires Node 18 or newer. It selects the matching optional native
package for Linux x86_64 with glibc, Windows x64, or macOS arm64/x86_64. Keep
optional dependencies enabled. There is no install script, compiler or runtime
download from GitHub: the configured npm registry supplies every package, even
with `--ignore-scripts`. The launcher verifies its pinned native manifest and
executable checksum before forwarding the original arguments, stdio and result.

The platform packages contain verified GitHub Release payloads, including remote
images and notices. They remain unsigned. Registry integrity and the embedded
checksums do not claim a separate publisher signature. Unsupported platforms,
missing optional packages and changed payloads refuse with a recovery step.

Use `npm update -g @stateengine/cli` to update, or
`npm uninstall -g @stateengine/cli` to remove the package. Package management does
not start a service or delete StateEngine history, configuration or provider login.

## Packaging a release

Download the tagged release's `release.json` and four matching archives, then run:

```sh
python -B scripts/release/npm_release.py --release-dir /downloaded/release --out /new/npm-packages
```

The generator checks the archive checksums, safe file paths and full manifest
inventories, then uses the existing native payload publisher. It refuses mismatched
source commits, versions or targets before exposing a complete package directory.
`publish-order.json` lists the four platform packages before `@stateengine/cli`;
pack and publish those exact directories in that order, with public scoped access.
Publish only a previously unused version matching the release tag and workspace
version; a reserved placeholder version cannot be overwritten. Qualify the packed
packages through the actual configured registry before changing its latest tag.
