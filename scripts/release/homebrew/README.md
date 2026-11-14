# Homebrew tap

The tap is `StateEngine/homebrew-tap`. Once a qualified release formula has been
published there, install with:

```sh
brew install stateengine/tap/stateengine
```

The formula downloads an exact tagged GitHub Release archive and Homebrew verifies
its SHA-256 value. It supports Linux x86_64 and macOS arm64/x86_64 without compiling
from source. Full payloads, remote images and notices stay together under
Homebrew's `libexec`; Homebrew supplies the `se` link and owns upgrades/removal.
The home-directory installer is not invoked and no shell profile is rewritten.

Use `brew upgrade stateengine` or `brew uninstall stateengine`. Removing the
formula does not remove StateEngine history, configuration or provider login.
The release remains unsigned; a Homebrew checksum is not a publisher signature.

## Generate the release formula

Download the qualified tagged release's `release.json` and matching archives, then:

```sh
python -B scripts/release/brew_release.py --release-dir /downloaded/release --out /new/tap/Formula/stateengine.rb
```

The generator verifies archive digests and complete release inventories before
emitting the formula, and refuses to overwrite an existing output. It copies the
configured license identifier from the exact release source's Cargo metadata;
`--repository` can select the checkout containing that Git object. It neither
chooses a new license nor guesses a compound license expression.

Review the generated formula in the tap and exercise `brew fetch`, `brew install`,
`brew test`, upgrade and removal on native supported machines before publishing
the tap update. No formula with synthetic checksums or missing release assets
should be published, and no Windows or unsupported Linux architecture is offered.
