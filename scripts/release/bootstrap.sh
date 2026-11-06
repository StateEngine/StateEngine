#!/bin/sh
# One-shot installer for Linux x86_64 and macOS (arm64, x86_64).
#
#     curl -fsSL <base>/bootstrap.sh | sh
#
# The one-liner fetches the release index, downloads the signed package for
# this platform, verifies its published checksum and its signature, and hands
# off to the SE Code installer (secode update --from). It keeps no state of
# its own, so running it twice is safe: the second run re-verifies and
# updates the installation. It needs only curl, tar and openssl. No compiler
# and no Node are required.
#
# The one-liner installs signed releases only: the index must name
# trust "signed:<scheme>", each package entry must carry a signature URL,
# and the public verification key is a release-time setting stamped into
# this script. An unsigned release is refused, not bypassed.
set -eu
umask 077

fail() { printf 'Install refused: %s\n' "$*" >&2; exit 1; }

# Release-time settings: the release job stamps these two lines when it
# publishes. Nothing is published until then.
SE_RELEASE_BASE_DEFAULT=''
SE_RELEASE_PUBLIC_KEY_B64_DEFAULT=''   # base64 DER/SPKI public key
base=${SE_RELEASE_BASE:-$SE_RELEASE_BASE_DEFAULT}
if [ "$#" -ge 1 ]; then base=$1; fi
if [ -z "$base" ]; then
    fail 'no release base URL is set; the release host stamps this script when it publishes, or set SE_RELEASE_BASE for a local release server'
fi
case "$base" in
    http://*|https://*) ;;
    *) fail "the release base URL must start with http:// or https://: $base" ;;
esac
base=${base%/}
pub_key_b64=${SE_RELEASE_PUBLIC_KEY_B64:-$SE_RELEASE_PUBLIC_KEY_B64_DEFAULT}

macos=0
case "$(uname -s):$(uname -m)" in
    Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
    Darwin:arm64) macos=1; target=aarch64-apple-darwin ;;
    Darwin:x86_64) macos=1; target=x86_64-apple-darwin ;;
    *) fail "this machine is not supported by this one-liner: $(uname -s) on $(uname -m); supported are Linux x86_64 and macOS arm64 or x86_64" ;;
esac
command -v curl >/dev/null 2>&1 || fail 'curl is not installed; install curl for your system and rerun the one-liner'
command -v tar >/dev/null 2>&1 || fail 'tar is not installed; install tar for your system and rerun the one-liner'
command -v openssl >/dev/null 2>&1 || fail 'openssl is not installed; install openssl for your system and rerun the one-liner'

work=$(mktemp -d "${TMPDIR:-/tmp}/se-one-line.XXXXXX") || fail 'cannot create a temporary directory'
trap 'rm -rf "$work"' EXIT INT TERM

printf 'Fetching the release index from %s\n' "$base"
curl -fsSL --retry 2 -o "$work/index.json" "$base/releases/index.json" \
    || fail "cannot reach $base/releases/index.json; check the URL and your network connection, then rerun the one-liner"
grep -q '"schema": "secode.release-index.v1"' "$work/index.json" \
    || fail 'the release index is not a readable secode.release-index.v1 document; do not install from it, and tell the maintainer the base URL'
index_version=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$work/index.json")
[ -n "$index_version" ] || fail 'the release index names no version; do not install from it'

# The release job emits each package entry on one line, indented under
# "packages"; a shape change bumps the schema and this refusal stays honest.
entry=$(sed -n "s/^  \"$target\": \(.*\),\{0,1\}$/\1/p" "$work/index.json")
[ -n "$entry" ] || fail "the release index has no package for this platform ($target); supported targets are in the index"
pkg_url=$(printf '%s' "$entry" | sed -n 's/.*"url": "\([^"]*\)".*/\1/p')
pkg_sha256=$(printf '%s' "$entry" | sed -n 's/.*"sha256": "\([0-9a-f]\{64\}\)".*/\1/p')
pkg_signature=$(printf '%s' "$entry" | sed -n 's/.*"signature": "\([^"]*\)".*/\1/p')
[ -n "$pkg_url" ] || fail "the release index entry for $target has no package URL"
[ -n "$pkg_sha256" ] || fail "the release index entry for $target has no published checksum; do not install unverified bytes"
[ -n "$pkg_signature" ] || fail "the release index entry for $target names no signature; the one-liner only installs signed releases"
case "$pkg_url" in
    http://*|https://*) archive_url=$pkg_url ;;
    /*) archive_url="$base$pkg_url" ;;
    *) fail "the release index entry for $target has a bad package URL: $pkg_url" ;;
esac
case "$archive_url" in *.tar.gz) ;; *) fail "the release package URL for $target must end in .tar.gz: $pkg_url" ;; esac
case "$pkg_signature" in
    http://*|https://*) sig_url=$pkg_signature ;;
    /*) sig_url="$base$pkg_signature" ;;
    *) fail "the release index entry for $target has a bad signature URL: $pkg_signature" ;;
esac

printf 'Downloading %s (release %s)...\n' "$(printf '%s' "$archive_url" | sed 's|.*/||')" "$index_version"
curl -fsSL --retry 2 -o "$work/package" "$archive_url" \
    || fail "the download from $archive_url failed; check your network connection and rerun the one-liner"
if [ "$macos" -eq 1 ]; then
    actual=$(shasum -a 256 "$work/package" | sed 's/^\([0-9a-f]\{64\}\).*/\1/')
else
    actual=$(sha256sum "$work/package" | sed 's/^\([0-9a-f]\{64\}\).*/\1/')
fi
[ "$actual" = "$pkg_sha256" ] \
    || fail 'the downloaded package does not match its published checksum; do not bypass this check, rerun the one-liner, and if it repeats tell the maintainer which version you installed'

trust=$(sed -n 's/^  "trust": "\([^"]*\)",$/\1/p' "$work/index.json")
case "$trust" in
    signed:*) scheme=${trust#signed:} ;;
    *) fail 'this release is not signed; the one-liner only installs signed releases, so check back when the signed release is published' ;;
esac
if [ -z "$pub_key_b64" ]; then
    fail 'no public verification key is set for this release; the one-liner only installs signed releases, so check back when the signed release is published'
fi
printf 'Verifying the signature (%s)...\n' "$scheme"
curl -fsSL --retry 2 -o "$work/package.sig" "$sig_url" \
    || fail "the signature from $sig_url could not be downloaded; do not install unsigned-by-omission, rerun the one-liner"
if ! printf '%s' "$pub_key_b64" | (if [ "$macos" -eq 1 ]; then base64 -D; else base64 -d; fi) > "$work/pub.der"; then
    fail 'the release public key is not readable base64; do not install from it'
fi
case "$scheme" in
    rsa-sha256)
        if ! openssl pkey -pubin -inform DER -in "$work/pub.der" -out "$work/pub.pem" 2>/dev/null \
            || ! openssl dgst -sha256 -verify "$work/pub.pem" -signature "$work/package.sig" "$work/package" >/dev/null 2>&1; then
            fail 'the package signature does not verify against the release key; do not install it, and tell the maintainer which version you tried'
        fi
        ;;
    *) fail "signature scheme $scheme is not supported by this installer build; do not install until the installer names it" ;;
esac

printf 'Extracting and checking the package...\n'
tar -xzf "$work/package" -C "$work" \
    || fail 'the package is not a readable tar.gz archive; the release is corrupt, do not install it, and tell the maintainer which version you tried'
pkgroot=$(find "$work" -mindepth 1 -maxdepth 1 -type d | sed -n '1p')
extra=$(find "$work" -mindepth 1 -maxdepth 1 -type d | sed -n '2p')
[ -n "$pkgroot" ] && [ -z "$extra" ] \
    || fail 'the package must hold exactly one top-level folder; this one does not, so do not install it'
[ -f "$pkgroot/secode" ] && [ -x "$pkgroot/secode" ] \
    || fail 'the package is missing its installer command (secode); do not install it'
if [ -f "$pkgroot/stateengine/stateengine-payload.json" ]; then
    grep -q '"schema": "stateengine.se-payload.v1"' "$pkgroot/stateengine/stateengine-payload.json" \
        || fail 'the package carries a StateEngine payload that is not a readable stateengine.se-payload.v1 manifest; do not install it'
    bundles_se=1
else
    bundles_se=0
fi

printf 'Installing release %s as your normal user...\n' "$index_version"
if ! "$pkgroot/secode" update --from "$pkgroot"; then
    rc=$?
    fail "the installer stopped (exit $rc); read the message it printed above, do what it says, and rerun the one-liner"
fi
if [ "$bundles_se" -eq 1 ]; then
    printf 'Installed. Open a new terminal and run: se --version\n'
else
    printf 'Installed SE Code without the StateEngine engine; se is not available in this package. Open a new terminal and run: secode --version\n'
fi
