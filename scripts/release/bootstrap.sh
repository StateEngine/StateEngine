#!/bin/sh
# One-shot installer for Linux x86_64 and macOS (arm64, x86_64).
#
#     curl -fsSL <base>/bootstrap.sh | sh
#
# The one-liner fetches the release index, downloads the signed package for
# this platform, verifies its published checksum and its signature, and hands
# off to the SE Code installer (secode update --from). It keeps no state of
# its own, so running it twice is safe: the second run re-verifies and
# updates the installation. It needs only curl, tar, openssl and awk. No
# compiler and no Node are required.
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
command -v awk >/dev/null 2>&1 || fail 'awk is not installed; install awk for your system and rerun the one-liner'

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
# The release package bundles the engine as one of two payload manifests:
# stateengine/native-payload.json (schema stateengine.native-payload/v1)
# from the current bundler, or the legacy
# stateengine/stateengine-payload.json (schema stateengine.se-payload.v1)
# from older packages. When both are present the native manifest is the
# package's; a present manifest whose schema is wrong is a refusal, never a
# fallback to the other file.
#
# Recognition holds the manifest JSON contract, not a text pattern: the file
# is exactly one JSON document, compact or indented, its root is an object,
# and the root "schema" string equals the expected schema. A malformed
# document, a non-object root, or a schema token nested below the root is a
# refusal. The check below is a strict POSIX awk parser, because this route
# may run on a machine with no Node and no Python, and it bounds nesting at
# the same order as PowerShell 5.1's ConvertFrom-Json.
json_manifest_schema_is() {
    # $1 = manifest path, $2 = expected root schema
    awk -v expected="$2" '
{
    lines[NR] = $0
    linelen[NR] = length($0)
}
END {
    nl = NR
    li = 1
    ci = 1
    err = 0
    rootkind = ""
    roothas = 0
    rootschema = ""
    mark = sprintf("%c", 1)
    skip_ws()
    if (cur() != "") parse_value(1, 1)
    if (!err) {
        skip_ws()
        if (cur() != "") err = 1
        else if (rootkind != "object") err = 1
        else if (!roothas) err = 1
        else if (rootschema != expected) err = 1
    }
    exit err ? 1 : 0
}
function cur(   c) {
    if (li > nl) return ""
    if (ci > linelen[li]) return "\n"
    return substr(lines[li], ci, 1)
}
function advance() {
    if (li > nl) return
    ci++
    if (ci > linelen[li]) { li++; ci = 1 }
}
function saved() {
    svli = li
    svc = ci
}
function restore() {
    li = svli
    ci = svc
}
function peek(k,   i, c, s) {
    s = ""
    for (i = 1; i <= k; i++) {
        c = cur()
        if (c == "") return s
        s = s c
        advance()
    }
    return s
}
function skip_ws(   c) {
    for (;;) {
        c = cur()
        if (c == " " || c == "\t" || c == "\n" || c == "\r") {
            advance()
            continue
        }
        break
    }
}
function hex2dec(h,   i, v) {
    v = 0
    for (i = 1; i <= 4; i++)
        v = v * 16 + index("0123456789abcdef", tolower(substr(h, i, 1))) - 1
    return v
}
function parse_value(d, isroot,   c) {
    if (err) return
    if (d > 1026) { err = 1; return }
    skip_ws()
    c = cur()
    if (c == "{") parse_object(d, isroot)
    else if (c == "[") { if (isroot) rootkind = "array"; parse_array(d) }
    else if (c == "\"") { if (isroot) rootkind = "string"; parse_string() }
    else if (c == "-" || (c >= "0" && c <= "9")) { if (isroot) rootkind = "number"; parse_number() }
    else if (c == "t") { if (isroot) rootkind = "literal"; advance(); if (peek(3) != "rue") err = 1 }
    else if (c == "f") { if (isroot) rootkind = "literal"; advance(); if (peek(4) != "alse") err = 1 }
    else if (c == "n") { if (isroot) rootkind = "literal"; advance(); if (peek(3) != "ull") err = 1 }
    else err = 1
}
function parse_number(   c) {
    c = cur()
    if (c == "-") advance()
    c = cur()
    if (c == "0") advance()
    else if (c >= "1" && c <= "9") {
        while (cur() >= "0" && cur() <= "9") advance()
    } else { err = 1; return }
    if (cur() == ".") {
        advance()
        if (!(cur() >= "0" && cur() <= "9")) { err = 1; return }
        while (cur() >= "0" && cur() <= "9") advance()
    }
    if (cur() == "e" || cur() == "E") {
        advance()
        if (cur() == "+" || cur() == "-") advance()
        if (!(cur() >= "0" && cur() <= "9")) { err = 1; return }
        while (cur() >= "0" && cur() <= "9") advance()
    }
}
function parse_object(d, isroot,   c, key) {
    if (err) return
    advance()
    for (;;) {
        skip_ws()
        c = cur()
        if (c == "}") {
            advance()
            if (isroot) rootkind = "object"
            return
        }
        if (c != "\"") { err = 1; return }
        parse_string()
        if (err) return
        key = strval
        skip_ws()
        if (cur() != ":") { err = 1; return }
        advance()
        if (isroot && key == "schema") {
            skip_ws()
            if (cur() != "\"") { err = 1; return }
            parse_string()
            if (err) return
            rootschema = strval
            roothas = 1
        } else {
            parse_value(d + 1, 0)
            if (err) return
        }
        skip_ws()
        c = cur()
        if (c == ",") { advance(); continue }
        if (c == "}") {
            advance()
            if (isroot) rootkind = "object"
            return
        }
        err = 1
        return
    }
}
function parse_array(d,   c) {
    if (err) return
    advance()
    skip_ws()
    if (cur() == "]") { advance(); return }
    for (;;) {
        parse_value(d + 1, 0)
        if (err) return
        skip_ws()
        c = cur()
        if (c == ",") { advance(); continue }
        if (c == "]") { advance(); return }
        err = 1
        return
    }
}
function parse_string(   c, out, hex, code) {
    if (err) return
    advance()
    out = ""
    for (;;) {
        c = cur()
        if (c == "") { err = 1; break }
        if (c == "\"") { advance(); strval = out; return }
        if (c != "\\") {
            if (c < " ") { err = 1; break }
            out = out c
            advance()
            continue
        }
        advance()
        c = cur()
        if (c == "") { err = 1; break }
        if (c == "\"") { out = out "\""; advance() }
        else if (c == "\\") { out = out "\\"; advance() }
        else if (c == "/") { out = out "/"; advance() }
        else if (c == "b") { out = out "\b"; advance() }
        else if (c == "f") { out = out "\f"; advance() }
        else if (c == "n") { out = out "\n"; advance() }
        else if (c == "r") { out = out "\r"; advance() }
        else if (c == "t") { out = out "\t"; advance() }
        else if (c == "u") {
            advance()
            hex = peek(4)
            if (hex !~ /^[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]$/) { err = 1; break }
            code = hex2dec(hex)
            if (code >= 55296 && code <= 56319) {
                saved()
                if (peek(6) !~ /^\\u[DEde][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]$/) restore()
                out = out mark
            } else if (code >= 32 && code <= 126) out = out sprintf("%c", code)
            else out = out mark
        }
        else { err = 1; break }
    }
}
    ' "$1"
}

bundles_se=0
if [ -f "$pkgroot/stateengine/native-payload.json" ]; then
    json_manifest_schema_is "$pkgroot/stateengine/native-payload.json" 'stateengine.native-payload/v1' \
        || fail 'the package carries a native StateEngine payload that is not a readable stateengine.native-payload/v1 manifest; do not install it'
    bundles_se=1
elif [ -f "$pkgroot/stateengine/stateengine-payload.json" ]; then
    json_manifest_schema_is "$pkgroot/stateengine/stateengine-payload.json" 'stateengine.se-payload.v1' \
        || fail 'the package carries a StateEngine payload that is not a readable stateengine.se-payload.v1 manifest; do not install it'
    bundles_se=1
fi

printf 'Installing release %s as your normal user...\n' "$index_version"
if "$pkgroot/secode" update --from "$pkgroot"; then
    :
else
    rc=$?
    fail "the installer stopped (exit $rc); read the message it printed above, do what it says, and rerun the one-liner"
fi
if [ "$bundles_se" -eq 1 ]; then
    printf 'Installed. Open a new terminal and run: se --version\n'
else
    printf 'Installed SE Code without the StateEngine engine; se is not available in this package. Open a new terminal and run: secode --version\n'
fi
