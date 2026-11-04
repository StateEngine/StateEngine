#!/bin/sh
# Standalone Linux/macOS installation. Removal belongs to the native se uninstall operation.
set -eu
umask 077
fail() { printf 'Install refused: %s\n' "$*" >&2; exit 1; }
hash_input() {
    if [ "$macos" -eq 1 ]; then shasum -a 256; else sha256sum; fi
}
file_digest() { sum=$(hash_input < "$1") || return "$?"; printf '%s' "${sum%% *}"; }
# Flush exact paths with the bundled per-file fsync on every platform. A system `sync FILE` is
# not a per-file flush everywhere: uutils coreutils (Ubuntu 26.04) calls the global sync(), which
# waits on every filesystem's writeback while the installation claim is held.
flush() { "$bundle/se" __install-sync "$@"; }
json_string() { printf '"'; printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; printf '"'; }
json_block() {
    awk 'BEGIN { printf "\"" } { for (i=1; i<=length($0); i++) { c=substr($0,i,1); if (c=="\\" || c=="\"") printf "\\"; printf "%s",c } printf "\\n" } END { printf "\"" }' "$1"
}
plain_path() {
    path=$1
    case "$path" in /*) ;; *) fail "installation path must be absolute: $path" ;; esac
    case "$path" in *'
'*) fail 'installation paths must not contain line breaks' ;; esac
    if printf '%s' "$path" | LC_ALL=C grep -q '[[:cntrl:]]'; then fail 'installation paths must not contain control characters'; fi
    while [ "$path" != / ]; do
        [ ! -L "$path" ] || fail "symbolic-link path component: $path"
        if [ -e "$path" ] && [ "$path" != "$1" ]; then
            [ -d "$path" ] || fail "parent path is not a directory: $path"
        fi
        path=$(dirname "$path")
    done
}
# All input and destination checks precede creation of installation directories.
macos=0
case "$(uname -s):$(uname -m)" in
    Linux:x86_64) archive_target=x86_64-unknown-linux-gnu ;;
    Darwin:arm64) macos=1; archive_target=aarch64-apple-darwin ;;
    Darwin:x86_64) macos=1; archive_target=x86_64-apple-darwin ;;
    *) fail 'this archive requires native Linux x86_64 or macOS arm64/x86_64' ;;
esac
native_held=0
recover=0
if [ "$#" -ge 1 ] && [ "$1" = --native-held ]; then
    native_held=1
    shift
fi
if [ "$#" -eq 1 ] && [ "$1" = --recover ]; then recover=1; shift; fi
[ "$#" -eq 0 ] || fail 'usage: sh ./install.sh [--recover]'
bundle=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
links=$(find "$bundle" -type l -print)
[ -z "$links" ] || fail 'extract the archive without symbolic links'
if LC_ALL=C grep -v -q '^[0-9a-f]\{64\}  [A-Za-z0-9_./+-]\{1,\}$' "$bundle/SHA256SUMS"; then fail 'invalid checksum inventory'; fi
actual_files=$(cd "$bundle" && find . -type f -print)
actual_files=$(printf '%s\n' "$actual_files" | sed 's|^\./||')
actual_files=$(printf '%s\n' "$actual_files" | LC_ALL=C sort)
expected_files=$(sed 's/^[0-9a-f]\{64\}  //' "$bundle/SHA256SUMS")
expected_files=$(printf '%s\nSHA256SUMS\n' "$expected_files" | LC_ALL=C sort)
[ "$actual_files" = "$expected_files" ] || fail 'archive contains unlisted or duplicate files'
while IFS= read -r entry || [ -n "$entry" ]; do
    expected_digest=${entry%% *}
    relative=${entry#*  }
    case "/$relative/" in *"/../"*|*"/./"*|*"//"*) fail 'non-normal archive checksum path' ;; esac
    [ "$(file_digest "$bundle/$relative")" = "$expected_digest" ] || fail "archive checksum differs: $relative"
done < "$bundle/SHA256SUMS"
field() { sed -n "s/^  \"$1\": \"\([^\"]*\)\",\{0,1\}$/\1/p" "$bundle/manifest.json"; }
[ "$(field target)" = "$archive_target" ] || fail 'archive target does not match this installer'
[ "$(field variant)" = standalone ] && [ "$(field trust)" = unsigned ] || fail 'unsupported archive variant'
case ${HOME-} in /*) ;; *) fail 'HOME must be an absolute user-home path' ;; esac
bin=$HOME/.local/bin
assets=$HOME/.local/share/stateengine/installation
if [ "$macos" -eq 1 ]; then data=${SE_HOME:-$HOME/Library/Application Support/StateEngine}
else data=${SE_HOME:-${XDG_STATE_HOME:-$HOME/.local/state}/stateengine}; fi
record=$data/standalone-install.json
partial=$data/standalone-install.partial
plain_path "$partial"
if [ "$recover" -eq 1 ]; then
    [ -d "$partial" ] || fail "partial installation is absent: $partial"
else [ ! -e "$partial" ] || fail "partial installation at $partial; resume with: sh \"$bundle/install.sh\" --recover"; fi
for destination in "$bin/se" "$assets" "$record"; do
    plain_path "$destination"
    if [ "$recover" -eq 1 ]; then
        : # The protected journal and original archive are checked under the native claim.
    elif [ "$native_held" -eq 1 ] && [ "$destination" = "$assets" ]; then
        [ -d "$assets" ] || fail "native installation assets directory is absent: $assets"
    else [ ! -e "$destination" ] || fail "existing installation path is preserved; run se uninstall before reinstalling: $destination"; fi
done
if [ "$recover" -eq 0 ] && command -v se >/dev/null 2>&1; then fail "another se command is already on PATH: $(command -v se)"; fi
profiles='.profile'
fish_file=''
case ${SHELL-} in
    */fish)
        profiles=''
        fish_file=${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/stateengine.fish
        plain_path "$fish_file"
        [ "$recover" -eq 1 ] || [ ! -e "$fish_file" ] || fail "existing fish configuration is preserved: $fish_file"
        ;;
    ''|*/sh|*/bash|*/dash|*/ksh|*/zsh)
        if [ -e "$HOME/.bash_profile" ] || [ -L "$HOME/.bash_profile" ]; then profiles="$profiles .bash_profile"
        elif [ -e "$HOME/.bash_login" ] || [ -L "$HOME/.bash_login" ]; then profiles="$profiles .bash_login"; fi
        case ${SHELL-} in */zsh) profiles="$profiles .zprofile" ;; esac
        ;;
    *) fail 'supported login shells are sh, bash, dash, ksh, zsh and fish; open one of these shells before installing' ;;
esac
profile_metadata() {
profile_digests=''
for name in $profiles; do
    profile=$HOME/$name
    plain_path "$profile"
    if [ -e "$profile" ]; then
        [ -f "$profile" ] && [ -r "$profile" ] && [ -w "$profile" ] || fail "login profile is unreadable or not writable: $profile"
        if grep -q -F '# >>> StateEngine PATH >>>' "$profile"; then fail "unrecorded PATH block is preserved: $profile"; fi
        prior=$(file_digest "$profile")
        prior_bytes=$(wc -c < "$profile")
    else prior=absent; prior_bytes=0; fi
    profile_digests="$profile_digests$name $prior $prior_bytes
"
done
}
if [ "$recover" -eq 0 ]; then profile_metadata; fi
# The inventory contains only safe relative names, so this list needs no path splitting.
asset_files='manifest.json build.json NOTICE.txt notices.tar uninstall.sh'
# Native preparation rejects unsafe existing homes, creates absent homes with
# the same protection as init, and retains the account-wide installation claim.
if [ "$native_held" -eq 0 ]; then
    set -- __install-hold --prepare-program --home "$data"
    for name in $profiles; do set -- "$@" --profile "$HOME/$name"; done
    if [ -n "$fish_file" ]; then set -- "$@" --fish-directory "$(dirname "$fish_file")"; fi
    if [ -n "${XDG_STATE_HOME-}" ]; then set -- "$@" --xdg-state-home "$XDG_STATE_HOME"; fi
    if [ -n "${XDG_CONFIG_HOME-}" ]; then set -- "$@" --xdg-config-home "$XDG_CONFIG_HOME"; fi
    # Retain the public caller while the native holder watches its lifetime.
    if [ "$recover" -eq 1 ]; then
        "$bundle/se" "$@" -- /bin/sh "$bundle/install.sh" --native-held --recover
    else "$bundle/se" "$@" -- /bin/sh "$bundle/install.sh" --native-held; fi
    exit "$?"
fi
# This reads custody from the native channel only after verifying the inherited
# account-wide kernel claim. A worker marker or environment list grants nothing.
created_directories=$("$bundle/se" __install-home-check "$data") || fail 'native installation claim or directory custody is absent'
owner=$(id -u)
stage=''
temp_payload=''
done_install=0
publish_file() {
    # Recovery resumes only bytes owned by the matching protected journal.
    if [ "$recover" -eq 1 ] && [ -e "$2" ]; then
        plain_path "$2"
        [ -f "$2" ] && cmp -s "$1" "$2" || fail "partial destination changed; preserved: $2"
        flush "$2" "$(dirname "$2")"
        return
    fi
    # Copy and flush on the destination filesystem, then claim without replace.
    temp_payload=$(mktemp "$(dirname "$2")/.se-publish-XXXXXXXX")
    cp "$1" "$temp_payload"
    chmod "$3" "$temp_payload"
    flush "$temp_payload"
    # link(2) through the bundled binary: the claim refuses atomically against
    # any existing destination, of any kind; no precheck can own the interval.
    "$bundle/se" __install-publish "$temp_payload" "$2" || { rm "$temp_payload"; temp_payload=''; fail "destination appeared during installation: $2"; }
    if [ ! -f "$2" ] || [ ! "$2" -ef "$temp_payload" ]; then
        rm "$temp_payload"; temp_payload=''
        fail "destination appeared during installation: $2"
    fi
    rm "$temp_payload"
    temp_payload=''
    flush "$2" "$(dirname "$2")"
}
# Stream only the original prefix; neither profile bytes nor secrets reach disk.
# Record the producer's status separately: a successful hash cannot hide a short read.
prefix_digest() {
    hash_scratch=$(mktemp -d "$stage/.hash-XXXXXXXX") || return 1
    hash_status=0
    (
        copy_status=0
        if [ "$macos" -eq 1 ]; then
            dd if="$1" bs=1 count="$2" 2>/dev/null || copy_status=$?
        else head -c "$2" "$1" || copy_status=$?; fi
        printf '%s\n' "$copy_status" > "$hash_scratch/status"
    ) | hash_input > "$hash_scratch/result" || hash_status=$?
    copy_status=$(cat "$hash_scratch/status") || return 1
    [ "$copy_status" -eq 0 ] && [ "$hash_status" -eq 0 ] || return 1
    hash_value=$(cat "$hash_scratch/result") || return 1
    rm "$hash_scratch/status" "$hash_scratch/result" || return 1
    rmdir "$hash_scratch" || return 1
    printf '%s' "${hash_value%% *}"
}

profile_append_matches() {
    profile=$HOME/$1
    [ ! -L "$profile" ] && [ -f "$profile" ] || return 1
    prior=$(cat "$stage/$1.digest") || return 1
    prior_bytes=$(cat "$stage/$1.bytes") || return 1
    current_bytes=$(wc -c < "$profile") || return 1
    block_bytes=$(wc -c < "$stage/path-block") || return 1
    appended_bytes=$((current_bytes - prior_bytes))
    [ "$appended_bytes" -ge 0 ] && [ "$appended_bytes" -le "$block_bytes" ] || return 1
    if [ "$prior" != absent ]; then
        prefix=$(prefix_digest "$profile" "$prior_bytes") || return 1
        [ "$prefix" = "$prior" ] || return 1
    else [ "$prior_bytes" -eq 0 ] || return 1; fi
    if [ "$macos" -eq 0 ]; then
        cmp -s -n "$appended_bytes" -i "$prior_bytes":0 "$profile" "$stage/path-block"
        return $?
    fi
    compare_scratch=$(mktemp -d "$stage/.compare-XXXXXXXX") || return 1
    compare_status=0
    (
        copy_status=0
        dd if="$stage/path-block" bs=1 count="$appended_bytes" 2>/dev/null || copy_status=$?
        printf '%s\n' "$copy_status" > "$compare_scratch/status"
    ) | cmp -s - "$profile" 0 "$prior_bytes" || compare_status=$?
    copy_status=$(cat "$compare_scratch/status") || return 1
    [ "$copy_status" -eq 0 ] || compare_status=1
    rm "$compare_scratch/status" || return 1
    rmdir "$compare_scratch" || return 1
    return "$compare_status"
}
remove_stale_temps() {
    plain_path "$1"
    [ -d "$1" ] || return 0
    [ -r "$1" ] && [ -x "$1" ] || fail "cannot inspect stale installation scratch: $1"
    for stale in "$1/$2"????????; do
        [ -f "$stale" ] && [ ! -L "$stale" ] || continue
        suffix=${stale##*/}
        suffix=${suffix#"$2"}
        case "$suffix" in *[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]*) continue ;; esac
        if [ "$macos" -eq 1 ]; then stale_owner=$(stat -f %u "$stale")
        else stale_owner=$(stat -c %u "$stale"); fi
        [ -n "$stale_owner" ] || fail "cannot read stale installation scratch owner: $stale"
        [ "$stale_owner" = "$owner" ] || continue
        rm "$stale" || fail "cannot remove owned stale installation scratch: $stale"
    done
}
cleanup() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$done_install" -eq 0 ]; then
        [ -z "$stage" ] || printf 'Partial installation preserved at %s\nResume with: sh "%s/install.sh" --recover\n' "$stage" "$bundle" >&2
        exit "$exit_code"
    fi
    if [ -n "$stage" ]; then
        find "$stage" -depth -type f -exec rm {} +
        find "$stage" -depth -type d -exec rmdir {} \;
        if [ -e "$stage" ]; then
            printf 'Installation scratch cleanup incomplete: %s\n' "$stage" >&2
            exit_code=1
        fi
    fi
    if [ "$exit_code" -eq 0 ]; then
        flush "$data" || exit_code=1
    fi
    if [ "$exit_code" -eq 0 ]; then
        printf 'Installed se at %s\nOpen a fresh login terminal and run se --version.\n' "$bin/se"
    fi
    # The native holder retains the identities of its created directories and
    # owns failed-child directory cleanup; the script never removes them by name.
    exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for directory in "$bin" "$assets" "$data"; do
    [ -d "$directory" ] && [ ! -L "$directory" ] || fail "native installation directory is absent or linked: $directory"
done
stage=$partial
resume=0
if [ "$recover" -eq 1 ]; then
    recovery=$("$bundle/se" __install-recovery-check "$data" && printf 'end\n') || fail 'partial journal or matching archive is unreadable'
    {
        IFS= read -r mode
        IFS= read -r saved_profiles
        IFS= read -r saved_fish
        IFS= read -r end_marker
    } <<RECOVERY
$recovery
RECOVERY
    [ "$end_marker" = end ] || fail 'native recovery response is incomplete'
    if [ "$mode" = resume ]; then
        resume=1; profiles=$saved_profiles; fish_file=$saved_fish
    elif [ "$mode" = fresh ]; then
        # No payload was published before the interrupted journal was complete.
        find "$stage" -depth -type f -exec rm {} +
        profile_metadata
    else fail 'unknown native recovery state'; fi
else mkdir "$stage"; fi
if [ "$resume" -eq 0 ]; then
cat > "$stage/path-block" <<'BLOCK'

# >>> StateEngine PATH >>>
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH" ;;
esac
# <<< StateEngine PATH <<<
BLOCK
while read -r name prior prior_bytes; do
    if [ -n "$name" ]; then
        printf '%s\n' "$prior" > "$stage/$name.digest"
        printf '%s\n' "$prior_bytes" > "$stage/$name.bytes"
    fi
done <<DIGESTS
$profile_digests
DIGESTS
if [ -n "$fish_file" ]; then
    cat > "$stage/fish-config" <<'FISH'
# StateEngine PATH (owned standalone configuration)
if not contains -- "$HOME/.local/bin" $PATH
    set -gx PATH "$HOME/.local/bin" $PATH
end
FISH
fi
{
    printf '{\n  "schema": "stateengine-install/v1",\n  "owner": '; json_string "$owner"
    checksum=$(file_digest "$bundle/se")
    printf ',\n  "files": [\n    {"path": '; json_string "$bin/se"; printf ', "sha256": "%s"}' "$checksum"
    for relative in $asset_files; do
        checksum=$(file_digest "$bundle/$relative")
        printf ',\n    {"path": '; json_string "$assets/$relative"; printf ', "sha256": "%s"}' "$checksum"
    done
    if [ -n "$fish_file" ]; then
        checksum=$(file_digest "$stage/fish-config")
        printf ',\n    {"path": '; json_string "$fish_file"; printf ', "sha256": "%s"}' "$checksum"
    fi
    printf '\n  ],\n  "created_directories": ['
    comma=''
    while IFS= read -r directory; do
        if [ -n "$directory" ]; then printf '%s' "$comma"; json_string "$directory"; comma=','; fi
    done <<DIRECTORIES
$created_directories
DIRECTORIES
    printf '],\n  "path_edits": ['
    comma=''
    for name in $profiles; do
        printf '%s\n    {"target": ' "$comma"; json_string "$HOME/$name"; printf ', "before_sha256": '
        prior=$(cat "$stage/$name.digest")
        if [ "$prior" != absent ]; then json_string "$prior"; else printf null; fi
        prior_bytes=$(cat "$stage/$name.bytes")
        printf ', "before_bytes": %s, "block": ' "$prior_bytes"; json_block "$stage/path-block"; printf '}'
        comma=','
    done
    printf '\n  ]}\n'
} > "$stage/install.json"
file_digest "$bundle/manifest.json" > "$stage/.manifest-ready"
set -- "$stage/install.json" "$stage/.manifest-ready" "$stage/path-block"
for name in $profiles; do set -- "$@" "$stage/$name.digest" "$stage/$name.bytes"; done
if [ -n "$fish_file" ]; then set -- "$@" "$stage/fish-config"; fi
flush "$@" "$stage" "$data"
# Publish readiness only after the entire original journal is durable.
# link(2) through the bundled binary refuses any existing claim atomically.
"$bundle/se" __install-publish "$stage/.manifest-ready" "$stage/manifest.sha256" || fail "manifest claim failed: $stage/manifest.sha256"
[ -f "$stage/manifest.sha256" ] && [ "$stage/manifest.sha256" -ef "$stage/.manifest-ready" ] || fail "manifest claim failed: $stage/manifest.sha256"
rm "$stage/.manifest-ready"
flush "$stage/manifest.sha256" "$stage"
fi
# Only the exclusive claimant may scrub earlier scratch in shared destinations.
remove_stale_temps "$HOME" .se-profile-
remove_stale_temps "$bin" .se-publish-
remove_stale_temps "$data" .se-publish-
if [ -n "$fish_file" ]; then remove_stale_temps "$(dirname "$fish_file")" .se-publish-; fi
for relative in $asset_files; do
    publish_file "$bundle/$relative" "$assets/$relative" 644
done
publish_file "$bundle/se" "$bin/se" 755
if [ -n "$fish_file" ]; then
    publish_file "$stage/fish-config" "$fish_file" 600
fi
for name in $profiles; do
    profile=$HOME/$name
    prior=$(cat "$stage/$name.digest")
    if [ ! -e "$profile" ] && [ ! -L "$profile" ]; then
        [ "$prior" = absent ] || fail "original login profile is absent: $profile"
        (set -C; : > "$profile") || fail "login profile appeared during installation: $profile"
    fi
    profile_append_matches "$name" || fail "login profile changed; preserved: $profile"
    dd if="$stage/path-block" bs=1 skip="$appended_bytes" >> "$profile" 2>/dev/null
    flush "$profile" "$HOME"
    profile_append_matches "$name" && [ "$appended_bytes" -eq "$block_bytes" ] || fail "login profile append readback failed: $profile"
done
for relative in $asset_files; do cmp -s "$assets/$relative" "$bundle/$relative" || fail "installed asset readback failed: $relative"; done
cmp -s "$bin/se" "$bundle/se" || fail 'installed binary readback failed'
set -- "$bundle/se" __install-files-check "$bin/se"
for relative in $asset_files; do set -- "$@" "$assets/$relative"; done
"$@" || fail 'native installed-file ownership readback failed'
publish_file "$stage/install.json" "$record" 600
cmp -s "$record" "$stage/install.json" || fail 'ownership record readback failed'
"$bundle/se" __install-files-check "$record" || fail 'native ownership record readback failed'
done_install=1
