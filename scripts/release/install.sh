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
if [ "$#" -eq 1 ] && [ "$1" = --native-held ]; then
    native_held=1
    shift
fi
[ "$#" -eq 0 ] || fail 'usage: sh ./install.sh'
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
for destination in "$bin/se" "$assets" "$record"; do
    plain_path "$destination"
    if [ "$native_held" -eq 1 ] && [ "$destination" = "$assets" ]; then
        [ -d "$assets" ] || fail "native installation assets directory is absent: $assets"
    else [ ! -e "$destination" ] || fail "existing installation path is preserved; run se uninstall before reinstalling: $destination"; fi
done
if command -v se >/dev/null 2>&1; then fail "another se command is already on PATH: $(command -v se)"; fi
profiles='.profile'
fish_file=''
case ${SHELL-} in
    */fish)
        profiles=''
        fish_file=${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/stateengine.fish
        plain_path "$fish_file"
        [ ! -e "$fish_file" ] || fail "existing fish configuration is preserved: $fish_file"
        ;;
    ''|*/sh|*/bash|*/dash|*/ksh|*/zsh)
        if [ -e "$HOME/.bash_profile" ] || [ -L "$HOME/.bash_profile" ]; then profiles="$profiles .bash_profile"
        elif [ -e "$HOME/.bash_login" ] || [ -L "$HOME/.bash_login" ]; then profiles="$profiles .bash_login"; fi
        case ${SHELL-} in */zsh) profiles="$profiles .zprofile" ;; esac
        ;;
    *) fail 'supported login shells are sh, bash, dash, ksh, zsh and fish; open one of these shells before installing' ;;
esac
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
# The inventory contains only safe relative names, so this list needs no path splitting.
asset_files='manifest.json build.json NOTICE.txt uninstall.sh'
for relative in $actual_files; do
    case "$relative" in notices/*) asset_files="$asset_files $relative" ;; esac
done
# Native preparation rejects unsafe existing homes, creates absent homes with
# the same protection as init, and retains the account-wide installation claim.
if [ "$native_held" -eq 0 ]; then
    set -- __install-hold --prepare-program --home "$data"
    for name in $profiles; do set -- "$@" --profile "$HOME/$name"; done
    if [ -n "$fish_file" ]; then set -- "$@" --fish-directory "$(dirname "$fish_file")"; fi
    if [ -n "${XDG_STATE_HOME-}" ]; then set -- "$@" --xdg-state-home "$XDG_STATE_HOME"; fi
    if [ -n "${XDG_CONFIG_HOME-}" ]; then set -- "$@" --xdg-config-home "$XDG_CONFIG_HOME"; fi
    exec "$bundle/se" "$@" -- /bin/sh "$bundle/install.sh" --native-held
fi
# This reads custody from the native channel only after verifying the inherited
# account-wide kernel claim. A worker marker or environment list grants nothing.
created_directories=$("$bundle/se" __install-home-check "$data") || fail 'native installation claim or directory custody is absent'
owner=$(id -u)
stage=''
temp_payload=''
payload_destination=''
payload_kind=''
claimed=0
published_asset_files=''
published_binary=0
published_fish=0
done_install=0
publish_file() {
    # Copy and flush on the destination filesystem, then claim without overwrite.
    temp_payload=$(mktemp "$(dirname "$2")/.se-publish-XXXXXXXX")
    payload_destination=$2
    payload_kind=$4
    cp "$1" "$temp_payload"
    chmod "$3" "$temp_payload"
    flush "$temp_payload"
    ln "$temp_payload" "$2" || fail "destination appeared during installation: $2"
    case "$4" in
        binary) published_binary=1 ;; fish) published_fish=1 ;;
        asset) published_asset_files="$5 $published_asset_files" ;;
    esac
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
truncate_profile() {
    if [ "$macos" -eq 1 ]; then dd if=/dev/null of="$1" bs=1 seek="$2" 2>/dev/null
    else truncate -s "$2" "$1"; fi
}
cleanup() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    set +e
    rollback_complete=1
    if [ -n "$temp_payload" ] && [ "$payload_destination" -ef "$temp_payload" ]; then
        case "$payload_kind" in
            binary) published_binary=1 ;; fish) published_fish=1 ;;
            asset) published_asset_files="${payload_destination#"$assets"/} $published_asset_files" ;;
        esac
    fi
    if [ "$done_install" -eq 0 ]; then
        for name in $profiles; do
            [ "$claimed" -eq 1 ] || continue
            profile=$HOME/$name
            prior=$(cat "$stage/$name.digest")
            if [ -f "$stage/$name.started" ]; then
                if profile_append_matches "$name"; then
                    if [ "$prior" = absent ]; then
                        if rm "$profile"; then flush "$HOME" || rollback_complete=0
                        else rollback_complete=0; fi
                    elif truncate_profile "$profile" "$prior_bytes" && flush "$profile" &&
                         [ "$(file_digest "$profile")" = "$prior" ]; then :
                    else rollback_complete=0; fi
                else rollback_complete=0; fi
            elif [ ! -L "$profile" ] && [ -f "$profile" ] && [ "$(file_digest "$profile")" = "$prior" ]; then :
            elif [ -e "$profile" ] || [ -L "$profile" ]; then rollback_complete=0; fi
        done
        if [ "$published_fish" -eq 1 ]; then
            if [ ! -L "$fish_file" ] && cmp -s "$fish_file" "$stage/fish-config"; then rm "$fish_file" || rollback_complete=0
            else rollback_complete=0; fi
        fi
        if [ "$published_binary" -eq 1 ]; then
            if [ ! -L "$bin/se" ] && cmp -s "$bin/se" "$bundle/se"; then rm "$bin/se" || rollback_complete=0
            else rollback_complete=0; fi
        fi
        for relative in $published_asset_files; do
            file=$assets/$relative
            if [ ! -L "$file" ] && cmp -s "$file" "$bundle/$relative"; then rm "$file" || rollback_complete=0
            else rollback_complete=0; fi
        done
        if [ "$claimed" -eq 1 ] && [ "$rollback_complete" -eq 1 ] && [ "$record" -ef "$stage/install.json" ]; then rm "$record"; fi
        [ "$rollback_complete" -eq 1 ] || printf 'Rollback incomplete; owned paths and blocks remain recorded: %s\n' "$record" >&2
    fi
    [ -z "$temp_payload" ] || rm "$temp_payload"
    if [ -n "$stage" ]; then
        find "$stage" -depth -type p -exec rm {} +
        find "$stage" -depth -type f -exec rm {} +
        find "$stage" -depth -type d -exec rmdir {} \;
        if [ -e "$stage" ]; then
            printf 'Installation scratch cleanup incomplete: %s\n' "$stage" >&2
            [ "$exit_code" -ne 0 ] || exit_code=1
        fi
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
stage=$(mktemp -d "$data/.install-XXXXXXXX")
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
        printf ', "block": '; json_block "$stage/path-block"; printf '}'
        comma=','
    done
    printf '\n  ]}\n'
} > "$stage/install.json"
flush "$stage/install.json"
ln "$stage/install.json" "$record" || fail 'another installation already owns the record'
claimed=1
flush "$record" "$data"
# Only the exclusive claimant may scrub earlier scratch in shared destinations.
remove_stale_temps "$HOME" .se-profile-
remove_stale_temps "$bin" .se-publish-
if [ -n "$fish_file" ]; then remove_stale_temps "$(dirname "$fish_file")" .se-publish-; fi
for relative in $asset_files; do
    publish_file "$bundle/$relative" "$assets/$relative" 644 asset "$relative"
done
publish_file "$bundle/se" "$bin/se" 755 binary
if [ -n "$fish_file" ]; then
    publish_file "$stage/fish-config" "$fish_file" 600 fish
fi
for name in $profiles; do
    profile=$HOME/$name
    prior=$(cat "$stage/$name.digest")
    if [ "$prior" != absent ]; then
        if [ -L "$profile" ] || [ ! -f "$profile" ] || [ "$(file_digest "$profile")" != "$prior" ]; then
            fail "login profile changed during installation: $profile"
        fi
    else [ ! -e "$profile" ] && [ ! -L "$profile" ] || fail "login profile appeared during installation: $profile"; fi
    if [ "$prior" = absent ]; then
        (set -C; : > "$profile") || fail "login profile appeared during installation: $profile"
    fi
    : > "$stage/$name.started"
    cat "$stage/path-block" >> "$profile"
    flush "$profile" "$HOME"
    profile_append_matches "$name" && [ "$appended_bytes" -eq "$block_bytes" ] || fail "login profile append readback failed: $profile"
done
for relative in $asset_files; do cmp -s "$assets/$relative" "$bundle/$relative" || fail "installed asset readback failed: $relative"; done
cmp -s "$bin/se" "$bundle/se" || fail 'installed binary readback failed'
cmp -s "$record" "$stage/install.json" || fail 'ownership record readback failed'
set -- "$bundle/se" __install-files-check "$bin/se"
for relative in $asset_files; do set -- "$@" "$assets/$relative"; done
"$@" || fail 'native installed-file ownership readback failed'
done_install=1
printf 'Installed se at %s\nOpen a fresh login terminal and run se --version.\n' "$bin/se"
