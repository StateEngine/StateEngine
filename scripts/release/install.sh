#!/bin/sh
# Standalone Linux installation. Removal belongs to the native se uninstall operation.
set -eu
umask 077
fail() { printf 'Install refused: %s\n' "$*" >&2; exit 1; }
file_digest() { sum=$(sha256sum < "$1") || return "$?"; printf '%s' "${sum%% *}"; }
json_string() { printf '"'; printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; printf '"'; }
json_block() { printf '"'; sed -z 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g' "$1"; printf '"'; }
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
        path=$(dirname -- "$path")
    done
}
# All input and destination checks precede creation of installation directories.
[ "$#" -eq 0 ] || fail 'usage: sh ./install.sh'
[ "$(uname -s):$(uname -m)" = Linux:x86_64 ] || fail 'this archive requires Linux x86_64'
bundle=$(CDPATH='' cd -P -- "$(dirname -- "$0")" && pwd)
links=$(find "$bundle" -type l -print -quit)
[ -z "$links" ] || fail 'extract the archive without symbolic links'
(cd "$bundle" && sha256sum --check --strict --quiet SHA256SUMS) || fail 'archive checksums do not match'
if LC_ALL=C grep -v -q '^[0-9a-f]\{64\}  [A-Za-z0-9_./+-]\{1,\}$' "$bundle/SHA256SUMS"; then fail 'invalid checksum inventory'; fi
actual_files=$(find "$bundle" -type f -printf '%P\n')
actual_files=$(printf '%s\n' "$actual_files" | LC_ALL=C sort)
expected_files=$(sed 's/^[0-9a-f]\{64\}  //' "$bundle/SHA256SUMS")
expected_files=$(printf '%s\nSHA256SUMS\n' "$expected_files" | LC_ALL=C sort)
[ "$actual_files" = "$expected_files" ] || fail 'archive contains unlisted or duplicate files'
field() { sed -n "s/^  \"$1\": \"\([^\"]*\)\",\{0,1\}$/\1/p" "$bundle/manifest.json"; }
[ "$(field target)" = x86_64-unknown-linux-gnu ] || fail 'archive target does not match this installer'
[ "$(field variant)" = standalone ] && [ "$(field trust)" = unsigned ] || fail 'unsupported archive variant'
case ${HOME-} in /*) ;; *) fail 'HOME must be an absolute user-home path' ;; esac
bin=$HOME/.local/bin
assets=$HOME/.local/share/stateengine/installation
data=${SE_HOME:-${XDG_STATE_HOME:-$HOME/.local/state}/stateengine}
record=$data/standalone-install.json
for destination in "$bin/se" "$assets" "$record"; do
    plain_path "$destination"
    [ ! -e "$destination" ] || fail "existing installation path is preserved; run se uninstall before reinstalling: $destination"
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
    else prior=absent; fi
    profile_digests="$profile_digests$name $prior
"
done
# The inventory contains only safe relative names, so this list needs no path splitting.
asset_files='manifest.json build.json NOTICE.txt uninstall.sh'
for relative in $actual_files; do
    case "$relative" in notices/*) asset_files="$asset_files $relative" ;; esac
done
owner=$(id -u)
created_directories=''
stage=''
temp_profile=''
temp_payload=''
payload_destination=''
payload_kind=''
claimed=0
published_assets=0
published_binary=0
published_fish=0
done_install=0
asset_directories=''
create_directory() {
    if [ -d "$1" ]; then return; fi
    create_directory "$(dirname -- "$1")"
    if mkdir -- "$1" 2>/dev/null; then
        created_directories=$(printf '%s\n%s' "$1" "$created_directories")
    elif [ -d "$1" ] && [ ! -L "$1" ]; then :
    else fail "cannot create installation directory: $1"; fi
}
publish_file() {
    # Copy and flush on the destination filesystem, then claim without overwrite.
    temp_payload=$(mktemp "$(dirname -- "$2")/.se-publish-XXXXXXXX")
    payload_destination=$2
    payload_kind=$4
    cp -- "$1" "$temp_payload"
    chmod "$3" "$temp_payload"
    sync "$temp_payload"
    ln -- "$temp_payload" "$2" || fail "destination appeared during installation: $2"
    case "$4" in binary) published_binary=1 ;; fish) published_fish=1 ;; esac
    rm -- "$temp_payload"
    temp_payload=''
    sync "$2" "$(dirname -- "$2")"
}
cleanup() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    set +e
    rollback_complete=1
    rollback_profile=''
    if [ -n "$temp_payload" ] && [ "$payload_destination" -ef "$temp_payload" ]; then
        case "$payload_kind" in binary) published_binary=1 ;; fish) published_fish=1 ;; esac
    fi
    if [ "$claimed" -eq 1 ] && [ -d "$assets" ] && [ ! -d "$stage/assets" ]; then published_assets=1; fi
    if [ "$done_install" -eq 0 ]; then
        for name in $profiles; do
            [ "$claimed" -eq 1 ] || continue
            profile=$HOME/$name
            prior=$(cat "$stage/$name.digest")
            current=''
            if [ ! -L "$profile" ] && [ -f "$profile" ]; then current=$(file_digest "$profile"); fi
            after=''
            if [ -f "$stage/$name.after-digest" ]; then after=$(cat "$stage/$name.after-digest"); fi
            if [ -n "$after" ] && [ "$current" = "$after" ]; then
                if [ "$prior" != absent ]; then
                    rollback_profile=$(mktemp "$HOME/.se-profile-XXXXXXXX")
                    bytes=$(wc -c < "$profile")
                    block_bytes=$(wc -c < "$stage/path-block")
                    prefix_bytes=$((bytes - block_bytes))
                    if cmp -s -i "$prefix_bytes":0 -- "$profile" "$stage/path-block" &&
                       cp --attributes-only --preserve=mode,ownership,xattr -- "$profile" "$rollback_profile" &&
                       head -c "$prefix_bytes" -- "$profile" > "$rollback_profile" &&
                       [ "$(file_digest "$rollback_profile")" = "$prior" ] && mv -- "$rollback_profile" "$profile"; then rollback_profile=''
                    else rollback_complete=0; fi
                else rm -- "$profile" || rollback_complete=0; fi
            elif [ -n "$current" ] && [ "$current" = "$prior" ]; then :
            elif [ -e "$profile" ] || [ -L "$profile" ]; then rollback_complete=0; fi
        done
        if [ "$published_fish" -eq 1 ]; then
            if [ ! -L "$fish_file" ] && cmp -s -- "$fish_file" "$stage/fish-config"; then rm -- "$fish_file" || rollback_complete=0
            else rollback_complete=0; fi
        fi
        if [ "$published_binary" -eq 1 ]; then
            if [ ! -L "$bin/se" ] && cmp -s -- "$bin/se" "$bundle/se"; then rm -- "$bin/se" || rollback_complete=0
            else rollback_complete=0; fi
        fi
        if [ "$published_assets" -eq 1 ]; then
            for relative in $asset_files; do
                file=$assets/$relative
                if [ ! -L "$file" ] && cmp -s -- "$file" "$bundle/$relative"; then rm -- "$file"
                elif [ -e "$file" ] || [ -L "$file" ]; then rollback_complete=0; fi
            done
            for relative in $asset_directories; do rmdir -- "$assets/$relative" 2>/dev/null; done
            rmdir -- "$assets" 2>/dev/null
            if [ -e "$assets" ] || [ -L "$assets" ]; then rollback_complete=0; fi
        fi
        if [ "$claimed" -eq 1 ] && [ "$rollback_complete" -eq 1 ] && [ "$record" -ef "$stage/install.json" ]; then rm -- "$record"; fi
        [ "$rollback_complete" -eq 1 ] || printf 'Rollback incomplete; owned paths and blocks remain recorded: %s\n' "$record" >&2
    fi
    [ -z "$temp_profile" ] || rm -- "$temp_profile"
    [ -z "$rollback_profile" ] || rm -- "$rollback_profile"
    [ -z "$temp_payload" ] || rm -- "$temp_payload"
    if [ -n "$stage" ]; then
        find "$stage" -depth -type f -exec rm -- {} +
        find "$stage" -depth -type d -exec rmdir -- {} \;
        if [ -e "$stage" ]; then
            printf 'Installation scratch cleanup incomplete: %s\n' "$stage" >&2
            [ "$exit_code" -ne 0 ] || exit_code=1
        fi
    fi
    # A losing writer may have created parents that the record owner still needs.
    # Keep them while any installation record remains, including partial rollback.
    if [ "$done_install" -eq 0 ] && [ ! -e "$record" ] && [ ! -L "$record" ]; then
        while IFS= read -r directory; do
            [ -z "$directory" ] || rmdir -- "$directory" 2>/dev/null
        done <<DIRECTORIES
$created_directories
DIRECTORIES
    fi
    exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
create_directory "$bin"
create_directory "$(dirname -- "$assets")"
create_directory "$data"
if [ -n "$fish_file" ]; then create_directory "$(dirname -- "$fish_file")"; fi
stage=$(mktemp -d "$data/.install-XXXXXXXX")
mkdir "$stage/assets"
cp -- "$bundle/manifest.json" "$bundle/build.json" "$bundle/NOTICE.txt" "$bundle/uninstall.sh" "$stage/assets/"
cp -R -- "$bundle/notices" "$stage/assets/notices"
asset_directories=$(find "$stage/assets" -depth -mindepth 1 -type d -printf '%P\n')
cat > "$stage/path-block" <<'BLOCK'

# >>> StateEngine PATH >>>
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH" ;;
esac
# <<< StateEngine PATH <<<
BLOCK
while read -r name prior; do
    [ -z "$name" ] || printf '%s\n' "$prior" > "$stage/$name.digest"
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
    for relative in $asset_directories; do printf '%s' "$comma"; json_string "$assets/$relative"; comma=','; done
    printf '%s' "$comma"; json_string "$assets"
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
sync "$stage/install.json"
ln -- "$stage/install.json" "$record" || fail 'another installation already owns the record'
claimed=1
sync "$record" "$data"
mv -T -n -- "$stage/assets" "$assets"
[ ! -d "$stage/assets" ] || fail 'installation assets appeared during installation'
published_assets=1
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
    temp_profile=$(mktemp "$HOME/.se-profile-XXXXXXXX")
    if [ "$prior" != absent ]; then
        cp --attributes-only --preserve=mode,ownership,xattr -- "$profile" "$temp_profile"
        cat -- "$profile" > "$temp_profile"
        [ "$(file_digest "$temp_profile")" = "$prior" ] || fail "login profile changed while reading: $profile"
    fi
    cat "$stage/path-block" >> "$temp_profile"
    after=$(file_digest "$temp_profile")
    printf '%s\n' "$after" > "$stage/$name.after-digest"
    sync "$temp_profile"
    mv -- "$temp_profile" "$profile"
    temp_profile=''
    [ "$(file_digest "$profile")" = "$after" ] || fail "login profile readback failed: $profile"
done
for relative in $asset_files; do cmp -s -- "$assets/$relative" "$bundle/$relative" || fail "installed asset readback failed: $relative"; done
cmp -s -- "$bin/se" "$bundle/se" || fail 'installed binary readback failed'
cmp -s -- "$record" "$stage/install.json" || fail 'ownership record readback failed'
done_install=1
printf 'Installed se at %s\nOpen a fresh login terminal and run se --version.\n' "$bin/se"
