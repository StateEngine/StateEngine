#!/bin/sh
# Standalone Linux installation. Uninstall effects belong to `se uninstall`.
set -eu
umask 077
fail() { printf 'Install refused: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 0 ] || fail 'usage: sh ./install.sh'
[ "$(uname -s):$(uname -m)" = Linux:x86_64 ] || fail 'this archive requires Linux x86_64'
bundle=$(CDPATH='' cd -P -- "$(dirname -- "$0")" && pwd)
[ -z "$(find "$bundle" -type l -print -quit)" ] || fail 'extract the archive without symbolic links'
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
case ${SHELL-/bin/sh} in */sh|*/bash|*/dash|*/ash|*/ksh|*/zsh) ;; *) fail 'use a supported sh, bash, ksh or zsh login shell' ;; esac
root=$HOME/.local
bin=$root/bin
assets=$root/share/stateengine/installation
record=$bin/install.json
case "$HOME" in *'
'*) fail 'home and state paths must not contain line breaks' ;; esac
if printf '%s' "$HOME" | LC_ALL=C grep -q '[[:cntrl:]]'; then fail 'home path must not contain control characters'; fi
check_path() {
    path=$1
    while [ "$path" != / ]; do
        [ ! -L "$path" ] || fail "symbolic-link path component: $path"
        [ ! -e "$path/.git" ] || fail "installation state must be outside a repository: $path"
        path=$(dirname -- "$path")
    done
}
check_path "$bin"
check_path "$assets"
[ ! -e "$record" ] && [ ! -L "$record" ] || fail "installation record exists; run se uninstall before reinstalling: $record"
[ ! -e "$bin/se" ] && [ ! -L "$bin/se" ] || fail "existing command is preserved: $bin/se"
[ ! -e "$assets" ] && [ ! -L "$assets" ] || fail "existing installation assets are preserved: $assets"
if command -v se >/dev/null 2>&1; then fail "another se command is already on PATH: $(command -v se)"; fi
mkdir -p -- "$bin" "$(dirname -- "$assets")"
stage=$(mktemp -d "$bin/.install-XXXXXXXX")
temp_profile=''
done_install=0
claimed=0
published_assets=0
published_binary=0
profiles=''
cleanup() {
    exit_code=$?
    trap - EXIT HUP INT TERM
    set +e
    rollback_complete=1
    if [ "$done_install" -eq 0 ]; then
        for name in $profiles; do
            [ "$claimed" -eq 1 ] || continue
            profile=$HOME/$name
            if [ ! -L "$profile" ] && [ -f "$stage/$name.after" ] && cmp -s -- "$profile" "$stage/$name.after"; then
                if [ -f "$stage/$name.before" ]; then
                    temp_profile=$(mktemp "$HOME/.se-profile-XXXXXXXX")
                    if cp -p -- "$stage/$name.before" "$temp_profile" && mv -- "$temp_profile" "$profile"; then temp_profile=''
                    else rollback_complete=0; fi
                else
                    rm -- "$profile" || rollback_complete=0
                fi
            elif [ -f "$stage/$name.before" ] && cmp -s -- "$profile" "$stage/$name.before"; then
                :
            elif [ -e "$profile" ] || [ -L "$profile" ]; then
                printf 'Rollback preserves a changed login profile: %s\n' "$profile" >&2
                rollback_complete=0
            fi
        done
        if [ "$published_binary" -eq 1 ]; then
            if cmp -s -- "$bin/se" "$bundle/se"; then rm -- "$bin/se" || rollback_complete=0
            else rollback_complete=0; fi
        fi
        if [ "$published_assets" -eq 1 ]; then
            find "$assets" -type f -print | while IFS= read -r file; do
                rel=${file#"$assets/"}
                if [ ! -L "$file" ] && cmp -s -- "$file" "$bundle/$rel"; then rm -- "$file"
                else printf 'Rollback preserves changed installation file: %s\n' "$file" >&2; fi
            done
            find "$assets" -depth -type d -exec rmdir -- {} \; 2>/dev/null
            [ ! -e "$assets" ] || rollback_complete=0
        fi
        if [ "$claimed" -eq 1 ] && [ "$rollback_complete" -eq 1 ] && [ "$record" -ef "$stage/install.json" ]; then rm -- "$record"; fi
        [ "$rollback_complete" -eq 1 ] || printf 'Rollback is incomplete; ownership record retained for se uninstall: %s\n' "$record" >&2
    fi
    [ -z "$temp_profile" ] || rm -- "$temp_profile"
    find "$stage" -depth -type f -exec rm -- {} +
    find "$stage" -depth -type d -exec rmdir -- {} \;
    exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$stage/assets"
cp -- "$bundle/manifest.json" "$bundle/build.json" "$bundle/NOTICE.txt" "$bundle/uninstall.sh" "$stage/assets/"
cp -R -- "$bundle/notices" "$stage/assets/notices"
cat > "$stage/path-block" <<'EOF'

# >>> StateEngine PATH >>>
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH" ;;
esac
# <<< StateEngine PATH <<<
EOF
profiles='.profile'
if [ -e "$HOME/.bash_profile" ] || [ -L "$HOME/.bash_profile" ]; then profiles="$profiles .bash_profile"
elif [ -e "$HOME/.bash_login" ] || [ -L "$HOME/.bash_login" ]; then profiles="$profiles .bash_login"; fi
case ${SHELL-} in */zsh) profiles="$profiles .zprofile" ;; esac
for name in $profiles; do
    profile=$HOME/$name
    [ ! -L "$profile" ] || fail "symbolic-link login profile is preserved: $profile"
    if [ -e "$profile" ]; then
        [ -f "$profile" ] && [ -r "$profile" ] || fail "login profile is unreadable: $profile"
        if grep -q -F '# >>> StateEngine PATH >>>' "$profile"; then fail "unrecorded PATH block is preserved: $profile"; fi
        cp -p -- "$profile" "$stage/$name.before"
        cp -p -- "$profile" "$stage/$name.after"
        iconv -f UTF-8 -t UTF-8 "$stage/$name.before" > /dev/null || fail "login profile is not readable UTF-8: $profile"
        LC_ALL=C tr -d '\011\012\015' < "$stage/$name.before" > "$stage/profile-control-check"
        if LC_ALL=C grep -q '[[:cntrl:]]' "$stage/profile-control-check"; then fail "login profile has unsupported control bytes: $profile"; fi
    else
        : > "$stage/$name.after"
    fi
    cat "$stage/path-block" >> "$stage/$name.after"
done
json_string() { printf '"'; printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; printf '"'; }
json_file() {
    printf '"'
    sed -z 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g; s/\t/\\t/g; s/\r/\\r/g; s/\x08/\\b/g; s/\x0c/\\f/g' "$1"
    printf '"'
}
hash() { sum=$(sha256sum -- "$1") || return "$?"; printf '%s' "${sum%% *}"; }
find "$stage/assets" -type f -print > "$stage/asset-files"
LC_ALL=C sort "$stage/asset-files" -o "$stage/asset-files"
{
    printf '{\n  "schema": "stateengine-install/v1",\n  "install_root": '; json_string "$root"
    printf ',\n  "owner": '; json_string "$(id -u)"
    checksum=$(hash "$bundle/se")
    printf ',\n  "files": [\n    {"path": "bin/se", "sha256": "%s"}' "$checksum"
    while IFS= read -r file; do
        rel=${file#"$stage/assets/"}
        checksum=$(hash "$file")
        printf ',\n    {"path": '; json_string "share/stateengine/installation/$rel"; printf ', "sha256": "%s"}' "$checksum"
    done < "$stage/asset-files"
    printf '\n  ],\n  "path_edits": ['
    comma=''
    for name in $profiles; do
        printf '%s\n    {"target": ' "$comma"; json_string "$HOME/$name"
        printf ', "before": '
        if [ -f "$stage/$name.before" ]; then json_file "$stage/$name.before"; else printf null; fi
        printf ', "after": '; json_file "$stage/$name.after"; printf '}'
        comma=','
    done
    printf '\n  ]}\n'
} > "$stage/install.json"
# A durable ownership description precedes effects. A retry never overwrites it.
ln -- "$stage/install.json" "$record" || fail 'another installation already owns the record'
claimed=1
mv -T -n -- "$stage/assets" "$assets"
[ ! -d "$stage/assets" ] || fail 'installation assets appeared during installation'
published_assets=1
cp -- "$bundle/se" "$stage/se"
chmod 755 "$stage/se"
ln -- "$stage/se" "$bin/se" || fail 'the destination command appeared during installation'
published_binary=1
for name in $profiles; do
    profile=$HOME/$name
    if [ -f "$stage/$name.before" ]; then
        cmp -s -- "$profile" "$stage/$name.before" || fail "login profile changed during installation: $profile"
    else
        [ ! -e "$profile" ] && [ ! -L "$profile" ] || fail "login profile appeared during installation: $profile"
    fi
    temp_profile=$(mktemp "$HOME/.se-profile-XXXXXXXX")
    cp -p -- "$stage/$name.after" "$temp_profile"
    mv -- "$temp_profile" "$profile"
    temp_profile=''
    cmp -s -- "$profile" "$stage/$name.after" || fail "login profile readback failed: $profile"
done
cmp -s -- "$bin/se" "$bundle/se" || fail 'installed binary readback failed'
cmp -s -- "$record" "$stage/install.json" || fail 'ownership record readback failed'
done_install=1
printf 'Installed se at %s\nOpen a fresh login terminal and run se --version.\n' "$bin/se"
