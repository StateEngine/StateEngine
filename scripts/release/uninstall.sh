#!/bin/sh
# The native owner operation prints its plan and owns stop, removal and readback.
set -eu
binary=$HOME/.local/bin/se
case "$(uname -s)" in
    Darwin) data=${SE_HOME:-$HOME/Library/Application Support/StateEngine} ;;
    *) data=${SE_HOME:-${XDG_STATE_HOME:-$HOME/.local/state}/stateengine} ;;
esac
record=$data/standalone-install.json
for path in "$binary" "$record"; do
    case "$path" in /*) ;; *) printf 'Uninstall refused: installation paths must be absolute.\n' >&2; exit 1 ;; esac
    while [ "$path" != / ]; do
        if [ -L "$path" ]; then printf 'Uninstall refused: linked installation path: %s\n' "$path" >&2; exit 1; fi
        path=$(dirname "$path")
    done
done
if [ -L "$binary" ] || [ -L "$record" ] || [ ! -f "$binary" ] || [ ! -r "$record" ]; then
    printf 'Uninstall refused: installed binary or ownership record is absent, linked or unreadable.\n' >&2
    exit 1
fi
bundle=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
expected=$(sed -n '/^    "se": {/,/^    }/s/.*"sha256": "\([0-9a-f]*\)".*/\1/p' "$bundle/manifest.json")
if [ "$(uname -s)" = Darwin ]; then sum=$(shasum -a 256 < "$binary")
else sum=$(sha256sum < "$binary"); fi
actual=${sum%% *}
if [ "${#expected}" -ne 64 ] || [ "$actual" != "$expected" ]; then
    printf 'Uninstall refused: installed se differs from this archive; invoke the current installed se uninstall instead: %s\n' "$binary" >&2
    exit 1
fi
exec "$binary" uninstall "$@"
