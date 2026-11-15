#!/bin/sh
# r11 probe (issue 381). Run on the destination host THROUGH THE PRODUCT'S
# OWN SSH PATH (the same path that produced the r10 dest-prepare
# diagnostic), BEFORE the first product pairing call. The judge may pass
# the per-digest cache directory as $1 to record its pre-existing state.
# All output is tagged; collect it verbatim.
set -u
echo '== r11-probe =='
echo "ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "login-shell=${SHELL:-unset}"
echo "current-shell=$0"
ps -p $$ -o comm= 2>/dev/null | sed 's/^/ps-comm=/'
echo "umask=$(umask)"
echo "uid=$(id -u) user=$(id -un)"
rt="$HOME/.stateengine-runtime"
if [ -e "$rt" ]; then
  stat -c 'pre-existing %n owner=%u mode=%a' "$rt"
  find "$rt" -maxdepth 1 -exec stat -c 'pre-existing-child %n owner=%u mode=%a' {} \;
else
  echo 'pre-existing .stateengine-runtime absent'
fi
stat -c 'home %n owner=%u mode=%a' "$HOME"
if [ "${1:-}" != "" ]; then
  if [ -e "$1" ]; then stat -c 'pre-existing-digest %n owner=%u mode=%a' "$1"; else echo 'pre-existing digest dir absent'; fi
fi
pa="$HOME/.r11-probe-a"
pb="$HOME/.r11-probe-b"
rm -rf "$pa" "$pb"
mkdir -m 700 "$pa" 2>&1
echo "explicit-700 rc=$?"
(umask 077 && mkdir "$pb") 2>&1
echo "subshell-umask077 rc=$?"
stat -c 'probe %n mode=%a' "$pa" "$pb" 2>&1
rm -rf "$pa" "$pb"
sh -c '
  ambient=$(umask)
  d=/tmp/.r11-probe-sh
  rm -rf "$d"
  (umask 077 && mkdir "$d") 2>/dev/null
  m=$(stat -c %a "$d" 2>/dev/null || echo mkdir-failed)
  echo "sh-child ambient=$ambient subshell-mkdir-mode=$m"
  rm -rf "$d"'
echo '== r11-probe end =='
