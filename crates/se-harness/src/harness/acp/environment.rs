//! Only OS execution and network context is implicit; provider settings and
//! credentials require named opt-in in the harness descriptor.
use std::ffi::OsString;

const NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "TERM",
    "SSH_AUTH_SOCK",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "SystemRoot",
    "windir",
    "ComSpec",
    "PATHEXT",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "ProgramData",
    "ProgramFiles",
];

pub(super) fn inherited() -> Vec<(OsString, OsString)> {
    let mut entries: Vec<_> = NAMES
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
        .collect();
    entries.extend(crate::acp::network_environment());
    entries
}
