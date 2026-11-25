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
    // Proxy and TLS trust settings, so a harness reaches its provider the same
    // way other tools on this machine do.
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
];

/// Lower-case proxy spellings are distinct variables outside Windows, where
/// names are case-insensitive and the upper-case read already finds them.
#[cfg(not(windows))]
const LOWER_CASE: &[&str] = &["https_proxy", "http_proxy", "all_proxy", "no_proxy"];
#[cfg(windows)]
const LOWER_CASE: &[&str] = &[];

pub(super) fn inherited() -> Vec<(OsString, OsString)> {
    NAMES
        .iter()
        .chain(LOWER_CASE)
        .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
        .collect()
}
