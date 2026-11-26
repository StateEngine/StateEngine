//! Shared proxy and TLS trust environment variables inherited by provider
//! children and the detached host.
use std::ffi::OsString;

/// Proxy and TLS trust settings a provider needs to reach its endpoint the way
/// other tools on this machine do. The detached host carries them across its
/// environment boundary and every provider child inherits them.
pub const NETWORK_ENVIRONMENT: &[&str] = &[
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    // Lower-case spellings are distinct variables outside Windows; there the
    // case-insensitive read finds the upper-case value instead.
    #[cfg(not(windows))]
    "https_proxy",
    #[cfg(not(windows))]
    "http_proxy",
    #[cfg(not(windows))]
    "all_proxy",
    #[cfg(not(windows))]
    "no_proxy",
];

/// Whether `name` is one of the shared proxy or TLS trust environment names.
pub fn is_network_environment(name: &str) -> bool {
    NETWORK_ENVIRONMENT.iter().any(|allowed| {
        if cfg!(windows) {
            allowed.eq_ignore_ascii_case(name)
        } else {
            *allowed == name
        }
    })
}

/// The network settings present in this process's environment.
pub fn network_environment() -> Vec<(OsString, OsString)> {
    NETWORK_ENVIRONMENT
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| ((*name).into(), value)))
        .collect()
}
