//! The built-in private-file boundary. It is applied to every name before any
//! open, on every read path, and no ignore-file negation can override it.
//!
//! Secret dot-directories (`.git`, `.ssh`, `.aws`, ...) are denied outright,
//! with everything beneath them. No other directory is denied by name, so
//! source trees such as `src/secrets/` or `secret_store/` stay indexable.
//! Files are judged by name and extension: keys, certificates and secret-named
//! data files are denied, while source such as `credentials.py`,
//! `src/id_map.rs`, `config.ts` or `src/secrets/provider.rs` stays allowed.
//! Inside a directory named exactly `secret` or `secrets`, extensionless and
//! data or configuration files are denied too (`deploy/secrets/db.yaml`).

/// Dot-directories that hold credentials or repository internals, matched as
/// any directory component.
const SECRET_DIRS: &[&str] = &[
    ".git",
    ".stateengine",
    ".ssh",
    ".aws",
    ".gnupg",
    ".azure",
    ".kube",
    ".env",
];

/// Dot names that always hold credentials or repository internals, matched as
/// the file name.
const SECRET_NAMES: &[&str] = &[
    ".git",
    ".stateengine",
    ".ssh",
    ".aws",
    ".gnupg",
    ".azure",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".env",
];

/// Key, certificate and password-store containers, denied whatever the name.
const KEY_EXTENSIONS: &[&str] = &[
    "pem", "key", "p12", "pfx", "p8", "jks", "keystore", "ppk", "kdbx",
];

/// Default private-key names written by SSH key generation.
const SSH_KEY_STEMS: &[&str] = &[
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_ecdsa_sk",
    "id_ed25519_sk",
    "id_xmss",
];

/// Name prefixes that suggest stored secrets when the file holds data.
const SECRET_PREFIXES: &[&str] = &[
    "secret",
    "credentials",
    "service-account",
    "service_account",
];

/// Data and configuration formats a secret-named file may store values in.
const DATA_EXTENSIONS: &[&str] = &[
    "json",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "txt",
    "xml",
    "properties",
    "plist",
    "dat",
    "env",
];

/// Directory names whose data and extensionless files are treated as secret.
const SECRET_DATA_DIRS: &[&str] = &["secret", "secrets"];

/// Source-code suffixes: an SSH key stem carrying one of these is a program,
/// not a key.
const CODE_EXTENSIONS: &[&str] = &[
    "rs", "py", "pyi", "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "go", "java", "kt",
    "kts", "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "cs", "zig", "swift", "rb", "php",
    "scala", "sh", "bash", "zsh", "ps1", "lua", "dart", "ex", "exs", "erl", "hs", "ml", "fs",
    "vue", "svelte", "sql",
];

/// Whether a root-relative directory may be entered. Denying a directory
/// denies everything beneath it.
pub fn directory_denied(path: &str) -> bool {
    path.split('/').any(secret_directory)
}

/// Whether a root-relative file may be opened, observed or searched.
pub fn file_denied(path: &str) -> bool {
    let (dirs, leaf) = match path.rsplit_once('/') {
        Some((dirs, leaf)) => (Some(dirs), leaf),
        None => (None, path),
    };
    let dirs = || dirs.into_iter().flat_map(|dirs| dirs.split('/'));
    if dirs().any(secret_directory) {
        return true;
    }
    let parent = dirs().last();
    let docker_config = parent.is_some_and(|dir| dir.eq_ignore_ascii_case(".docker"))
        && leaf.eq_ignore_ascii_case("config.json");
    let in_secret_dir = dirs().any(|dir| contains_ci(SECRET_DATA_DIRS, dir));
    docker_config
        || secret_name(leaf)
        || secret_file_name(leaf)
        || (in_secret_dir && data_or_bare(extension(leaf)))
}

fn secret_directory(name: &str) -> bool {
    contains_ci(SECRET_DIRS, name) || starts_with_ci(name, ".env.")
}

fn secret_name(name: &str) -> bool {
    contains_ci(SECRET_NAMES, name) || starts_with_ci(name, ".env.")
}

fn data_or_bare(extension: Option<&str>) -> bool {
    extension.is_none_or(|ext| contains_ci(DATA_EXTENSIONS, ext))
}

fn secret_data_name(name: &str, extension: Option<&str>) -> bool {
    data_or_bare(extension)
        && SECRET_PREFIXES
            .iter()
            .any(|prefix| starts_with_ci(name, prefix))
}

fn secret_file_name(name: &str) -> bool {
    // A bare dotfile such as `.pem` has no stem, but its suffix still names
    // a key format.
    let suffix = name.rsplit_once('.').map(|(_, ext)| ext);
    if suffix.is_some_and(|ext| contains_ci(KEY_EXTENSIONS, ext)) {
        return true;
    }
    let extension = extension(name);
    let code = extension.is_some_and(|ext| contains_ci(CODE_EXTENSIONS, ext));
    let stem = name.split('.').next().unwrap_or(name);
    if !code && contains_ci(SSH_KEY_STEMS, stem) {
        return true;
    }
    secret_data_name(name, extension)
}

/// The text after the last dot, when the name has a non-empty stem before it.
fn extension(name: &str) -> Option<&str> {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => Some(ext),
        _ => None,
    }
}

fn contains_ci(list: &[&str], value: &str) -> bool {
    list.iter().any(|item| item.eq_ignore_ascii_case(value))
}

fn starts_with_ci(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_locations_and_key_files_are_denied() {
        for path in [
            ".git/config",
            "a/.ssh/known_hosts",
            ".env",
            "web/.env.local",
            ".docker/config.json",
            "certs/server.PEM",
            "keys/id_ed25519",
            "keys/id_rsa.pub",
            "secrets.yaml",
            "deploy/service-account-prod.json",
            "credentials",
        ] {
            assert!(file_denied(path), "{path} must be denied");
        }
    }

    #[test]
    fn ordinary_source_with_secret_like_names_is_allowed() {
        for path in [
            "src/id_map.rs",
            "auth/credentials.py",
            "config.ts",
            "settings.py",
            "credentials/mod.rs",
            "src/secret_store.rs",
            ".docker/README.md",
            ".envrc",
        ] {
            assert!(!file_denied(path), "{path} must be allowed");
        }
        assert!(!directory_denied("credentials"));
        assert!(directory_denied("pkg/.aws"));
        assert!(!directory_denied("deploy/secrets"));
        assert!(file_denied("deploy/secrets/db.yaml"));
    }
}
