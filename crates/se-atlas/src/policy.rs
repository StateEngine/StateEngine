//! The built-in private-file boundary.
use se_types::code::{AtlasText, RelativePath};
const DENIED_EXACT: &[&str] = &[
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
    "secret",
    "secrets",
    "credentials",
    "credential",
    "keystore",
    "config.js",
    "config.mjs",
    "config.cjs",
    "config.ts",
    "config.py",
    "config.json",
    "config.yaml",
    "config.yml",
    "config.toml",
    "config.ini",
    "settings.py",
];
const DENIED_PREFIXES: &[&[u8]] = &[
    b".env",
    b"id_",
    b"secret.",
    b"secrets.",
    b"credentials.",
    b"credential.",
    b"service-account.",
    b"service_account.",
];
const DENIED_SUFFIXES: &[&[u8]] = &[b".pem", b".key", b".p12", b".pfx", b".jks", b".keystore"];
/// Always denied before traversal, observation or live text access. Ignore-file
/// negations cannot override this private-file boundary.
pub fn built_in_denied(path: &RelativePath) -> bool {
    path.as_str().split('/').any(|part| {
        let bytes = part.as_bytes();
        DENIED_EXACT
            .iter()
            .any(|name| part.eq_ignore_ascii_case(name))
            || DENIED_PREFIXES.iter().any(|prefix| {
                bytes
                    .get(..prefix.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            })
            || DENIED_SUFFIXES.iter().any(|suffix| {
                bytes
                    .len()
                    .checked_sub(suffix.len())
                    .is_some_and(|start| bytes[start..].eq_ignore_ascii_case(suffix))
            })
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_paths_are_denied_in_any_component() -> se_types::Result<()> {
        for name in [
            ".env",
            ".env.production",
            "src/secrets.py",
            "config.js",
            "a/credentials.json",
            "a/ID_ed25519",
            "keys/client.PEM",
            ".aws/config",
            "secret/subdir/code.py",
            "dir/key.p12",
        ] {
            assert!(built_in_denied(&RelativePath::new(name)?), "{name}");
        }
        for name in [
            "src/main.rs",
            "src/config_policy.rs",
            "src/environment.ts",
            "tests/fixture.js",
        ] {
            assert!(!built_in_denied(&RelativePath::new(name)?), "{name}");
        }
        Ok(())
    }
}
