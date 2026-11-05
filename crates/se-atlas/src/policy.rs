use crate::{
    errors::{AtlasResult, capacity},
    model::*,
};
use se_types::code::AtlasText;
use std::time::Duration;
pub fn validate(policy: &AtlasPolicy) -> AtlasResult<()> {
    if policy.max_files == 0
        || policy.max_files > 100_000
        || policy.max_change_rows == 0
        || policy.max_change_rows > 50_000
        || policy.change_retention_days == 0
        || policy.change_retention_days > 30
        || policy.max_cache_bytes > 512_000_000
        || policy.total_reserved_bytes > ANONYMOUS_BYTES
        || policy.parse.reserved_bytes > PARSER_BYTES
        || policy.parse.max_source_bytes > 524_288
        || policy.parse.max_rows > 65_536
        || policy.parse.max_work > Duration::from_millis(200)
        || policy.parse.max_work.is_zero()
    {
        return Err(se_types::SeError::invalid(
            "Atlas policy",
            "the finite source, parser, retention, cache and measured steady-state ceilings",
        ));
    }
    let bytes: usize = policy
        .ignore
        .global_patterns
        .iter()
        .map(String::len)
        .sum::<usize>()
        + policy
            .ignore
            .generated_prefixes
            .iter()
            .map(|p| p.as_str().len())
            .sum::<usize>();
    if bytes > 32768 || policy.ignore.generated_prefixes.len() > 32 {
        return Err(capacity("Atlas ignore metadata", bytes as u64, 32768));
    }
    if policy.watch.max_directories > 6144
        || policy.watch.max_mapping_bytes > 98304
        || u64::from(policy.watch.max_directories) * 16 > u64::from(policy.watch.max_mapping_bytes)
        || policy
            .watch
            .observed_os_limit
            .is_some_and(|os| u64::from(policy.watch.max_directories) > os / 8)
    {
        return Err(se_types::SeError::invalid(
            "Atlas watch budget",
            "the shared OS-fraction, 6144-directory and compact mapping bounds",
        ));
    }
    Ok(())
}
pub fn language(path: &RelativePath) -> Option<Language> {
    match path.as_str().rsplit('.').next()? {
        "js" | "mjs" | "cjs" => Some(Language::JavaScript),
        "jsx" => Some(Language::Jsx),
        "ts" | "mts" | "cts" => Some(Language::TypeScript),
        "tsx" => Some(Language::Tsx),
        "rs" => Some(Language::Rust),
        "py" | "pyi" => Some(Language::Python),
        _ => None,
    }
}

/// Always denied before traversal, observation or live text access. Ignore-file
/// negations cannot override this private-file boundary.
pub fn built_in_denied(path: &RelativePath) -> bool {
    path.as_str().split('/').any(|part| {
        let name = part.to_ascii_lowercase();
        matches!(
            name.as_str(),
            ".git"
                | ".stateengine"
                | ".ssh"
                | ".aws"
                | ".gnupg"
                | ".azure"
                | ".kube"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
                | "secret"
                | "secrets"
                | "credentials"
                | "credential"
                | "keystore"
        ) || name.starts_with(".env")
            || name.starts_with("id_")
            || [
                "secret.",
                "secrets.",
                "credentials.",
                "credential.",
                "service-account.",
                "service_account.",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
            || matches!(
                name.as_str(),
                "config.js"
                    | "config.mjs"
                    | "config.cjs"
                    | "config.ts"
                    | "config.py"
                    | "config.json"
                    | "config.yaml"
                    | "config.yml"
                    | "config.toml"
                    | "config.ini"
                    | "settings.py"
            )
            || [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"]
                .iter()
                .any(|suffix| name.ends_with(suffix))
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_paths_are_denied_in_any_component() -> AtlasResult<()> {
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
