//! Legacy native component measurements, kept for installers that still
//! pass them. The v5 engine runs no native parser and ignores them.
use super::*;
#[cfg(any(
    all(target_os = "linux", target_env = "gnu", target_arch = "x86_64"),
    all(windows, target_arch = "x86_64")
))]
use se_atlas::{model::Language, parse::ParserPlacement};
impl NativeAtlasQualification {
    /// The measured six-grammar Linux/glibc component profile.
    #[cfg(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64"))]
    pub fn measured_linux_components() -> Result<Self> {
        let parsers = [
            Language::JavaScript,
            Language::Jsx,
            Language::TypeScript,
            Language::Tsx,
            Language::Rust,
            Language::Python,
        ]
        .into_iter()
        .map(|language| {
            ParserProfile::from_qualified_measurement(
                language,
                ParserPlacement::Incremental,
                65_536,
                8_192,
                8_000_000,
                3_000_000,
            )?
            .with_shared_grammar_pages(4_759_552, 5_473_485)
        })
        .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            sql: Some(SqlProfile::from_qualified_overhead(93_702)?),
            parsers,
        })
    }
    /// The measured Windows x64 component profile.
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub fn measured_windows_components() -> Result<Self> {
        let parsers = [
            Language::JavaScript,
            Language::Jsx,
            Language::TypeScript,
            Language::Tsx,
            Language::Rust,
            Language::Python,
        ]
        .into_iter()
        .map(|language| {
            ParserProfile::from_qualified_measurement(
                language,
                ParserPlacement::Incremental,
                65_536,
                8_192,
                8_000_000,
                3_000_000,
            )
        })
        .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            sql: Some(SqlProfile::from_qualified_joined(643_072)?),
            parsers,
        })
    }
}
