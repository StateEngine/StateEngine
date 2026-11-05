//! Independent Linux component measurements, kept separate from joined admission.
use super::*;
#[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
use se_atlas::parse::ParserPlacement;
impl NativeAtlasQualification {
    /// Ordinary installation uses the independently measured Linux components.
    /// Explicit SQL/parser selections retain their bounds; unknown targets
    /// still carry None. Larger source files remain honestly unqualified.
    pub(super) fn with_native_sql(mut self) -> Result<Self> {
        #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
        if self.sql.is_none() {
            if self.parsers.is_empty() {
                return Self::measured_linux_components();
            }
            self.sql = Some(SqlProfile::from_qualified_overhead(93_702)?);
        }
        Ok(self)
    }
    /// The measured six-grammar Linux/glibc component profile is the default.
    /// This does not qualify the joined owner/watch/query peak or other targets.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
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
                1024,
                512,
                678_298,
                256_000,
            )?
            .with_shared_grammar_pages(4_759_552, 5_473_485)
        })
        .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            sql: Some(SqlProfile::from_qualified_overhead(93_702)?),
            parsers,
        })
    }
    pub(super) fn memory(&self) -> MemoryBudget {
        MemoryBudget {
            anonymous_ceiling_bytes: ANONYMOUS_BYTES,
            shared_grammar_pages: self
                .parsers
                .iter()
                .filter_map(|profile| profile.shared_grammar_pages)
                .max_by_key(|pages| pages.reserved_bytes),
            joined_qualified: false,
        }
    }
}
