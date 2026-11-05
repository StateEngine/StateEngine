//! Report shared file-backed grammar pages separately from anonymous memory.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct GrammarPages {
    pub observed_bytes: u32,
    pub reserved_bytes: u32,
}

#[derive(
    Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct MemoryBudget {
    pub anonymous_ceiling_bytes: u32,
    /// One shared process-wide working set, never an allowance per grammar/root.
    pub shared_grammar_pages: Option<GrammarPages>,
    /// Individual parser/SQL probes alone do not qualify the joined owner.
    pub joined_qualified: bool,
}
