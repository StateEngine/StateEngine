//! Per-launch provider sign-in value carried from the launching owner terminal.
use zeroize::Zeroize;

/// Claude's sign-in variables. Its config location stays the host's, so transcripts
/// are watched where the provider writes them.
pub const CLAUDE: [&str; 2] = ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"];

#[derive(Clone, Default)]
pub struct SignIn(Vec<(String, String)>);
impl SignIn {
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self(pairs)
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}
impl std::fmt::Debug for SignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignIn([redacted])")
    }
}
impl Drop for SignIn {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|(_, value)| value.zeroize());
    }
}
