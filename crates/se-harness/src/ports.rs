//! Host-supplied ports injected into provider harness adapters.
use se_types::{AgentId, Result, Secret, SessionId};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

/// Host-supplied builder for Atlas hook configuration written into provider settings.
pub type AtlasHookConfigFn = fn(&Path, &Path) -> Option<serde_json::Value>;

/// Host-supplied registration port for attended Claude mail bell notifications.
pub trait BellRegistry: Send + Sync {
    fn register(
        &self,
        session: SessionId,
        agent: AgentId,
        bearer: &Secret,
        origin: String,
        hold_file: PathBuf,
    ) -> Result<String>;
    fn connected(&self, session: &SessionId) -> Result<bool>;
    fn retire(&self, session: &SessionId) -> Result<()>;
}

/// Role of a live display turn forwarded to remote observers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveTurnRole {
    User,
    Assistant,
    Tool,
}

/// Host-supplied observer for live Codex turn deltas and completions.
pub trait LivePublisher: Send + Sync {
    fn delta_at(&self, vendor: &str, role: LiveTurnRole, delta: &str, observed_at: Instant);
    fn complete_at(&self, vendor: &str, role: LiveTurnRole, text: &str, observed_at: Instant);
}
