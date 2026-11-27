//! Wire values grouped by product family; operation envelopes stay public here.
mod acp;
pub use acp::*;
pub use se_types::{ActorRef, CommitState, Named, Writer};
mod host_phases;
pub use host_phases::*;
mod diagnostics;
pub use diagnostics::*;
mod schema;
pub use schema::*;
mod init;
pub use init::*;
mod project_move;
pub use project_move::*;
mod files;
pub use files::*;
mod agent;
pub use agent::*;
mod secode;
pub use secode::*;
mod config;
pub use config::*;
mod status;
pub use status::*;
mod messages;
pub use messages::*;
mod runtime;
pub use runtime::*;
mod full_receipts;
pub use full_receipts::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WorktreeRemoveOutput {
    pub path: String,
    pub worktree_name: String,
    pub common_dir: String,
    pub forced: bool,
    pub pruned: bool,
}
