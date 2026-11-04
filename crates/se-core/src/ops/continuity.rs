//! One read-only continuity assembler for CLI/MCP resume and linked session
//! context. Authority, clock and the finite store snapshot come from adapters.
mod identity;
mod packet;
mod read;
mod rulings;
pub mod types;
use crate::commit::Cx;
use se_store::Snapshot;
use se_types::{Result, UnixMicros};
pub use types::*;

pub fn resume<R: Snapshot>(
    input: Resume,
    at: UnixMicros,
    cx: &mut Cx<'_, R>,
) -> Result<ResumeOutput> {
    input.validate()?;
    let identity = identity::resolve(input.preview_agent.as_ref(), cx)?;
    packet::resume(input, at, identity, cx)
}
pub fn context<R: Snapshot>(
    input: SessionContextRequest,
    at: UnixMicros,
    cx: &mut Cx<'_, R>,
) -> Result<SessionContextOutput> {
    input.validate()?;
    let identity = identity::resolve(None, cx)?;
    let resume = Resume {
        limit: input.limit,
        governing_cursor: input.governing_cursor,
        since: input.since,
        byte_budget: input.byte_budget,
        preview_agent: None,
    };
    packet::context(resume, at, identity, cx)
}

pub(super) fn metadata_budget() -> se_types::Result<se_store::ReadBudget> {
    read::budget(20)
}
