//! One read-only continuity assembler for CLI/MCP resume and linked session
//! context. Authority, clock and the finite store snapshot come from adapters.
mod commands;
mod compact;
mod cursor;
pub(crate) use cursor::{resume_since, validate_resume_since};
mod identity;
pub(crate) mod packet;
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
    resume_at_home(input, at, None, cx)
}
pub(crate) fn resume_at_home<R: Snapshot>(
    input: Resume,
    at: UnixMicros,
    home: Option<&std::path::Path>,
    cx: &mut Cx<'_, R>,
) -> Result<ResumeOutput> {
    input.validate()?;
    let mut identity = identity::resolve(input.preview_agent.as_ref(), cx)?;
    identity.command_home = home.map(std::path::Path::to_owned);
    packet::resume(input, at, identity, cx)
}
pub fn context<R: Snapshot>(
    input: SessionContextRequest,
    at: UnixMicros,
    cx: &mut Cx<'_, R>,
) -> Result<SessionContextOutput> {
    context_at_home(input, at, None, cx)
}
pub(crate) fn context_at_home<R: Snapshot>(
    input: SessionContextRequest,
    at: UnixMicros,
    home: Option<&std::path::Path>,
    cx: &mut Cx<'_, R>,
) -> Result<SessionContextOutput> {
    input.validate()?;
    let mut identity = identity::resolve(None, cx)?;
    identity.command_home = home.map(std::path::Path::to_owned);
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
