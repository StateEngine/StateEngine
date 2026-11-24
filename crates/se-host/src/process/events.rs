//! Coalesced native nudges on the host's supplied reactor. Native state remains
//! authoritative; a wake is never an exit, exec or process-count witness.
pub(super) use se_secode_service::Wake;

#[cfg(unix)]
pub(crate) use super::reactor::Reactor;
