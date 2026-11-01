#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

use crate::{
    EnumerationExtent, Population, ProcessIdentity, ProcessObservation, RemainingScope,
    ScopeExitBasis, ScopeIdentity, ScopeObservation,
};

pub(crate) enum Progress {
    #[cfg(target_os = "linux")]
    Pending,
    #[cfg(target_os = "linux")]
    Root(ProcessIdentity),
    Executed(ProcessIdentity, Box<ProcessObservation>),
}

pub(crate) fn empty(scope: ScopeIdentity) -> crate::ProcResult<ScopeObservation> {
    Ok(ScopeObservation {
        scope,
        remaining: RemainingScope {
            population: Population::Empty,
            known_live: Vec::new(),
            extent: EnumerationExtent::Complete,
            observed_at_unix_ns: crate::support::now()?,
        },
        exit_basis: Some(ScopeExitBasis::ObservedEmpty),
    })
}
