use super::identity::*;
use crate::support::*;
use crate::windows_native::job;
use crate::*;
#[cfg(test)]
use std::ptr;
#[cfg(test)]
use windows_sys::Win32::Security::Authorization::SE_KERNEL_OBJECT;

pub(super) struct Security(job::Security);
impl Security {
    pub fn owner_only() -> ProcResult<Self> {
        job::Security::owner_only()
            .map(Self)
            .map_err(|e| native(ProcErrorCode::ContainmentUnavailable, e.operation, e.source))
    }
    pub fn attributes(&self) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        self.0.attributes()
    }
}
pub(super) fn verify_job(job: &Handle) -> ProcResult<()> {
    // SAFETY: caller retains the live job handle through the DACL query.
    unsafe { job::verify_dacl(job.0) }.map_err(|failure| match failure {
        job::DaclFailure::Native(op, cause) => native(ProcErrorCode::RecoveryUnproved, op, cause),
        job::DaclFailure::Policy(reason) => input("job security", reason),
    })
}

#[cfg(test)]
#[path = "../../../tests/support/windows_job_policy.rs"]
mod judges;
