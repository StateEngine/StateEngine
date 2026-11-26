//! Refusals for operations the kernel never plans: owner CLI routes, remote
//! brokers and registered metadata produce their own output instead.
use crate::scope;
use se_types::SeError;

pub(super) fn remote_refused() -> SeError {
    SeError::invalid(
        "remote execution",
        "the protected source host broker; no direct store or Owner fallback",
    )
}

// Home-wide owner work: a diagnostic bundle, a store restore or a harness descriptor.
pub(super) fn home_owner_refused() -> SeError {
    SeError::invalid(
        "home-wide owner adapter",
        "the installed owner CLI; home-wide work is not a project-session tool",
    )
}

pub(super) fn doctor_refused() -> SeError {
    SeError::invalid(
        "doctor adapter",
        "the installed owner CLI with current native observations",
    )
}

pub(super) fn project_move_refused() -> SeError {
    SeError::invalid(
        "project move adapter",
        "the owner CLI with the native git identity observation",
    )
}

pub(super) fn metadata_refused() -> SeError {
    scope::unreadable(
        "metadata dispatch",
        "registered metadata produced no output",
    )
}
