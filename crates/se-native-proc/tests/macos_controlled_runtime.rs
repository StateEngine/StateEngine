//! Native controlled-runtime contract; public launch remains a separate qualification.
#![cfg(target_os = "macos")]
#[path = "support/macos_runtime/mod.rs"]
mod fixture;
use fixture::{Check, Home, scenarios};

#[test]
fn installed_helper_pauses_then_execs_same_birth_with_selected_streams() -> Check {
    let home = Home::new()?;
    scenarios::host_case(&home, "launch", None)
}
#[test]
fn authorization_eof_never_executes_the_provider() -> Check {
    let home = Home::new()?;
    scenarios::authorization_eof(&home)
}
#[test]
fn strict_scope_and_window_requests_refuse_before_exec() -> Check {
    let home = Home::new()?;
    scenarios::strict_refusals(&home)
}
#[test]
fn original_group_descendant_closes_with_identity_bound_stop() -> Check {
    let home = Home::new()?;
    scenarios::host_case(&home, "descendant", None)
}
#[test]
fn known_escape_remains_an_obligation_after_ordinary_stop() -> Check {
    let home = Home::new()?;
    scenarios::host_case(&home, "escape", None)
}
#[test]
fn cold_adoption_preserves_birth_without_another_exec() -> Check {
    let home = Home::new()?;
    scenarios::cold(&home, "cold")
}
#[test]
fn cold_live_root_keeps_previously_observed_escaped_child() -> Check {
    let home = Home::new()?;
    scenarios::cold(&home, "cold-escaped")
}
#[test]
fn cold_exited_root_cannot_erase_previously_observed_escaped_child() -> Check {
    let home = Home::new()?;
    scenarios::cold(&home, "cold-root-exited")
}
#[test]
fn native_replacement_and_unreadability_never_grant_stop_or_exit_proof() -> Check {
    let home = Home::new()?;
    let library = scenarios::fault_library(&home)?;
    for mode in ["replacement", "denied", "short", "zero", "enumeration"] {
        let case = Home::new()?;
        scenarios::host_case(&case, mode, Some(&library))?;
    }
    Ok(())
}
