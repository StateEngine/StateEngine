//! Whether this venue can host a same-user detached broker at all.
//!
//! A hosted Windows runner wraps every job it starts in a job object that
//! forbids breakaway, so no process there can supply job detachment. The
//! affected checks stay compiled and report themselves not run, rather than
//! passing without doing their work or being ignored. Every other venue runs
//! them for real, including a VM, a developer machine, and hosted Linux.

//
// Each including target uses a different subset on a different platform, so an
// unused item here is expected rather than a defect.
#![allow(
    dead_code,
    reason = "one shared rule, included by several test targets that use different parts of it"
)]

/// True only where detachment is known to be impossible before the test starts.
///
/// Job-object breakaway is a Windows concept, so this is false everywhere else
/// even though a hosted marker may be present: those venues keep running the
/// check. On Windows the marker is exact: `RUNNER_ENVIRONMENT=github-hosted` is
/// what the provider sets for its hosted images, and nothing else sets it. An
/// absent or different value runs the check, so a misconfigured venue fails
/// loudly instead of silently skipping.
pub fn hosted_runner_without_breakaway() -> bool {
    #[cfg(windows)]
    {
        std::env::var("RUNNER_ENVIRONMENT").is_ok_and(|value| value == "github-hosted")
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// The reason recorded for every check this venue cannot run.
pub const HOSTED_REASON: &str = "the hosted runner wraps this job in a job object that forbids breakaway, so no same-user detached broker can exist; run it on a VM or a developer machine";
