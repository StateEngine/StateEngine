//! Native CLI routing. Startup is called at process entry, before Bootstrap
//! reads configuration and before a worker or store is opened.
#[path = "route/direct.rs"]
pub mod direct;
#[path = "route/files.rs"]
pub mod files;
#[path = "route/identity.rs"]
pub mod identity;
#[path = "route/owner.rs"]
pub mod owner;
#[path = "route/setup.rs"]
pub mod setup;
#[path = "route/uninstall.rs"]
pub mod uninstall;

pub fn initialize_process() -> se_types::Result<()> {
    se_proc::initialize_file_creation_owner()
        .map(|_| ())
        .map_err(|error| {
            se_types::SeError::new(se_types::Detail::SourceUnreadable(
                se_types::details::SourceUnreadable {
                    subject: "process default file owner".into(),
                    reason: error.to_string(),
                    next_step: "Restore access to this process token and retry before opening state; existing foreign-owned files remain preserved".into(),
                },
            ))
            .with_cause(error)
        })
}
