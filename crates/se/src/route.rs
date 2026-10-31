//! Native CLI routing. Startup is called at process entry, before Bootstrap
//! reads configuration and before a worker or store is opened.
pub mod direct;
pub mod files;
pub mod owner;
pub mod setup;

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
