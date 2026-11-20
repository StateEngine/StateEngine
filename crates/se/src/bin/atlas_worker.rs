//! The dedicated Atlas cold worker image.
//!
//! This binary runs only the private worker entry; it is never a public
//! command, an agent session or an MCP server. Because it references none of
//! the CLI surface, the linker keeps the CLI's optional features out of the
//! address space the worker's cold containment limits cover.
use std::{env, io, io::Write, process::ExitCode};

/// Refuse misdelivered arguments before any state access; the host treats a
/// dead or silent worker as a startup failure with this text as its report.
fn misdelivered() -> ExitCode {
    eprintln!("se-atlas-worker: private Atlas cold entry only");
    ExitCode::from(78)
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 2 || args[1] != se_proc::atlas_worker::ENTRY {
        return misdelivered();
    }
    // The CLI entry performs the same initialization before worker dispatch;
    // the worker creates cache files, so its default owner must match.
    if let Err(error) = se_proc::initialize_file_creation_owner() {
        let failure = se_types::SeError::new(
            se_types::Detail::SourceUnreadable(se_types::details::SourceUnreadable {
                subject: "process default file owner".into(),
                reason: error.to_string(),
                next_step: "Restore access to the current process token and retry the command; no store or configuration file has been opened".into(),
            }),
        )
        .with_cause(error);
        let _ = writeln!(io::stderr(), "{failure}");
        return ExitCode::from(failure.class().exit_code());
    }
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    let result = se_host::atlas_cold::private_entry();
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    let result = Err(se_types::SeError::invalid(
        "Atlas cold worker",
        "native containment on this platform",
    ));
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(io::stderr(), "{error}");
            ExitCode::from(error.class().exit_code())
        }
    }
}
