//! Native private-entry refusal, bounded crash diagnostics and exact-child reuse.
#![cfg(all(any(windows, target_os = "macos"), not(debug_assertions)))]
use se_proc::atlas_worker::{AtlasWorker, ENTRY};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[test]
fn private_entry_requires_parent_custody_and_preserves_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let image = PathBuf::from(env!("CARGO_BIN_EXE_se")).canonicalize()?;
    let unowned = Command::new(&image)
        .arg(ENTRY)
        .stdin(Stdio::null())
        .output()?;
    assert!(!unowned.status.success());
    assert!(unowned.stdout.is_empty());
    assert!(
        !unowned.stderr.is_empty(),
        "unowned private entry lost its refusal"
    );
    {
        // Valid parent envelope, deliberately invalid shared cold request.
        let end = Instant::now() + Duration::from_secs(10);
        let mut worker = AtlasWorker::spawn(&image, b"{}", end)?;
        let status = loop {
            assert!(Instant::now() < end, "cold failure did not terminate");
            worker.wait_ready(Instant::now() + Duration::from_millis(100))?;
            assert!(
                worker.receive()?.is_none(),
                "invalid request emitted a protocol reply"
            );
            if let Some(status) = worker.try_reap()? {
                break status;
            }
        };
        assert!(!status.success());
        let diagnostic = worker.failure_diagnostic()?;
        assert!(
            diagnostic.contains("missing field"),
            "native failure lost its actual cause: {diagnostic}"
        );
        assert!(diagnostic.len() < 9000);
    }
    // Reaping and dropping that child release the one-child admission lease.
    let mut next = AtlasWorker::spawn(&image, b"{}", Instant::now() + Duration::from_secs(10))?;
    next.cancel()?;
    assert!(next.try_reap()?.is_some());
    Ok(())
}
