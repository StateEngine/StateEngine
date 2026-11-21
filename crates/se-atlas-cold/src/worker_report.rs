//! What is known about an Atlas worker when its connection or protocol fails:
//! how it exited and the tail of its stderr, so one failure can be diagnosed
//! without a reproduction. Shared by the cold job and the parse workers.
use se_proc::atlas_worker::AtlasWorker;

/// The worker's exit, if it has exited. A repeated reap returns the same status.
pub fn exit(worker: &mut AtlasWorker) -> String {
    match worker.try_reap() {
        Ok(Some(status)) => format!("worker exited ({status})"),
        Ok(None) => "worker still running".to_string(),
        Err(error) => format!("worker exit unreadable: {error}"),
    }
}
/// The bounded tail of the worker's stderr.
pub fn stderr(worker: &mut AtlasWorker) -> String {
    #[cfg(target_os = "linux")]
    {
        worker.stderr_report()
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        worker
            .failure_diagnostic()
            .unwrap_or_else(|error| format!("stderr unreadable: {error}"))
    }
}
