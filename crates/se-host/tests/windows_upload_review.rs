#![cfg(all(windows, feature = "remote"))]

use se_host::remote::ssh::{ImageProgress, prepare_image};
use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

// Invoke the public upload stage used by native first pairing, with real SSH.
#[tokio::test]
#[ignore = "requires an isolated native SSH service and pinned release image"]
async fn native_first_pairing_upload() {
    let payload = PathBuf::from(std::env::var_os("UPLOAD_REVIEW_PAYLOAD").expect("payload"));
    let output = PathBuf::from(std::env::var_os("UPLOAD_REVIEW_OUTPUT").expect("output"));
    let cancelled = Arc::new(AtomicBool::new(false));
    let timer_cancelled = Arc::clone(&cancelled);
    let (done, wait) = mpsc::channel();
    let timer = std::thread::spawn(move || {
        if wait.recv_timeout(Duration::from_secs(90)).is_err() {
            timer_cancelled.store(true, Ordering::Release);
        }
    });
    let mut events = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output.join("progress.jsonl"))
        .expect("progress file");
    let start = Instant::now();
    let mut progress = |event: ImageProgress| {
        let row = serde_json::json!({"wall_ms": start.elapsed().as_millis(), "event": event});
        writeln!(events, "{row}").expect("progress write");
        events.flush().expect("progress flush");
        Ok(())
    };
    let result = prepare_image("upload-review", &payload, &cancelled, &mut progress).await;
    let elapsed = start.elapsed();
    let _ = done.send(());
    timer.join().expect("cancellation timer join");
    let receipt = serde_json::json!({
        "passed": result.is_ok(),
        "error": result.as_ref().err().map(ToString::to_string),
        "elapsed_ms": elapsed.as_millis(),
        "fixture_cancelled": cancelled.load(Ordering::Acquire),
        "deadline_seconds": 90,
        "scope": "public prepare_image stage; no Owner enrollment or detached runtime"
    });
    std::fs::write(output.join("outcome.json"), receipt.to_string()).expect("receipt");
    assert!(result.is_ok(), "{receipt}");
}
