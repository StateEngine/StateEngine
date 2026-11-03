//! The public CLI observer controls this standalone host's natural exit.
#![cfg(all(feature = "listener", target_os = "linux"))]
#[path = "support/wave2_host_fixture.rs"]
mod support;
use se_host::*;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::BufRead,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use support::*;

#[test]
#[ignore = "subprocess entry driven by judges/shutdown_process_read.py"]
fn standalone_shutdown_process_fixture() -> Check {
    let initialized = initialize_host_process()?;
    let output = std::path::PathBuf::from(
        std::env::var_os("SE_SHUTDOWN_PROCESS_FIXTURE")
            .ok_or("observer output directory missing")?,
    );
    let f = Fixture::new()?;
    seed(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    let result = rt.block_on(async {
        let mut start = start(&f)?;
        let mut digest = Sha256::new();
        for arg in std::env::args_os() {
            let bytes = arg.as_encoded_bytes();
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        }
        let fields = start.epoch.owner.fields();
        start.epoch.owner = se_types::ProcessInstance::from_observation(se_types::ProcessFields {
            machine: fields.machine.clone(),
            boot: fields.boot.clone(),
            pid: fields.pid,
            started: fields.started.clone(),
            executable: fields.executable.clone(),
            argv_sha256: se_types::Sha256::from_bytes(digest.finalize().into()),
        })?;
        let mut host =
            HostedRuntime::prepare(initialized, start, rt.handle().clone(), &bound()?).await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let released = Arc::new(AtomicBool::new(false));
        let signal = released.clone();
        let stop = host.local_stop();
        let input = std::thread::spawn(move || {
            let mut line = String::new();
            let result = std::io::stdin().lock().read_line(&mut line);
            stop.request();
            signal.store(true, Ordering::Release);
            result
        });
        fs::write(
            output.join("ready.json"),
            serde_json::to_vec(
                &serde_json::json!({"home":f.options.state_directory,"pid":std::process::id()}),
            )?,
        )?;
        let report = host.serve(listener).await.finish(&bound()?).await;
        require(
            report.pending.is_empty() && report.transport_closed && report.endpoint_retired,
            "standalone fixture shutdown incomplete",
        )?;
        drop(report);
        fs::write(
            output.join("drained"),
            b"resources closed; application still alive",
        )?;
        while !released.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        input
            .join()
            .map_err(|_| "fixture control thread panicked")??;
        Ok(())
    });
    // Fixture's normal Drop removes its directory. This outside reader still
    // needs the protected receipt after the application exits; retain the
    // test's paths/IDs until process exit, without retaining any native handle.
    std::mem::forget(f);
    result
}
