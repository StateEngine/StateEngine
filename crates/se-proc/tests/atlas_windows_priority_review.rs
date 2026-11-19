//! Native readback from the real cold worker and its existing commit phase fence.
#![cfg(windows)]

use se_proc::{NativeSourceRoot, atlas_worker::AtlasWorker};
use se_types::{
    NativePath, ProjectId,
    code::{AtlasJobId, CacheEpoch, ContentHash, RootId},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs, io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    time::{Duration, Instant},
};
use windows_sys::Win32::System::Threading::{
    BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, GetPriorityClass, NORMAL_PRIORITY_CLASS,
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[path = "../../test-support/directory.rs"]
mod directory;

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
const FILES: usize = 24;

fn external_priority(pid: u32) -> io::Result<u32> {
    // SAFETY: query-only rights on the exact worker owned by this fixture.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess returned one fresh owned handle.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: the owned process handle is retained through the read.
    let class = unsafe { GetPriorityClass(process.as_raw_handle()) };
    if class == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(class)
}

fn parent_priority() -> io::Result<u32> {
    // SAFETY: the current-process pseudo-handle stays valid for the read.
    let class = unsafe { GetPriorityClass(GetCurrentProcess()) };
    if class == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(class)
}

fn seed(base: &Path) -> Check<Value> {
    let source = base.join("source");
    fs::create_dir(&source)?;
    for file in 0..FILES {
        let mut text = format!("//! Index fixture module {file}\n");
        for routine in 0..16 {
            text.push_str(&format!(
                "pub fn item_{file}_{routine}(value: u32) -> u32 {{ value + {routine} }}\n",
            ));
        }
        fs::write(source.join(format!("sample-{file:03}.rs")), text)?;
    }
    let pin = NativeSourceRoot::open(&source)?;
    Ok(json!({
        "job": AtlasJobId([4; 16]),
        "project": ProjectId::from_parts(1, [5; 10])?,
        "root": RootId::from_parts(1, [6; 10])?,
        "source_root": NativePath::from_local(source)?,
        "home": NativePath::from_local(base.join("atlas"))?,
        "physical_root": pin.physical_identity()?,
        "expected_epoch": null,
        "epoch": CacheEpoch::from_parts(1, [7; 10])?,
        "max_files": FILES,
        "ignore_digest": ContentHash([0; 32]),
        "global_patterns": [],
        "generated_prefixes": [],
    }))
}

fn next_frame(worker: &mut AtlasWorker, deadline: Instant) -> Check<Value> {
    while Instant::now() < deadline {
        worker.wait_ready(deadline.min(Instant::now() + Duration::from_secs(1)))?;
        if let Some(bytes) = worker.receive()? {
            return Ok(serde_json::from_slice(&bytes)?);
        }
        if let Some(status) = worker.try_reap()? {
            let diagnostic = worker.failure_diagnostic()?;
            return Err(format!("cold worker exited {status}; {diagnostic}").into());
        }
    }
    Err("cold worker exceeded the comparison allowance".into())
}

fn observe(worker: &mut AtlasWorker, deadline: Instant) -> Check<Value> {
    let mut samples = BTreeMap::new();
    let mut open = None::<(String, Instant)>;
    let mut observed_class = None;
    loop {
        let frame = next_frame(worker, deadline)?;
        match frame["kind"].as_str() {
            Some("Working") => (),
            Some("Progress") => continue,
            _ => return Err(format!("unexpected cold report {frame}").into()),
        }
        let path = frame["path"].as_str();
        match frame["phase"].as_str() {
            Some("SourceRead") if samples.len() == FILES => {
                // The first second-pass read waits for our permission. All
                // first-pass checkpoints have finished, and none of this
                // second pass contributes to the timing.
                break;
            }
            Some("SourceRead") => {
                let class = external_priority(worker.pid())?;
                if let Some(previous) = observed_class {
                    assert_eq!(
                        class, previous,
                        "worker class changed during the first pass"
                    );
                }
                observed_class = Some(class);
                worker.send_control(b"source", deadline)?;
            }
            Some("Resolve") => worker.send_control(b"source", deadline)?,
            Some("Commit") => {
                let path = path.ok_or("commit phase did not name a file")?;
                assert!(open.is_none(), "file entered a fallback commit: {path}");
                open = Some((path.to_owned(), Instant::now()));
                worker.send_control(b"source", deadline)?;
            }
            Some("Checkpoint") => {
                let (committed_path, started) = open.take().ok_or("checkpoint without commit")?;
                assert_eq!(path, Some(committed_path.as_str()));
                let elapsed = u64::try_from(started.elapsed().as_micros())?;
                assert!(samples.insert(committed_path, elapsed).is_none());
            }
            _ => (),
        }
    }
    let mut timings: Vec<_> = samples.values().copied().collect();
    timings.sort_unstable();
    let total: u64 = timings.iter().sum();
    Ok(json!({
        "worker_class": observed_class.ok_or("worker never reached source read")?,
        "parent_class": parent_priority()?,
        "sample_files": timings.len(),
        "commit_phase_mean_us": total as f64 / timings.len() as f64,
        "commit_phase_median_us": (timings[FILES / 2 - 1] + timings[FILES / 2]) as f64 / 2.0,
        "per_file_us": samples,
    }))
}

#[test]
fn windows_atlas_cold_priority_and_commit_phase() -> Check {
    let parent = parent_priority()?;
    assert_eq!(
        parent, NORMAL_PRIORITY_CLASS,
        "requires an ordinary-priority parent"
    );
    let image =
        std::path::PathBuf::from(std::env::var_os("SE_W3_SE_BIN").ok_or("native CLI missing")?)
            .canonicalize()?;
    se_proc::initialize_file_creation_owner()?;
    let base = directory::private_case_directory()?;
    let payload = seed(&base)?;
    let deadline = Instant::now() + Duration::from_secs(100);
    let mut worker = AtlasWorker::spawn_bounded(&image, &serde_json::to_vec(&payload)?, deadline)?;
    let result = observe(&mut worker, deadline);
    worker.cancel_until(Instant::now() + Duration::from_secs(2))?;
    let receipt = result?;
    let target = env!("CARGO_MANIFEST_DIR");
    let checkout = Path::new(target)
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace absent")?;
    let diagnostics = checkout.join("target").join("judge-diagnostics");
    fs::create_dir_all(&diagnostics)?;
    fs::write(
        diagnostics.join("atlas-cold-priority.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!("{receipt}");
    base.finish(Ok::<_, Box<dyn std::error::Error>>(()))?;
    assert_eq!(
        receipt["worker_class"].as_u64(),
        Some(u64::from(BELOW_NORMAL_PRIORITY_CLASS))
    );
    Ok(())
}
