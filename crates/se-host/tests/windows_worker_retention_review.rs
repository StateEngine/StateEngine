#![cfg(windows)]
//! A retained native birth judges the worker slot's cancellation and readmission.
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_atlas::{lifecycle::*, model::*};
use se_host::{
    atlas_cold::{job::ColdJob, protocol::Request},
    atlas_source::NativeAtlasSource,
};
use se_proc::atlas_worker::AtlasWorker;
use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn Error>>;

fn request(root: &Path) -> Check<Request> {
    let source_root = root.join("source");
    fs::create_dir(&source_root)?;
    fs::write(
        source_root.join("healthy.js"),
        "export function healthy(){return 42;}\n",
    )?;
    let project = se_types::ProjectId::from_parts(1, [81; 10])?;
    let id = RootId::from_parts(1, [82; 10])?;
    let home = root.join("atlas");
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: project.clone(),
            root: id.clone(),
            canonical_source_root: source_root.clone(),
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(id.as_str()),
            },
            git_metadata: None,
        },
        CaseMode::Sensitive,
    )?;
    Ok(Request {
        history_unavailable: None,
        job: AtlasJobId([83; 16]),
        project,
        root: id,
        source_root: se_types::NativePath::from_local(source_root)?,
        home: se_types::NativePath::from_local(home)?,
        physical_root: source.scope.physical_root,
        expected_epoch: None,
        epoch: CacheEpoch::from_parts(1, [84; 10])?,
        max_files: 8,
        ignore_digest: ContentHash([0; 32]),
        global_patterns: vec![],
        generated_prefixes: vec![],
    })
}

struct Observer {
    child: Child,
    output: BufReader<ChildStdout>,
    birth: serde_json::Value,
}
impl Observer {
    fn open(pid: u32, image: &Path) -> Check<Self> {
        let python = std::env::var_os("NATIVE_JUDGE_PYTHON").ok_or("native Python required")?;
        let script =
            std::env::var_os("WORKER_EXIT_JUDGE").ok_or("native exit observer required")?;
        let mut child = Command::new(python)
            .arg("-B")
            .arg(script)
            .arg(pid.to_string())
            .arg(image)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut output = BufReader::new(child.stdout.take().ok_or("observer stdout absent")?);
        let mut line = String::new();
        output.read_line(&mut line)?;
        let ready: serde_json::Value = serde_json::from_str(line.trim())?;
        assert_eq!(ready["ready"]["pid"].as_u64(), Some(u64::from(pid)));
        assert_eq!(ready["ready"]["exited"].as_bool(), Some(false));
        let birth = ready["ready"]["creation_filetime"].clone();
        assert!(birth.as_u64().is_some(), "native birth absent");
        println!("outside retained native worker: {}", line.trim());
        Ok(Self {
            child,
            output,
            birth,
        })
    }
    fn joined(mut self, pid: u32) -> Check {
        self.child
            .stdin
            .take()
            .ok_or("observer stdin absent")?
            .write_all(b"check\n")?;
        let mut witness = String::new();
        self.output.read_to_string(&mut witness)?;
        let status = self.child.wait()?;
        let mut errors = String::new();
        self.child
            .stderr
            .take()
            .ok_or("observer stderr absent")?
            .read_to_string(&mut errors)?;
        assert!(status.success(), "native exit readback failed: {errors}");
        let value: serde_json::Value = serde_json::from_str(witness.trim())?;
        assert_eq!(value["pid"].as_u64(), Some(u64::from(pid)));
        assert_eq!(value["creation_filetime"], self.birth);
        assert_eq!(value["native_handle_signalled"].as_bool(), Some(true));
        println!("outside exact native exit: {}", witness.trim());
        Ok(())
    }
}

#[test]
fn pending_reap_fences_the_slot_until_exact_native_exit() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let root = PathBuf::from(std::env::var_os("COLD_JUDGE_ROOT").ok_or("private root required")?);
    fs::create_dir(&root)?;
    let owner = cleanup_directory::PrivateDirectory::for_case(root.clone());
    let request = request(&root)?;
    let image =
        PathBuf::from(std::env::var_os("SE_ATLAS_WORKER_BIN").ok_or("shipping worker required")?)
            .canonicalize()?;
    let payload = serde_json::to_vec(&request)?;
    let mut pending_witnessed = false;
    for attempt in 0..16 {
        let end = Instant::now() + Duration::from_millis(500);
        let mut worker = AtlasWorker::spawn_bounded(&image, &payload, end)?;
        let pid = worker.pid();
        let observer = Observer::open(pid, &image)?;
        match worker.cancel_until(Instant::now()) {
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "{error}");
                let blocked = AtlasWorker::spawn_bounded(&image, &payload, end)
                    .err()
                    .ok_or("unreaped worker released the shared slot")?;
                assert_eq!(blocked.kind(), std::io::ErrorKind::InvalidData);
                assert!(
                    blocked
                        .to_string()
                        .contains("previous Atlas child has not been reaped")
                );
                worker.cancel_until(end)?;
                assert!(
                    Instant::now() <= end,
                    "retry reap exceeded original 500-ms clock"
                );
                pending_witnessed = true;
                println!("PASS pending native reap fences shared slot; attempt={attempt}");
            }
            Ok(()) => {
                assert!(
                    Instant::now() <= end,
                    "immediate reap exceeded original clock"
                );
            }
        }
        observer.joined(pid)?;
        drop(worker);
        if pending_witnessed {
            break;
        }
    }
    assert!(
        pending_witnessed,
        "native execution never exposed pending-reap state"
    );
    let mut successor = request;
    successor.epoch = CacheEpoch::from_parts(1, [85; 10])?;
    successor.job = AtlasJobId([86; 16]);
    let mut next = ColdJob::spawn(&image, successor)?;
    let next_pid = next.pid();
    let observer = Observer::open(next_pid, &image)?;
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        next.wait_ready(end)?;
        if let Some(summary) = next.poll()? {
            assert!(summary.coverage.discovery_complete);
            assert_eq!(summary.coverage.indexed_files, 1);
            assert_eq!(
                summary.epoch.as_ref(),
                Some(&CacheEpoch::from_parts(1, [85; 10])?)
            );
            break;
        }
        assert!(
            Instant::now() < end,
            "successor did not complete a real parse"
        );
    }
    observer.joined(next_pid)?;
    println!("PASS exact reap permits a real shipping successor and completed parse");
    drop(next);
    owner.finish(Ok(()))
}
