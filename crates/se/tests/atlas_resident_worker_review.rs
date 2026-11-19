#![cfg(any(target_os = "linux", windows))]

use se_atlas::{
    lifecycle::{CaseMode, SourceRead},
    model::*,
    parse::{ParserPlacement, ParserProfile},
};
use se_host::atlas_source::NativeAtlasSource;
use se_proc::atlas_worker::{AtlasWorker, MEMORY_BYTES};
use se_types::{NativePath, ProjectId, code::AtlasText};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Home(PathBuf);
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn frame(worker: &mut AtlasWorker, end: Instant) -> Check<Value> {
    loop {
        assert!(Instant::now() < end, "no complete reply before deadline");
        if let Some(bytes) = worker.receive()? {
            return Ok(serde_json::from_slice(&bytes)?);
        }
        let _ = worker.wait_ready((Instant::now() + Duration::from_millis(10)).min(end))?;
    }
}

fn windows_commit(_pid: u32) -> Check<Value> {
    #[cfg(windows)]
    {
        let command = format!(
            "$p=Get-Process -Id {_pid} -ErrorAction Stop; \"$($p.PrivateMemorySize64) $($p.PeakPagedMemorySize64)\""
        );
        let sample = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .output()?;
        assert!(sample.status.success(), "{:?}", sample);
        let sample: Vec<u64> = String::from_utf8(sample.stdout)?
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        assert_eq!(sample.len(), 2);
        Ok(json!({"private_commit":sample[0],"peak_commit":sample[1]}))
    }
    #[cfg(target_os = "linux")]
    Ok(Value::Null)
}

#[test]
fn resident_worker_replies_to_each_file_and_bounds_many_parses() -> Check {
    let home = Home(std::env::temp_dir().join(format!("atlas-review-{}", uuid::Uuid::new_v4())));
    fs::create_dir(&home.0)?;
    let root = home.0.canonicalize()?;
    let cache = root.join("cache");
    fs::create_dir(&cache)?;
    let project = ProjectId::from_parts(1, [1; 10])?;
    let root_id = RootId::from_parts(1, [2; 10])?;
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: project.clone(),
            root: root_id.clone(),
            canonical_source_root: root.clone(),
            cache: CacheLocation {
                directory: cache.clone(),
            },
            git_metadata: None,
        },
        if cfg!(windows) {
            CaseMode::InsensitivePreserving
        } else {
            CaseMode::Sensitive
        },
    )?;
    let profile = ParserProfile::from_qualified_measurement(
        Language::JavaScript,
        ParserPlacement::Incremental,
        524_288,
        65_536,
        1_000_000,
        10_000_000,
    )?;
    let low_profile = ParserProfile::from_qualified_measurement(
        Language::JavaScript,
        ParserPlacement::Incremental,
        65_536,
        65_536,
        20_000,
        250_000,
    )?;
    let source_root = NativePath::from_local(root.clone())?;
    let cache_directory = NativePath::from_local(cache)?;
    let default_image = std::env::var_os("SE_W3_SE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_se")));
    let image = std::env::var_os("SE_ATLAS_WORKER_BIN")
        .map(PathBuf::from)
        .unwrap_or(default_image)
        .canonicalize()?;
    let output = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/atlas-resident-worker-review");
    fs::create_dir_all(&output)?;
    let mut report = fs::File::create(output.join("review.jsonl"))?;
    let mut worker: Option<AtlasWorker> = None;
    let mut pid = 0;
    let end = Instant::now() + Duration::from_secs(105);

    for i in 0..401 {
        let path = RelativePath::new(format!("file{i:03}.js"))?;
        let marker = format!("file_{i}");
        let dense = matches!(i, 100 | 200 | 300);
        let low = matches!(i, 50 | 350);
        let text = if dense || low {
            "v=1;".repeat(if dense { 90_000 } else { 14_000 })
        } else {
            let declarations = (0..(i % 89))
                .map(|n| format!("export function value_{n}() {{ return {n}; }}\n"))
                .collect::<String>();
            let padding = " ".repeat((i * 5_183) % 49_152);
            format!("/* {padding} */\nexport function {marker}() {{ return {i}; }}\n{declarations}")
        };
        fs::write(root.join(path.as_str()), &text)?;
        let budget = ParseBudget {
            max_source_bytes: 524_288,
            max_rows: 65_536,
            max_work: Duration::from_millis(200),
            reserved_bytes: if low { 400_000 } else { PARSER_BYTES },
        };
        let SourceRead::Bytes(snapshot) =
            source.read_with_wall_timeout(&path, budget, Duration::from_secs(5))?
        else {
            panic!("fixture file {i} was unreadable")
        };
        let payload = serde_json::to_vec(&json!({
            "parse_only": true,
            "project": project, "root": root_id, "source_root": source_root,
            "cache_directory":cache_directory, "physical_root":source.scope.physical_root,
            "path":path, "identity":snapshot.identity, "content_hash":snapshot.content_hash,
            "language":Language::JavaScript, "budget":budget, "profile":if low { low_profile } else { profile },
        }))?;
        let file_end = end.min(Instant::now() + Duration::from_secs(5));
        if let Some(held) = worker.as_mut() {
            held.send_control(&payload, file_end)
                .unwrap_or_else(|error| panic!("file {i} request failed: {error}"));
        } else {
            let spawned = AtlasWorker::spawn(&image, &payload, end)?;
            pid = spawned.pid();
            worker = Some(spawned);
        }
        let held = worker.as_mut().unwrap();
        assert_eq!(held.pid(), pid);
        assert_eq!(frame(held, file_end)?, json!({"kind":"Ready"}), "file {i}");
        let start_commit = if matches!(i, 0 | 100 | 200 | 300 | 400) {
            windows_commit(pid)?
        } else {
            Value::Null
        };
        held.send_control(b"source", file_end)?;
        let start = frame(held, file_end)?;
        assert_eq!(start["kind"], "Start", "file {i}: {start}");
        assert_eq!(
            start["row"]["file"],
            json!(source.scope.file_id(&path)),
            "file {i}"
        );
        assert_eq!(
            start["row"]["hash"],
            json!(snapshot.content_hash),
            "file {i}"
        );
        let mut found = false;
        let mut rows = 0;
        loop {
            let row = frame(held, file_end)?;
            match row["kind"].as_str() {
                Some("Done") => break,
                Some("Symbol") => {
                    found |= row["row"]["name"] == marker;
                    rows += 1;
                }
                Some("Import" | "Reference" | "Scope") => rows += 1,
                _ => panic!("unexpected reply for file {i}: {row}"),
            }
        }
        let peak = held.observe_memory()?;
        assert!(peak <= MEMORY_BYTES);
        let sample = json!({
            "file": i, "pid":pid, "source_bytes":text.len(), "coverage":start["row"]["coverage"],
            "reserved_bytes":budget.reserved_bytes, "rows":rows, "found_marker":found, "peak_rss":peak,
            "before": start_commit,
            "after": if matches!(i, 0 | 100 | 200 | 300 | 400) { windows_commit(pid)? } else { Value::Null },
        });
        use std::io::Write;
        writeln!(report, "{sample}")?;
        if low || dense {
            assert!(
                start["row"]["coverage"]
                    .to_string()
                    .contains("ParseMemoryLimit"),
                "file {i}: {start}"
            );
            assert_eq!(rows, 0);
        } else {
            assert!(found, "file {i}: {start}");
        }
    }
    let mut held = worker.unwrap();
    held.cancel_until(Instant::now() + Duration::from_secs(2))?;
    assert!(held.try_reap()?.is_some());
    Ok(())
}
