//! Compare the native cold worker's disk policy on a full-history checkout.
#![cfg(all(target_os = "macos", not(debug_assertions)))]

#[path = "../../test-support/directory.rs"]
mod cleanup_directory;

use se_atlas::{lifecycle::*, model::*};
use se_host::{
    atlas_cold::{job::ColdJob, protocol::Request},
    atlas_source::NativeAtlasSource,
};
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn git(root: Option<&Path>, args: &[&str]) -> Check<String> {
    let mut command = Command::new("git");
    if let Some(root) = root {
        command.arg("-C").arg(root);
    }
    let output = command
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()?;
    if !output.status.success() {
        return Err(format!("git failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[test]
fn full_history_cold_disk_policy() -> Check {
    let fixture = cleanup_directory::private_case_directory()?;
    let result = (|| -> Check {
        let policy = std::env::var("ATLAS_MACOS_DISK_POLICY")?;
        if !matches!(policy.as_str(), "throttle" | "normal") {
            return Err("set ATLAS_MACOS_DISK_POLICY to throttle or normal".into());
        }
        let repository = std::env::var("ATLAS_FULL_REPOSITORY")?;
        let revision = std::env::var("ATLAS_SOURCE_COMMIT")?;
        if !matches!(revision.len(), 40 | 64) || !revision.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("ATLAS_SOURCE_COMMIT must be a full commit ID".into());
        }
        let source = fixture.join("source");
        let source_arg = source.to_str().ok_or("fixture path is not UTF-8")?;
        git(
            None,
            &["clone", "--no-hardlinks", "--", &repository, source_arg],
        )?;
        git(Some(&source), &["checkout", "--detach", &revision])?;
        let actual = git(Some(&source), &["rev-parse", "HEAD"])?;
        let shallow = git(Some(&source), &["rev-parse", "--is-shallow-repository"])?;
        let history: u64 = git(Some(&source), &["rev-list", "--count", "HEAD"])?.parse()?;
        if actual != revision.to_ascii_lowercase() || shallow != "false" || history < 1000 {
            return Err(
                "source must have the requested full commit and at least 1000 commits".into(),
            );
        }
        let project = se_types::ProjectId::from_parts(1, [42; 10])?;
        let root = RootId::from_parts(1, [43; 10])?;
        let home = fixture.join("atlas");
        let registration = RootRegistration {
            project: project.clone(),
            root: root.clone(),
            canonical_source_root: source.clone(),
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(root.as_str()),
            },
            git_metadata: None,
        };
        let registered = NativeAtlasSource::open(registration, CaseMode::Sensitive)?;
        let request = Request {
            history_unavailable: None,
            job: AtlasJobId([46; 16]),
            project,
            root,
            source_root: se_types::NativePath::from_local(source)?,
            home: se_types::NativePath::from_local(home)?,
            physical_root: registered.scope.physical_root,
            expected_epoch: None,
            epoch: CacheEpoch::from_parts(1, [47; 10])?,
            max_files: 100_000,
            ignore_digest: ContentHash([0; 32]),
            global_patterns: Vec::new(),
            generated_prefixes: Vec::new(),
        };
        println!(
            "ATLAS_POLICY mode={policy} revision={actual} history={history} nice=10 history_ingest=unavailable"
        );
        let started = Instant::now();
        let image = Path::new(env!("CARGO_BIN_EXE_se")).canonicalize()?;
        let mut job = ColdJob::spawn(&image, request)?;
        let summary = loop {
            if let Some(summary) = job.poll()? {
                break summary;
            }
            if started.elapsed() >= Duration::from_secs(900) {
                return Err("cold worker exceeded the 900 second limit".into());
            }
            job.wait_ready(Instant::now() + Duration::from_millis(100))?;
        };
        let coverage = &summary.coverage;
        println!(
            "ATLAS_POLICY_RESULT mode={policy} elapsed_ms={} discovered={} indexed={} partial={} deferred={} failed={} complete={} peak_bytes={} reasons={:?}",
            started.elapsed().as_millis(),
            coverage.discovered_files,
            coverage.indexed_files,
            coverage.partial_files,
            coverage.deferred_files,
            coverage.failed_files,
            coverage.discovery_complete,
            job.peak_observed_bytes,
            coverage.reasons
        );
        if !coverage.discovery_complete
            || coverage.discovered_files < 1000
            || summary.epoch.is_none()
        {
            return Err("cold worker did not complete a full-source epoch".into());
        }
        Ok(())
    })();
    fixture.finish(result)
}
