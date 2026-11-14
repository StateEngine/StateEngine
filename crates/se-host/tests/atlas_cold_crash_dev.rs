//! A real cold child completes, acknowledges, then remains alive: the parent
//! must not adopt its epoch until exact reap. Killing it preserves the old epoch.
#[cfg(all(any(target_os = "linux", target_os = "macos"), not(debug_assertions)))]
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
#[cfg(all(any(target_os = "linux", target_os = "macos"), not(debug_assertions)))]
mod native {
    use se_atlas::{
        cache::{connection::*, *},
        lifecycle::*,
        model::*,
    };
    use se_host::{
        atlas_cache::NativeAtlasCache,
        atlas_cold::{self, job::ColdJob, protocol::Request},
        atlas_source::NativeAtlasSource,
    };
    use std::path::{Path, PathBuf};
    use std::{
        error::Error,
        time::{Duration, Instant},
    };
    type Check<T = ()> = Result<T, Box<dyn Error>>;
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    fn coverage() -> Check<Coverage> {
        Ok(serde_json::from_value(
            serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":false,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
        )?)
    }
    fn prepared() -> Check<(super::cleanup_directory::PrivateDirectory, Request)> {
        let base = std::env::temp_dir().join(format!(
            "atlas-cold-crash-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir(&base)?;
        let root_owner = super::cleanup_directory::PrivateDirectory::for_case(base.clone());
        let source = base.join("source");
        std::fs::create_dir(&source)?;
        let project = se_types::ProjectId::from_parts(1, [42; 10])?;
        let root = RootId::from_parts(1, [43; 10])?;
        let home = base.join("atlas");
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
        let old = CacheEpoch::from_parts(1, [45; 10])?;
        let cache = NativeAtlasCache::create(&home, registered.scope.clone())?;
        let mut db = CacheConnection::create(
            &cache,
            &CacheSeed {
                identity: CacheIdentity {
                    scope: registered.scope.clone(),
                    epoch: old.clone(),
                },
                extractor_version: atlas_cold::EXTRACTOR.into(),
                ignore_digest: ContentHash([0; 32]),
                coverage: coverage()?,
                state: IndexState::Current,
            },
            ConnectionRole::ColdWriter,
            &SqlProfile::contained_cold(),
            end(),
        )?;
        assert_eq!(
            std::fs::read_dir(&source)?.count(),
            0,
            "baseline must actually be an empty repository"
        );
        pointer::publish(&cache, &mut db, None, end())?;
        drop(db);
        drop(cache);
        std::fs::write(source.join("good.js"), "export function added(){return 1;}")?;
        let request = Request {
            history_unavailable: None,
            job: AtlasJobId([46; 16]),
            project,
            root,
            source_root: se_types::NativePath::from_local(source)?,
            home: se_types::NativePath::from_local(home)?,
            physical_root: registered.scope.physical_root,
            expected_epoch: Some(old),
            epoch: CacheEpoch::from_parts(1, [47; 10])?,
            max_files: 32,
            ignore_digest: ContentHash([0; 32]),
            global_patterns: Vec::new(),
            generated_prefixes: Vec::new(),
        };
        Ok((root_owner, request))
    }
    #[cfg(target_os = "macos")]
    fn absent(pid: u32) -> Check {
        let output = std::process::Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "owned cold worker is still present"
        );
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "outside absence observation failed: {output:?}"
        );
        Ok(())
    }
    fn child_entry() -> Check {
        if std::env::current_exe()?
            .file_name()
            .is_some_and(|name| name == "atlas-abort-probe")
        {
            let (mut channel, bytes) = se_proc::atlas_worker::WorkerChannel::receive()?;
            let request: Request = serde_json::from_slice(&bytes)?;
            channel.send(&serde_json::to_vec(
                &atlas_cold::protocol::Reply::Working {
                    job: request.job,
                    path: Some(se_types::code::RelativePath::new("good.js")?),
                    phase: atlas_cold::protocol::Phase::Parse,
                },
            )?)?;
            eprintln!("intentional native abort diagnostic");
            std::process::abort();
        }
        #[cfg(target_os = "linux")]
        let pressure = std::env::current_exe()?
            .file_name()
            .is_some_and(|name| name == "atlas-pressure-probe");
        #[cfg(target_os = "linux")]
        let mut padding = Vec::<u8>::new();
        #[cfg(target_os = "linux")]
        if pressure {
            let used = se_proc::atlas_worker::virtual_bytes()?;
            let bytes = usize::try_from(
                (se_proc::atlas_worker::ADDRESS_SPACE_BYTES - 4_000_000)
                    .checked_sub(used)
                    .ok_or("pressure fixture baseline is already too large")?,
            )?;
            padding.try_reserve_exact(bytes)?;
            // Reserve address space without faulting every page into RSS.
            // Even the maximum 2 MB arena credit cannot supply the
            // unchanged 8 MB cancellation/SQL margin at this occupancy.
            assert!(
                se_proc::atlas_worker::virtual_bytes()?
                    > se_proc::atlas_worker::ADDRESS_SPACE_BYTES - 6_000_000
            );
        }
        let code = atlas_cold::private_entry()?;
        #[cfg(target_os = "linux")]
        std::hint::black_box(&padding);
        #[cfg(target_os = "linux")]
        if pressure {
            return if code == 0 {
                Ok(())
            } else {
                Err("pressure worker failed the job".into())
            };
        }
        if code != 0 {
            return Err("production cold worker refused the fixture".into());
        }
        #[cfg(target_os = "macos")]
        {
            use std::io::Write;
            let executable = std::env::current_exe()?;
            let marker = executable
                .parent()
                .ok_or("owned probe parent absent")?
                .join("completed.fixture");
            let staging = marker.with_extension("pending");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)?;
            file.write_all(std::process::id().to_string().as_bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(staging, marker)?;
        }
        // Deliberately remain alive after the actual production completion
        // protocol and its parent acknowledgment. No SQL/channel survives.
        loop {
            std::thread::park();
        }
    }
    fn old_graph(cache: &NativeAtlasCache, request: &Request, old: &[u8]) -> Check {
        let source = request.source()?;
        let mut current = pointer::open_current(
            cache,
            &source.scope,
            ConnectionRole::ExternalReader,
            &SqlProfile::contained_cold(),
            end(),
        )?
        .ok_or("old epoch absent after crash")?;
        assert_eq!(
            &current.connection.identity().epoch,
            request.expected_epoch.as_ref().ok_or("old epoch absent")?
        );
        assert_eq!(cache.read_pointer()?.as_deref(), Some(old));
        current.connection.read(end(), |sql| {
            let files: i64 = sql
                .prepare("SELECT count(*) FROM files")?
                .query_row([], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("old epoch witness", &e.to_string()))?;
            assert_eq!(files, 0, "a crash changed the old graph");
            Ok(())
        })?;
        drop(current);
        Ok(())
    }
    fn completion_image(base: &Path) -> Check<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            let _ = base;
            Ok(std::env::current_exe()?)
        }
        #[cfg(target_os = "macos")]
        {
            let image = base.join("atlas-cold-completion-probe");
            std::fs::copy(std::env::current_exe()?, &image)?;
            Ok(image.canonicalize()?)
        }
    }
    fn completion(base: &Path, request: &Request, cache: &NativeAtlasCache, old: &[u8]) -> Check {
        let source = request.source()?;
        let completion_image = completion_image(base)?;
        let mut job = ColdJob::spawn(&completion_image, request.clone())?;
        let pid = job.pid();
        let deadline = end();
        loop {
            job.wait_ready(Instant::now() + Duration::from_millis(50))?;
            assert!(
                job.poll()?.is_none(),
                "an unreaped child published its epoch"
            );
            #[cfg(target_os = "linux")]
            match std::fs::read_link(format!("/proc/{pid}/fd/3")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
                Ok(_) => (),
            }
            #[cfg(target_os = "macos")]
            match std::fs::read(base.join("completed.fixture")) {
                Ok(bytes) => {
                    assert_eq!(bytes, pid.to_string().as_bytes());
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                job.cancel()?;
                return Err("child did not complete and close its channel".into());
            }
        }
        #[cfg(target_os = "linux")]
        assert!(
            Path::new(&format!("/proc/{pid}")).exists(),
            "the completion probe exited before the exact-reap assertion"
        );
        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("/bin/ps")
                .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
                .output()?;
            assert!(
                output.status.success(),
                "outside owned-command observation failed: {output:?}"
            );
            let expected = format!(
                "{} {}",
                completion_image.canonicalize()?.display(),
                se_proc::atlas_worker::ENTRY
            );
            assert_eq!(String::from_utf8(output.stdout)?.trim(), expected);
        }
        assert_eq!(
            cache.read_pointer()?.as_deref(),
            Some(old),
            "completion without reap changed the published pointer"
        );
        let mut candidate = CacheConnection::open(
            cache,
            CacheIdentity {
                scope: source.scope.clone(),
                epoch: request.epoch.clone(),
            },
            ConnectionRole::ExternalReader,
            &SqlProfile::contained_cold(),
            end(),
        )?
        .ok_or("completed candidate absent")?;
        candidate.read(end(), |sql| {
            let files: i64 = sql
                .prepare("SELECT count(*) FROM files")?
                .query_row([], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("crash fixture", &e.to_string()))?;
            assert_eq!(
                files, 1,
                "the real child did not finish its candidate graph"
            );
            Ok(())
        })?;
        drop(candidate);
        job.cancel_until(end())?;
        assert!(
            job.poll().is_err(),
            "a killed child was treated as a successfully reaped producer"
        );
        #[cfg(target_os = "linux")]
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "killed child was not reaped"
        );
        #[cfg(target_os = "macos")]
        absent(pid)?;
        old_graph(cache, request, old)?;
        drop(job);
        Ok(())
    }
    fn abnormal_exit(
        base: &Path,
        request: &Request,
        cache: &NativeAtlasCache,
        old: &[u8],
    ) -> Check {
        let image = base.join("atlas-abort-probe");
        std::fs::copy(std::env::current_exe()?, &image)?;
        let mut failed = ColdJob::spawn(&image, request.clone())?;
        let deadline = end();
        let error = loop {
            failed.wait_ready(Instant::now() + Duration::from_millis(50))?;
            match failed.poll() {
                Err(error) => break error,
                Ok(None) if Instant::now() < deadline => (),
                _ => return Err("native abort was not reported as a refusal".into()),
            }
        };
        let se_types::Detail::AtlasUnreadable(detail) = error.body.detail() else {
            return Err(format!("native failure lost its typed path: {error}").into());
        };
        assert_eq!(detail.path, "good.js");
        for expected in [
            "SIGABRT",
            "last_phase=Parse",
            "64000000",
            "intentional native abort diagnostic",
        ] {
            assert!(
                detail.reason.contains(expected),
                "native failure lost {expected}: {error}"
            );
        }
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{}", failed.pid())).exists());
        #[cfg(target_os = "macos")]
        absent(failed.pid())?;
        assert_eq!(cache.read_pointer()?.as_deref(), Some(old));
        drop(failed);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn memory_pressure(base: &Path, request: Request, cache: &NativeAtlasCache) -> Check {
        let source = request.source()?;
        let image = base.join("atlas-pressure-probe");
        std::fs::copy(std::env::current_exe()?, &image)?;
        let mut pressure_request = request;
        pressure_request.epoch = CacheEpoch::from_parts(1, [49; 10])?;
        pressure_request.job = AtlasJobId([50; 16]);
        let mut pressure = ColdJob::spawn(&image, pressure_request)?;
        let deadline = end();
        let summary = loop {
            pressure.wait_ready(Instant::now() + Duration::from_millis(50))?;
            match pressure.poll()? {
                Some(summary) => break summary,
                None if Instant::now() < deadline => (),
                None => return Err("pressure worker did not complete".into()),
            }
        };
        assert_eq!(
            summary.coverage.failed_files, 1,
            "memory pressure left a file Indexed instead of a typed refusal"
        );
        let mut current = pointer::open_current(
            cache,
            &source.scope,
            ConnectionRole::ExternalReader,
            &SqlProfile::contained_cold(),
            end(),
        )?
        .ok_or("pressure candidate was not independently readable")?;
        current.connection.read(end(), |sql| {
            let (path, coverage): (String, String) = sql
                .prepare("SELECT path,coverage_json FROM files")?
                .query_row([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| se_types::SeError::invalid("pressure witness", &e.to_string()))?;
            assert_eq!(path, "good.js");
            let FileCoverage::Failed { error } = serde_json::from_str(&coverage)
                .map_err(|e| se_types::SeError::invalid("pressure coverage", &e.to_string()))?
            else {
                return Err(se_types::SeError::invalid(
                    "pressure witness",
                    "a retained typed per-file refusal",
                ));
            };
            let se_types::Detail::AtlasUnreadable(detail) = error.detail() else {
                return Err(se_types::SeError::invalid(
                    "pressure witness",
                    "the address-space budget refusal",
                ));
            };
            assert_eq!(detail.path, "good.js");
            for expected in [
                "atlas-resource-budget:",
                "96000000 available",
                "virtual address space",
                "8 MB cancellation/SQL margin",
            ] {
                assert!(
                    detail.reason.contains(expected),
                    "typed memory refusal lost {expected}: {detail:?}"
                );
            }
            Ok(())
        })?;
        drop(current);
        drop(pressure);
        Ok(())
    }
    pub(super) fn run() -> Check {
        se_proc::initialize_file_creation_owner()?;
        if std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == se_proc::atlas_worker::ENTRY)
        {
            return child_entry();
        }
        let (base, request) = prepared()?;
        let cache =
            NativeAtlasCache::open(&request.home.to_local()?, request.source()?.scope.clone())?
                .ok_or("old cache absent")?;
        let old = cache.read_pointer()?.ok_or("old pointer absent")?;
        completion(&base, &request, &cache, &old)?;
        println!(
            "PASS actual completed cold child cannot publish before exact reap; crash preserves independently reopened old epoch"
        );
        abnormal_exit(&base, &request, &cache, &old)?;
        println!(
            "PASS native abort reports its typed file, signal, phase, limit and bounded stderr"
        );
        #[cfg(target_os = "linux")]
        {
            memory_pressure(&base, request, &cache)?;
            println!(
                "PASS native memory pressure becomes a typed per-file refusal before parser allocation"
            );
            println!("3 passed; 0 failed");
        }
        #[cfg(target_os = "macos")]
        println!("2 passed; 0 failed; Linux virtual-address-space pressure case NOT GRADED");
        drop(cache);
        base.finish(Ok(()))
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|v| v == "--list") {
        if !std::env::args().any(|v| v == "--ignored") {
            println!("atlas_cold_crash_dev: test");
        }
        return Ok(());
    }
    #[cfg(all(any(target_os = "linux", target_os = "macos"), not(debug_assertions)))]
    native::run()?;
    #[cfg(not(all(any(target_os = "linux", target_os = "macos"), not(debug_assertions))))]
    println!("0 passed; 0 failed; 1 skipped (requires native Linux or macOS release image)");
    Ok(())
}
