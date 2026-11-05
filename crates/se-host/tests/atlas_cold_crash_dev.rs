//! A real cold child completes, acknowledges, then remains alive: the parent
//! must not adopt its epoch until exact reap. Killing it preserves the old epoch.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
mod linux {
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
    use std::{
        error::Error,
        path::{Path, PathBuf},
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
    fn prepared() -> Check<(PathBuf, Request)> {
        let base = std::env::temp_dir().join(format!(
            "5p-cold-crash-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let source = base.join("source");
        std::fs::create_dir_all(&source)?;
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
        let db = CacheConnection::create(
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
        pointer::publish(&cache, &db, None, end())?;
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
        Ok((base, request))
    }
    pub(super) fn run() -> Check {
        se_proc::initialize_file_creation_owner()?;
        if std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == se_proc::atlas_worker::ENTRY)
        {
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
            let pressure = std::env::current_exe()?
                .file_name()
                .is_some_and(|name| name == "atlas-pressure-probe");
            let mut padding = Vec::<u8>::new();
            if pressure {
                let used = se_proc::atlas_worker::virtual_bytes()?;
                let bytes = usize::try_from(
                    58_000_000u64
                        .checked_sub(used)
                        .ok_or("pressure fixture baseline is already too large")?,
                )?;
                padding.try_reserve_exact(bytes)?;
                padding.resize(bytes, 0);
            }
            let code = atlas_cold::private_entry()?;
            std::hint::black_box(&padding);
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
            // Deliberately remain alive after the actual production completion
            // protocol and its parent acknowledgment. No SQL/channel survives.
            loop {
                std::thread::park();
            }
        }
        let (base, request) = prepared()?;
        let source = request.source()?;
        let home = request.home.to_local()?;
        let cache =
            NativeAtlasCache::open(&home, source.scope.clone())?.ok_or("old cache absent")?;
        let old = cache.read_pointer()?.ok_or("old pointer absent")?;
        let mut job = ColdJob::spawn(&std::env::current_exe()?, request.clone())?;
        let pid = job.pid();
        let deadline = end();
        loop {
            job.wait_ready(Instant::now() + Duration::from_millis(50))?;
            assert!(
                job.poll()?.is_none(),
                "an unreaped child published its epoch"
            );
            match std::fs::read_link(format!("/proc/{pid}/fd/3")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
                Ok(_) => (),
            }
            if Instant::now() >= deadline {
                job.cancel()?;
                return Err("child did not complete and close its channel".into());
            }
        }
        assert!(
            Path::new(&format!("/proc/{pid}")).exists(),
            "the completion probe exited before the exact-reap assertion"
        );
        assert_eq!(
            cache.read_pointer()?.as_deref(),
            Some(old.as_slice()),
            "completion without reap changed the published pointer"
        );
        let candidate = CacheConnection::open(
            &cache,
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
        job.cancel()?;
        assert!(
            job.poll().is_err(),
            "a killed child was treated as a successfully reaped producer"
        );
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "killed child was not reaped"
        );
        let current = pointer::open_current(
            &cache,
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
        assert_eq!(cache.read_pointer()?.as_deref(), Some(old.as_slice()));
        current.connection.read(end(), |sql| {
            let files: i64 = sql
                .prepare("SELECT count(*) FROM files")?
                .query_row([], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("old epoch witness", &e.to_string()))?;
            assert_eq!(files, 0, "a crash changed the old graph");
            Ok(())
        })?;
        drop(current);
        drop(job);
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
        assert!(!Path::new(&format!("/proc/{}", failed.pid())).exists());
        assert_eq!(cache.read_pointer()?.as_deref(), Some(old.as_slice()));
        drop(failed);
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
        let current = pointer::open_current(
            &cache,
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
            assert!(
                coverage.contains("64000000") && coverage.contains("virtual address space"),
                "memory refusal lost its limit or resource: {coverage}"
            );
            Ok(())
        })?;
        drop(current);
        drop(pressure);
        drop(cache);
        drop(source);
        std::fs::remove_dir_all(base)?;
        println!(
            "PASS actual completed cold child cannot publish before exact reap; crash preserves independently reopened old epoch"
        );
        println!(
            "PASS native abort reports its typed file, signal, phase, limit and bounded stderr"
        );
        println!(
            "PASS native memory pressure becomes a typed per-file refusal before parser allocation"
        );
        println!("3 passed; 0 failed");
        Ok(())
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(target_os = "linux", not(debug_assertions)))]
    linux::run()?;
    #[cfg(not(all(target_os = "linux", not(debug_assertions))))]
    println!("0 passed; 0 failed; 1 skipped (requires native Linux release image)");
    Ok(())
}
