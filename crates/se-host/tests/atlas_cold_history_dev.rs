//! Real parser -> exact reap -> contained Git -> host writer -> pointer reader.
//! Component profile values come from the measured Linux owner profile; this
//! development consumer does not certify the joined production owner's memory.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
#[path = "../../test-support/atlas_clock.rs"]
mod test_clock;
#[cfg(all(target_os = "linux", not(debug_assertions)))]
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
#[cfg(all(target_os = "linux", not(debug_assertions)))]
mod native {
    use se_atlas::{
        cache::{connection::*, *},
        controller::Controller,
        lifecycle::*,
        model::*,
    };
    use se_host::{
        atlas_cache::NativeAtlasCache,
        atlas_renewal::NativeRenewal,
        atlas_runtime::{NativeRuntime, drive_child},
        atlas_source::NativeAtlasSource,
    };
    use se_types::code::{QueryText, RecordHit, RecordPointer};
    use std::{
        fs,
        path::Path,
        process::Command,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn git(root: &Path, args: &[&str]) -> Check {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Fixture Human")
            .env("GIT_COMMITTER_NAME", "Fixture Human")
            .env("GIT_AUTHOR_EMAIL", "atlas-fixture.invalid")
            .env("GIT_COMMITTER_EMAIL", "atlas-fixture.invalid")
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "Git fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }
    struct NoRecords;
    impl se_atlas::query::RecordReader for NoRecords {
        fn read(
            &self,
            _: &se_types::ProjectId,
            _: &AtlasPrincipal,
            _: &RecordPointer,
            _: Option<&QueryText>,
        ) -> se_types::Result<se_types::Read<RecordHit>> {
            Err(se_types::SeError::invalid(
                "history fixture",
                "unexpected record read",
            ))
        }
        fn literal_read(
            &self,
            _: &se_types::ProjectId,
            _: &AtlasPrincipal,
            _: &RecordPointer,
            _: &QueryText,
        ) -> se_types::Result<se_types::Read<RecordHit>> {
            Err(se_types::SeError::invalid(
                "history fixture",
                "unexpected literal read",
            ))
        }
        fn body(
            &self,
            _: &se_types::ProjectId,
            _: &AtlasPrincipal,
            _: &RecordPointer,
            _: Option<&QueryText>,
        ) -> se_types::Result<se_types::Read<se_types::code::HitBody>> {
            Err(se_types::SeError::invalid(
                "history fixture",
                "unexpected record body",
            ))
        }
    }
    fn count(db: &mut CacheConnection<'_>, sql: &str) -> se_types::Result<i64> {
        db.read(end(), |db| {
            db.prepare(sql)?
                .query_row([], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("history witness", &e.to_string()))
        })
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Case {
        Bounded,
        Wide,
        Unqualified,
        Unreadable,
    }
    pub fn run() -> Check {
        se_proc::initialize_file_creation_owner()?;
        if std::env::args_os()
            .nth(1)
            .is_some_and(|a| a == se_proc::atlas_worker::ENTRY)
        {
            let code = se_host::atlas_cold::private_entry()?;
            return if code == 0 {
                Ok(())
            } else {
                Err("cold fixture refused".into())
            };
        }
        let cases: &[Case] = if std::env::args().any(|arg| arg == "--wide-history") {
            &[Case::Wide]
        } else {
            &[
                Case::Bounded,
                Case::Wide,
                Case::Unqualified,
                Case::Unreadable,
            ]
        };
        for case in cases {
            run_case(*case)?;
        }
        println!("{} passed; 0 failed", cases.len());
        Ok(())
    }
    fn run_case(case: Case) -> Check {
        let bounded = case == Case::Bounded;
        let expected_reason = if bounded {
            CoverageReason::ResultLimit
        } else {
            CoverageReason::HistoryUnavailable
        };
        let base = std::env::temp_dir().join(format!(
            "atlas-cold-history-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let source = base.join("source");
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&base)?;
        let _root_owner = super::cleanup_directory::PrivateDirectory::adopt(base.clone());
        fs::create_dir(&source)?;
        git(&source, &["init", "--initial-branch=main"])?;
        for index in 0..5 {
            fs::write(
                source.join("good.js"),
                format!("export function history_{index}() {{ return {index}; }}\n"),
            )?;
            git(&source, &["add", "--", "good.js"])?;
            git(
                &source,
                &["commit", "-m", &format!("native_history_marker_{index}")],
            )?;
        }
        // Secret-only history must not supply an actor, touch, subject or hit.
        fs::write(source.join(".env"), "PRIVATE_FIXTURE=not-a-real-secret\n")?;
        git(&source, &["add", "--", ".env"])?;
        git(&source, &["commit", "-m", "secret_only_marker"])?;
        if case == Case::Wide {
            for index in 0..33 {
                fs::write(
                    source.join(format!("wide_{index}.js")),
                    format!("export function wide_{index}() {{ return {index}; }}\n"),
                )?;
            }
            git(&source, &["add", "--", "."])?;
            git(&source, &["commit", "-m", "wide_history_marker"])?;
        }
        if case == Case::Unreadable {
            fs::remove_file(source.join(".git/HEAD"))?;
        }
        let project = se_types::ProjectId::from_parts(1, [42; 10])?;
        let root = RootId::from_parts(1, [43; 10])?;
        let home = base.join("atlas");
        let directory = source.join(".git");
        let identity = se_proc::NativeSourceRoot::open(&directory)?.physical_identity()?;
        let registration = RootRegistration {
            project: project.clone(),
            root: root.clone(),
            canonical_source_root: source,
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(root.as_str()),
            },
            git_metadata: Some(GitMetadataRegistration {
                physical_git_directory: directory.clone(),
                physical_common_directory: directory,
                git_directory_identity: identity,
                common_directory_identity: identity,
            }),
        };
        let policy = AtlasPolicy {
            enabled: true,
            max_files: 64,
            max_change_rows: 50_000,
            change_retention_days: 30,
            max_cache_bytes: 512_000_000,
            total_reserved_bytes: 2_000_000,
            parse: ParseBudget {
                max_source_bytes: 524288,
                max_rows: 65536,
                max_work: Duration::from_millis(200),
                reserved_bytes: 1_000_000,
            },
            ignore: IgnorePolicy {
                global_patterns: Vec::new(),
                generated_prefixes: Vec::new(),
                digest: ContentHash([0; 32]),
            },
            watch: WatchBudget {
                max_directories: 0,
                max_mapping_bytes: 0,
                observed_os_limit: None,
            },
        };
        let mut controller = Controller::new(NativeRuntime::new(
            home.clone(),
            std::env::current_exe()?,
            NativeRenewal::new(Vec::new())?,
            if case == Case::Unqualified {
                None
            } else {
                Some(SqlProfile::from_qualified_overhead(93_702)?)
            },
        )?);
        controller.register(registration.clone(), policy)?;
        controller.activate(root.clone(), ReconcileReason::FirstSession)?;
        if let NextWork::AfterEventDebounce(wait) = controller.next_work() {
            std::thread::sleep(wait);
        }
        println!("owner={} phase=before-cold", std::process::id());
        controller.work_quantum(Duration::from_millis(200))?;
        drive_child(&mut controller)?;
        let parser = controller
            .runtime()
            .child_pid()
            .ok_or("parser did not start")?;
        println!("parser={parser}");
        let deadline = end();
        while controller.runtime().child_pid().is_some() {
            if Instant::now() >= deadline {
                return Err("cold history consumer deadline".into());
            }
            controller
                .runtime_mut()
                .wait_child_ready(Instant::now() + Duration::from_millis(100))?;
            drive_child(&mut controller)?;
        }
        assert!(
            !Path::new(&format!("/proc/{parser}")).exists(),
            "parser was not exactly reaped"
        );
        let summary = controller.summary(&root)?;
        if let IndexState::Suspended { reason } = summary.state {
            return Err(se_types::SeError::from(reason).into());
        }
        println!("owner={} phase=adopted", std::process::id());
        assert!(
            summary.epoch.is_some(),
            "successful source parser has no published epoch"
        );
        if !bounded {
            let error = summary
                .coverage
                .history_unavailable
                .as_ref()
                .ok_or("history failure diagnostic absent")?;
            let text = se_types::SeError::from(error.clone()).to_string();
            let expected = match case {
                Case::Wide => "exceeds 32 changed paths",
                Case::Unqualified => "requires measured host SQL overhead",
                Case::Unreadable => "HEAD is absent",
                Case::Bounded => panic!("bounded fixture reached unavailable-history assertions"),
            };
            assert!(text.contains(expected), "wrong history failure: {text}");
            assert!(
                summary
                    .coverage
                    .reasons
                    .contains(&CoverageReason::HistoryUnavailable)
            );
        }
        let source = NativeAtlasSource::open(registration, CaseMode::Sensitive)?;
        // A reconciled/legacy source snapshot may say Current while its Git
        // seed still has an older continuation. Reads must keep that limit.
        let legacy = NativeAtlasCache::create(&home, source.scope.clone())?;
        let mut writer = CacheConnection::open(
            &legacy,
            CacheIdentity {
                scope: source.scope.clone(),
                epoch: summary.epoch.clone().ok_or("epoch absent")?,
            },
            ConnectionRole::HostWriter,
            &SqlProfile::from_qualified_overhead(93_702)?,
            end(),
        )?
        .ok_or("legacy writer absent")?;
        writer.write(131072, end(), |sql| {
            sql.prepare("UPDATE meta SET state_json='\"Current\"' WHERE singleton=1")?
                .execute([])
                .map_err(|e| se_types::SeError::invalid("legacy source state", &e.to_string()))?;
            Ok(())
        })?;
        let mut scan = se_atlas::coverage::CoverageScan::default();
        while !scan.step(&mut writer, end())? {}
        let mut scanned = summary.coverage.clone();
        scan.apply(&mut scanned)?;
        assert!(
            scanned.reasons.contains(&expected_reason),
            "source reconciliation erased the independent Git bound"
        );
        writer.write(131072, end(), |sql| {
            sql.prepare("UPDATE meta SET coverage_json=?1 WHERE singleton=1")?
                .execute([serde_json::to_string(&scanned).map_err(|e| {
                    se_types::SeError::invalid("refreshed coverage", &e.to_string())
                })?])
                .map_err(|e| se_types::SeError::invalid("refreshed coverage", &e.to_string()))?;
            Ok(())
        })?;
        drop(writer);
        drop(legacy);
        let cache = NativeAtlasCache::open(&home, source.scope.clone())?.ok_or("cache absent")?;
        let mut current = pointer::open_current(
            &cache,
            &source.scope,
            ConnectionRole::ExternalReader,
            &SqlProfile::contained_cold(),
            end(),
        )?
        .ok_or("pointer absent")?;
        assert!(!current.epoch_retired);
        assert_eq!(
            count(&mut current.connection, "SELECT count(*) FROM commits")?,
            if bounded { 3 } else { 0 }
        );
        assert_eq!(
            count(
                &mut current.connection,
                "SELECT count(*) FROM commits WHERE subject='secret_only_marker'"
            )?,
            0
        );
        assert_eq!(
            count(
                &mut current.connection,
                "SELECT count(*) FROM files WHERE path='.env'"
            )?,
            0
        );
        let bound: Option<String> = current.connection.read(end(), |sql| {
            sql.prepare("SELECT history_bound FROM record_feed")?
                .query_row([], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("history bound", &e.to_string()))
        })?;
        if bounded {
            let bound: se_atlas::history::HistoryBound =
                serde_json::from_str(&bound.ok_or("history bound absent")?)?;
            assert_eq!(bound.limit, se_atlas::history::HistoryLimit::CommitCount);
            assert!(
                bound.next.is_some(),
                "the partial seed hid its continuation"
            );
        } else {
            assert!(
                bound.is_none(),
                "unavailable history fabricated a successful cursor"
            );
        }
        assert_eq!(
            count(&mut current.connection, "SELECT count(*) FROM files")?,
            if case == Case::Wide { 34 } else { 1 },
            "source files did not publish independently"
        );
        assert_eq!(
            count(&mut current.connection, "SELECT count(*) FROM changes")?,
            0,
            "cold history fabricated edits"
        );
        let touches = count(
            &mut current.connection,
            "SELECT count(*) FROM touches WHERE target_kind='file'",
        )?;
        if bounded {
            assert!(touches > 0, "Git seed did not reach file ranking");
        } else {
            assert_eq!(touches, 0, "unavailable history fabricated file activity");
        }
        use se_types::code::{
            AtlasValidation, FindQuery, SearchKind, SearchMode, SearchOrder, SearchScope,
        };
        let _clock = super::test_clock::control();
        let mut reader = se_atlas::query::QueryReader::new(
            &mut current.connection,
            se_atlas::query::ReaderContext {
                memory: None,
                viewer: AtlasPrincipal::Human(se_types::HumanId::from_parts(1, [44; 10])?),
                records: &NoRecords,
                source: Some(&source),
                hostless: false,
                epoch_retired: false,
                now_unix_ms: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)?
                        .as_millis()
                        .try_into()?,
                ),
                record_feed_current: true,
            },
        );
        let found = reader.find(&FindQuery {
            query: QueryText::new("native_history_marker_4")?,
            kind: SearchKind::Commit,
            scope: SearchScope {
                paths: Vec::new(),
                languages: Vec::new(),
            },
            next: None,
            budget: se_types::code::Validate.query_budget(10, 16384)?,
            mode: Some(SearchMode::Literal),
            order: SearchOrder::Relevance,
            full: false,
            regex: false,
        })?;
        assert!(
            found.index.coverage.reasons.contains(&expected_reason),
            "bounded history disappeared from production query coverage"
        );
        assert!(
            matches!(&found.data, se_types::Read::Present { value } if !value.page.window().complete()),
            "partial Git history was advertised as complete"
        );
        assert!(
            matches!(&found.data, se_types::Read::Present { value } if value.page.items().len()==usize::from(bounded)),
            "production commit reader did not decode the real Git seed"
        );
        assert_eq!(
            found.index.coverage.history_unavailable, summary.coverage.history_unavailable,
            "query reader lost the durable history diagnostic"
        );
        let source_hit = reader.find(&FindQuery {
            query: QueryText::new("history_4")?,
            kind: SearchKind::Symbol,
            scope: SearchScope {
                paths: Vec::new(),
                languages: Vec::new(),
            },
            next: None,
            budget: se_types::code::Validate.query_budget(10, 16384)?,
            mode: Some(SearchMode::Literal),
            order: SearchOrder::Relevance,
            full: false,
            regex: false,
        })?;
        assert!(
            matches!(source_hit.data, se_types::Read::Present { value } if value.page.items().len()==1),
            "production reader cannot use the successfully parsed source"
        );
        drop(current);
        drop(cache);
        assert!(
            fs::read_dir(&base)?.all(|entry| entry.is_ok_and(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".se-atlas-git-"))),
            "private Git control remained"
        );
        controller.close(root, CloseReason::HostDrain, Duration::from_secs(2))?;
        fs::remove_dir_all(&base)?;
        println!(
            "PASS {case:?}: real parser reaped, source epoch/query usable, optional history limitation and diagnostic retained"
        );
        Ok(())
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|v| v == "--list") {
        if !std::env::args().any(|v| v == "--ignored") {
            println!("atlas_cold_history_dev: test");
        }
        return Ok(());
    }
    #[cfg(all(target_os = "linux", not(debug_assertions)))]
    native::run()?;
    #[cfg(not(all(target_os = "linux", not(debug_assertions))))]
    println!("0 passed; 0 failed; 1 skipped (requires native Linux release image)");
    Ok(())
}
