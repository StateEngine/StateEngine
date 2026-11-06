//! Development integration exercise. Synthetic capacity profiles exercise the
//! algorithm only; they are NOT measured admission profiles or B4 evidence.
use se_atlas::{
    cache::{connection::*, *},
    lifecycle::*,
    model::*,
    parse::*,
    resolve::{self, catalog::SqlCatalog},
    scope::Scope,
    source::RegisteredSource,
    update::{batch, file, observation},
};
use se_host::{atlas_cache::NativeAtlasCache, atlas_source::NativeAtlasSource};
use se_types::code::AtlasText;
use std::{
    error::Error,
    fs,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[path = "atlas_ingest_dev/counts.rs"]
mod counts;
#[path = "atlas_ingest_dev/coverage.rs"]
mod coverage_scan;
#[path = "atlas_ingest_dev/exclusion.rs"]
mod exclusion;
type Check = Result<(), Box<dyn Error>>;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn budget() -> ParseBudget {
    ParseBudget {
        max_source_bytes: 524288,
        max_rows: 4096,
        max_work: Duration::from_millis(200),
        reserved_bytes: 16_000_000,
    }
}
fn ingest(
    source: &RegisteredSource<NativeAtlasSource>,
    db: &CacheConnection<'_>,
    parser: &mut SemanticParser,
    path: &RelativePath,
    language: Language,
    cold: bool,
    serial: u64,
) -> Check {
    let SourceRead::Bytes(snapshot) = source.read(path, budget())? else {
        return Err("source not read".into());
    };
    let mut parsed = parser.parse(&snapshot, language, budget())?;
    db.read(deadline(), |sql| {
        resolve::resolve(
            &mut parsed,
            path,
            &mut SqlCatalog {
                sql,
                deadline: deadline(),
            },
            deadline(),
        )
        .map(|_| ())
    })?;
    assert_eq!(source.verify(&snapshot)?, SourceVerification::Unchanged);
    db.write(2_000_000, deadline(), |sql| {
        if !cold {
            batch::begin(sql, serial, BulkReason::FilesystemBurst, false)?;
        }
        file::apply(sql, &source.scope, &snapshot, &parsed, cold, serial)?;
        if !cold {
            batch::publish(sql, 1000 + serial as i64, false)?;
        }
        Ok(())
    })?;
    counts::check(db)?;
    Ok(())
}
#[test]
fn complete_file_stale_recovery_and_publication() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let dir = std::env::temp_dir().join(format!(
        "atlas-ingest-dev-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let project = se_types::ProjectId::from_parts(1, [1; 10])?;
    let root = RootId::from_parts(1, [2; 10])?;
    let home = dir.join("atlas");
    let registration = RootRegistration {
        project: project.clone(),
        root: root.clone(),
        canonical_source_root: dir.clone(),
        cache: CacheLocation {
            directory: home.join(project.as_str()).join(root.as_str()),
        },
        git_metadata: None,
    };
    let source = NativeAtlasSource::open(registration, CaseMode::Sensitive)?;
    let scope: Scope = source.scope.clone();
    let cache = NativeAtlasCache::create(&home, scope.clone())?;
    let coverage: Coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":false,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":false,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: scope.clone(),
            epoch: CacheEpoch::from_parts(1, [4; 10])?,
        },
        extractor_version: "development".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state: IndexState::Updating {
            pending_files: 1,
            pending_change_batches: 0,
            discovery_complete: false,
        },
    };
    let sql_profile = SqlProfile::from_qualified_overhead(1)?;
    let db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &sql_profile,
        deadline(),
    )?;
    let mut parser = SemanticParser::cold_child(
        scope.clone(),
        [
            Language::JavaScript,
            Language::Jsx,
            Language::TypeScript,
            Language::Tsx,
            Language::Rust,
            Language::Python,
        ]
        .into_iter()
        .map(|language| {
            ParserProfile::from_qualified_measurement(
                language,
                ParserPlacement::ColdChild,
                524288,
                4096,
                4_000_000,
                8_000_000,
            )
        })
        .collect::<se_atlas::errors::AtlasResult<Vec<_>>>()?,
    )?;
    let path = RelativePath::new("a.js")?;
    for (index, body) in [
        "export function f(){return 1;} f();",
        "export function f(){return 2;} f();",
        "export function f( {",
        "export function f(){return 3;} f();",
    ]
    .iter()
    .enumerate()
    {
        fs::write(dir.join("a.js"), body)?;
        ingest(
            &source,
            &db,
            &mut parser,
            &path,
            Language::JavaScript,
            index == 0,
            index as u64,
        )?;
        let reader = CacheConnection::open(
            &cache,
            seed.identity.clone(),
            ConnectionRole::ExternalReader,
            &sql_profile,
            deadline(),
        )?
        .ok_or("reader missing")?;
        reader.read(deadline(), |sql| {
            let count: i64 = sql
                .prepare("SELECT count(*) FROM symbols")?
                .query_row([], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
            assert!(count >= 2, "no retained semantic baseline");
            let coverage: String = sql
                .prepare("SELECT coverage_json FROM files")?
                .query_row([], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
            if index == 2 {
                assert!(coverage.contains("Stale"), "{coverage}");
            } else {
                assert_eq!(coverage, "\"Indexed\"");
            }
            let changes: i64 = sql
                .prepare("SELECT count(*) FROM changes")?
                .query_row([], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
            if index == 0 {
                assert_eq!(changes, 0);
            }
            if index == 3 {
                let reset: i64 = sql
                    .prepare(
                        "SELECT count(*) FROM changes WHERE baseline_reset=1 AND kind='FileOnly'",
                    )?
                    .query_row([], |r| r.get(0))
                    .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
                assert_eq!(reset, 1);
            }
            Ok(())
        })?;
    }
    // A real source refusal preserves the baseline and unknown observations.
    fs::remove_file(dir.join("a.js"))?;
    fs::create_dir(dir.join("a.js"))?;
    let failure = source
        .read(&path, budget())
        .err()
        .ok_or("directory was accepted as source")?;
    db.write(2_000_000, deadline(), |sql| {
        observation::unparsed(
            sql,
            &scope,
            &path,
            Some(Language::JavaScript),
            observation::UnparsedObservation::Failed(&failure.body),
            10,
        )
        .map(|_| ())
    })?;
    counts::check(&db)?;
    let reader = CacheConnection::open(
        &cache,
        seed.identity.clone(),
        ConnectionRole::ExternalReader,
        &sql_profile,
        deadline(),
    )?
    .ok_or("reader absent")?;
    reader.read(deadline(), |sql| {
        let (hash, size, coverage): (Option<Vec<u8>>, Option<i64>, String) = sql
            .prepare("SELECT observed_hash,bytes,coverage_json FROM files WHERE path='a.js'")?
            .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
        assert_eq!(hash, None);
        assert_eq!(size, None);
        assert!(coverage.contains("Stale"));
        Ok(())
    })?;
    drop(reader);
    fs::remove_dir(dir.join("a.js"))?;
    fs::write(dir.join("a.js"), "export function f(){return 4;} f();")?;
    ingest(
        &source,
        &db,
        &mut parser,
        &path,
        Language::JavaScript,
        false,
        11,
    )?;
    fs::remove_file(dir.join("a.js"))?;
    assert!(matches!(source.read(&path, budget())?, SourceRead::Removed));
    db.write(2_000_000, deadline(), |sql| {
        batch::begin(sql, 12, BulkReason::FilesystemBurst, false)?;
        assert!(observation::removed(sql, &scope, &path, false, 12)?);
        batch::publish(sql, 1012, false)?;
        Ok(())
    })?;
    counts::check(&db)?;
    let cases = [
        (
            Language::JavaScript,
            "late.js",
            "caller.js",
            "export function target(){return 1;}",
            "import {target as t} from './late.js'; t();",
        ),
        (
            Language::Jsx,
            "late.jsx",
            "caller.jsx",
            "export function target(){return 1;}",
            "import {target as t} from './late.jsx'; t();",
        ),
        (
            Language::TypeScript,
            "late.ts",
            "caller.ts",
            "export function target(){return 1;}",
            "import {target as t} from './late.ts'; t();",
        ),
        (
            Language::Tsx,
            "late.tsx",
            "caller.tsx",
            "export function target(){return 1;}",
            "import {target as t} from './late.tsx'; t();",
        ),
        (
            Language::Rust,
            "src/late.rs",
            "src/lib.rs",
            "pub fn target()->u32 {1}",
            "use crate::late::target as t; pub fn caller(){t(); crate::late::target();}",
        ),
        (
            Language::Python,
            "late.py",
            "caller.py",
            "def target():\n    return 1\n",
            "from late import target as t\nt()\n",
        ),
    ];
    fs::create_dir(dir.join("src"))?;
    for (language, target, importer, target_body, importer_body) in cases {
        let importer = RelativePath::new(importer)?;
        fs::write(dir.join(importer.as_str()), importer_body)?;
        ingest(&source, &db, &mut parser, &importer, language, true, 20)?;
        fs::write(dir.join(target), target_body)?;
        ingest(
            &source,
            &db,
            &mut parser,
            &RelativePath::new(target)?,
            language,
            true,
            21,
        )?;
        let reader = CacheConnection::open(
            &cache,
            seed.identity.clone(),
            ConnectionRole::ExternalReader,
            &sql_profile,
            deadline(),
        )?
        .ok_or("reader absent")?;
        reader.read(deadline(), |sql| {
            let queued: bool = sql
                .prepare("SELECT EXISTS(SELECT 1 FROM pending_paths WHERE path_key=?1)")?
                .query_row([importer.as_str()], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
            assert!(queued, "missing {language:?} importer repair");
            Ok(())
        })?;
        ingest(&source, &db, &mut parser, &importer, language, false, 22)?;
        reader.read(deadline(),|sql| {
            let resolved:i64=sql.prepare("SELECT count(*) FROM refs r JOIN files f ON f.id=r.file WHERE f.path=?1 AND r.accuracy='ExplicitImport' AND r.target IS NOT NULL")?.query_row([importer.as_str()],|r|r.get(0)).map_err(|e|se_types::SeError::invalid("development SQL",&e.to_string()))?;
            assert!(resolved>0,"unresolved {language:?} import");
            let removed:i64=sql.prepare("SELECT count(*) FROM files WHERE path='a.js'")?.query_row([],|r|r.get(0)).map_err(|e|se_types::SeError::invalid("development SQL",&e.to_string()))?;
            assert_eq!(removed,0);Ok(())
        })?;
    }
    // Actual mutual imports converge after one byte-identical repair. Clearing
    // this fixture's old queue isolates propagation from the earlier cases.
    let cycle_a = RelativePath::new("cycle-a.js")?;
    let cycle_b = RelativePath::new("cycle-b.js")?;
    fs::write(
        dir.join(cycle_a.as_str()),
        "import {b} from './cycle-b.js'; export function a(){return b();}",
    )?;
    fs::write(
        dir.join(cycle_b.as_str()),
        "import {a} from './cycle-a.js'; export function b(){return a();}",
    )?;
    for (path, serial) in [
        (&cycle_a, 30),
        (&cycle_b, 31),
        (&cycle_a, 32),
        (&cycle_b, 33),
    ] {
        ingest(
            &source,
            &db,
            &mut parser,
            path,
            Language::JavaScript,
            true,
            serial,
        )?;
    }
    db.write(65536, deadline(), |sql| {
        sql.prepare("DELETE FROM pending_paths")?
            .execute([])
            .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
        Ok(())
    })?;
    fs::write(
        dir.join(cycle_a.as_str()),
        "import {b} from './cycle-b.js'; export function a(){return b()+1;}",
    )?;
    ingest(
        &source,
        &db,
        &mut parser,
        &cycle_a,
        Language::JavaScript,
        false,
        34,
    )?;
    ingest(
        &source,
        &db,
        &mut parser,
        &cycle_b,
        Language::JavaScript,
        false,
        35,
    )?;
    db.write(65536, deadline(), |sql| {
        sql.prepare("DELETE FROM pending_paths WHERE path_key='cycle-b.js' AND serial=34")?
            .execute([])
            .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
        let pending: i64 = sql
            .prepare("SELECT count(*) FROM pending_paths")?
            .query_row([], |r| r.get(0))
            .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
        assert_eq!(
            pending, 0,
            "unchanged importer repair re-enqueued its mutually importing peer"
        );
        Ok(())
    })?;
    let base = RelativePath::new("export-base.js")?;
    let barrel = RelativePath::new("export-barrel.js")?;
    let user = RelativePath::new("export-user.js")?;
    fs::write(
        dir.join(base.as_str()),
        "export function target(){return 1;}",
    )?;
    fs::write(
        dir.join(barrel.as_str()),
        "export {target as relay} from './export-base.js';",
    )?;
    fs::write(
        dir.join(user.as_str()),
        "import {relay} from './export-barrel.js'; relay();",
    )?;
    for (path, serial) in [(&base, 40), (&barrel, 41), (&user, 42)] {
        ingest(
            &source,
            &db,
            &mut parser,
            path,
            Language::JavaScript,
            true,
            serial,
        )?;
    }
    db.write(65536, deadline(), |sql| {
        sql.prepare("DELETE FROM pending_paths")?
            .execute([])
            .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
        Ok(())
    })?;
    fs::write(dir.join(base.as_str()), "export const target=2;")?;
    ingest(
        &source,
        &db,
        &mut parser,
        &base,
        Language::JavaScript,
        false,
        43,
    )?;
    ingest(
        &source,
        &db,
        &mut parser,
        &barrel,
        Language::JavaScript,
        false,
        44,
    )?;
    db.read(deadline(), |sql| {
        let queued: bool = sql
            .prepare("SELECT EXISTS(SELECT 1 FROM pending_paths WHERE path_key='export-user.js')")?
            .query_row([], |r| r.get(0))
            .map_err(|e| se_types::SeError::invalid("development SQL", &e.to_string()))?;
        assert!(
            queued,
            "unchanged re-export text hid its changed target binding"
        );
        Ok(())
    })?;
    ingest(
        &source,
        &db,
        &mut parser,
        &user,
        Language::JavaScript,
        false,
        45,
    )?;
    db.read(deadline(),|sql| {
        let resolved:i64=sql.prepare("SELECT count(*) FROM refs r JOIN files f ON f.id=r.file JOIN symbols s ON s.id=r.target WHERE f.path='export-user.js' AND r.accuracy='ExplicitImport' AND s.kind='Variable'")?.query_row([],|r|r.get(0)).map_err(|e|se_types::SeError::invalid("development SQL",&e.to_string()))?;
        assert!(resolved>0,"re-export repair did not reach the replacement symbol");
        Ok(())
    })?;
    let split = RelativePath::new("split.js")?;
    fs::write(
        dir.join(split.as_str()),
        "export function getHTTPResponse2_id(){return 1;}",
    )?;
    ingest(
        &source,
        &db,
        &mut parser,
        &split,
        Language::JavaScript,
        true,
        46,
    )?;
    db.read(deadline(), |sql| {
        for query in ["split_name:HTTP", "split_name:gHR2i"] {
            let matches: i64 = sql
                .prepare("SELECT count(*) FROM symbol_fts WHERE symbol_fts MATCH ?1")?
                .query_row([query], |r| r.get(0))
                .map_err(|e| se_types::SeError::invalid("development FTS", &e.to_string()))?;
            assert!(
                matches > 0,
                "writer did not index the shared identifier tokens: {query}"
            );
        }
        Ok(())
    })?;
    exclusion::exercise(&source, &db, &mut parser, &dir)?;
    counts::check(&db)?;
    counts::rank_and_touch_absence(&db)?;
    coverage_scan::exercise(&db, &seed.coverage)?;
    drop(db);
    drop(cache);
    drop(source);
    // This exact private fixture contains only files created by this test.
    fs::remove_dir_all(&dir)?;
    Ok(())
}
