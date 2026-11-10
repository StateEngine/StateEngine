#![cfg(target_os = "linux")]
//! Development consumer of the real controller/runtime, retained filesystem and
//! scoped SQL ports. Synthetic parser/SQL profiles are NOT B4 qualification.
use se_atlas::{
    cache::{connection::*, *},
    controller::Controller,
    lifecycle::*,
    model::*,
    parse::{ParserPlacement, ParserProfile},
};
use se_host::{
    atlas_cache::NativeAtlasCache, atlas_renewal::NativeRenewal, atlas_runtime::NativeRuntime,
    atlas_source::NativeAtlasSource,
};
use se_types::code::AtlasText;
use std::{
    fs,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn policy(watches: u32) -> se_types::Result<AtlasPolicy> {
    Ok(AtlasPolicy {
        ignore: IgnorePolicy {
            global_patterns: vec!["*.global".into()],
            generated_prefixes: vec![RelativePath::new("generated")?],
            digest: ContentHash([0; 32]),
        },
        watch: WatchBudget {
            max_directories: watches,
            max_mapping_bytes: watches * 16,
            observed_os_limit: None,
        },
        enabled: true,
        max_files: 1000,
        parse: ParseBudget {
            max_source_bytes: 16384,
            max_rows: 512,
            max_work: Duration::from_millis(150),
            reserved_bytes: 1_000_000,
        },
        total_reserved_bytes: 2_000_000,
        change_retention_days: 30,
        max_change_rows: 50_000,
        max_cache_bytes: 512_000_000,
    })
}
fn strings(
    connection: &CacheConnection<'_>,
    query: &str,
) -> se_atlas::errors::AtlasResult<Vec<String>> {
    connection.read(deadline(), |sql| {
        let mut statement = sql.prepare(query)?;
        let mut rows = statement
            .query([])
            .map_err(|e| se_types::SeError::invalid("test SQL", &e.to_string()))?;
        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| se_types::SeError::invalid("test SQL", &e.to_string()))?
        {
            out.push(
                row.get(0)
                    .map_err(|e| se_types::SeError::invalid("test SQL", &e.to_string()))?,
            );
        }
        Ok(out)
    })
}
fn drain(
    controller: &mut Controller<NativeRuntime<NativeRenewal>>,
) -> Result<u32, Box<dyn std::error::Error>> {
    // This is the source-event-armed debounce, not an idle product timer.
    std::thread::sleep(Duration::from_millis(20));
    let mut steps = 0;
    for _ in 0..1000 {
        match controller.next_work() {
            NextWork::Ready => {
                let report =
                    se_host::atlas_renewal::drive_quantum(controller, Duration::from_millis(200))?
                        .ok_or("ready work absent")?;
                steps += 1;
                // Source work can outlast the publication delay on a busy host.
                // Leave publication to its explicit consumer even when due now.
                if !controller.work_pending(&report.root) {
                    return Ok(steps);
                }
            }
            NextWork::AfterEventDebounce(wait) if wait <= Duration::from_millis(20) => {
                std::thread::sleep(wait + Duration::from_millis(1))
            }
            NextWork::AfterEventDebounce(_) | NextWork::Park => {
                return if steps > 0 {
                    Ok(steps)
                } else {
                    Err("pending renewal did not expose executable work".into())
                };
            }
        }
    }
    Err("bounded consumer did not finish".into())
}
fn publish(controller: &mut Controller<NativeRuntime<NativeRenewal>>) -> Check {
    match controller.next_work() {
        NextWork::AfterEventDebounce(wait) => {
            assert!(wait <= Duration::from_secs(11));
            std::thread::sleep(wait + Duration::from_millis(10));
        }
        NextWork::Ready => {}
        NextWork::Park => return Err("completed source work did not arm publication".into()),
    }
    assert_eq!(controller.next_work(), NextWork::Ready);
    let report = se_host::atlas_renewal::drive_quantum(controller, Duration::from_millis(200))?
        .ok_or("source-armed publication absent")?;
    assert_eq!(report.phase, WorkPhase::Commit);
    assert_eq!(controller.next_work(), NextWork::Park);
    Ok(())
}
fn runtime(
    home: &std::path::Path,
) -> Result<NativeRuntime<NativeRenewal>, Box<dyn std::error::Error>> {
    let profiles = [Language::Rust, Language::JavaScript]
        .into_iter()
        .map(|language| {
            ParserProfile::from_qualified_measurement(
                language,
                ParserPlacement::Incremental,
                16384,
                512,
                500_000,
                200_000,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NativeRuntime::new(
        home.to_owned(),
        std::env::current_exe()?,
        NativeRenewal::new(profiles)?,
        Some(SqlProfile::from_qualified_overhead(1)?),
    )?)
}
fn retained(
    home: &std::path::Path,
    registration: &RootRegistration,
    query: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let source = NativeAtlasSource::open(registration.clone(), CaseMode::Sensitive)?;
    let cache = NativeAtlasCache::open(home, source.scope.clone())?.ok_or("cache absent")?;
    let profile = SqlProfile::from_qualified_overhead(1)?;
    let current = pointer::open_current(
        &cache,
        &source.scope,
        ConnectionRole::ExternalReader,
        &profile,
        deadline(),
    )?
    .ok_or("published cache absent")?;
    Ok(strings(&current.connection, query)?)
}
#[path = "atlas_renewal/runtime.rs"]
mod runtime_consumer;
