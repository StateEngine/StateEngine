//! Development attribution through the host's actual pooled-read and writer ports.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use serde_json::json;
use std::{
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
#[path = "support/store_fixture.rs"]
mod fixture;
#[path = "support/host_fixture.rs"]
mod host_fixture;
#[path = "support/native_read_identity.rs"]
mod native;
use fixture::*;
use host_fixture::{host, options, wait};

static NATIVE: Mutex<Vec<f64>> = Mutex::new(Vec::new());
struct TimedIdentity(Box<dyn ReadConnectionIdentity>);
impl ReadConnectionIdentity for TimedIdentity {
    fn validate(&self, path: &Path) -> StoreResult<()> {
        let started = Instant::now();
        let result = self.0.validate(path);
        NATIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(started.elapsed().as_secs_f64() * 1000.0);
        result
    }
}
fn identity(path: &Path) -> StoreResult<Box<dyn ReadConnectionIdentity>> {
    Ok(Box::new(TimedIdentity(native::open_identity(path)?)))
}
#[test]
fn measure_pooled_reads_beside_real_commits() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(64)?, lease.clone())?;
    let client = writer.client();
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let pool = reader.phase_pool(identity)?;
    let mut cohorts = serde_json::Map::new();
    for mode in ["idle", "committing"] {
        let mut rows = Vec::new();
        NATIVE
            .lock()
            .map_err(|_| "native timing lock poisoned")?
            .clear();
        for n in 0..100 {
            let key = format!("read-attribution-{mode}-{n}");
            let mut committed = None;
            if mode == "committing" {
                committed = Some(wait(client.submit(f.send(
                    Actor::Agent(f.a.clone()),
                    Actor::Agent(f.b.clone()),
                    message()?,
                    "finite observer message",
                    &key,
                )?)?)??);
            }
            let started = Instant::now();
            let phase = pool.read_phase()?;
            let checkout_ms = started.elapsed().as_secs_f64() * 1000.0;
            let started = Instant::now();
            present(phase.runtime_owner()?)?;
            let owner_ms = started.elapsed().as_secs_f64() * 1000.0;
            let started = Instant::now();
            let mut read = phase.into_snapshot(f.self_scope(&f.a))?;
            if let Some(original) = committed {
                let retained = present(
                    read.operation_receipt(Actor::Agent(f.a.clone()), request(&key)?.key)?,
                )?;
                if retained.events != original.events {
                    return Err("readback differs from committed write".into());
                }
            }
            let receipt_ms = started.elapsed().as_secs_f64() * 1000.0;
            let started = Instant::now();
            read.close()?;
            let close_ms = started.elapsed().as_secs_f64() * 1000.0;
            rows.push(json!({"checkout_ms":checkout_ms,"owner_ms":owner_ms,"receipt_ms":receipt_ms,"close_ms":close_ms}));
        }
        let native = NATIVE
            .lock()
            .map_err(|_| "native timing lock poisoned")?
            .clone();
        cohorts.insert(
            mode.into(),
            json!({"samples":rows,"native_validation_ms":native}),
        );
    }
    pool.close()?;
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    let report = json!({"platform":std::env::consts::OS,"cohorts":cohorts});
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    std::fs::create_dir_all(&out)?;
    std::fs::write(
        out.join("native-read-phase.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
