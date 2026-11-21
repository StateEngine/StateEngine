//! Reviewer judge: a restore keeps the replaced store under `preserved/`; a later
//! forget must erase that copy too, or name it among the copies it leaves.
use se_store::*;
use std::time::{Duration, Instant};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[allow(dead_code)]
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait_until};

const SECRET: &str = "restore-then-forget-5c1e88d0-synthetic-private-text";
const BUDGET: Duration = Duration::from_secs(60);

fn files_holding(
    root: &std::path::Path,
    needle: &[u8],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut hits = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file()
                && std::fs::read(entry.path())?
                    .windows(needle.len())
                    .any(|w| w == needle)
            {
                hits.push(entry.path().display().to_string());
            }
        }
    }
    hits.sort();
    Ok(hits)
}

#[test]
fn forget_after_restore_leaves_no_unnamed_preserved_copy() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    drop(h);
    drop(lease);
    let lease = Lease::acquire_with_backup_ports(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
        true,
    )?;
    let deadline = || Instant::now() + BUDGET;
    let h = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    let writer = h.start_writer(options(256)?, lease.clone())?;
    let sent = wait_until(
        writer.client().submit(f.send(
            Actor::Human(f.owner.clone()),
            Actor::Agent(f.a.clone()),
            message()?,
            SECRET,
            "secret",
        )?)?,
        deadline(),
    )??;
    let backup = SqliteFactory::backup(&f.options, lease.clone(), writer.backup_context(), BUDGET)?;
    drop(wait_until(writer.drain(BUDGET), deadline())??);

    let admission = f.admission(Scope::Registry, Actor::Human(f.owner.clone()));
    let restored = SqliteFactory::restore_backup(
        &f.options,
        backup.published.clone(),
        &request("restore")?,
        f.store.clone(),
        &admission,
        &*lease,
    )?;
    let home = f.options.state_directory.clone();
    assert!(
        files_holding(&home, SECRET.as_bytes())?
            .iter()
            .any(|p| p.contains("preserved")),
        "positive control: the replaced store is preserved with the text"
    );
    let incarnation: i64 = rusqlite::Connection::open(home.join("state.db"))?.query_row(
        "SELECT incarnation FROM store_info WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let writer = restored.host.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let plan = wait_until(
        client.erasure_plan(vec![sent.primary_event.clone()])?,
        deadline(),
    )??;
    let report = wait_until(
        client.erase(
            plan.clone(),
            ErasureApproval {
                erasure: plan.id,
                owner: f.owner.clone(),
                expected_incarnation: u64::try_from(incarnation)?,
                buffer_witnesses: vec![],
                accept_named_residuals: true,
            },
        )?,
        deadline(),
    )??;
    assert!(report.cleanup_complete, "cleanup completed: {report:?}");
    drop(wait_until(writer.drain(BUDGET), deadline())??);
    let left = files_holding(&home, SECRET.as_bytes())?;
    let named = plan.residuals.iter().any(|r| {
        r.location
            .to_local()
            .is_ok_and(|p| p.starts_with(home.join("preserved")))
    });
    assert!(
        left.is_empty() || named,
        "forget reported success but these files keep the text and no residual names them: {left:?}"
    );
    Ok(())
}
