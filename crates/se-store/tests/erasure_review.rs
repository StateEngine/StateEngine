//! Reviewer judge: forgetting one message removes its bytes from every file the
//! store owns, keeps the neighbouring message, and refuses a mismatched approval.
use se_store::*;
use std::time::{Duration, Instant};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[allow(dead_code)]
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait_until};

const FORGOTTEN: &str = "forget-me-7f3a9c2e-synthetic-private-text";
const KEPT: &str = "keep-me-41d8b6aa-synthetic-neighbour-text";
const BUDGET: Duration = Duration::from_secs(60);

/// Reads one owned file. Windows refuses reads of the lease file and SQLite's
/// shared-memory index while they are locked (ERROR_LOCK_VIOLATION); neither
/// holds message text, so only those two may be skipped, and only for that error.
fn read_owned(path: &std::path::Path) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if cfg!(windows)
                && error.raw_os_error() == Some(33)
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name == "runtime.lock" || name.ends_with("-shm")) =>
        {
            Ok(None)
        }
        Err(error) => Err(format!("{}: {error}", path.display()).into()),
    }
}
/// Each owned copy once: the database and its WAL count as a single copy.
fn copies(files: &[String]) -> Vec<String> {
    let mut copies: Vec<String> = files
        .iter()
        .map(|path| path.strip_suffix("-wal").unwrap_or(path).to_owned())
        .collect();
    copies.sort();
    copies.dedup();
    copies
}
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
                && read_owned(&entry.path())?
                    .is_some_and(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
            {
                hits.push(entry.path().display().to_string());
            }
        }
    }
    hits.sort();
    Ok(hits)
}

#[test]
fn forget_erases_one_body_from_database_log_and_backups() -> Check {
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
    let h = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    let writer = h.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let owner = Actor::Human(f.owner.clone());
    let agent = Actor::Agent(f.a.clone());
    let deadline = || Instant::now() + BUDGET;
    let forgotten = wait_until(
        client.submit(f.send(owner.clone(), agent.clone(), message()?, FORGOTTEN, "gone")?)?,
        deadline(),
    )??;
    let kept = wait_until(
        client.submit(f.send(owner.clone(), agent, message()?, KEPT, "kept")?)?,
        deadline(),
    )??;
    assert_eq!(forgotten.state, CommitState::Committed);
    assert_eq!(kept.state, CommitState::Committed);
    drop(SqliteFactory::backup(
        &f.options,
        lease.clone(),
        writer.backup_context(),
        BUDGET,
    )?);
    let home = f.options.state_directory.clone();
    let before = files_holding(&home, FORGOTTEN.as_bytes())?;
    assert!(
        before.iter().any(|p| p.contains("backups")),
        "positive control: a pre-erasure backup holds the text in the clear: {before:?}"
    );

    let plan = wait_until(
        client.erasure_plan(vec![forgotten.primary_event.clone()])?,
        deadline(),
    )??;
    assert!(
        !plan.owned_generations.is_empty(),
        "the plan names the backup"
    );
    assert_eq!(plan.targets.len(), 1);

    let approval = |incarnation| ErasureApproval {
        erasure: plan.id,
        owner: f.owner.clone(),
        expected_incarnation: incarnation,
        buffer_witnesses: vec![],
        accept_named_residuals: true,
    };
    let refused = wait_until(client.erase(plan.clone(), approval(99))?, deadline())?;
    assert!(refused.is_err(), "a stale incarnation is refused");
    // A checkpoint may move the text between the database and its WAL at any
    // time; the database with its WAL is one copy.
    assert_eq!(
        copies(&files_holding(&home, FORGOTTEN.as_bytes())?),
        copies(&before),
        "a refused approval erases nothing"
    );
    let unconfirmed = ErasureApproval {
        accept_named_residuals: false,
        ..approval(1)
    };
    if !plan.residuals.is_empty() {
        let refused = wait_until(client.erase(plan.clone(), unconfirmed)?, deadline())?;
        assert!(refused.is_err(), "named residuals need explicit acceptance");
    }

    let report = wait_until(client.erase(plan.clone(), approval(1))?, deadline())??;
    assert!(report.cleanup_complete, "cleanup completed: {report:?}");
    assert!(report.completed_event.is_some());
    assert_eq!(
        files_holding(&home, FORGOTTEN.as_bytes())?,
        Vec::<String>::new(),
        "while the writer still runs, no owned file keeps the forgotten text"
    );
    let again = wait_until(client.erase(plan.clone(), approval(1))?, deadline())?;
    assert!(again.is_err(), "a completed erasure does not run twice");
    let replan = wait_until(
        client.erasure_plan(vec![forgotten.primary_event.clone()])?,
        deadline(),
    )?;
    assert!(replan.is_err(), "a forgotten body cannot be planned again");

    drop(wait_until(writer.drain(BUDGET), deadline())??);
    drop(lease);
    assert_eq!(
        files_holding(&home, FORGOTTEN.as_bytes())?,
        Vec::<String>::new(),
        "no owned file keeps the forgotten text"
    );
    assert!(
        !files_holding(&home, KEPT.as_bytes())?.is_empty(),
        "the neighbouring message survives"
    );
    Ok(())
}
