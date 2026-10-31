#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use std::time::Duration;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
#[allow(
    dead_code,
    reason = "Only native host construction is needed by backup consumers."
)]
mod host_fixture;
use host_fixture::host;

/// Protects: E3 — unbound directory/publication ports never produce a successful backup or clean-close receipt.
#[test]
fn unavailable_native_ports_refuse_and_release_backup_reservations() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let context = host.backup_context();
    let head = host.info()?.head;
    for _ in 0..2 {
        let error = SqliteFactory::backup(
            &f.options,
            lease.clone(),
            context.clone(),
            Duration::from_secs(2),
        )
        .err()
        .ok_or("unwired backup succeeded")?;
        assert_eq!(error.code, StoreErrorCode::BackupFailed);
        assert!(
            error.cause.contains("directory preparation is not wired"),
            "{}",
            error.cause
        );
    }
    assert_eq!(host.info()?.head, head);
    assert!(!f.options.state_directory.join("backups").try_exists()?);
    let error = host
        .close_clean(&*lease, Duration::from_secs(2))
        .err()
        .ok_or("unwired clean close succeeded")?;
    assert_eq!(error.code, StoreErrorCode::BackupFailed);
    let reopened = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    assert_eq!(reopened.info()?.head, head);
    Ok(())
}

/// Protects: E3 — backup shares the finite read-slot limit and refuses wrong generation/home before filesystem publication.
#[test]
fn backup_budget_and_context_fences_do_not_leak_read_slots() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let context = host.backup_context();
    let a = host.snapshot(f.scoped(Visibility::Owner))?;
    let b = host.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        SqliteFactory::backup(
            &f.options,
            lease.clone(),
            context.clone(),
            Duration::from_secs(2)
        )
        .err()
        .ok_or("third reader admitted")?
        .code,
        StoreErrorCode::Backpressure
    );
    drop(a);
    drop(b);
    lease.identity.lock().map_err(|_| "lease mutex")?.generation = 2;
    assert_eq!(
        SqliteFactory::backup(
            &f.options,
            lease.clone(),
            context.clone(),
            Duration::from_secs(2)
        )
        .err()
        .ok_or("wrong generation admitted")?
        .code,
        StoreErrorCode::GenerationChanged
    );
    lease.identity.lock().map_err(|_| "lease mutex")?.generation = 1;
    let wrong = StoreOptions {
        state_directory: f.home.join("other-state"),
        busy_timeout: Duration::from_secs(1),
    };
    assert_eq!(
        SqliteFactory::backup(
            &wrong,
            lease.clone(),
            context.clone(),
            Duration::from_secs(2)
        )
        .err()
        .ok_or("wrong home admitted")?
        .code,
        StoreErrorCode::GenerationChanged
    );
    assert_eq!(
        SqliteFactory::backup(&f.options, lease.clone(), context, Duration::ZERO)
            .err()
            .ok_or("zero deadline admitted")?
            .code,
        StoreErrorCode::BackupFailed
    );
    let a = host.snapshot(f.scoped(Visibility::Owner))?;
    let b = host.snapshot(f.scoped(Visibility::Owner))?;
    drop((a, b));
    Ok(())
}
