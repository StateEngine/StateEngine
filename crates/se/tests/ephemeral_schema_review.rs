//! Reviewer check: the native host upgrades a schema-16 store to the current
//! schema with the same catalog a fresh store has, keeps every existing agent a
//! usable saved seat, and then records and retires a temporary agent.
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use se_host::{HostedRuntime, initialize_host_process};
use se_store::*;
use support::*;

type Catalog = Vec<(String, String, Option<String>)>;

fn database(f: &Fixture) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open(f.options.state_directory.join("state.db"))
}

fn catalog(f: &Fixture) -> Result<Catalog, Box<dyn std::error::Error>> {
    let db = database(f)?;
    let rows = db
        .prepare(
            "SELECT type,name,sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

fn version(f: &Fixture) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(database(f)?.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

/// Undo exactly what schemas 18 and 17 add, leaving a schema-16 store with data.
fn schema_sixteen(f: &Fixture) -> Check {
    seed(f)?;
    database(f)?.execute_batch(
        "DROP TABLE published_turns;
         DROP INDEX principals_retired;
         ALTER TABLE principals DROP COLUMN ephemeral_ttl_seconds;
         ALTER TABLE principals DROP COLUMN ephemeral_one_shot;
         ALTER TABLE principals DROP COLUMN retired_seq;
         PRAGMA user_version=16",
    )?;
    Ok(())
}

fn run_native_host(f: &Fixture) -> Check {
    let initialized = initialize_host_process()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(f)?, rt.handle().clone(), &bound()?).await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        host.local_stop().request();
        let report = host.serve(listener).await.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "native fixture endpoint did not close",
        )
    })
}

/// Protects: 16 -> current is additive. The migrated catalog equals a fresh one,
/// existing agents stay saved seats, and the new lifecycle works afterwards.
#[test]
fn schema_sixteen_upgrades_to_the_fresh_catalog_and_keeps_saved_seats() -> Check {
    let fresh = Fixture::new()?;
    seed(&fresh)?;
    let expected = catalog(&fresh)?;
    let current = version(&fresh)?;
    assert!(current >= 17, "a fresh store is older than schema 17");

    let old = Fixture::new()?;
    schema_sixteen(&old)?;
    assert_eq!(version(&old)?, 16);
    let reader = present(SqliteFactory::open_reader(&old.options)?)?;
    assert_eq!(
        reader.info()?.schema_version,
        16,
        "a read-only open migrated"
    );
    run_native_host(&old)?;
    assert_eq!(version(&old)?, current, "the native host did not migrate");
    assert_eq!(
        catalog(&old)?,
        expected,
        "migrated and fresh catalogs differ"
    );

    let (agents, temporary): (u32, u32) = database(&old)?.query_row(
        "SELECT count(*), count(*) FILTER (WHERE retired_seq IS NOT NULL
             OR ephemeral_one_shot != 0 OR ephemeral_ttl_seconds IS NOT NULL)
         FROM principals WHERE principal_kind='agent'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((agents, temporary), (2, 0), "existing agents changed kind");

    let (mut writer, lease) = direct(&old)?;
    let owner = old.owner_project();
    let refused = writer.append(
        old.batch(
            owner.clone(),
            Some(request("retire-saved")?),
            vec![EventBody::AgentRetired {
                agent: old.a.clone(),
                reason: RetirementReason::Cancelled,
                final_session: None,
            }],
        )?,
        &*lease,
    );
    require(refused.is_err(), "a migrated saved seat was retired")?;
    let helper = agent()?;
    writer.append(
        old.batch(
            owner.clone(),
            Some(request("temporary")?),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Agent(helper.clone()),
                kind: PrincipalKind::Agent,
                owner: old.owner.clone(),
                created_by: Some(Actor::Agent(old.a.clone())),
                name: "Migrated Helper".into(),
                role: String::new(),
                ephemeral: Some(EphemeralSpec {
                    one_shot: true,
                    ttl_seconds: 60,
                }),
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    writer.append(
        old.batch(
            owner,
            Some(request("retire-temporary")?),
            vec![EventBody::AgentRetired {
                agent: helper,
                reason: RetirementReason::Cancelled,
                final_session: None,
            }],
        )?,
        &*lease,
    )?;
    writer.close()?;
    Ok(())
}
