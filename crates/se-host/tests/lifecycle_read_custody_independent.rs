//! Protects: lifecycle reads close snapshots, observe committed writes, and
//! retain the host's original native database identity across reused checkouts.
#![cfg(all(feature = "listener", target_os = "linux"))]
#[path = "support/wave2_host_fixture.rs"]
mod support;
use se_host::{channels::ChannelTargets, *};
use se_store::*;
use std::fs;
use support::*;

fn profiles(f: &Fixture) -> Check {
    let (mut writer, lease) = direct(f)?;
    for (agent, key) in [(&f.a, "custody-profile-a"), (&f.b, "custody-profile-b")] {
        writer.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(key)?),
                vec![EventBody::ProfileSaved {
                    agent: agent.clone(),
                    profile: profile(),
                    expected: Expected::Absent,
                }],
            )?,
            &*lease,
        )?;
    }
    writer.close()?;
    Ok(())
}
fn profile() -> Profile {
    Profile {
        provider: Provider::Codex,
        model: None,
        permission: PermissionProfile::WorkspaceWrite,
        named_profile: "codex".into(),
        effort: None,
    }
}
fn selection(f: &Fixture) -> ChannelTargets {
    ChannelTargets {
        project: f.project.clone(),
        after: None,
    }
}

/// A different SQLite writer connection commits between two native Owner reads.
/// No read transaction may survive the return of the first selection page.
#[test]
fn lifecycle_selection_rereads_a_profile_committed_after_a_warm_page() -> Check {
    let f = Fixture::new()?;
    seed(&f)?;
    profiles(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host = HostedRuntime::prepare(
            initialize_host_process()?,
            start(&f)?,
            rt.handle().clone(),
            &bound()?,
        )
        .await?;
        configure_private_listener(&mut host)?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let result: Check = async {
            let channels = host.channels()?;
            for _ in 0..3 {
                let before = channels.targets(selection(&f), &bound()?).await?;
                assert!(before.items().iter().all(|row| row.profile_revision == 1));
                assert_eq!(before.items().len(), 2);
            }
            let mut changed = profile();
            changed.model = Some("fresh-model".into());
            host.execution_context()
                .writer
                .submit(f.batch(
                    f.owner_project(),
                    Some(fixture::request("custody-profile-change")?),
                    vec![EventBody::ProfileSaved {
                        agent: f.a.clone(),
                        profile: changed,
                        expected: revision(1)?,
                    }],
                )?)?
                .await?;
            for _ in 0..3 {
                let after = channels.targets(selection(&f), &bound()?).await?;
                let row = after
                    .items()
                    .iter()
                    .find(|row| row.target.agent == f.a)
                    .ok_or("updated agent absent")?;
                assert_eq!(
                    row.profile_revision, 2,
                    "warm lifecycle read retained an old snapshot"
                );
            }
            Ok(())
        }
        .await;
        stop.request();
        let report = host.serve(listener).await.finish(&bound()?).await;
        assert!(report.pending.is_empty() && report.transport_closed && report.endpoint_retired);
        result
    })
}

/// Same SQL header and owner generation are insufficient when the native file
/// behind the pathname changed; restoration must recover the original fixture.
#[test]
fn lifecycle_selection_refuses_a_replaced_database_after_warming_and_recovers() -> Check {
    let f = Fixture::new()?;
    seed(&f)?;
    profiles(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host = HostedRuntime::prepare(
            initialize_host_process()?, start(&f)?, rt.handle().clone(), &bound()?,
        ).await?;
        configure_private_listener(&mut host)?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let result: Check = async {
            let channels = host.channels()?;
            assert_eq!(channels.targets(selection(&f), &bound()?).await?.items().len(), 2);
            let path = f.options.state_directory.join("state.db");
            let original = f.options.state_directory.join("original-retained.db");
            fs::rename(&path, &original)?;
            let copied = fs::copy(&original, &path);
            let observation: Check = async {
                copied?;
                for _ in 0..3 {
                    require(channels.targets(selection(&f), &bound()?).await.is_err(),
                        "lifecycle read accepted a different native database with the same SQL header")?;
                }
                Ok(())
            }.await;
            // Restore before evaluating the observation or draining native custody.
            if path.try_exists()? { fs::remove_file(&path)?; }
            fs::rename(&original, &path)?;
            assert_eq!(channels.targets(selection(&f), &bound()?).await?.items().len(), 2);
            observation
        }.await;
        stop.request();
        let report = host.serve(listener).await.finish(&bound()?).await;
        assert!(report.pending.is_empty() && report.transport_closed && report.endpoint_retired);
        result
    })
}
