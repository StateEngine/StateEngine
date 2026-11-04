//! Author check through the production snapshot and selector decoder.
use super::*;
use se_store::*;
use se_types::{NativePath, ProjectId};
#[path = "../../../../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[test]
fn bad_project_is_counted_without_hiding_readable_projects() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let good = ProjectId::from_parts(1_700_000_100_000, [9; 10])?;
    direct.append(
        f.batch(
            f.admission(Scope::Project(good.clone()), Actor::Human(f.owner.clone())),
            None,
            vec![EventBody::ProjectRegistered {
                project: good.clone(),
                name: "Readable project".into(),
                roots: vec![Root {
                    path: NativePath::from_local(f.home.clone())?,
                    canonical_key: f.home.to_string_lossy().as_bytes().to_vec(),
                }],
                owner: f.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let mut read = direct.snapshot(ReadScope {
        admission: f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        visibility: Visibility::Owner,
    })?;
    let deadline = crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(5),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })?;
    let result = projects(
        &mut read,
        api::PageRequest {
            limit: 100,
            max_bytes: 65536,
            after: None,
        },
        &deadline,
    )
    .map_err(|e| format!("{e:?}"))?;
    let api::Read::Present { value } = result else {
        return Err("catalog was not present".into());
    };
    assert_eq!(value.items.len(), 1);
    assert_eq!(value.items[0].id.0, good.as_str());
    assert_eq!(value.window.returned, 1);
    assert_eq!(value.window.unreadable, 1);
    assert!(!value.window.complete);
    assert_eq!(value.window.stop_reason, api::StopReason::Unreadable);
    assert!(value.next.is_none());
    read.close()?;
    Ok(())
}
