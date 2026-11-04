//! Real store reads retain a broken project row alongside usable projects.
use super::*;
use se_store::{DirectStore, Expected, Root};
use se_types::{NativePath, ProjectId};
#[path = "../../../../../se-store/tests/support/store_fixture.rs"]
mod fixture;

#[test]
fn unreadable_project_root_does_not_hide_other_projects() -> fixture::Check {
    se_proc::initialize_file_creation_owner()?;
    let f = fixture::Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    // The fixture's original project has a retained but absent root. A second
    // project has valid native metadata; both must survive the owner listing.
    let other = ProjectId::from_parts(1_700_000_000_100, [9; 10])?;
    let admission = f.admission(Scope::Project(other.clone()), Actor::Human(f.owner.clone()));
    store.append(
        f.batch(
            admission,
            None,
            vec![EventBody::ProjectRegistered {
                project: other.clone(),
                name: "Readable project".into(),
                roots: vec![Root {
                    path: NativePath::from_local(f.home.clone())?,
                    canonical_key: b"owned-readable-root".to_vec(),
                }],
                owner: f.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let admission = f.admission(Scope::Registry, Actor::Human(f.owner.clone()));
    let rows = page(&store, &admission)?;
    assert_eq!(rows.items().len(), 2);
    let broken = rows
        .items()
        .iter()
        .find(|row| row.id == f.project)
        .ok_or("broken row was hidden")?;
    assert!(broken.root.is_none());
    assert!(!broken.errors.is_empty());
    let readable = rows
        .items()
        .iter()
        .find(|row| row.id == other)
        .ok_or("readable row was hidden")?;
    assert!(readable.root.is_some() && readable.errors.is_empty());
    assert_eq!(readable.owner_unread, Some(0));
    store.close()?;
    Ok(())
}
