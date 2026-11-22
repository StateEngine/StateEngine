//! A retained source answers its first identity from the open itself, and every
//! later identity, or any identity after bytes were read, from a fresh query.
#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;
use se_atlas::{
    lifecycle::{CaseMode, FileIdentity},
    model::*,
    source::RegisteredSource,
};
use se_atlas_cold::atlas_source::NativeAtlasSource;
use se_types::ProjectId;
use std::{
    fs,
    io::Read,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
fn source(
    name: &str,
) -> Result<
    (
        PathBuf,
        cleanup_directory::PrivateDirectory,
        RegisteredSource<NativeAtlasSource>,
    ),
    Box<dyn std::error::Error>,
> {
    let base = std::env::temp_dir().join(format!(
        "atlas-source-identity-{name}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&base)?;
    let owner = cleanup_directory::PrivateDirectory::for_case(base.clone());
    let root = base.join("root");
    fs::create_dir(&root)?;
    fs::write(root.join("pinned.rs"), "fn short() {}\n")?;
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: ProjectId::from_parts(1, [1; 10])?,
            root: RootId::from_parts(1, [2; 10])?,
            canonical_source_root: root.clone(),
            cache: CacheLocation {
                directory: base.join("cache"),
            },
            git_metadata: None,
        },
        CaseMode::Sensitive,
    )?;
    Ok((root, owner, source))
}
const LONGER: &str = "fn a_much_longer_body() {}\n";
fn size(identity: &FileIdentity) -> u64 {
    identity.size
}

#[test]
fn first_identity_is_the_open_baseline_and_later_ones_are_fresh() -> Check {
    let (root, owner, source) = source("baseline")?;
    let file = source
        .open(&RelativePath::new("pinned.rs")?)?
        .ok_or("pinned.rs absent")?;
    fs::write(root.join("pinned.rs"), LONGER)?;
    let first = file.identity()?;
    assert_eq!(
        size(&first),
        14,
        "the first identity was not the before-read baseline the open observed"
    );
    let later = file.identity()?;
    assert_eq!(
        size(&later),
        LONGER.len() as u64,
        "a later identity reused the open-time baseline"
    );
    assert_ne!(first, later);
    drop(file);
    drop(source);
    owner.finish(Ok(()))
}

#[test]
fn identity_after_a_read_is_never_the_open_baseline() -> Check {
    let (root, owner, source) = source("read")?;
    let mut file = source
        .open(&RelativePath::new("pinned.rs")?)?
        .ok_or("pinned.rs absent")?;
    let mut prefix = [0u8; 2];
    file.read_exact(&mut prefix)?;
    assert_eq!(&prefix, b"fn");
    fs::write(root.join("pinned.rs"), LONGER)?;
    let after_read = file.identity()?;
    assert_eq!(
        size(&after_read),
        LONGER.len() as u64,
        "an identity after reading bytes answered from the open-time baseline"
    );
    drop(file);
    drop(source);
    owner.finish(Ok(()))
}
