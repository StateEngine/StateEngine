//! Independent macOS admission measurements through production source/cache adapters.
mod measure;
mod parse;
mod sql;
use se_atlas::{model::*, scope::Scope};
use se_types::ProjectId;
use std::{
    error::Error,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn until() -> Instant {
    Instant::now() + Duration::from_secs(20)
}
fn scope(root: &Path) -> Result<Scope> {
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let native = se_proc::NativeSourceRoot::open(&source)?;
    Ok(Scope::new(
        RootRegistration {
            project: ProjectId::from_parts(1, [7; 10])?,
            root: RootId::from_parts(1, [8; 10])?,
            canonical_source_root: source,
            cache: CacheLocation {
                directory: root
                    .join("cache")
                    .join(ProjectId::from_parts(1, [7; 10])?.as_str())
                    .join(RootId::from_parts(1, [8; 10])?.as_str()),
            },
            git_metadata: None,
        },
        native.physical_identity()?,
    )?)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let root = PathBuf::from(args.get(1).ok_or("private fixture directory required")?);
    std::fs::create_dir(&root)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    se_proc::initialize_file_creation_owner()?;
    measure::install();
    let scope = scope(&root)?;
    let report = if args.get(2).map(String::as_str) == Some("sql") {
        sql::run(scope, &root)?
    } else {
        parse::run(
            scope,
            args.get(2).ok_or("grammar required")?,
            args.get(3).ok_or("pattern required")?,
        )?
    };
    println!("{}", serde_json::to_string(&report)?);
    std::fs::remove_dir_all(&root)?;
    Ok(())
}
