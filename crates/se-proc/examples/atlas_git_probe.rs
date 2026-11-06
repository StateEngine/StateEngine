//! Exercise the production bounded reader against registered local metadata.
use se_proc::{
    NativeSourceRoot,
    atlas_git::{GitRegistration, GitRepository},
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if args.len() != 4 {
        return Err(
            "usage: atlas_git_probe GIT_IMAGE GIT_DIR COMMON_DIR NEW_PRIVATE_CONTROL_DIR".into(),
        );
    }
    let registration = GitRegistration {
        git_directory: args[1].clone(),
        common_directory: args[2].clone(),
        git_identity: NativeSourceRoot::open(&args[1])?.physical_identity()?,
        common_identity: NativeSourceRoot::open(&args[2])?.physical_identity()?,
    };
    let reader = GitRepository::open(&args[0], &registration, &args[3])?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let result = if let Some(head) = reader.head()? {
        let tree = reader.root_tree(&head, deadline)?;
        let window = reader.window(&head, 4, deadline)?;
        serde_json::json!({"state":"present","head":head,"tree":tree,"commits":window.commits.len(),"paths":window.commits.iter().map(|c|c.paths.len()).sum::<usize>(),"next":window.next,"limit":format!("{:?}",window.limit)})
    } else {
        serde_json::json!({"state":"unborn"})
    };
    reader.close()?;
    println!("{result}");
    Ok(())
}
