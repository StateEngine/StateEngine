//! Named workspace permission for Git without a second command service.
use super::error;
#[cfg(test)]
use crate::test_directory as cleanup_directory;
use se_types::Result;
use std::{io::ErrorKind, path::PathBuf};

pub(super) fn roots(workspace: PathBuf, git_write: bool) -> Result<Vec<PathBuf>> {
    if !git_write {
        return Ok(vec![workspace]);
    }
    let workspace =
        se_proc::canonicalize_path(&workspace).map_err(|cause| error("Git workspace", cause))?;
    let metadata = workspace.join(".git");
    let info = std::fs::symlink_metadata(&metadata)
        .map_err(|cause| error("Git workspace metadata", cause))?;
    if !info.is_dir()
        || info.file_type().is_symlink()
        || se_proc::canonicalize_path(&metadata)
            .map_err(|cause| error("Git workspace metadata", cause))?
            != metadata
    {
        return Err(error(
            "Git workspace permission",
            "use a dedicated clone with a physical .git directory; linked or shared worktree metadata is not authorized",
        ));
    }
    for path in [metadata.join("commondir"), metadata.join("worktrees")] {
        match std::fs::symlink_metadata(&path) {
            Err(cause) if cause.kind() == ErrorKind::NotFound => {}
            Err(cause) => return Err(error("Git workspace metadata", cause)),
            Ok(_) => {
                return Err(error(
                    "Git workspace permission",
                    "use a dedicated clone without shared Git worktree metadata",
                ));
            }
        }
    }
    Ok(vec![workspace, metadata])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_refuses_gitfile_shared_linked_and_missing_metadata()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let workspace =
            std::env::temp_dir().join(format!("se-git-profile-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&workspace)?;
        let _root_owner = cleanup_directory::PrivateDirectory::for_case(workspace.clone());
        let result = (|| -> std::result::Result<(), Box<dyn std::error::Error>> {
            assert_eq!(roots(workspace.clone(), false)?, vec![workspace.clone()]);
            assert!(roots(workspace.clone(), true).is_err());
            let metadata = workspace.join(".git");
            std::fs::write(&metadata, "gitdir: /another-agent/common/worktrees/seat\n")?;
            assert!(roots(workspace.clone(), true).is_err());
            std::fs::remove_file(&metadata)?;
            std::fs::create_dir(&metadata)?;
            let canonical = se_proc::canonicalize_path(&workspace)?;
            assert_eq!(
                roots(workspace.clone(), true)?,
                vec![canonical.clone(), canonical.join(".git")]
            );
            for marker in ["commondir", "worktrees"] {
                let path = metadata.join(marker);
                std::fs::write(&path, "shared")?;
                assert!(roots(workspace.clone(), true).is_err());
                std::fs::remove_file(path)?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                std::fs::remove_dir(&metadata)?;
                symlink(&workspace, &metadata)?;
                assert!(roots(workspace.clone(), true).is_err());
                std::fs::remove_file(&metadata)?;
            }
            Ok(())
        })();
        _root_owner.finish(result)
    }
}
