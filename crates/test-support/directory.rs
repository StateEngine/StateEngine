// Short, exclusively created fixture roots avoid shared redirected temp parents.
use std::error::Error;
#[cfg(unix)]
use std::path::PathBuf;
#[path = "directory_owner.rs"]
mod owner;
pub use owner::PrivateDirectory;

#[allow(dead_code)]
pub fn private_directory() -> Result<PrivateDirectory, Box<dyn Error>> {
    #[cfg(target_os = "macos")]
    let parent = PathBuf::from("/private/tmp");
    #[cfg(all(unix, not(target_os = "macos")))]
    let parent = PathBuf::from("/tmp");
    #[cfg(windows)]
    let parent = std::env::temp_dir();
    for _ in 0..32 {
        // Eight hex digits leave room for stock hash-addressed socket aliases.
        let mut nonce = [0u8; 4];
        se_proc::fill_entropy(&mut nonce)?;
        let root = parent.join(se_types::hex_lower(&nonce));
        let mut custody = se_proc::NativeDirectoryCreation::begin();
        match custody.create(&root) {
            Ok(files) => drop(files),
            Err(error) => {
                for cleanup in custody.rollback() {
                    match cleanup.result {
                        Ok(
                            se_proc::DirectoryRemoval::Removed
                            | se_proc::DirectoryRemoval::AlreadyAbsent,
                        ) => {}
                        result => eprintln!(
                            "retained partial fixture root {}: {result:?}",
                            cleanup.path.display()
                        ),
                    }
                }
                return Err(error.into());
            }
        }
        if custody.paths().contains(&root) {
            return Ok(PrivateDirectory::adopt(root));
        }
    }
    Err("no fresh private fixture directory was created".into())
}

#[allow(dead_code)]
pub fn private_case_directory() -> Result<PrivateDirectory, Box<dyn Error>> {
    Ok(private_directory()?.until_success())
}
