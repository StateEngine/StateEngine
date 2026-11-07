// Short, exclusively created fixture roots avoid shared redirected temp parents.
use std::{error::Error, path::PathBuf};

pub fn private_directory() -> Result<PathBuf, Box<dyn Error>> {
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
        drop(custody.create(&root)?);
        if custody.paths().contains(&root) {
            return Ok(root);
        }
    }
    Err("no fresh private fixture directory was created".into())
}
