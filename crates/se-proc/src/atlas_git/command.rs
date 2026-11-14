//! One closed Git command shared by the native containment backends.
use std::{path::Path, process::Command};

pub(super) fn prepare(image: &Path, control: &Path, objects: &Path, args: Vec<String>) -> Command {
    let mut command = std::process::Command::new(image);
    command
        .current_dir(control)
        .env_clear()
        .env("HOME", control)
        .env("XDG_CONFIG_HOME", control)
        .env("GIT_DIR", control)
        .env("GIT_OBJECT_DIRECTORY", objects)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("LC_ALL", "C")
        .env("GIT_PAGER", "cat")
        .args([
            "--no-optional-locks",
            "--no-replace-objects",
            "-c",
            "core.packedGitWindowSize=1048576",
            "-c",
            "core.packedGitLimit=8388608",
            "-c",
            "core.deltaBaseCacheLimit=1048576",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.multiPackIndex=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "protocol.allow=never",
        ])
        .args(args);
    command
}
