//! Version-only fixtures use the public harness and existing native test helpers.
#![allow(
    dead_code,
    reason = "The version and launch integration binaries use different fixture methods."
)]
use se_core::config_policy::ConfigFile;
use se_host::{
    BlockingPool, CallContext, CodexHarness, Harness, HarnessKind, ProbeRequest, ProviderVersion,
    UnixProviderIo,
};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
#[path = "../../../test-support/directory.rs"]
mod directory;
#[path = "../../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
pub type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub fn context() -> Check<CallContext> {
    Ok(CallContext::new(
        se_types::Generation::new(1)?,
        Duration::from_secs(5),
    ))
}
pub struct Fixture {
    pub root: PathBuf,
    pub image: PathBuf,
    pub runtime: tokio::runtime::Runtime,
}
impl Fixture {
    pub fn new() -> Check<Self> {
        let root = fs::canonicalize(directory::private_directory()?)?;
        let image = root.join("native-provider");
        let source = root.join("provider.rs");
        fs::write(&source, include_str!("codex_version_native.rs"))?;
        let output =
            std::process::Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                .args(["--edition=2024", "-C", "debuginfo=0"])
                .arg(&source)
                .arg("-o")
                .arg(&image)
                .output_executable()?;
        if !output.status.success() {
            return Err(format!(
                "native version fixture compilation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()?;
        Ok(Self {
            root,
            image,
            runtime,
        })
    }
    pub fn harness(&self) -> CodexHarness {
        CodexHarness::new(
            Arc::new(UnixProviderIo),
            BlockingPool::new(self.runtime.handle().clone()),
            self.root.clone(),
            self.root.clone(),
            21345,
            ConfigFile::default(),
        )
    }
    /// Mirrors the launch resolver: observe the currently selected image on
    /// every call, never replay an old stamp as if it were a fresh observation.
    pub fn direct(&self, harness: &CodexHarness, image: &Path) -> Check<ProviderVersion> {
        let stamp = se_proc::native_ipc::ExecutableStamp::observe(image)?;
        Ok(self.runtime.block_on(harness.probe_direct(
            ProbeRequest {
                kind: HarnessKind::CodexAppServer,
                command: image.to_owned(),
            },
            stamp,
            context()?,
        ))?)
    }
    pub fn fresh(&self, harness: &CodexHarness, image: &Path) -> Check<ProviderVersion> {
        Ok(self.runtime.block_on(harness.probe(
            ProbeRequest {
                kind: HarnessKind::CodexAppServer,
                command: image.to_owned(),
            },
            context()?,
        ))?)
    }
    pub fn children(&self) -> Check<usize> {
        let text = match fs::read_to_string(self.root.join("version-children.log")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        for line in text.lines() {
            assert!(line.parse::<u32>()? > 0);
        }
        Ok(text.lines().count())
    }
    pub fn unsupported(&self, path: &Path, preserve_mtime: bool) -> Check {
        let before = fs::metadata(path)?;
        let mut bytes = fs::read(path)?;
        let supported = b"codex-cli 0.152.0";
        let offsets: Vec<_> = bytes
            .windows(supported.len())
            .enumerate()
            .filter_map(|(at, value)| (value == supported).then_some(at))
            .collect();
        assert_eq!(
            offsets.len(),
            1,
            "patch one exact version literal in a native image"
        );
        bytes[offsets[0]..offsets[0] + supported.len()].copy_from_slice(b"codex-cli 0.151.0");
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if preserve_mtime {
            file.set_times(fs::FileTimes::new().set_modified(before.modified()?))?;
            assert_eq!(fs::metadata(path)?.modified()?, before.modified()?);
        }
        assert_eq!(fs::metadata(path)?.len(), before.len());
        Ok(())
    }
    /// These fixtures create only immediate regular files and explicit aliases.
    /// Preserve unexpected directories rather than recursively deleting them.
    pub fn cleanup(self) -> Check {
        let entries = fs::read_dir(&self.root)?.collect::<Result<Vec<_>, _>>()?;
        for entry in &entries {
            let kind = entry.file_type()?;
            assert!(
                kind.is_file() || kind.is_symlink(),
                "unexpected fixture child: {:?}",
                entry.path()
            );
        }
        for entry in entries {
            fs::remove_file(entry.path())?;
        }
        fs::remove_dir(&self.root)?;
        Ok(())
    }
}
