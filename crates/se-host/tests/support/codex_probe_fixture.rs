//! Version-only fixtures use the public harness and existing native test helpers.
#![allow(
    dead_code,
    reason = "The version and launch integration binaries use different fixture methods."
)]
use se_core::config_policy::ConfigFile;
#[cfg(unix)]
use se_host::UnixProviderIo;
use se_host::{
    BlockingPool, CallContext, CodexHarness, Harness, HarnessKind, ProbeRequest, ProviderVersion,
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
/// The version probe path never opens provider IO. On Windows the production
/// port needs a live process runtime reservation, so the native judge binds
/// this refusing stand-in: any IO attempt fails the test loudly.
#[cfg(windows)]
struct VersionOnlyIo;
#[cfg(windows)]
impl VersionOnlyIo {
    fn refuse(&self, operation: &str) -> se_types::SeError {
        se_types::SeError::new(se_types::Detail::StateConflict(
            se_types::details::StateConflict {
                subject: "version-only native judge fixture".into(),
                reason: format!(
                    "provider {operation} is refused: this fixture exercises version qualification only"
                ),
                next_step: "No provider attach is attempted by the native version reuse judges."
                    .into(),
            },
        ))
    }
}
#[cfg(windows)]
impl se_host::ProviderIoPlatform for VersionOnlyIo {
    fn open(
        &self,
        _owner: &se_proc::OwnedProcess,
        _identity: &se_host::SessionIdentity,
    ) -> se_types::Result<se_host::ProviderIo> {
        Err(self.refuse("open"))
    }
    fn read<'a>(
        &'a self,
        _transport: &'a se_host::ProviderTransport,
        _stream: se_host::ProviderStream,
        _maximum_bytes: std::num::NonZeroU32,
        _cx: se_host::CallContext,
    ) -> se_host::HostFuture<'a, se_host::StreamRead> {
        Box::pin(async { Err(self.refuse("read")) })
    }
    fn write<'a>(
        &'a self,
        _transport: &'a se_host::ProviderTransport,
        _bytes: Vec<u8>,
        _cx: se_host::CallContext,
    ) -> se_host::HostFuture<'a, se_host::StreamWrite> {
        Box::pin(async { Err(self.refuse("write")) })
    }
    fn finish_input<'a>(
        &'a self,
        _transport: &'a se_host::ProviderTransport,
        _cx: se_host::CallContext,
    ) -> se_host::HostFuture<'a, ()> {
        Box::pin(async { Err(self.refuse("finish input")) })
    }
    fn close<'a>(
        &'a self,
        _transport: &'a se_host::ProviderTransport,
        _cx: se_host::CallContext,
    ) -> se_host::HostFuture<'a, ()> {
        Box::pin(async { Err(self.refuse("close")) })
    }
}
pub struct Fixture {
    pub root: PathBuf,
    pub image: PathBuf,
    pub runtime: tokio::runtime::Runtime,
    _root: directory::PrivateDirectory,
}
impl Fixture {
    pub fn new() -> Check<Self> {
        let root = directory::private_directory()?;
        let canonical = se_proc::canonicalize_path(&root)?;
        #[cfg(not(windows))]
        let image = canonical.join("native-provider");
        #[cfg(windows)]
        let image = canonical.join("native-provider.exe");
        let source = canonical.join("provider.rs");
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
        #[cfg(windows)]
        assert!(
            se_proc::native_ipc::ExecutableStamp::observe(&image)?.is_some(),
            "the native fixture must use a directly reusable image path"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()?;
        Ok(Self {
            root: canonical,
            image,
            runtime,
            _root: root,
        })
    }
    pub fn harness(&self) -> CodexHarness {
        #[cfg(unix)]
        let io: Arc<dyn se_host::ProviderIoPlatform> = Arc::new(UnixProviderIo);
        #[cfg(windows)]
        let io: Arc<dyn se_host::ProviderIoPlatform> = Arc::new(VersionOnlyIo);
        CodexHarness::new(
            io,
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
    /// Preserve unexpected directories rather than recursively deleting them;
    /// `_root` removes the directory itself, so this leaves its own tree intact.
    pub fn cleanup(&self) -> Check {
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
        Ok(())
    }
}
