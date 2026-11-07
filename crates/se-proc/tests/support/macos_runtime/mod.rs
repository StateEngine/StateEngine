use se_proc::*;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub mod lifecycle;
pub mod native;
pub mod provider;
pub mod reactor;
pub mod scenarios;
pub type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub fn error(value: ProcError) -> String {
    format!("{value:?}")
}
pub fn machine() -> Check<MachineId> {
    Ok(MachineId::new("darwin-controlled-fixture")?)
}
pub fn until() -> Instant {
    Instant::now() + Duration::from_secs(15)
}
pub fn wait(mut ready: impl FnMut() -> Check<bool>) -> Check {
    let end = until();
    loop {
        if ready()? {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err("native fixture deadline elapsed".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub fn root() -> Check<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("SE_MACOS_JUDGE_ROOT").ok_or("fixture root absent")?,
    ))
}
pub fn json<T: serde::Serialize>(path: impl AsRef<Path>, value: &T) -> Check {
    let path = path.as_ref();
    let pending = path.with_extension("pending");
    fs::write(&pending, serde_json::to_vec(value)?)?;
    fs::rename(pending, path)?;
    Ok(())
}
pub struct Home(pub PathBuf);
impl Home {
    pub fn new() -> Check<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let nonce = se_types::hex_lower(&random_secret()?.expose()[..16]);
        let path = std::env::temp_dir().join(format!("se-macos-runtime-{nonce}"));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let home = Self(fs::canonicalize(path)?);
        println!("native runtime fixture: {}", home.0.display());
        Ok(home)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        // Native identity + full argv are reread before every cleanup signal.
        for name in [
            "pin-child.json",
            "pin-provider.json",
            "pin-helper.json",
            "pin-host.json",
        ] {
            let result = (|| -> Check {
                match fs::read(self.0.join(name)) {
                    Ok(bytes) => native::cleanup(&serde_json::from_slice(&bytes)?)?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
                Ok(())
            })();
            if let Err(e) = result {
                eprintln!("retained native fixture {} ({name}): {e}", self.0.display());
            }
        }
        // Retain the small transcript, including original pins, for the native job.
    }
}
