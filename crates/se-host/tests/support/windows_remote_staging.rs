//! Native PowerShell observations with invocation-owned cache leaves and joined children.
#[path = "windows_profile_staging.rs"]
mod profile;
#[path = "../../src/remote/native_image/staging.rs"]
mod staging;
pub use profile::profile_paths_and_shells;

use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub type Check = Result<(), Box<dyn std::error::Error + Send + Sync>>;
type Value<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn require(value: bool, reason: &str) -> Check {
    if value { Ok(()) } else { Err(reason.into()) }
}

fn run(command: &str, bytes: Option<&[u8]>) -> Value<Output> {
    run_bounded(command, bytes, Duration::from_secs(15))
}

fn run_bounded(command: &str, bytes: Option<&[u8]>, maximum: Duration) -> Value<Output> {
    let arguments: Vec<_> = command.split_ascii_whitespace().collect();
    require(
        arguments.first() == Some(&"powershell.exe"),
        "fixed PowerShell command absent",
    )?;
    let mut child = Command::new(arguments[0])
        .args(&arguments[1..])
        .stdin(if bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(bytes) = bytes {
        let input = child.stdin.take().ok_or("owned stdin absent");
        let written = input.and_then(|mut input| {
            input
                .write_all(bytes)
                .map_err(|_| "binary stdin write failed")
        });
        if let Err(error) = written {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            let output = child.wait_with_output()?;
            return Err(format!("{error}; joined receiver: {}", output.status).into());
        }
    }
    let deadline = Instant::now() + maximum;
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill()?;
            let output = child.wait_with_output()?;
            return Err(format!(
                "owned PowerShell exceeded {maximum:?}; joined: {}",
                output.status
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    require(
        output.stdout.len() <= 65536 && output.stderr.len() <= 65536,
        "PowerShell response exceeded its observation bound",
    )?;
    Ok(output)
}

fn script(value: &str) -> Value<Output> {
    run(&staging::powershell(value), None)
}

fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub struct Fixture {
    profile: PathBuf,
    relative: String,
    digest: String,
    pub bytes: Vec<u8>,
}
impl Fixture {
    fn new() -> Value<Self> {
        let output = script(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::Write([Environment]::GetFolderPath('UserProfile'))",
        )?;
        require(
            output.status.success(),
            "native profile observation refused",
        )?;
        let profile = PathBuf::from(String::from_utf8(output.stdout)?);
        require(
            profile.is_absolute(),
            "native profile observation was not absolute",
        )?;
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        );
        let mut bytes = nonce.into_bytes();
        bytes.extend((0..=u8::MAX).cycle().take(65536));
        let digest = se_types::hex_lower(&Sha256::digest(&bytes));
        Ok(Self {
            profile,
            relative: format!(".stateengine-runtime/{digest}"),
            digest,
            bytes,
        })
    }
    pub fn image(&self) -> String {
        format!("{}/se.exe", self.relative)
    }
    pub fn upload(&self, suffix: &str) -> String {
        format!("{}.upload-{suffix}", self.image())
    }
    pub fn local(&self, relative: &str) -> PathBuf {
        self.profile.join(relative)
    }
    pub fn prepare(&self) -> Value<bool> {
        self.prepare_path(&self.relative)
    }
    pub fn prepare_path(&self, relative: &str) -> Value<bool> {
        Ok(run(&staging::prepare(relative, true, false), None)?
            .status
            .success())
    }
    pub fn receive(&self, relative: &str, bytes: &[u8]) -> Value<bool> {
        Ok(run(&staging::receive(relative, true), Some(bytes))?
            .status
            .success())
    }
    pub fn verify(&self, relative: &str) -> Value<bool> {
        Ok(
            run(&staging::verify(relative, &self.digest, true, false), None)?
                .status
                .success(),
        )
    }
    pub fn publish(&self, relative: &str) -> Value<bool> {
        Ok(run(&staging::publish(relative, &self.image(), true), None)?
            .status
            .success())
    }
    pub fn remove(&self, relative: &str) -> Value<bool> {
        Ok(run(&staging::remove(relative, true), None)?
            .status
            .success())
    }
    pub fn install(&self) -> Check {
        require(self.prepare()?, "safe runtime directory refused")?;
        let upload = self.upload("seed");
        require(self.receive(&upload, &self.bytes)?, "seed receive refused")?;
        require(self.publish(&upload)?, "seed publication refused")?;
        require(self.verify(&self.image())?, "seed image did not verify")
    }
    pub fn foreign_write(&self, add: bool) -> Check {
        let path = literal(
            self.local(&self.relative)
                .to_str()
                .ok_or("cache path is not UTF-8")?,
        );
        let action = if add {
            "AddAccessRule"
        } else {
            "RemoveAccessRuleAll"
        };
        let output = script(&format!(
            "$ErrorActionPreference='Stop'; $p={path}; $a=Get-Acl -LiteralPath $p; $s=[Security.Principal.SecurityIdentifier]::new('S-1-1-0'); $r=[Security.AccessControl.FileSystemAccessRule]::new($s,'Modify','ContainerInherit,ObjectInherit','None','Allow'); $a.{action}($r); Set-Acl -LiteralPath $p -AclObject $a"
        ))?;
        require(output.status.success(), "owned cache ACL change refused")
    }
    pub fn junction(&self) -> Value<String> {
        let target = self.local(&format!("{}/target", self.relative));
        std::fs::create_dir(&target)?;
        let relative = format!("{}/junction", self.relative);
        let link = literal(
            self.local(&relative)
                .to_str()
                .ok_or("junction path is not UTF-8")?,
        );
        let target = literal(target.to_str().ok_or("junction target is not UTF-8")?);
        let output = script(&format!(
            "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path {link} -Target {target} | Out-Null; if (-not ((Get-Item -LiteralPath {link} -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {{exit 1}}"
        ))?;
        require(
            output.status.success(),
            "owned junction fixture did not form",
        )?;
        Ok(relative)
    }
    pub fn remove_junction(&self, relative: &str) -> Check {
        std::fs::remove_dir(self.local(relative))?;
        Ok(())
    }
    fn cleanup(&self) -> Check {
        let leaf = self.local(&self.relative);
        if leaf.try_exists()? {
            std::fs::remove_dir_all(&leaf)?;
        }
        require(
            !leaf.try_exists()?,
            "owned cache leaf remained after cleanup",
        )
    }
}

pub fn with_fixture(body: impl FnOnce(&Fixture) -> Check) -> Check {
    let fixture = Fixture::new()?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&fixture)));
    let cleanup = fixture.cleanup();
    match (result, cleanup) {
        (Ok(result), Ok(())) => result,
        (Ok(result), Err(cleanup)) => {
            Err(format!("control: {result:?}; cleanup: {cleanup}").into())
        }
        (Err(panic), cleanup) => {
            if let Err(error) = cleanup {
                eprintln!("owned fixture cleanup failed: {error}");
            }
            std::panic::resume_unwind(panic)
        }
    }
}
