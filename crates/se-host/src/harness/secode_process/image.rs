//! Hold both native images across probing and launch.
use super::{incompatible, unreadable};
use se_types::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct Images {
    pub cli: PathBuf,
    pub server: PathBuf,
    pub version: String,
    pub resume_supported: bool,
    cli_pin: se_proc::NativeSourcePin,
    server_pin: se_proc::NativeSourcePin,
    cli_digest: [u8; 32],
    server_digest: [u8; 32],
    cli_bytes: u64,
    server_bytes: u64,
}
impl Images {
    pub fn server_sha256(&self) -> se_types::Sha256 {
        se_types::Sha256::from_bytes(self.server_digest)
    }
    pub fn open(cli: &Path) -> Result<Self> {
        let cli =
            se_proc::canonicalize_path(cli).map_err(|e| unreadable("SE Code native image", e))?;
        let parent = cli
            .parent()
            .ok_or_else(|| incompatible("CLI image has no package directory"))?;
        let server = parent.join(if cfg!(windows) {
            "secode-server.exe"
        } else {
            "secode-server"
        });
        let (cli_pin, cli_digest, cli_bytes) = pin(&cli)?;
        let (server_pin, server_digest, server_bytes) = pin(&server)?;
        let mut images = Self {
            cli,
            server,
            version: String::new(),
            resume_supported: false,
            cli_pin,
            server_pin,
            cli_digest,
            server_digest,
            cli_bytes,
            server_bytes,
        };
        images.validate()?;
        super::bundle::verify(&images)?;
        Ok(images)
    }
    pub fn validate(&mut self) -> Result<()> {
        for (pin, expected) in [
            (&mut self.cli_pin, (self.cli_digest, self.cli_bytes)),
            (
                &mut self.server_pin,
                (self.server_digest, self.server_bytes),
            ),
        ] {
            pin.validate_path(pin.path())
                .map_err(|e| unreadable("SE Code executable identity", e))?;
            if digest(pin)? != expected {
                return Err(incompatible(
                    "a selected SE Code image changed after its probe; retain the original launch identities",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn require_entry(&self, server: bool, value: &serde_json::Value) -> Result<()> {
        let (path, hash, bytes) = if server {
            (&self.server, self.server_digest, self.server_bytes)
        } else {
            (&self.cli, self.cli_digest, self.cli_bytes)
        };
        let binary = if server { "secode-server" } else { "secode" };
        let filename = if cfg!(windows) {
            format!("{binary}.exe")
        } else {
            binary.to_owned()
        };
        if path.file_name().and_then(|s| s.to_str()) != Some(filename.as_str())
            || value["bin"].as_str() != Some(binary)
            || value["sha256"].as_str() != Some(se_types::hex_lower(&hash).as_str())
            || value["bytes"].as_u64() != Some(bytes)
        {
            return Err(incompatible(
                "a bundled native image differs from its manifest path, hash or size",
            ));
        }
        Ok(())
    }
}
fn pin(path: &Path) -> Result<(se_proc::NativeSourcePin, [u8; 32], u64)> {
    let mut pin = se_proc::NativeSourcePin::open(path)
        .map_err(|e| unreadable("SE Code image pin", e))?
        .ok_or_else(|| incompatible("a selected SE Code native image is absent"))?;
    let (digest, bytes) = digest(&mut pin)?;
    Ok((pin, digest, bytes))
}
fn digest(pin: &mut se_proc::NativeSourcePin) -> Result<([u8; 32], u64)> {
    let mut hash = Sha256::new();
    let mut offset = 0;
    const MAXIMUM: u64 = 512 * 1024 * 1024;
    loop {
        let chunk = pin
            .read_at(offset, 256 * 1024)
            .map_err(|e| unreadable("SE Code executable read", e))?;
        offset = chunk.next_offset;
        if offset > MAXIMUM {
            return Err(incompatible("native image exceeds the 512 MiB read bound"));
        }
        hash.update(chunk.bytes);
        if chunk.end_of_file {
            break;
        }
    }
    pin.validate_path(pin.path())
        .map_err(|e| unreadable("SE Code executable readback", e))?;
    Ok((hash.finalize().into(), offset))
}
