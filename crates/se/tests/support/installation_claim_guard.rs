//! Serialize the suites that drive the account-wide installation claim.
//!
//! Native installation custody comes from the effective account, not from
//! `HOME` or `--home`, so a private fixture home cannot isolate it. Separate
//! test processes that drive `se uninstall` or the installer therefore contend
//! on one claim. This is adjacent test plumbing: it never takes, bypasses or
//! weakens the product claim, and the lock file it opens is not a path the
//! product reads.
use std::{
    fs::{File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
    process::Output,
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(180);
const POLL: Duration = Duration::from_millis(100);

/// One cross-process guard for this account's installation effects.
pub struct Guard {
    // Closing the handle releases the advisory lock. The file stays in place so
    // a later holder reacquires the same inode instead of racing an unlink.
    _file: File,
}

/// A per-account lock outside every fixture and outside the account profile,
/// keyed by the account's own claim path. Two accounts on one machine never
/// share it, and an overridden `HOME` cannot redirect it to another account.
fn path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let claim = se_proc::installation_claim_path()
        .map_err(|error| format!("native account claim path is unavailable: {error}"))?;
    let digest = Sha256::digest(claim.as_os_str().as_encoded_bytes());
    let key = se_types::hex_lower(&digest[..16]);
    Ok(std::env::temp_dir().join(format!("stateengine-install-claim-test-{key}.lock")))
}

fn open(target: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(target)
}

/// Wait for exclusive use of this account's installation effects.
///
/// Contention is another test process, not a product verdict, so no suite may
/// read it as evidence about the code under test. A bounded wait that expires
/// refuses by name rather than quietly proceeding.
pub fn acquire() -> Result<Guard, Box<dyn std::error::Error>> {
    let target = path()?;
    let file = open(&target).map_err(|error| {
        format!(
            "cannot open the account installation test lock {}: {error}",
            target.display()
        )
    })?;
    let deadline = Instant::now() + WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Guard { _file: file }),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(POLL);
            }
            Err(TryLockError::WouldBlock) => {
                return Err(format!(
                    "another test process still holds the account-wide installation claim after {} seconds; run these suites one at a time",
                    WAIT.as_secs()
                )
                .into());
            }
            Err(TryLockError::Error(error)) => {
                return Err(format!(
                    "cannot coordinate the account-wide installation claim through {}: {error}",
                    target.display()
                )
                .into());
            }
        }
    }
}

/// The product's pre-write refusal when another process holds the account claim.
///
/// The guard serializes only test processes that take it; a real installer, an
/// older checkout or a harness script can still hold the claim. This refusal
/// changed nothing and the product marks it retryable. Every other refusal,
/// including other conflicts, stays the caller's verdict.
#[allow(
    dead_code,
    reason = "shared guard; only suites that read CLI refusals call this"
)]
pub fn contended(output: &Output) -> bool {
    output.status.code() == Some(1)
        && serde_json::from_slice::<serde_json::Value>(&output.stdout).is_ok_and(|row| {
            row["code"] == "state-conflict"
                && row["detail"]["subject"]
                    .as_str()
                    .is_some_and(|subject| subject.starts_with("installation lock "))
                && row["detail"]["reason"]
                    == "Native installation custody is contended by another operation"
        })
}

/// Rerun `call` while an outside holder keeps the account claim, for at most
/// thirty seconds; the last output is returned unchanged either way.
#[allow(
    dead_code,
    reason = "shared guard; only suites that read CLI refusals call this"
)]
pub fn retry_contended(
    mut call: impl FnMut() -> io::Result<Output>,
) -> Result<Output, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let output = call()?;
        if !contended(&output) || Instant::now() >= deadline {
            return Ok(output);
        }
        std::thread::sleep(POLL);
    }
}
