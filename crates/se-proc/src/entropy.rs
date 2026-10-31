//! OS-CSPRNG secret allocation. No path, seed, fallback or process-global RNG.
use se_types::Secret;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct NativeEntropyError {
    pub operation: &'static str,
    pub native_code: Option<i64>,
}
impl std::fmt::Display for NativeEntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} failed (native code {:?}); no secret allocated",
            self.operation, self.native_code
        )
    }
}
impl std::error::Error for NativeEntropyError {}

/// Allocates exactly 32 fresh OS-CSPRNG bytes in a redacted, zeroizing Secret.
/// Callers own protected publication; this function does no file or log I/O.
/// A failed or partial native fill is zeroized and never returned.
pub fn random_secret() -> Result<Secret, NativeEntropyError> {
    let mut bytes = Zeroizing::new(vec![0u8; 32]);
    fill(&mut bytes)?;
    Secret::new(std::mem::take(&mut *bytes)).map_err(|_| NativeEntropyError {
        operation: "construct fixed-size native secret",
        native_code: None,
    })
}
#[cfg(target_os = "linux")]
fn fill(bytes: &mut [u8]) -> Result<(), NativeEntropyError> {
    let mut offset = 0;
    while offset < bytes.len() {
        // SAFETY: the writable slice suffix is retained and exactly bounded;
        // flags=0 selects the initialized kernel CSPRNG, never weak fallback.
        let n = unsafe {
            libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
        };
        if n < 0 {
            let cause = std::io::Error::last_os_error();
            if cause.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(NativeEntropyError {
                operation: "getrandom",
                native_code: cause.raw_os_error().map(i64::from),
            });
        }
        if n == 0 {
            return Err(NativeEntropyError {
                operation: "getrandom returned no bytes",
                native_code: None,
            });
        }
        offset += n as usize;
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn fill(bytes: &mut [u8]) -> Result<(), NativeEntropyError> {
    // SAFETY: exactly 32 writable retained bytes, below getentropy's 256-byte limit.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } == 0 {
        return Ok(());
    }
    Err(NativeEntropyError {
        operation: "getentropy",
        native_code: std::io::Error::last_os_error()
            .raw_os_error()
            .map(i64::from),
    })
}
#[cfg(windows)]
fn fill(bytes: &mut [u8]) -> Result<(), NativeEntropyError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    // SAFETY: retained exact writable buffer; null algorithm is required for the
    // OS-preferred CSPRNG flag, and no caller seed is supplied.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(NativeEntropyError {
            operation: "BCryptGenRandom",
            native_code: Some(i64::from(status)),
        })
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn fill(_bytes: &mut [u8]) -> Result<(), NativeEntropyError> {
    Err(NativeEntropyError {
        operation: "native CSPRNG unsupported on this platform",
        native_code: None,
    })
}
