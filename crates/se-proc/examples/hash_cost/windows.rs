use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{Read, Seek},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::CloseHandle,
    Security::Cryptography::*,
    Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ},
    System::Memory::*,
};
type Outcome<T> = Result<T, Box<dyn Error>>;
const MODES: [&str; 7] = [
    "sha2-buffer-64k",
    "sha2-buffer-1m",
    "sha2-mapped",
    "sha2-memory",
    "cng-buffer-64k",
    "cng-mapped",
    "read-only-64k",
];

fn status(value: i32) -> Outcome<()> {
    if value < 0 {
        Err(format!("Native digest operation failed: {value:#x}").into())
    } else {
        Ok(())
    }
}
struct Cng {
    algorithm: BCRYPT_ALG_HANDLE,
    hash: BCRYPT_HASH_HANDLE,
}
impl Cng {
    fn new() -> Outcome<Self> {
        let mut this = Self {
            algorithm: ptr::null_mut(),
            hash: ptr::null_mut(),
        };
        // SAFETY: writable handle output and a documented static algorithm identifier.
        status(unsafe {
            BCryptOpenAlgorithmProvider(
                &mut this.algorithm,
                BCRYPT_SHA256_ALGORITHM,
                ptr::null(),
                0,
            )
        })?;
        // SAFETY: live provider, writable hash output; null object storage requests native allocation.
        status(unsafe {
            BCryptCreateHash(
                this.algorithm,
                &mut this.hash,
                ptr::null_mut(),
                0,
                ptr::null(),
                0,
                0,
            )
        })?;
        Ok(this)
    }
    fn update(&mut self, bytes: &[u8]) -> Outcome<()> {
        let count = u32::try_from(bytes.len())?;
        // SAFETY: live hash and a borrowed slice with its exact checked length.
        status(unsafe { BCryptHashData(self.hash, bytes.as_ptr(), count, 0) })
    }
    fn finish(self) -> Outcome<Vec<u8>> {
        let mut bytes = vec![0; 32];
        // SAFETY: live SHA-256 state and exactly 32 writable output bytes.
        status(unsafe { BCryptFinishHash(self.hash, bytes.as_mut_ptr(), 32, 0) })?;
        Ok(bytes)
    }
}
impl Drop for Cng {
    fn drop(&mut self) {
        // SAFETY: each non-null handle was uniquely returned to this owner; hash closes first.
        unsafe {
            if !self.hash.is_null() {
                BCryptDestroyHash(self.hash);
            }
            if !self.algorithm.is_null() {
                BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
        }
    }
}

fn mapped(file: &File, length: usize, cng: bool) -> Outcome<Vec<u8>> {
    // SAFETY: retained read-only file, no named object, bounded existing file size.
    let mapping = unsafe {
        CreateFileMappingW(
            file.as_raw_handle(),
            ptr::null(),
            PAGE_READONLY,
            0,
            0,
            ptr::null(),
        )
    };
    if mapping.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: live mapping, read-only view, exact previously bounded length.
    let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, length) };
    if view.Value.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: uniquely owned mapping with no live view.
        unsafe {
            CloseHandle(mapping);
        }
        return Err(error.into());
    }
    let result = (|| {
        // SAFETY: mapped readable file bytes; a retained writer-excluding handle prevents mutation.
        let bytes = unsafe { std::slice::from_raw_parts(view.Value.cast::<u8>(), length) };
        if cng {
            let mut hasher = Cng::new()?;
            for block in bytes.chunks(64 * 1024) {
                hasher.update(block)?;
            }
            hasher.finish()
        } else {
            Ok(Sha256::digest(bytes).to_vec())
        }
    })();
    // SAFETY: hashing is complete; release this exact view before its mapping handle.
    let unmapped = unsafe { UnmapViewOfFile(view) };
    // SAFETY: uniquely owned mapping and no further access to its view.
    let closed = unsafe { CloseHandle(mapping) };
    if unmapped == 0 || closed == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    result
}

fn buffered(mut file: File, size: usize, cng: bool, read_only: bool) -> Outcome<(Vec<u8>, u64)> {
    file.rewind()?;
    let mut sha = Sha256::new();
    let mut native = if cng { Some(Cng::new()?) } else { None };
    let mut buffer = vec![0; size];
    let mut total = 0;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if let Some(native) = &mut native {
            native.update(&buffer[..count])?;
        } else if !read_only {
            sha.update(&buffer[..count]);
        } else {
            std::hint::black_box(&buffer[..count]);
        }
    }
    let digest = match native {
        Some(native) => native.finish()?,
        None if read_only => Vec::new(),
        None => sha.finalize().to_vec(),
    };
    Ok((digest, total))
}

fn pin(path: &Path) -> Outcome<File> {
    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(path)?)
}
pub(super) fn run() -> Outcome<()> {
    let path = std::path::PathBuf::from(std::env::args_os().nth(1).ok_or("Image path absent")?);
    let expected = std::env::args()
        .nth(2)
        .ok_or("Expected image digest absent")?;
    let held = pin(&path)?;
    let metadata = held.metadata()?;
    let length = usize::try_from(metadata.len())?;
    if !metadata.is_file() || length == 0 || length > 512 * 1024 * 1024 {
        return Err("Image outside proof bounds".into());
    }
    let memory = std::fs::read(&path)?;
    let initial = format!("{:x}", Sha256::digest(&memory));
    if initial != expected {
        return Err("Retained shipping image digest differs".into());
    }
    let mut samples = Vec::new();
    for round in 0..110 {
        for offset in 0..MODES.len() {
            let mode = MODES[(round + offset) % MODES.len()];
            let begin = Instant::now();
            let (digest, count) = match mode {
                "sha2-memory" => (Sha256::digest(&memory).to_vec(), length as u64),
                "sha2-mapped" => (mapped(&pin(&path)?, length, false)?, length as u64),
                "cng-mapped" => (mapped(&pin(&path)?, length, true)?, length as u64),
                _ => buffered(
                    pin(&path)?,
                    if mode == "sha2-buffer-1m" {
                        1024 * 1024
                    } else {
                        64 * 1024
                    },
                    mode.starts_with("cng"),
                    mode.starts_with("read-only"),
                )?,
            };
            let ms = begin.elapsed().as_secs_f64() * 1000.0;
            if count != length as u64 {
                return Err("Full-byte observation length differs".into());
            }
            if !mode.starts_with("read-only") {
                let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                if hex != expected {
                    return Err("SHA-256 backend result differs".into());
                }
            }
            samples.push(serde_json::json!({"round":round,"mode":mode,"warmup":round<10,"ms":ms,"bytes":count}));
        }
    }
    let final_hash = format!("{:x}", Sha256::digest(std::fs::read(&path)?));
    if final_hash != expected || held.metadata()?.len() != length as u64 {
        return Err("Shipping image changed during observation".into());
    }
    println!(
        "{}",
        serde_json::json!({
            "image":path,"image_bytes":length,"image_sha256":expected,
            "cpu":{"sha":std::is_x86_feature_detected!("sha"),"sse2":std::is_x86_feature_detected!("sse2"),"ssse3":std::is_x86_feature_detected!("ssse3"),"sse41":std::is_x86_feature_detected!("sse4.1"),"avx2":std::is_x86_feature_detected!("avx2")},
            "samples":samples,
            "scope":"Author hashing performance observation with cached pages; no authentication or public status acceptance claim"
        })
    );
    Ok(())
}
