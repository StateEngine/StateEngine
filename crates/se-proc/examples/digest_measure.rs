//! Disposable throughput measurement; not an executable proof or correctness gate.
use sha2::Digest as _;
use std::{
    fs::File,
    hint::black_box,
    io::{Read, Seek, SeekFrom},
    time::Instant,
};

enum Hash {
    Rust(sha2::Sha256),
    Native(aws_lc_rs::digest::Context),
}
impl Hash {
    fn new(native: bool) -> Self {
        if native {
            Self::Native(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256))
        } else {
            Self::Rust(sha2::Sha256::new())
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Rust(h) => h.update(bytes),
            Self::Native(h) => h.update(bytes),
        }
    }
    fn finish(self) -> Vec<u8> {
        match self {
            Self::Rust(h) => h.finalize().to_vec(),
            Self::Native(h) => h.finish().as_ref().to_vec(),
        }
    }
}
fn usage() -> std::io::Result<(f64, i64)> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the writable structure on success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the successful call above initialized the structure.
    let usage = unsafe { usage.assume_init() };
    let cpu = (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as f64 * 1000.0
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1000.0;
    Ok((cpu, usage.ru_maxrss))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("expected INPUT BACKEND MODE".into());
    }
    let native = match args[2].as_str() {
        "native" => true,
        "sha2" => false,
        _ => return Err("backend".into()),
    };
    let memory = match args[3].as_str() {
        "memory" => true,
        "file" => false,
        _ => return Err("mode".into()),
    };
    let mut file = File::open(&args[1])?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
        return Err("input must be a nonempty regular file below the proof cap".into());
    }
    let bytes = if memory {
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Some(data)
    } else {
        None
    };
    let mut samples = Vec::new();
    let mut expected = None;
    for index in 0..101 {
        let cpu = usage()?.0;
        let started = Instant::now();
        let mut hash = Hash::new(native);
        let mut read = 0;
        if let Some(bytes) = &bytes {
            for chunk in bytes.chunks(64 * 1024) {
                hash.update(black_box(chunk));
                read += chunk.len();
            }
        } else {
            file.seek(SeekFrom::Start(0))?;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(black_box(&buffer[..count]));
                read += count;
            }
        }
        let digest = black_box(hash.finish());
        let wall_ms = started.elapsed().as_secs_f64() * 1000.0;
        let (cpu_after, rss) = usage()?;
        if read as u64 != metadata.len() {
            return Err("byte count changed".into());
        }
        if let Some(prior) = &expected {
            if prior != &digest {
                return Err("digest changed".into());
            }
        } else {
            expected = Some(digest);
        }
        samples.push(serde_json::json!({"index":index,"wall_ms":wall_ms,"cpu_ms":cpu_after-cpu,"bytes_read":if memory {0}else{read},"bytes_hashed":read,"peak_rss_kib":rss}));
    }
    let digest = expected.ok_or("no digest")?;
    println!(
        "{}",
        serde_json::json!({"backend":args[2],"mode":args[3],"input_bytes":metadata.len(),"chunk_bytes":65536,"hash_count":samples.len(),"digest":se_types::hex_lower(&digest),"samples":samples})
    );
    Ok(())
}
