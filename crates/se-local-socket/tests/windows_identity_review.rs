//! Protects: Windows AF_UNIX socket and directory identity checks, exact
//! handle-disposed removal, and nonblocking tokio bridge liveness/half-close.
#![cfg(windows)]

use se_local_socket::identity::{ObjectId, Removal};
use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uds_windows::UnixListener;

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Check<Self> {
        let mut nonce = [0_u8; 4];
        se_proc::fill_entropy(&mut nonce)?;
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let hex = u32::from_be_bytes(nonce);
        let path = std::env::temp_dir().join(format!("se-{tag}-{seq}-{hex:08x}"));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn replaced_af_unix_socket_returns_invalid_data_and_preserves_replacement() -> Check {
    let scratch = Scratch::new("rep")?;
    let socket = scratch.0.join("s");
    let first = UnixListener::bind(&socket)?;
    let recorded = ObjectId::local_socket(&socket)?;
    drop(first);

    // Keep the original socket object allocated under another name so NTFS
    // cannot recycle its file index for the replacement.
    let displaced = scratch.0.join("displaced");
    fs::rename(&socket, &displaced)?;
    let second = UnixListener::bind(&socket)?;

    let refused = recorded.remove_local_socket(&socket);
    assert!(
        matches!(&refused, Err(error) if error.kind() == io::ErrorKind::InvalidData),
        "a replacement AF_UNIX socket was not refused with InvalidData: {refused:?}"
    );
    assert!(
        fs::symlink_metadata(&socket).is_ok(),
        "the replacement AF_UNIX socket was removed"
    );

    drop(second);
    let current = ObjectId::local_socket(&socket)?;
    assert_ne!(current, recorded);
    assert_eq!(current.remove_local_socket(&socket)?, Removal::Removed);
    assert_eq!(current.remove_local_socket(&socket)?, Removal::Absent);
    Ok(())
}

#[test]
fn regular_file_returns_invalid_input_and_is_preserved() -> Check {
    let scratch = Scratch::new("reg")?;
    let socket = scratch.0.join("s");
    let listener = UnixListener::bind(&socket)?;
    let recorded = ObjectId::local_socket(&socket)?;
    drop(listener);
    fs::remove_file(&socket)?;

    fs::write(&socket, b"not a socket")?;
    let observe_socket = ObjectId::local_socket(&socket);
    assert!(
        matches!(&observe_socket, Err(error) if error.kind() == io::ErrorKind::InvalidInput),
        "a regular file was not refused as InvalidInput for local_socket: {observe_socket:?}"
    );
    let observe_dir = ObjectId::directory(&socket);
    assert!(
        matches!(&observe_dir, Err(error) if error.kind() == io::ErrorKind::InvalidInput),
        "a regular file was not refused as InvalidInput for directory: {observe_dir:?}"
    );

    let refused = recorded.remove_local_socket(&socket);
    assert!(
        matches!(&refused, Err(error) if error.kind() == io::ErrorKind::InvalidInput),
        "remove_local_socket did not refuse a regular file with InvalidInput: {refused:?}"
    );
    assert_eq!(fs::read(&socket)?, b"not a socket");
    Ok(())
}

#[test]
fn ntfs_directory_junction_returns_invalid_input_and_preserves_target() -> Check {
    let scratch = Scratch::new("junc")?;
    let target = scratch.0.join("target");
    fs::create_dir(&target)?;
    let marker = target.join("keep.txt");
    fs::write(&marker, b"keep")?;

    let junction = scratch.0.join("j");
    let output = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "mklink /J failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let as_dir = ObjectId::directory(&junction);
    assert!(
        matches!(&as_dir, Err(error) if error.kind() == io::ErrorKind::InvalidInput),
        "an NTFS junction was not refused with InvalidInput for directory: {as_dir:?}"
    );
    let as_socket = ObjectId::local_socket(&junction);
    assert!(
        matches!(&as_socket, Err(error) if error.kind() == io::ErrorKind::InvalidInput),
        "an NTFS junction was not refused with InvalidInput for local_socket: {as_socket:?}"
    );

    let target_id = ObjectId::directory(&target)?;
    let remove_attempt = target_id.remove_directory(&junction);
    assert!(
        matches!(&remove_attempt, Err(error) if error.kind() == io::ErrorKind::InvalidInput),
        "remove_directory did not refuse an NTFS junction with InvalidInput: {remove_attempt:?}"
    );
    assert!(fs::symlink_metadata(&junction).is_ok());
    assert_eq!(fs::read(&marker)?, b"keep");

    // Remove the junction itself before scratch cleanup.
    fs::remove_dir(&junction)?;
    Ok(())
}

#[test]
fn swapped_directory_returns_invalid_data_and_preserves_replacement() -> Check {
    let scratch = Scratch::new("dir")?;
    let dir = scratch.0.join("cx");
    fs::create_dir(&dir)?;
    let recorded = ObjectId::directory(&dir)?;

    let displaced = scratch.0.join("cx-displaced");
    fs::rename(&dir, &displaced)?;
    fs::create_dir(&dir)?;

    let refused = recorded.remove_directory(&dir);
    assert!(
        matches!(&refused, Err(error) if error.kind() == io::ErrorKind::InvalidData),
        "a swapped directory was not refused with InvalidData: {refused:?}"
    );
    assert!(dir.is_dir(), "the replacement directory was removed");

    let current = ObjectId::directory(&dir)?;
    assert_ne!(current, recorded);
    assert_eq!(current.remove_directory(&dir)?, Removal::Removed);
    assert_eq!(current.remove_directory(&dir)?, Removal::Absent);
    Ok(())
}

#[test]
fn bridge_survives_idle_ticks_round_trips_half_closes_and_reports_stale_refused() -> Check {
    let scratch = Scratch::new("br")?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;

    // A stale AF_UNIX socket with no listener maps WSAENETDOWN to ConnectionRefused.
    // Give Windows afunix.sys a brief moment to finish listener teardown after close.
    let stale = scratch.0.join("stale");
    let listener = UnixListener::bind(&stale)?;
    drop(listener);
    std::thread::sleep(Duration::from_millis(25));
    let stale_err = runtime.block_on(se_local_socket::connect(&stale));
    match stale_err {
        Ok(_) => return Err("stale AF_UNIX socket unexpectedly accepted a connection".into()),
        Err(error) => assert_eq!(
            error.kind(),
            io::ErrorKind::ConnectionRefused,
            "stale AF_UNIX socket did not report ConnectionRefused: {error:?}"
        ),
    }

    // Live socket: stay idle across multiple 250 ms WSAPoll ticks, round-trip,
    // half-close outbound writes (Shutdown::Write), and receive final server frames.
    let live = scratch.0.join("live");
    let listener = UnixListener::bind(&live)?;
    let server = std::thread::spawn(move || -> io::Result<()> {
        let (mut peer, _) = listener.accept()?;
        let mut ping = [0_u8; 16];
        peer.read_exact(&mut ping)?;
        if &ping != b"ping-after-idle\n" {
            return Err(io::Error::other("unexpected ping payload"));
        }
        peer.write_all(b"pong-after-idle\n")?;
        peer.flush()?;

        // Wait for the client's half-close EOF before sending the final frames.
        let mut closing = Vec::new();
        peer.read_to_end(&mut closing)?;
        if !closing.is_empty() {
            return Err(io::Error::other("unexpected bytes after half-close"));
        }
        peer.write_all(b"last-frame-after-half-close\n")?;
        peer.flush()?;
        Ok(())
    });

    runtime.block_on(async {
        let mut stream = se_local_socket::connect(&live).await?;
        // Span more than two 250 ms WSAPoll ticks with zero traffic.
        std::thread::sleep(Duration::from_millis(650));

        stream.write_all(b"ping-after-idle\n").await?;
        stream.flush().await?;
        let mut pong = [0_u8; 16];
        stream.read_exact(&mut pong).await?;
        assert_eq!(&pong, b"pong-after-idle\n");

        stream.shutdown().await?;

        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await?;
        assert_eq!(tail, b"last-frame-after-half-close\n");
        Ok::<(), io::Error>(())
    })?;

    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}
