//! Native EOF controls that witness pending I/O before closing the peer.
use super::*;
use std::time::Duration;

type Check = Result<(), Box<dyn std::error::Error>>;

fn pair() -> IpcNativeResult<(NativePipeStream, OwnedHandle)> {
    NativePipeStream::worker_pair(IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}

fn event() -> io::Result<OwnedHandle> {
    owned(
        // SAFETY: anonymous noninheritable event; ownership transfers immediately.
        unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) },
        "create EOF control event",
    )
    .map_err(|error| error.source)
}

fn require_pending(result: i32) -> Check {
    if result != 0 {
        return Err("control operation completed before peer closure".into());
    }
    // SAFETY: the caller's ReadFile/WriteFile is the preceding native call.
    let code = unsafe { GetLastError() };
    if code != ERROR_IO_PENDING {
        return Err(format!("control did not witness pending I/O: {code}").into());
    }
    Ok(())
}

#[test]
fn peer_close_after_observed_pending_read_is_eof() -> Check {
    let (server, peer) = pair()?;
    let event = event()?;
    // SAFETY: zero initializes OVERLAPPED; event/buffer stay live through wait.
    let mut operation: OVERLAPPED = unsafe { zeroed() };
    operation.hEvent = event.as_raw_handle();
    let mut bytes = [0u8; 1];
    // SAFETY: retained connected handle, writable buffer and OVERLAPPED. Once
    // pending is witnessed, production wait drains it before any allocation drops.
    require_pending(unsafe {
        ReadFile(
            server.handle.as_raw_handle(),
            bytes.as_mut_ptr(),
            1,
            ptr::null_mut(),
            &mut operation,
        )
    })?;
    drop(peer);
    assert_eq!(
        wait(
            server.handle.as_raw_handle(),
            &mut operation,
            true,
            &server.bound
        )?,
        0
    );
    Ok(())
}

#[test]
fn peer_close_before_public_read_is_eof() -> Check {
    let (mut server, peer) = pair()?;
    drop(peer);
    assert_eq!(server.read(&mut [0u8; 1])?, 0);
    Ok(())
}

#[test]
fn closed_peer_public_write_still_fails() -> Check {
    let (mut server, peer) = pair()?;
    drop(peer);
    let result = server.write(b"payload");
    assert!(
        result.is_err(),
        "closed-peer write became success: {result:?}"
    );
    Ok(())
}

#[test]
fn peer_close_after_observed_pending_write_still_fails() -> Check {
    let (server, peer) = pair()?;
    let event = event()?;
    // SAFETY: zero initializes OVERLAPPED; event/buffer stay live through wait.
    let mut operation: OVERLAPPED = unsafe { zeroed() };
    operation.hEvent = event.as_raw_handle();
    // Larger than the private pipe's 64 KiB outbound buffer, with no peer read.
    let bytes = vec![b'x'; 128 * 1024];
    // SAFETY: retained connected handle and readable buffer/OVERLAPPED remain
    // live until production wait drains this exact pending write.
    require_pending(unsafe {
        WriteFile(
            server.handle.as_raw_handle(),
            bytes.as_ptr(),
            bytes.len() as u32,
            ptr::null_mut(),
            &mut operation,
        )
    })?;
    drop(peer);
    let result = wait(
        server.handle.as_raw_handle(),
        &mut operation,
        false,
        &server.bound,
    );
    assert!(
        result.is_err(),
        "pending closed-peer write became success: {result:?}"
    );
    Ok(())
}
