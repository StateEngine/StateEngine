//! Unit tests for private Windows console-interrupt startup entry custody.
use super::*;
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle, OwnedHandle};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn dup_inheritable(src: *mut std::ffi::c_void) -> Check<OwnedHandle> {
    let mut dup = ptr::null_mut();
    // SAFETY: `src` is a live handle; `dup` receives a fresh inheritable duplicate.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            src,
            GetCurrentProcess(),
            &mut dup,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `DuplicateHandle` transferred sole ownership of `dup`.
    Ok(unsafe { OwnedHandle::from_raw_handle(dup) })
}

fn assert_still_inheritable(handle: &OwnedHandle, label: &str) {
    let mut flags = 0;
    // SAFETY: querying flags on a live owned handle.
    let ok = unsafe { GetHandleInformation(handle.as_raw_handle(), &mut flags) };
    assert_ne!(ok, 0, "{label}: handle was closed");
    assert_ne!(
        flags & HANDLE_FLAG_INHERIT,
        0,
        "{label}: inherit flag mutated"
    );
}

#[test]
fn startup_latch_is_one_shot_and_ignores_ordinary_argv() -> Check {
    let latch = AtomicBool::new(false);
    let normal = vec![OsString::from("se"), OsString::from("status")];
    assert!(dispatch_startup_entry(&normal, &latch).is_none());
    assert!(!latch.load(Ordering::Acquire));

    let bad_arity = vec![
        OsString::from("se"),
        OsString::from(CONSOLE_INTERRUPT_ENTRY),
    ];
    let first = dispatch_startup_entry(&bad_arity, &latch)
        .ok_or("private marker was ignored")?
        .err()
        .ok_or("missing request accepted")?;
    assert_eq!(first.code, ProcErrorCode::InvalidInput);

    let second = dispatch_startup_entry(&bad_arity, &latch)
        .ok_or("second private marker call returned None")?
        .err()
        .ok_or("second startup entry call succeeded")?;
    assert_eq!(second.code, ProcErrorCode::InvalidInput);
    assert!(format!("{:?}", second.detail).contains("startup entry may run only once"));
    Ok(())
}

#[test]
fn duplicate_and_non_inheritable_selectors_preserve_caller_handles() -> Check {
    let (reader, writer) = std::io::pipe()?;
    let r_owned = OwnedHandle::from(reader);
    let w_owned = OwnedHandle::from(writer);
    let h1 = dup_inheritable(r_owned.as_raw_handle())?;
    let h2 = dup_inheritable(w_owned.as_raw_handle())?;
    let root = current_process_identity(MachineId::new("interrupt-dup-test")?)
        .map_err(|e| format!("current_process_identity: {e:?}"))?;

    let dup_req = serde_json::json!({
        "root": &root,
        "root_handle": h1.as_raw_handle() as usize as u64,
        "job_handle": h1.as_raw_handle() as usize as u64,
    })
    .to_string();
    let err = run_console_interrupt(OsStr::new(&dup_req))
        .err()
        .ok_or("duplicate selectors accepted")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert_still_inheritable(&h1, "duplicate selectors");

    let non_inh_req = serde_json::json!({
        "root": &root,
        "root_handle": r_owned.as_raw_handle() as usize as u64,
        "job_handle": h2.as_raw_handle() as usize as u64,
    })
    .to_string();
    let err = run_console_interrupt(OsStr::new(&non_inh_req))
        .err()
        .ok_or("non-inheritable handle accepted")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    let mut flags = 0;
    // SAFETY: querying flags on a live owned handle.
    let ok = unsafe { GetHandleInformation(r_owned.as_raw_handle(), &mut flags) };
    assert_ne!(ok, 0, "non-inheritable handle was closed");
    assert_still_inheritable(&h2, "unused job handle");
    Ok(())
}

#[test]
fn non_job_pid_zero_and_inheritable_socket_refuse_before_duplication() -> Check {
    let (_, writer) = std::io::pipe()?;
    let w_owned = OwnedHandle::from(writer);
    let pipe_inh = dup_inheritable(w_owned.as_raw_handle())?;
    // SAFETY: `GetCurrentProcess` returns the constant current-process pseudo-handle.
    let proc_inh = dup_inheritable(unsafe { GetCurrentProcess() })?;
    let root = current_process_identity(MachineId::new("interrupt-kind-test")?)
        .map_err(|e| format!("current_process_identity: {e:?}"))?;

    let bad_job_req = serde_json::json!({
        "root": &root,
        "root_handle": proc_inh.as_raw_handle() as usize as u64,
        "job_handle": pipe_inh.as_raw_handle() as usize as u64,
    })
    .to_string();
    let err = run_console_interrupt(OsStr::new(&bad_job_req))
        .err()
        .ok_or("pipe accepted as job capability")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(format!("{:?}", err.detail).contains("the original inherited job capability"));

    let mut zero_root = root.clone();
    zero_root.pid = ProcessId(0);
    let zero_req = serde_json::json!({
        "root": &zero_root,
        "root_handle": pipe_inh.as_raw_handle() as usize as u64,
        "job_handle": proc_inh.as_raw_handle() as usize as u64,
    })
    .to_string();
    let err = run_console_interrupt(OsStr::new(&zero_req))
        .err()
        .ok_or("pid == 0 accepted")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(format!("{:?}", err.detail).contains("nonzero pid"));

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let raw_sock = listener.as_raw_socket() as *mut std::ffi::c_void;
    // SAFETY: setting HANDLE_FLAG_INHERIT on our live owned test socket; cleared below.
    let set_ok =
        unsafe { SetHandleInformation(raw_sock, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
    assert_ne!(set_ok, 0);
    let sock_req = serde_json::json!({
        "root": &root,
        "root_handle": raw_sock as usize as u64,
        "job_handle": pipe_inh.as_raw_handle() as usize as u64,
    })
    .to_string();
    let sock_res = run_console_interrupt(OsStr::new(&sock_req));
    // SAFETY: restoring non-inheritable flag on our live owned test socket.
    let restored = unsafe { SetHandleInformation(raw_sock, HANDLE_FLAG_INHERIT, 0) };
    assert_ne!(restored, 0, "socket handle was closed or corrupted");
    let err = sock_res
        .err()
        .ok_or("inheritable socket accepted as process capability")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(format!("{:?}", err.detail).contains("the original inherited process capability"));
    let _ = listener.local_addr()?;

    assert_still_inheritable(&proc_inh, "process");
    assert_still_inheritable(&pipe_inh, "pipe");
    Ok(())
}
