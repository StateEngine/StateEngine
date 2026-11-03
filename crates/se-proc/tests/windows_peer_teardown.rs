//! Real process/pipe consumers; a cross-compile is not a native Windows grade.
#![cfg(windows)]
use se_proc::{native_ipc::*, *};
use std::{
    ffi::OsStr,
    io::{BufRead, Read, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    },
    process::{Child, Command, Stdio},
    ptr,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::*},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn owned(raw: HANDLE) -> Check<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful native creation transferred this unique reference.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn bound() -> IpcIoBound {
    IpcIoBound {
        deadline: Instant::now() + Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn new(sddl: &str) -> Check<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: NUL-terminated SDDL and writable owned-allocation output.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(sddl)).as_ptr(),
                1,
                &mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(raw))
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: this descriptor uniquely owns the LocalAlloc allocation.
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Client(Child);
impl Client {
    fn exit(&mut self) -> Check {
        drop(self.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.0.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                return Err("owned pipe child did not consume EOF".into());
            }
            std::thread::park_timeout(Duration::from_millis(5));
        }
        Ok(())
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        // The fixture's only wait is stdin EOF; never terminate another PID.
        if let Err(error) = self.exit() {
            eprintln!("owned pipe child cleanup: {error}");
        }
    }
}
struct PipeChild {
    server: OwnedHandle,
    client: Client,
    sid: String,
    duplicate: OwnedHandle,
}
impl PipeChild {
    fn new() -> Check<Self> {
        let IpcPrincipal::Windows { sid } = observe_ipc_self()?.principal().clone() else {
            return Err("missing SID".into());
        };
        let descriptor = Descriptor::new(&format!("O:{sid}D:P(A;;GA;;;{sid})"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let suffix = se_types::hex_lower(&random_secret()?.expose()[..12]);
        let name = format!(r"\\.\pipe\se-peer-teardown-{}-{suffix}", std::process::id());
        // SAFETY: private descriptor/name outlive creation; returned handle is owned below.
        let server = owned(unsafe {
            CreateNamedPipeW(
                wide(OsStr::new(&name)).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                &attributes,
            )
        })?;
        let mut child = Client(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "windows_pipe_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("SE_PEER_TEARDOWN_PIPE", &name)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        let stdout = child.0.stdout.take().ok_or("child stdout")?;
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                match line {
                    Ok(line) if line.contains("PIPE-HANDLE:") => {
                        let marker = line.find("PIPE-HANDLE:").unwrap_or_default();
                        let _ = send.send(line[marker..].to_owned());
                        break;
                    }
                    Err(_) => break,
                    _ => (),
                }
            }
        });
        let line = receive.recv_timeout(Duration::from_secs(15))?;
        let handle: usize = line
            .strip_prefix("PIPE-HANDLE:")
            .ok_or("child handle marker")?
            .parse()?;
        // SAFETY: the child has already opened this private instance, so this
        // call either acknowledges that connection or reports PIPE_CONNECTED.
        if unsafe { ConnectNamedPipe(server.as_raw_handle(), ptr::null_mut()) } == 0
            && std::io::Error::last_os_error().raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32)
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut duplicate = ptr::null_mut();
        // SAFETY: exact still-owned child handle and its explicitly published
        // pipe handle; the duplicate keeps the connected pipe alive after exit.
        if unsafe {
            DuplicateHandle(
                child.0.as_raw_handle(),
                handle as HANDLE,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let duplicate = owned(duplicate)?;
        let peer = observe_ipc_peer_bounded(server.as_handle(), IpcPeerSide::Client, &bound())?;
        assert_eq!(peer.pid(), child.0.id());
        Ok(Self {
            server,
            client: child,
            sid,
            duplicate,
        })
    }
}

#[test]
fn exited_pipe_peer_is_changed_even_when_its_process_pin_cannot_be_read() -> Check {
    let mut fixture = PipeChild::new()?;
    let pid = fixture.client.0.id();
    fixture.client.exit()?;
    // Release the last explicit process handle, retaining only the pipe ends.
    drop(fixture.client);
    let mut reported = 0;
    // SAFETY: retained connected server reference and writable PID output.
    let found =
        unsafe { GetNamedPipeClientProcessId(fixture.server.as_raw_handle(), &mut reported) };
    assert_ne!(found, 0);
    assert_eq!(reported, pid);
    let refusal =
        observe_ipc_peer_bounded(fixture.server.as_handle(), IpcPeerSide::Client, &bound())
            .err()
            .ok_or("exited peer was authenticated")?;
    println!(
        "exited pipe PID={pid}: {refusal}; native={:?}",
        refusal.source.raw_os_error()
    );
    assert_eq!(refusal.code, IpcNativeErrorCode::PeerChanged);
    drop(fixture.duplicate);
    Ok(())
}

#[test]
fn a_live_but_denied_peer_stays_unreadable_and_never_becomes_absent() -> Check {
    let mut fixture = PipeChild::new()?;
    let descriptor = Descriptor::new(&format!(
        "O:{}D:P(D;;0x00101000;;;{})(A;;GA;;;{})",
        fixture.sid, fixture.sid, fixture.sid
    ))?;
    let (mut present, mut defaulted, mut acl) = (0, 0, ptr::null_mut());
    // SAFETY: retained descriptor owns the ACL through SetSecurityInfo.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
        || acl.is_null()
    {
        return Err("fixture DACL missing".into());
    }
    // SAFETY: only the exact test child's process object is changed; its
    // already-owned handle and stdin EOF still permit natural cleanup.
    let code = unsafe {
        SetSecurityInfo(
            fixture.client.0.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null_mut(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(code as i32).into());
    }
    let refusal =
        observe_ipc_peer_bounded(fixture.server.as_handle(), IpcPeerSide::Client, &bound())
            .err()
            .ok_or("denied peer was authenticated")?;
    assert_eq!(refusal.code, IpcNativeErrorCode::Unreadable);
    assert_eq!(
        refusal.source.raw_os_error(),
        Some(ERROR_ACCESS_DENIED as i32)
    );
    let observed = read_process_until(
        se_types::MachineId::new("denied-pipe-child")?,
        ProcessId(fixture.client.0.id()),
        Instant::now() + Duration::from_millis(50),
    );
    let refusal = observed
        .err()
        .ok_or("access denial became a process fact")?;
    assert_eq!(refusal.code, ProcErrorCode::IdentityUnreadable);
    assert_eq!(
        refusal.native.as_ref().and_then(|cause| cause.code),
        Some(i64::from(ERROR_ACCESS_DENIED))
    );
    assert!(fixture.client.0.try_wait()?.is_none());
    fixture.client.exit()?;
    Ok(())
}

#[test]
fn bounded_read_joins_real_child_teardown_to_the_exact_native_exit() -> Check {
    for _ in 0..32 {
        let mut fixture = PipeChild::new()?;
        let machine = se_types::MachineId::new("bounded-teardown-child")?;
        let ProcessRead::Present(before) =
            read_process(machine.clone(), ProcessId(fixture.client.0.id()))
                .map_err(|e| format!("{e:?}"))?
        else {
            return Err("ready native child absent".into());
        };
        drop(fixture.client.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match read_process_until(machine.clone(), before.identity.pid, deadline)
                .map_err(|e| format!("{e:?}"))?
            {
                ProcessRead::Present(live) => {
                    assert_eq!(live.identity, before.identity);
                    if Instant::now() >= deadline {
                        return Err("child exit deadline".into());
                    }
                    std::thread::yield_now();
                }
                ProcessRead::ExitedRecord {
                    pid, start, status, ..
                } => {
                    assert_eq!(pid, before.identity.pid);
                    assert_eq!(start, before.identity.start);
                    assert_eq!(status, ExitStatus::Code(37));
                    break;
                }
                ProcessRead::Absent { .. } => {
                    return Err("the retained child object was falsely absent".into());
                }
            }
        }
        fixture.client.exit()?;
    }
    Ok(())
}

#[test]
#[ignore = "Spawned only by the real native peer teardown consumers"]
fn windows_pipe_child() -> Check {
    let name = std::env::var_os("SE_PEER_TEARDOWN_PIPE").ok_or("private pipe name")?;
    let stream = NativePipeStream::connect(&name, bound())?;
    println!("PIPE-HANDLE:{}", stream.channel().as_raw_handle() as usize);
    std::io::stdout().flush()?;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    std::process::exit(37);
}
