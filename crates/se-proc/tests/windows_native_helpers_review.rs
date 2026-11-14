//! Public-consumer checks for the shared Windows security and launch mechanics.
//! Native Windows execution is required; a cross-check supplies no runtime grade.
#![cfg(windows)]
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_proc::{native_ipc::*, *};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{JobObjects::*, Pipes::*, SystemServices::JOB_OBJECT_QUERY, Threading::*},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn proc_error(error: ProcError) -> String {
    format!("{error:?}")
}
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn owned(raw: HANDLE) -> Check<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the successful native creation/query transferred this unique handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn new(text: &str) -> Check<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: NUL-terminated SDDL lives through the call and raw is writable.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(text)).as_ptr(),
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
        // SAFETY: this uniquely owned allocation came from the SDDL conversion API.
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Home(cleanup_directory::PrivateDirectory);
impl Home {
    fn new() -> Check<Self> {
        se_proc::initialize_file_creation_owner()?;
        let path = cleanup_directory::private_case_directory()?;
        drop(NativeStateFiles::create(&path)?);
        Ok(Self(path.cleanup_on_drop()))
    }
}
fn sid() -> Check<String> {
    match observe_ipc_self()?.principal() {
        IpcPrincipal::Windows { sid } => Ok(sid.clone()),
        _ => Err("Windows principal absent".into()),
    }
}
fn dacl(path: &Path, text: &str) -> Check {
    let descriptor = Descriptor::new(text)?;
    let (mut present, mut defaulted, mut acl) = (0, 0, ptr::null_mut());
    // SAFETY: descriptor owns the native ACL until SetNamedSecurityInfoW returns.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
        || acl.is_null()
    {
        return Err("fixture has no native DACL".into());
    }
    // SAFETY: the exact owned fixture path is terminated; acl remains retained above.
    let code = unsafe {
        SetNamedSecurityInfoW(
            wide(path.as_os_str()).as_ptr(),
            SE_FILE_OBJECT,
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
    Ok(())
}

#[test]
fn private_state_and_installation_records_keep_distinct_acl_policies() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open(&home.0)?;
    let user = sid()?;
    let path = home.0.join("installation.json");
    fs::write(&path, b"preserve original installation bytes")?;
    // The private store forbids every foreign grant; installation custody allows
    // foreign read-only grants and does not require a SYSTEM full-control ACE.
    for foreign in ["", "(A;;FR;;;WD)"] {
        dacl(&path, &format!("D:P(A;;FA;;;{user}){foreign}"))?;
        let mut record = OwnedFile::open(&path)?.ok_or("owned record absent")?;
        record.claim_installation_record()?;
        assert_eq!(record.read(128)?, b"preserve original installation bytes");
        drop(record);
        assert_eq!(
            files
                .readback(&path)
                .err()
                .ok_or("private read admitted installation-only DACL")?
                .code,
            StateFileErrorCode::LocationUnsafe
        );
    }
    dacl(
        &path,
        &format!("D:P(A;;FA;;;{user})(A;;FA;;;SY)(A;;FW;;;WD)"),
    )?;
    let mut record = OwnedFile::open(&path)?.ok_or("foreign-writable record disappeared")?;
    assert_eq!(
        record
            .claim_installation_record()
            .err()
            .ok_or("foreign writer admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    drop(record);
    assert_eq!(fs::read(&path)?, b"preserve original installation bytes");
    dacl(&path, &format!("D:P(A;;FA;;;{user})(A;;FA;;;SY)"))?;
    let mut bytes = Vec::new();
    files
        .readback(&path)?
        .ok_or("restored private record absent")?
        .read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"preserve original installation bytes");
    Ok(())
}

#[test]
fn ipc_keeps_its_current_user_only_policy_instead_of_the_store_system_exception() -> Check {
    let home = Home::new()?;
    let user = sid()?;
    for (index, extra) in ["", "(A;;GR;;;SY)"].iter().enumerate() {
        let name = format!(
            r"\\.\pipe\{}-{index}",
            home.0.file_name().ok_or("fixture leaf")?.to_string_lossy()
        );
        let descriptor = Descriptor::new(&format!("O:{user}D:P(A;;GA;;;{user}){extra}"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: terminated unique pipe name and retained descriptor/attributes.
        let pipe = owned(unsafe {
            CreateNamedPipeW(
                wide(OsStr::new(&name)).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                &attributes,
            )
        })?;
        let result = NativePipeStream::connect(
            OsStr::new(&name),
            IpcIoBound {
                deadline: Instant::now() + Duration::from_secs(5),
                cancelled: Arc::new(AtomicBool::new(false)),
            },
        );
        if extra.is_empty() {
            drop(result?);
        } else {
            assert_eq!(
                result.err().ok_or("IPC admitted a SYSTEM grant")?.code,
                IpcNativeErrorCode::UnsafeEndpoint
            );
        }
        drop(pipe);
        drop(NativePipeReservation::create(OsStr::new(&name))?);
    }
    Ok(())
}

struct Notices;
impl ExitSink for Notices {
    fn notify(&self, _: ExitNotice) {}
}
struct Scope<'a> {
    runtime: &'a NativeProcessRuntime,
    process: OwnedProcess,
    generation: GenerationId,
    released: bool,
}
impl Scope<'_> {
    fn wait_exit(&mut self) -> Check<StopWitness> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match self
                .runtime
                .witness_exit(&self.process)
                .map_err(proc_error)?
            {
                StopObservation::Complete(witness) => {
                    self.runtime
                        .release(&self.process, &witness)
                        .map_err(proc_error)?;
                    self.released = true;
                    return Ok(*witness);
                }
                _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                _ => return Err("exact launched scope did not exit".into()),
            }
        }
    }
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let cleanup = (|| -> Check {
            if let StopObservation::Complete(witness) = self
                .runtime
                .witness_exit(&self.process)
                .map_err(proc_error)?
            {
                self.runtime
                    .release(&self.process, &witness)
                    .map_err(proc_error)?;
                self.released = true;
                return Ok(());
            }
            let stop = self
                .runtime
                .prepare_stop(
                    &self.process,
                    self.generation,
                    Instant::now() + Duration::from_secs(5),
                )
                .map_err(proc_error)?;
            self.runtime
                .request_stop(stop)
                .map_err(proc_error)?
                .dispatch
                .map_err(proc_error)?;
            self.wait_exit()?;
            Ok(())
        })();
        if let Err(error) = cleanup {
            eprintln!("exact Windows native judge scope cleanup failed: {error}");
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn launched_child_has_only_explicit_stdio_and_starts_in_its_exact_job() -> Check {
    let home = Home::new()?;
    let executable = std::env::current_exe()?;
    let machine = MachineId::new("windows-native-helper-judge")?;
    let owner = current_process_identity(machine.clone()).map_err(proc_error)?;
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let host = HostInstanceId(nonce);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let runtime = NativeProcessRuntime::open(HostConfig {
        machine,
        instance: host,
        helper_executable: executable.clone(),
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 1,
            max_diagnostic_members: 4,
            max_observation_bytes: 65536,
            max_stdio_buffer_bytes: 4096,
        },
    })
    .map_err(proc_error)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: initialized native attributes create one uniquely owned manual-reset event.
    let excluded = owned(unsafe { CreateEventW(&attributes, 1, 0, ptr::null()) })?;
    // SAFETY: this live owned event has modify-state and synchronization access.
    assert_ne!(unsafe { SetEvent(excluded.as_raw_handle()) }, 0);
    assert_eq!(
        // SAFETY: observe our own event without waiting or transferring ownership.
        unsafe { WaitForSingleObject(excluded.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
    // SAFETY: reset our own event before testing child inheritance.
    assert_ne!(unsafe { ResetEvent(excluded.as_raw_handle()) }, 0);
    fs::write(home.0.join("stdin"), b"explicit input marker")?;
    let spec = LaunchSpec {
        executable_custody: None,
        lifecycle: lifecycle.clone(),
        generation,
        executable,
        arguments: vec![
            "--exact".into(),
            "windows_native_launch_child".into(),
            "--ignored".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        cwd: home.0.to_path_buf(),
        environment: Environment {
            entries: vec![
                (
                    "NATIVE_HELPER_JUDGE_ROOT".into(),
                    home.0.as_os_str().to_owned(),
                ),
                (
                    "NATIVE_HELPER_EXCLUDED_EVENT".into(),
                    (excluded.as_raw_handle() as usize).to_string().into(),
                ),
            ],
        },
        stdio: StandardIo {
            stdin: Some(File::open(home.0.join("stdin"))?),
            stdout: Some(File::create(home.0.join("stdout"))?),
            stderr: Some(File::create(home.0.join("stderr"))?),
        },
        mode: LaunchMode::Headless,
        window: None,
        policy: LaunchPolicy {
            containment: ContainmentRequirement::KernelScope,
            writes: WritePolicy::Workspace {
                roots: vec![home.0.to_path_buf()],
                scratch: home.0.to_path_buf(),
            },
            network: NetworkPolicy::Allow,
            hardening: OptionalHardening::Off,
        },
        deadline: Instant::now() + Duration::from_secs(15),
        notifications: Arc::new(Notices),
    };
    let prepared = runtime
        .prepare_launch(
            LaunchReservation {
                format_version: 1,
                lifecycle,
                host,
                owner,
                generation,
                scope_nonce: nonce,
                parent: ReservationParent::Windows,
                created_at_unix_ns: 1,
            },
            spec,
        )
        .map_err(proc_error)?;
    let ScopeIdentity::WindowsJob { name, .. } = &prepared.checkpoint.scope else {
        return Err("Windows job checkpoint absent".into());
    };
    fs::write(home.0.join("job-name"), name)?;
    let mut scope = Scope {
        runtime: &runtime,
        process: prepared.process,
        generation,
        released: false,
    };
    let ticket = match runtime.begin_launch(prepared.prepared) {
        LaunchStart::Pending { ticket, .. } => ticket,
        LaunchStart::Failed(failure) => {
            return Err(format!("native creation failed: {:?}", failure.error).into());
        }
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let record = loop {
        match runtime.poll_launch(&ticket).map_err(proc_error)? {
            LaunchProgress::Started(success) => break success.record,
            LaunchProgress::Pending if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5))
            }
            LaunchProgress::Failed(failure) => {
                return Err(format!("native launch failed: {:?}", failure.error).into());
            }
            _ => return Err("Windows launch did not publish its exact process record".into()),
        }
    };
    assert_eq!(record.entry, EntryMethod::WindowsJobList);
    assert_eq!(record.scope, prepared.checkpoint.scope);
    let witness = scope.wait_exit()?;
    assert!(
        matches!(
            witness.root,
            RootWitness::Identified {
                status: ExitStatus::Code(0),
                ..
            }
        ),
        "child failed: {} / {}",
        fs::read_to_string(home.0.join("stdout"))?,
        fs::read_to_string(home.0.join("stderr"))?
    );
    assert!(
        fs::read_to_string(home.0.join("stdout"))?.contains(&format!(
            "native stdout marker: pid={} exact job",
            record.root.pid.0
        ))
    );
    assert!(fs::read_to_string(home.0.join("stderr"))?.contains("native stderr marker"));
    assert_eq!(
        // SAFETY: the original parent event remains owned until after the child exited.
        unsafe { WaitForSingleObject(excluded.as_raw_handle(), 0) },
        WAIT_TIMEOUT,
        "unlisted inheritable parent event reached the child"
    );
    assert!(
        runtime
            .arena_snapshot()
            .map_err(proc_error)?
            .entries
            .is_empty()
    );
    Ok(())
}

#[test]
#[ignore = "Explicitly spawned by the public launch consumer with owned stdio/job/event fixtures"]
fn windows_native_launch_child() -> Check {
    let root =
        PathBuf::from(std::env::var_os("NATIVE_HELPER_JUDGE_ROOT").ok_or("child root absent")?);
    let job = fs::read_to_string(root.join("job-name"))?;
    // SAFETY: the parent supplies the exact public checkpoint name; this opens query-only custody.
    let job =
        owned(unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, wide(OsStr::new(&job)).as_ptr()) })?;
    let mut member = 0;
    assert_ne!(
        // SAFETY: current-process pseudo handle, retained query-only job and writable scalar output.
        unsafe { IsProcessInJob(GetCurrentProcess(), job.as_raw_handle(), &mut member) },
        0
    );
    assert_eq!(
        member, 1,
        "child reached its test body outside the exact prepared job"
    );
    let excluded: usize = std::env::var("NATIVE_HELPER_EXCLUDED_EVENT")?.parse()?;
    // SAFETY: the kernel validates this parent's handle selector; it is never adopted or closed.
    // If an ambient-inheritance regression leaks it, the parent observes this exact event becoming signalled.
    let _ = unsafe { SetEvent(excluded as HANDLE) };
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    assert_eq!(input, "explicit input marker");
    writeln!(
        std::io::stdout(),
        "native stdout marker: pid={} exact job",
        std::process::id()
    )?;
    writeln!(std::io::stderr(), "native stderr marker")?;
    Ok(())
}

#[path = "support/native_execution_boundary.rs"]
mod native_execution_boundary;
