//! Native fixtures for private policy checks. No production exports or policy substitutes.
use std::{
    ffi::{OsStr, OsString},
    fs,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Console::*, Threading::*},
};
pub(crate) type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(crate) fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}
pub(crate) fn own(raw: HANDLE) -> Check<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: caller transfers a successful native allocation exactly once.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
pub(crate) struct Descriptor(pub(crate) PSECURITY_DESCRIPTOR);
impl Descriptor {
    pub(crate) fn new(text: &str) -> Check<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: retained terminated input and writable LocalFree output.
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
    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
    pub(crate) fn acl(&self, sacl: bool) -> Check<*mut ACL> {
        let (mut present, mut defaulted, mut acl) = (0, 0, ptr::null_mut());
        // SAFETY: self retains a valid descriptor and all outputs are writable.
        let ok = unsafe {
            if sacl {
                GetSecurityDescriptorSacl(self.0, &mut present, &mut acl, &mut defaulted)
            } else {
                GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted)
            }
        };
        if ok == 0 || present == 0 || acl.is_null() {
            return Err("fixture ACL absent".into());
        }
        Ok(acl)
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: unique allocation returned by SDDL conversion.
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub(crate) fn user() -> Check<String> {
    // SAFETY: current-process pseudo handle is always valid for token query.
    unsafe { se_native_ipc::windows_process::process_sid(GetCurrentProcess()) }
        .map_err(|e| format!("{}: {}", e.operation, e.source).into())
}
pub(crate) struct Home(pub(crate) PathBuf);
impl Home {
    pub(crate) fn new() -> Check<Self> {
        se_state_files::initialize_file_creation_owner()?;
        let parent = std::env::temp_dir();
        for _ in 0..32 {
            let mut nonce = [0u8; 4];
            se_state_files::fill_entropy(&mut nonce)?;
            let root = parent.join(se_types::hex_lower(&nonce));
            let mut custody = se_state_files::NativeDirectoryCreation::begin();
            match custody.create(&root) {
                Ok(files) => drop(files),
                Err(error) => {
                    for _ in custody.rollback() {}
                    return Err(error.into());
                }
            }
            if custody.paths().contains(&root) {
                drop(se_state_files::NativeStateFiles::create(&root)?);
                return Ok(Self(root));
            }
        }
        Err("no fresh private fixture directory was created".into())
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
pub(crate) fn event() -> Check<OwnedHandle> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: creates an unnamed inheritable, initially unsignaled manual-reset event.
    own(unsafe { CreateEventW(&attributes, 1, 0, ptr::null()) })
}
pub(crate) fn signaled(event: &OwnedHandle) -> Check<bool> {
    // SAFETY: retained event and zero-time observation.
    match unsafe { WaitForSingleObject(event.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(std::io::Error::last_os_error().into()),
    }
}
pub(crate) fn flags(raw: HANDLE) -> Check<u32> {
    let mut flags = 0;
    // SAFETY: borrowed live handle and writable flag output.
    if unsafe { GetHandleInformation(raw, &mut flags) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(flags)
}
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ChildPlan {
    pub(crate) report: PathBuf,
    pub(crate) excluded: usize,
    pub(crate) allowed: Option<usize>,
    pub(crate) input: Option<usize>,
    pub(crate) claim: Option<(u32, u32, u32)>,
}
pub(crate) const CHILD: &str = "windows_policy_fixture::inherited_child";
pub(crate) fn child_args(plan: &ChildPlan) -> Check<Vec<OsString>> {
    // --skip is an accepted libtest argument: it transports data without changing
    // global environment or adding arguments that the test harness would reject.
    Ok(vec![
        "--exact".into(),
        CHILD.into(),
        "--ignored".into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
        "--skip".into(),
        serde_json::to_string(plan)?.into(),
    ])
}
pub(crate) fn file_key(raw: HANDLE) -> Check<(u32, u32, u32)> {
    // SAFETY: native POD output is initialized before query.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: borrowed file handle and exact writable output.
    if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}
// Query only our own process. This is an independent child-table observation,
// needed because install-hold intentionally keeps the duplicate's value private.
fn owns_claim(key: (u32, u32, u32)) -> Check<bool> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Entry {
        handle: HANDLE,
        handles: usize,
        pointers: usize,
        access: u32,
        kind: u32,
        attributes: u32,
        reserved: u32,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process: HANDLE,
            class: u32,
            buffer: *mut std::ffi::c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut storage = vec![0usize; 128];
    loop {
        let mut needed = 0;
        // SAFETY: aligned writable bounded buffer and immutable current-process handle.
        let status = unsafe {
            NtQueryInformationProcess(
                GetCurrentProcess(),
                51,
                storage.as_mut_ptr().cast(),
                (storage.len() * size_of::<usize>()) as u32,
                &mut needed,
            )
        };
        if status == 0 {
            let count = storage[0];
            let bytes = storage.len() * size_of::<usize>();
            if count > 4096 || 2 * size_of::<usize>() + count * size_of::<Entry>() > bytes {
                return Err("invalid own-process handle snapshot".into());
            }
            for i in 0..count {
                // SAFETY: the validated native count bounds each aligned entry inside retained storage.
                let entry =
                    unsafe { ptr::read_unaligned(storage.as_ptr().add(2).cast::<Entry>().add(i)) };
                if file_key(entry.handle).is_ok_and(|actual| actual == key) {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        if status as u32 != 0xc0000004 || needed as usize > 1024 * 1024 {
            return Err(format!("own handle snapshot refused: {status:#x}, bytes={needed}").into());
        }
        let next = (needed as usize)
            .div_ceil(size_of::<usize>())
            .max(storage.len() * 2);
        if next * size_of::<usize>() > 1024 * 1024 {
            return Err("own handle snapshot exceeds bound".into());
        }
        storage.resize(next, 0);
    }
}
#[test]
#[ignore = "spawned only by the native inheritance parents with an owned plan"]
fn inherited_child() -> Check {
    let args: Vec<_> = std::env::args().collect();
    let i = args
        .iter()
        .position(|arg| arg == "--skip")
        .ok_or("missing child plan")?;
    let plan: ChildPlan = serde_json::from_str(args.get(i + 1).ok_or("missing plan bytes")?)?;
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: native standard-handle selectors; query only this child's table.
        flags(unsafe { GetStdHandle(which) })?;
    }
    if let Some(input) = plan.input {
        assert_eq!(
            // SAFETY: native standard-input selector; parent gave this exact inherited event.
            unsafe { GetStdHandle(STD_INPUT_HANDLE) } as usize,
            input,
            "explicit stdin changed"
        );
        assert_ne!(
            // SAFETY: exact explicitly inherited input event supplied in the plan.
            unsafe { SetEvent(input as HANDLE) },
            0,
            "explicit stdin was not usable"
        );
    }
    if let Some(key) = plan.claim {
        assert!(
            owns_claim(key)?,
            "explicit install claim missing from child handle table"
        );
    }
    if let Some(allowed) = plan.allowed {
        assert_ne!(
            // SAFETY: parent supplied the exact explicitly inherited event handle.
            unsafe { SetEvent(allowed as HANDLE) },
            0,
            "explicit uninstall handle missing"
        );
    }
    // A raw value can be reused in a child. The parent checks the original event
    // object, so a child-side invalid-handle result is never the exclusion proof.
    // SAFETY: SetEvent validates a possibly absent handle without dereferencing it.
    unsafe {
        SetEvent(plan.excluded as HANDLE);
    }
    fs::write(
        plan.report,
        b"stdio and explicit handles observed in actual child",
    )?;
    Ok(())
}
pub(crate) fn report(plan: &ChildPlan, excluded: &OwnedHandle) -> Check {
    assert_eq!(
        fs::read(&plan.report)?,
        b"stdio and explicit handles observed in actual child"
    );
    assert!(
        !signaled(excluded)?,
        "unlisted inheritable event leaked into spawned child"
    );
    Ok(())
}
