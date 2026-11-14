//! Scope a denied-access fixture to one thread without changing the process token.
use std::{
    marker::PhantomData,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    rc::Rc,
};
use windows_sys::Win32::{Foundation::*, Security::*, System::Threading::*};

pub struct WithoutPrivileges {
    previous: Option<OwnedHandle>,
    active: bool,
    _thread: PhantomData<Rc<()>>,
}
fn own(raw: HANDLE) -> OwnedHandle {
    // SAFETY: callers pass only a successful native token creation output.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}
impl WithoutPrivileges {
    pub fn enter() -> std::io::Result<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: current thread, read/duplicate/restore rights and writable token output.
        let present = unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                1,
                &mut raw,
            )
        };
        let previous = if present != 0 {
            Some(own(raw))
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
                return Err(error);
            }
            None
        };
        let process;
        let source = if let Some(token) = &previous {
            token.as_raw_handle()
        } else {
            // SAFETY: current process, query/duplicate rights and writable token output.
            if unsafe {
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw)
            } == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            process = own(raw);
            process.as_raw_handle()
        };
        // SAFETY: retained source token; create a private impersonation copy.
        if unsafe {
            DuplicateTokenEx(
                source,
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let private = own(raw);
        // SAFETY: disable privileges only on the unshared copy, including debug-DACL bypass.
        if unsafe {
            AdjustTokenPrivileges(
                private.as_raw_handle(),
                1,
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: attach the private token only to this thread; the guard cannot move threads.
        if unsafe { SetThreadToken(ptr::null(), private.as_raw_handle()) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            previous,
            active: true,
            _thread: PhantomData,
        })
    }
    pub fn restore(&mut self) -> std::io::Result<()> {
        if !self.active {
            return Ok(());
        }
        let token = self
            .previous
            .as_ref()
            .map_or(ptr::null_mut(), AsRawHandle::as_raw_handle);
        // SAFETY: restore the retained original token, or clear only this thread's impersonation.
        if unsafe { SetThreadToken(ptr::null(), token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for WithoutPrivileges {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("restore denied-peer fixture thread token: {error}");
        }
    }
}
