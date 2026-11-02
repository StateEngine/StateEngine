use std::ffi::c_void;
use windows_sys::Win32::Foundation::LocalFree;

/// One uniquely owned LocalFree-family allocation. Callers construct this only
/// from a native allocation output, including a null output on failure.
pub(crate) struct Allocation(pub(crate) *mut c_void);

impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this exact allocation was transferred by a LocalFree-family API.
            unsafe { LocalFree(self.0) };
        }
    }
}
