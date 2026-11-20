use std::ffi::c_void;
use windows_sys::Win32::Foundation::LocalFree;

/// One uniquely owned LocalFree-family allocation. Callers construct this only
/// from a native allocation output, including a null output on failure.
pub struct Allocation(*mut c_void);

impl Allocation {
    /// # Safety
    /// `raw` must be null or a uniquely owned LocalFree-family allocation.
    pub unsafe fn from_raw(raw: *mut c_void) -> Self {
        Self(raw)
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this exact allocation was transferred by a LocalFree-family API.
            unsafe { LocalFree(self.0) };
        }
    }
}
