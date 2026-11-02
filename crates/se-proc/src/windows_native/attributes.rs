//! One aligned process-attribute allocation. Referenced arrays remain borrowed
//! until deletion; callers retain handles, startup data and all spawn policy.
//! https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
use super::{Error, Result, last};
use std::{marker::PhantomData, mem::size_of, ptr};
use windows_sys::Win32::{Foundation::HANDLE, System::Threading::*};

pub(crate) struct Attributes<'a> {
    storage: Vec<usize>,
    initialized: bool,
    _values: PhantomData<&'a [HANDLE]>,
}
impl<'a> Attributes<'a> {
    pub fn new(
        count: u32,
        size_operation: &'static str,
        init_operation: &'static str,
    ) -> Result<Self> {
        let mut bytes = 0;
        // SAFETY: documented sizing call uses a null list and writable size output.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut bytes) };
        if bytes == 0 {
            return Err(last(size_operation));
        }
        let mut list = Self {
            storage: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
            _values: PhantomData,
        };
        // SAFETY: retained usize storage has the required alignment and byte capacity.
        if unsafe { InitializeProcThreadAttributeList(list.pointer(), count, 0, &mut bytes) } == 0 {
            return Err(last(init_operation));
        }
        list.initialized = true;
        Ok(list)
    }
    pub fn set(
        &mut self,
        attribute: usize,
        values: &'a [HANDLE],
        operation: &'static str,
    ) -> Result<()> {
        // SAFETY: native input-only array is borrowed until this list is destroyed,
        // as required by UpdateProcThreadAttribute. No values are modified.
        if unsafe {
            UpdateProcThreadAttribute(
                self.pointer(),
                0,
                attribute,
                values.as_ptr().cast_mut().cast(),
                std::mem::size_of_val(values),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(Error {
                operation,
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }
    pub fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_ptr().cast_mut().cast()
    }
}
impl Drop for Attributes<'_> {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: this list was initialized and still owns its aligned backing storage.
            unsafe { DeleteProcThreadAttributeList(self.pointer()) };
        }
    }
}
