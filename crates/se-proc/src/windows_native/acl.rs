//! Descriptor ownership and borrowed ACL traversal, without caller policy.
use super::allocation::Allocation;
use std::{io, marker::PhantomData, mem::size_of, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, HANDLE},
    Security::{Authorization::*, *},
    System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE},
};

pub(crate) struct SecurityDescriptor {
    allocation: Allocation,
    pub owner: PSID,
    dacl: *mut ACL,
    sacl: *mut ACL,
}

impl SecurityDescriptor {
    pub fn query(handle: HANDLE, kind: SE_OBJECT_TYPE, information: u32) -> io::Result<Self> {
        let (mut owner, mut dacl, mut sacl, mut raw) = (
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        // SAFETY: caller retains a readable native object; all outputs start null.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                kind,
                information,
                if information & OWNER_SECURITY_INFORMATION != 0 {
                    &mut owner
                } else {
                    ptr::null_mut()
                },
                ptr::null_mut(),
                if information & DACL_SECURITY_INFORMATION != 0 {
                    &mut dacl
                } else {
                    ptr::null_mut()
                },
                if information & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION) != 0 {
                    &mut sacl
                } else {
                    ptr::null_mut()
                },
                &mut raw,
            )
        };
        let allocation = Allocation(raw);
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Self {
            allocation,
            owner,
            dacl,
            sacl,
        })
    }

    pub fn named_owner(name: &[u16]) -> io::Result<Self> {
        let (mut owner, mut raw) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: caller supplies a retained terminated native name; only owner is requested.
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut raw,
            )
        };
        let allocation = Allocation(raw);
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(Self {
            allocation,
            owner,
            dacl: ptr::null_mut(),
            sacl: ptr::null_mut(),
        })
    }

    pub fn control(&self) -> io::Result<u16> {
        let (mut control, mut revision) = (0, 0);
        // SAFETY: successful native descriptor remains owned through this query.
        if unsafe { GetSecurityDescriptorControl(self.allocation.0, &mut control, &mut revision) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(control)
    }

    pub fn dacl(&self) -> Option<Acl<'_>> {
        self.acl(self.dacl)
    }
    pub fn sacl(&self) -> Option<Acl<'_>> {
        self.acl(self.sacl)
    }

    fn acl(&self, raw: *mut ACL) -> Option<Acl<'_>> {
        // SAFETY: a non-null pointer belongs to this retained successful descriptor.
        if raw.is_null() || unsafe { IsValidAcl(raw) } == 0 {
            return None;
        }
        Some(Acl {
            raw,
            _descriptor: PhantomData,
        })
    }
}

pub(crate) struct Acl<'a> {
    raw: *mut ACL,
    _descriptor: PhantomData<&'a SecurityDescriptor>,
}
impl Acl<'_> {
    pub fn len(&self) -> u16 {
        // SAFETY: construction validated the ACL and the descriptor borrow keeps it alive.
        unsafe { (*self.raw).AceCount }
    }
    pub fn ace(&self, index: u16) -> io::Result<Ace<'_>> {
        let mut raw = ptr::null_mut();
        // SAFETY: retained valid ACL and native checked index, with writable ACE output.
        if unsafe { GetAce(self.raw, u32::from(index), &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Ace {
            raw,
            _acl: PhantomData,
        })
    }
}
pub(crate) struct Ace<'a> {
    raw: *mut std::ffi::c_void,
    _acl: PhantomData<&'a ACL>,
}
impl Ace<'_> {
    pub fn header(&self) -> &ACE_HEADER {
        // SAFETY: successful GetAce supplies a header within the borrowed valid ACL.
        unsafe { &*self.raw.cast::<ACE_HEADER>() }
    }
    pub fn allowed(&self) -> Option<&ACCESS_ALLOWED_ACE> {
        if u32::from(self.header().AceType) != ACCESS_ALLOWED_ACE_TYPE
            || usize::from(self.header().AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
        {
            return None;
        }
        // SAFETY: native header type/extent establish this layout inside the borrowed ACL.
        Some(unsafe { &*self.raw.cast::<ACCESS_ALLOWED_ACE>() })
    }
    pub fn mandatory_label(&self) -> Option<&SYSTEM_MANDATORY_LABEL_ACE> {
        if u32::from(self.header().AceType) != SYSTEM_MANDATORY_LABEL_ACE_TYPE
            || usize::from(self.header().AceSize) < size_of::<SYSTEM_MANDATORY_LABEL_ACE>()
        {
            return None;
        }
        // SAFETY: native header type/extent establish this layout inside the borrowed ACL.
        Some(unsafe { &*self.raw.cast::<SYSTEM_MANDATORY_LABEL_ACE>() })
    }
}
