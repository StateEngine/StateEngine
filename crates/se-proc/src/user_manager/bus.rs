//! Owned messages and bounded calls on the native user's private manager connection.
use super::symbols::*;
use std::{
    ffi::{CStr, CString, c_char, c_void},
    time::Instant,
};

pub(super) struct Bus<'a> {
    pub api: &'a Api,
    pub raw: Handle,
    deadline: Instant,
}
pub(super) struct Message<'a> {
    api: &'a Api,
    pub raw: Handle,
}

impl<'a> Bus<'a> {
    pub fn connect(
        api: &'a Api,
        address: &CStr,
        deadline: Instant,
        client: bool,
    ) -> Result<Self, String> {
        let mut raw = null();
        // SAFETY: exact native connection output, owned by the guard below.
        checked(unsafe { (api.new)(&mut raw) })?;
        let bus = Self { api, raw, deadline };
        // SAFETY: a retained connection and NUL-terminated native address; start queues nonblocking authentication.
        checked(unsafe { (api.address)(raw, address.as_ptr()) })?;
        // SAFETY: select peer or bus-daemon protocol before starting authentication.
        checked(unsafe { (api.client)(raw, i32::from(client)) })?;
        // SAFETY: FD passing is negotiated before this private Unix connection starts.
        checked(unsafe { (api.negotiate)(raw, 1) })?;
        // SAFETY: this new private peer connection is configured and uniquely owned.
        checked(unsafe { (api.start)(raw) })?;
        Ok(bus)
    }
    pub fn remaining(&self) -> Result<u64, String> {
        let left = self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_micros();
        if left == 0 {
            return Err("native manager admission deadline elapsed".into());
        }
        Ok(left.min(u64::MAX as u128) as u64)
    }
    pub fn request(
        &self,
        path: &CStr,
        interface: &CStr,
        member: &CStr,
    ) -> Result<Message<'a>, String> {
        self.request_to(c"org.freedesktop.systemd1", path, interface, member)
    }
    pub fn request_to(
        &self,
        destination: &CStr,
        path: &CStr,
        interface: &CStr,
        member: &CStr,
    ) -> Result<Message<'a>, String> {
        let mut raw = null();
        // SAFETY: retained connection, exact output, and four immutable terminated native names.
        checked(unsafe {
            (self.api.message)(
                self.raw,
                &mut raw,
                destination.as_ptr(),
                path.as_ptr(),
                interface.as_ptr(),
                member.as_ptr(),
            )
        })?;
        Ok(Message { api: self.api, raw })
    }
    pub fn call(&self, request: &Message<'_>) -> Result<Message<'a>, String> {
        let mut reply = null();
        let micros = self.remaining()?;
        // SAFETY: retained messages and connection, finite nonzero timeout, optional error storage omitted.
        checked(unsafe { (self.api.timeout)(self.raw, micros) })?;
        // SAFETY: exact reply output and an explicit deadline on this synchronous native call.
        checked(unsafe { (self.api.call)(self.raw, request.raw, micros, null(), &mut reply) })?;
        Ok(Message {
            api: self.api,
            raw: reply,
        })
    }
    pub fn property(
        &self,
        path: &CStr,
        interface: &CStr,
        name: &CStr,
        signature: &CStr,
    ) -> Result<Message<'a>, String> {
        let request = self.request(path, c"org.freedesktop.DBus.Properties", c"Get")?;
        request.string(b's', interface)?;
        request.string(b's', name)?;
        let reply = self.call(&request)?;
        reply.enter(b'v', signature)?;
        Ok(reply)
    }
    pub fn fd(&self) -> Result<i32, String> {
        // SAFETY: immutable descriptor query on the retained connection.
        checked(unsafe { (self.api.fd)(self.raw) })
    }
}
impl Message<'_> {
    pub fn uint(&self) -> Result<u32, String> {
        let mut value = 0u32;
        // SAFETY: exact writable 32-bit output for the native unsigned field.
        if checked(unsafe {
            (self.api.read)(self.raw, b'u' as c_char, (&mut value as *mut u32).cast())
        })? != 1
        {
            return Err("native manager reply integer is absent".into());
        }
        Ok(value)
    }
    pub fn string(&self, kind: u8, text: &CStr) -> Result<(), String> {
        // SAFETY: kind is a native string/object-path type and text is terminated.
        checked(unsafe { (self.api.append)(self.raw, kind as c_char, text.as_ptr().cast()) })?;
        Ok(())
    }
    pub fn descriptor(&self, fd: &i32) -> Result<(), String> {
        // SAFETY: the borrowed descriptor remains live; sd-bus duplicates its reference.
        checked(unsafe { (self.api.append)(self.raw, b'h' as c_char, (fd as *const i32).cast()) })?;
        Ok(())
    }
    pub fn open(&self, kind: u8, signature: &CStr) -> Result<(), String> {
        // SAFETY: literal container type/signature, retained writable native message.
        checked(unsafe { (self.api.open)(self.raw, kind as c_char, signature.as_ptr()) })?;
        Ok(())
    }
    pub fn close(&self) -> Result<(), String> {
        // SAFETY: this builder owns the last successfully opened container.
        checked(unsafe { (self.api.close)(self.raw) })?;
        Ok(())
    }
    pub fn enter(&self, kind: u8, signature: &CStr) -> Result<(), String> {
        // SAFETY: literal expected reply container and retained read cursor.
        if checked(unsafe { (self.api.enter)(self.raw, kind as c_char, signature.as_ptr()) })? != 1
        {
            return Err("native manager reply container is absent".into());
        }
        Ok(())
    }
    pub fn read_string(&self, kind: u8) -> Result<String, String> {
        let mut value = std::ptr::null();
        // SAFETY: exact pointer output for a native string/object-path field.
        if checked(unsafe {
            (self.api.read)(
                self.raw,
                kind as c_char,
                (&mut value as *mut *const c_char).cast(),
            )
        })? != 1
        {
            return Err("native manager reply string is absent".into());
        }
        text(value)
    }
    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        let mut data: *const c_void = std::ptr::null();
        let mut size = 0;
        // SAFETY: exact borrowed array pointer/size outputs; byte element type matches the native reply.
        if checked(unsafe { (self.api.array)(self.raw, b'y' as c_char, &mut data, &mut size) })?
            != 1
            || size != 16
            || data.is_null()
        {
            return Err("native unit invocation identity is not 16 bytes".into());
        }
        // SAFETY: the native message retains the exact validated byte extent.
        Ok(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) }.to_vec())
    }
}
impl Drop for Message<'_> {
    fn drop(&mut self) {
        // SAFETY: uniquely owned native message reference; its Api outlives it.
        unsafe {
            (self.api.message_unref)(self.raw);
        }
    }
}
impl Drop for Bus<'_> {
    fn drop(&mut self) {
        // SAFETY: uniquely owned connection; no flush or unbounded I/O during cleanup.
        unsafe {
            (self.api.unref)(self.raw);
        }
    }
}
pub(super) fn name(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|e| e.to_string())
}
