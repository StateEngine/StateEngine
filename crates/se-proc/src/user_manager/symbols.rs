//! Optional native bus ABI. Linux machines without the library keep session hosts.
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr,
};

pub(super) type Handle = *mut c_void;
// One declaration supplies each field and its loader signature together.
macro_rules! native_api {
    ($($field:ident: $symbol:literal => $signature:ty),+ $(,)?) => {
        pub(super) struct Api {
            library: Handle,
            $(pub $field: $signature,)+
        }
        impl Api {
            pub fn load() -> Option<Self> {
                // SAFETY: literal native library name and supported loader flags.
                let library = unsafe { libc::dlopen(c"libsystemd.so.0".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
                if library.is_null() { return None; }
                $(
                    // SAFETY: the live library owns this stable ABI symbol until Api drops.
                    let address = unsafe { libc::dlsym(library, concat!($symbol, "\0").as_ptr().cast()) };
                    if address.is_null() {
                        // SAFETY: no native references have escaped this load.
                        unsafe { libc::dlclose(library); }
                        return None;
                    }
                    // SAFETY: the declaration supplies the exact documented native ABI.
                    let $field = unsafe { std::mem::transmute::<*mut c_void, $signature>(address) };
                )+
                Some(Self { library, $($field,)+ })
            }
        }
    };
}
native_api! {
    new: "sd_bus_new" => unsafe extern "C" fn(*mut Handle) -> c_int,
    address: "sd_bus_set_address" => unsafe extern "C" fn(Handle, *const c_char) -> c_int,
    start: "sd_bus_start" => unsafe extern "C" fn(Handle) -> c_int,
    negotiate: "sd_bus_negotiate_fds" => unsafe extern "C" fn(Handle, c_int) -> c_int,
    fd: "sd_bus_get_fd" => unsafe extern "C" fn(Handle) -> c_int,
    timeout: "sd_bus_set_method_call_timeout" => unsafe extern "C" fn(Handle, u64) -> c_int,
    unref: "sd_bus_unref" => unsafe extern "C" fn(Handle) -> Handle,
    message: "sd_bus_message_new_method_call" => unsafe extern "C" fn(Handle, *mut Handle, *const c_char, *const c_char, *const c_char, *const c_char) -> c_int,
    append: "sd_bus_message_append_basic" => unsafe extern "C" fn(Handle, c_char, *const c_void) -> c_int,
    open: "sd_bus_message_open_container" => unsafe extern "C" fn(Handle, c_char, *const c_char) -> c_int,
    close: "sd_bus_message_close_container" => unsafe extern "C" fn(Handle) -> c_int,
    call: "sd_bus_call" => unsafe extern "C" fn(Handle, Handle, u64, Handle, *mut Handle) -> c_int,
    read: "sd_bus_message_read_basic" => unsafe extern "C" fn(Handle, c_char, *mut c_void) -> c_int,
    array: "sd_bus_message_read_array" => unsafe extern "C" fn(Handle, c_char, *mut *const c_void, *mut usize) -> c_int,
    enter: "sd_bus_message_enter_container" => unsafe extern "C" fn(Handle, c_char, *const c_char) -> c_int,
    message_unref: "sd_bus_message_unref" => unsafe extern "C" fn(Handle) -> Handle,
}
impl Drop for Api {
    fn drop(&mut self) {
        // SAFETY: dependent messages/connections borrow Api and have already dropped.
        unsafe {
            libc::dlclose(self.library);
        }
    }
}
pub(super) fn checked(value: c_int) -> Result<c_int, String> {
    if value < 0 {
        Err(std::io::Error::from_raw_os_error(-value).to_string())
    } else {
        Ok(value)
    }
}
pub(super) fn text(value: *const c_char) -> Result<String, String> {
    if value.is_null() {
        return Err("native manager returned an absent string".into());
    }
    // SAFETY: successful sd-bus string reads borrow a validated NUL-terminated message field.
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    if bytes.len() > 4096 {
        return Err("native manager string exceeds 4096 bytes".into());
    }
    String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())
}
pub(super) fn null() -> Handle {
    ptr::null_mut()
}
