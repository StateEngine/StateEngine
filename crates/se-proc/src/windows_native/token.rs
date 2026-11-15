//! Aligned, bounded native token reads. The caller chooses the token class and
//! extent; this module owns only query storage, retries and returned-byte checks.
use crate::{
    ProcErrorCode, ProcResult,
    support::{input, native},
};
use std::{io, mem::size_of, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE},
    Security::{GetTokenInformation, TOKEN_INFORMATION_CLASS},
};

pub(crate) struct TokenBuffer {
    storage: Vec<usize>,
    pub used: usize,
}
impl TokenBuffer {
    pub fn as_ptr(&self) -> *const usize {
        self.storage.as_ptr()
    }
}
// Token queries use aligned owned buffers and bounded resizing: a token's
// variable data may change after the sizing probe. Never decode a short value.
pub(crate) fn token_buffer(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    minimum: usize,
    maximum: usize,
) -> ProcResult<TokenBuffer> {
    let mut needed = 0;
    // SAFETY: documented null sizing probe with retained token and writable length.
    unsafe {
        GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed);
    }
    for _ in 0..3 {
        let capacity = (needed as usize).max(minimum).saturating_add(256);
        if capacity > 65536 {
            return Err(input(
                "detached broker token",
                "native token buffer exceeds 64 KiB",
            ));
        }
        let mut storage = vec![0usize; capacity.div_ceil(size_of::<usize>())];
        let mut returned = 0;
        // SAFETY: aligned initialized allocation of at least capacity bytes;
        // the token and output length remain retained throughout this query.
        let ok = unsafe {
            GetTokenInformation(
                token,
                class,
                storage.as_mut_ptr().cast(),
                capacity as u32,
                &mut returned,
            )
        };
        if ok != 0 {
            if (returned as usize) < minimum
                || returned as usize > maximum
                || returned as usize > capacity
            {
                return Err(input(
                    "detached broker token",
                    &format!(
                        "class {class}: returned {returned} bytes, allowed {minimum}..={maximum}, capacity {capacity}"
                    ),
                ));
            }
            return Ok(TokenBuffer {
                storage,
                used: returned as usize,
            });
        }
        let cause = io::Error::last_os_error();
        if cause.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "read detached broker token context",
                cause,
            ));
        }
        needed = returned;
    }
    Err(input(
        "detached broker token",
        &format!("class {class}: size did not stabilize after three native reads"),
    ))
}
