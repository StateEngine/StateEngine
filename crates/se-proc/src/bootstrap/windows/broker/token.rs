//! Native token context; broker children must preserve effective group and privilege rights.
use super::*;
use windows_sys::Win32::Security::*;

#[derive(Clone, Eq, PartialEq)]
pub(in crate::bootstrap::windows) struct Context {
    user: (String, u32),
    logon: (u32, i32),
    session: u32,
    elevation: i32,
    integrity: String,
    groups: Vec<(String, u32)>,
    privileges: Vec<(u32, i32, u32)>,
}
struct TokenBuffer {
    storage: Vec<usize>,
    used: usize,
}
impl TokenBuffer {
    fn as_ptr(&self) -> *const usize {
        self.storage.as_ptr()
    }
}
// Token queries use aligned owned buffers and bounded resizing: a token's
// variable data may change after the sizing probe. Never decode a short value.
fn token_buffer(
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
            return Err(fail("read detached broker token context", cause));
        }
        needed = returned;
    }
    Err(input(
        "detached broker token",
        &format!("class {class}: size did not stabilize after three native reads"),
    ))
}
// Private callers instantiate this only with fixed-size, pointer-free native token POD.
fn token_value<T: Copy>(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> ProcResult<T> {
    let storage = token_buffer(token, class, size_of::<T>(), size_of::<T>())?;
    // SAFETY: successful native query initialized at least sizeof(T) bytes;
    // usize allocation aligns every fixed token POD used by these private callers.
    Ok(unsafe { *storage.as_ptr().cast::<T>() })
}
pub(in crate::bootstrap::windows) fn context(process: HANDLE) -> ProcResult<Context> {
    let mut raw = ptr::null_mut();
    // SAFETY: retained process and writable owned token output, query access only.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("open detached broker token"));
    }
    let token = handle(raw, "own detached broker token")?;
    token_context(token.as_raw_handle())
}
fn token_context(token: HANDLE) -> ProcResult<Context> {
    // UAC-filtered tokens are normal interactive users. Only actual restricting
    // SIDs or an app-container boundary refuse; elevation/integrity still match.
    // SAFETY: clearing this thread's last-error distinguishes FALSE from failure.
    unsafe {
        SetLastError(ERROR_SUCCESS);
    }
    // SAFETY: retained TOKEN_QUERY handle for a read-only native restriction query.
    let restricted = unsafe { IsTokenRestricted(token) };
    if restricted == 0 {
        let cause = io::Error::last_os_error();
        if cause.raw_os_error() != Some(ERROR_SUCCESS as i32) {
            return Err(fail("read detached broker restricting SIDs", cause));
        }
    }
    if restricted != 0 || token_value::<u32>(token, TokenIsAppContainer)? != 0 {
        return Err(input(
            "detached broker token",
            "restricted and app-container tokens cannot use a native parent broker",
        ));
    }
    let stats: TOKEN_STATISTICS = token_value(token, TokenStatistics)?;
    let buffer = token_buffer(
        token,
        TokenIntegrityLevel,
        size_of::<TOKEN_MANDATORY_LABEL>(),
        65536,
    )?;
    // SAFETY: successful aligned label output remains retained through SID conversion.
    let integrity = crate::windows_native::sid_text(unsafe {
        (*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid
    })
    .map_err(|e| fail(e.operation, e.source))?;
    Ok(Context {
        user: {
            let buffer = token_buffer(token, TokenUser, size_of::<TOKEN_USER>(), 65536)?;
            // SAFETY: successful native TOKEN_USER output and its pointed SID remain retained.
            let user = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User };
            (
                crate::windows_native::sid_text(user.Sid)
                    .map_err(|e| fail(e.operation, e.source))?,
                user.Attributes,
            )
        },
        logon: (
            stats.AuthenticationId.LowPart,
            stats.AuthenticationId.HighPart,
        ),
        session: token_value(token, TokenSessionId)?,
        elevation: token_value(token, TokenElevationType)?,
        integrity,
        groups: groups(token)?,
        privileges: privileges(token)?,
    })
}

fn groups(token: HANDLE) -> ProcResult<Vec<(String, u32)>> {
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let buffer = token_buffer(token, TokenGroups, offset, 65536)?;
    // SAFETY: successful native header output occupies the retained aligned buffer.
    let count = unsafe { (*buffer.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount } as usize;
    let bytes = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|n| offset.checked_add(n))
        .ok_or_else(|| input("detached broker groups", "native group count overflow"))?;
    if bytes > buffer.used {
        return Err(input(
            "detached broker groups",
            "native group array exceeds returned bytes",
        ));
    }
    // SAFETY: checked array extent and native offset/alignment; SID storage remains retained.
    let values = unsafe {
        std::slice::from_raw_parts(
            buffer
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let mut result = Vec::with_capacity(count);
    for value in values {
        result.push((
            crate::windows_native::sid_text(value.Sid).map_err(|e| fail(e.operation, e.source))?,
            value.Attributes,
        ));
    }
    result.sort();
    Ok(result)
}
fn privileges(token: HANDLE) -> ProcResult<Vec<(u32, i32, u32)>> {
    let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let buffer = token_buffer(token, TokenPrivileges, offset, 65536)?;
    // SAFETY: successful native header output occupies the retained aligned buffer.
    let count = unsafe { (*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>()).PrivilegeCount } as usize;
    let bytes = count
        .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|n| offset.checked_add(n))
        .ok_or_else(|| {
            input(
                "detached broker privileges",
                "native privilege count overflow",
            )
        })?;
    if bytes > buffer.used {
        return Err(input(
            "detached broker privileges",
            "native privilege array exceeds returned bytes",
        ));
    }
    // SAFETY: checked array extent and native offset/alignment in the retained output.
    let values = unsafe {
        std::slice::from_raw_parts(
            buffer
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<LUID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let mut result: Vec<_> = values
        .iter()
        .map(|value| {
            (
                value.Luid.LowPart,
                value.Luid.HighPart,
                value.Attributes & !SE_PRIVILEGE_USED_FOR_ACCESS,
            )
        })
        .collect();
    result.sort();
    Ok(result)
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;
