//! Deny-default repository reads; policy errors never fall back to an unrestricted Git.
use super::{invalid, runtime::Runtime};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString, c_char},
    io,
    path::Path,
};
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, error: *mut *mut c_char) -> i32;
    fn sandbox_free_error(error: *mut c_char);
}
fn quoted(path: &Path) -> io::Result<String> {
    let text = path
        .to_str()
        .filter(|s| s.len() <= 4096 && !s.contains('\0'))
        .ok_or_else(|| invalid("Git sandbox path must be bounded UTF-8"))?;
    let mut result = String::from("\"");
    for character in text.chars() {
        if character.is_control() {
            return Err(invalid("Git sandbox path contains control characters"));
        }
        if matches!(character, '\\' | '"') {
            result.push('\\')
        }
        result.push(character);
    }
    result.push('"');
    Ok(result)
}
pub(super) fn build(
    git: &Path,
    control: &Path,
    objects: &Path,
    runtime: &Runtime,
) -> io::Result<String> {
    runtime.check()?;
    let mut policy = String::from("(version 1)(deny default)(allow sysctl-read)");
    // A successful exec replaces this process. Fork remains denied; the only
    // executable name is this already-qualified image, under this same policy.
    policy.push_str(&format!("(allow process-exec (literal {}))", quoted(git)?));
    for root in [control, objects] {
        policy.push_str(&format!("(allow file-read* (subpath {}))", quoted(root)?));
    }
    let mut metadata = BTreeSet::new();
    for path in runtime.names() {
        policy.push_str(&format!(
            "(allow file-read* file-map-executable (literal {}))",
            quoted(path)?
        ));
        metadata.extend(path.ancestors().skip(1));
    }
    for path in [control, objects] {
        metadata.extend(path.ancestors().skip(1))
    }
    for path in metadata {
        policy.push_str(&format!(
            "(allow file-read-metadata (literal {}))",
            quoted(path)?
        ));
    }
    // The closed command explicitly disables user/system config with this sink.
    policy.push_str("(allow file-read-data file-read-metadata (literal \"/dev/null\"))");
    if policy.len() > 32_768 {
        return Err(invalid("Git sandbox policy exceeds its fixed bound"));
    }
    Ok(policy)
}
pub(super) fn apply(policy: &str) -> io::Result<()> {
    let policy = CString::new(policy).map_err(|_| invalid("Git sandbox policy contains NUL"))?;
    let mut error = std::ptr::null_mut();
    // SAFETY: terminated closed profile and valid native diagnostic output.
    let result = unsafe { sandbox_init(policy.as_ptr(), 0, &mut error) };
    if result == 0 {
        return Ok(());
    }
    let reason = if error.is_null() {
        "no native diagnostic".to_owned()
    } else {
        // SAFETY: sandbox_init owns the terminated diagnostic until it is freed.
        let diagnostic = unsafe { CStr::from_ptr(error) }.to_string_lossy();
        let text = if diagnostic.chars().count() > 512 {
            format!(
                "{} [diagnostic exceeded 512 characters]",
                diagnostic.chars().take(512).collect::<String>()
            )
        } else {
            diagnostic.into_owned()
        };
        // SAFETY: native diagnostic is released exactly once.
        unsafe { sandbox_free_error(error) };
        text
    };
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("Git filesystem sandbox refused: {reason}"),
    ))
}
