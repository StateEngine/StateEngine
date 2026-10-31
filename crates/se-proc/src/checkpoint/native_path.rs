use se_types::PathEncoding;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
pub(super) fn encoded(path: &Path) -> Result<PathEncoding, &'static str> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() > 32768 || bytes.contains(&0) {
            return Err("invalid bounded native path bytes");
        }
        Ok(PathEncoding::UnixBytes(bytes.to_vec()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let units: Vec<_> = path.as_os_str().encode_wide().collect();
        if units.len() > 32768 || units.contains(&0) {
            return Err("invalid bounded native UTF-16 path");
        }
        Ok(PathEncoding::WindowsUtf16(units))
    }
}
pub(super) fn local(value: PathEncoding) -> Result<PathBuf, &'static str> {
    let path = match value {
        #[cfg(unix)]
        PathEncoding::UnixBytes(bytes) => {
            use std::os::unix::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_vec(bytes))
        }
        #[cfg(windows)]
        PathEncoding::WindowsUtf16(units) => {
            use std::os::windows::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_wide(&units))
        }
        _ => return Err("native custody path belongs to another OS encoding"),
    };
    encoded(&path)?;
    Ok(path)
}
pub fn serialize<S: serde::Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    encoded(path)
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}
pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
    local(PathEncoding::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}
