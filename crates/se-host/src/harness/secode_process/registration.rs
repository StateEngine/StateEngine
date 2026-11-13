//! Bounded, pinned reads of the public service registration format.
use super::unreadable as error;
use se_types::Result;

pub(crate) fn registration_fields(bytes: &[u8]) -> Result<std::collections::BTreeMap<&str, &str>> {
    let text = std::str::from_utf8(bytes).map_err(|e| error("SE Code registration", e))?;
    let lines = text
        .strip_suffix('\n')
        .ok_or_else(|| error("SE Code registration", "complete terminator absent"))?
        .split('\n')
        .collect::<Vec<_>>();
    let keys = [
        "slot",
        "instance",
        "environment",
        "generation",
        "pid",
        "endpoint",
        "version",
        "registered_at",
    ];
    if bytes.len() > 8512 || lines.len() != 9 || lines[0] != "secode-service/registration/1" {
        return Err(error(
            "SE Code registration",
            "unsupported or incomplete bounded registration",
        ));
    }
    let mut result = std::collections::BTreeMap::new();
    for (line, key) in lines[1..].iter().zip(keys) {
        let (found, value) = line
            .split_once('=')
            .ok_or_else(|| error("SE Code registration", "field delimiter absent"))?;
        if found != key
            || value.is_empty()
            || value.len() > 1024
            || value.contains('=')
            || value.chars().any(char::is_control)
        {
            return Err(error(
                "SE Code registration",
                "noncanonical registration field",
            ));
        }
        result.insert(key, value);
    }
    Ok(result)
}
pub(crate) fn service_registration(profile: &std::path::Path) -> Result<Option<Vec<u8>>> {
    let path = profile.join("registration");
    let Some(mut pin) =
        se_proc::NativeSourcePin::open(&path).map_err(|e| error("SE Code registration read", e))?
    else {
        return Ok(None);
    };
    let raw = pin
        .read_at(0, 8513)
        .map_err(|e| error("SE Code registration read", e))?;
    if !raw.end_of_file || raw.bytes.len() > 8512 {
        return Err(error(
            "SE Code registration read",
            "registration exceeds its complete-read bound",
        ));
    }
    pin.validate_path(&path)
        .map_err(|e| error("SE Code registration custody", e))?;
    registration_fields(&raw.bytes)?;
    Ok(Some(raw.bytes))
}
