//! Hosted probe instrumentation. This module is absent from ordinary builds.
use se_atlas::errors::AtlasResult;
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

pub(crate) fn hold_finalization(home: &Path) -> AtlasResult<()> {
    if !home
        .join("watch-probe")
        .try_exists()
        .map_err(crate::atlas_cold::failure)?
    {
        return Ok(());
    }
    fs::write(home.join("watch-probe-arrived"), []).map_err(crate::atlas_cold::failure)?;
    let end = Instant::now() + Duration::from_secs(30);
    while !home
        .join("watch-probe-release")
        .try_exists()
        .map_err(crate::atlas_cold::failure)?
    {
        if Instant::now() >= end {
            return Err(crate::atlas_cold::failure(
                "watch probe finalization timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn event(
    source: &se_atlas::source::RegisteredSource<crate::atlas_source::NativeAtlasSource>,
    kind: &str,
) -> AtlasResult<bool> {
    let home = source
        .scope
        .registration
        .cache
        .directory
        .ancestors()
        .nth(2)
        .ok_or_else(|| crate::atlas_cold::failure("watch probe home absent"))?;
    let fault = match fs::read_to_string(home.join("watch-probe")) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(crate::atlas_cold::failure(error)),
    };
    fs::write(home.join(format!("watch-probe-saw-{kind}")), [])
        .map_err(crate::atlas_cold::failure)?;
    Ok(fault == kind)
}
