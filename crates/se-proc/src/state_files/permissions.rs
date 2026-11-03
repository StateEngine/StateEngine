//! Metadata-only repair custody. A permission snapshot is data, never authority
//! to open another object or to mutate its contents or ownership.
use super::Result;
#[cfg(any(target_os = "linux", windows))]
use super::effects::changed;
#[cfg(target_os = "linux")]
use super::unix::effects::permissions as os;
#[cfg(windows)]
use super::windows::effects::permissions as os;
#[cfg(not(any(target_os = "linux", windows)))]
use super::{StateFileErrorCode, failure};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PermissionKind {
    File,
    Directory,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum PermissionProtection {
    UnixMode { mode: u32, group: u32 },
    WindowsDacl { sddl: String, control: u16 },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionSnapshot {
    pub object: [u8; 32],
    pub owner: String,
    pub kind: PermissionKind,
    pub protection: PermissionProtection,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionRepairWitness {
    pub before: PermissionSnapshot,
    pub after: PermissionSnapshot,
}
pub struct PermissionRepairPin {
    path: PathBuf,
    observed: PermissionSnapshot,
    #[cfg(any(target_os = "linux", windows))]
    pin: os::Pin,
}
impl PermissionRepairPin {
    /// Absent is None. Links, unreadability and foreign ownership refuse.
    /// No content is read, and NativeStateFiles' protection policy is unchanged.
    pub fn open(path: &Path) -> Result<Option<Self>> {
        #[cfg(any(target_os = "linux", windows))]
        {
            let Some(pin) = os::Pin::open(path)? else {
                return Ok(None);
            };
            let observed = pin.snapshot()?;
            Ok(Some(Self {
                path: path.into(),
                observed,
                pin,
            }))
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        Err(failure(
            StateFileErrorCode::Unsupported,
            "permission repair requires Linux or Windows",
            path,
        ))
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn snapshot(&self) -> &PermissionSnapshot {
        &self.observed
    }

    /// Read-only native policy observation. Unreadable metadata and changed
    /// ownership remain errors; a readable loose mode/DACL is false.
    pub fn is_owner_only(&self) -> Result<bool> {
        #[cfg(any(target_os = "linux", windows))]
        {
            self.pin.check()?;
            let before = self.pin.snapshot()?;
            let private = self.pin.is_owner_only()?;
            self.pin.check()?;
            if before != self.pin.snapshot()? {
                return Err(changed(
                    "permission metadata changed during observation",
                    &self.path,
                ));
            }
            Ok(private)
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        Err(failure(
            StateFileErrorCode::Unsupported,
            "permission observation requires Linux or Windows",
            &self.path,
        ))
    }

    /// Compare on the held object and an independently reopened name before
    /// changing only permissions. A post-effect replacement is SourceChanged,
    /// not success: the original pinned object may already have been tightened.
    pub fn tighten_owner_only(
        &mut self,
        expected: &PermissionSnapshot,
    ) -> Result<PermissionRepairWitness> {
        #[cfg(any(target_os = "linux", windows))]
        {
            if &self.observed != expected || self.pin.snapshot()? != *expected {
                return Err(changed(
                    "expected permission or owner changed before repair",
                    &self.path,
                ));
            }
            self.pin.check()?;
            let before = Self::open(&self.path)?
                .ok_or_else(|| changed("permission repair target disappeared", &self.path))?;
            if before.snapshot() != expected {
                return Err(changed(
                    "named permission repair target changed",
                    &self.path,
                ));
            }
            self.pin.tighten(expected)?;
            self.pin.check()?;
            let after = Self::open(&self.path)?.ok_or_else(|| {
                changed(
                    "permission repair target disappeared after tightening",
                    &self.path,
                )
            })?;
            let actual = after.snapshot();
            if actual.object != expected.object
                || actual.owner != expected.owner
                || actual.kind != expected.kind
            {
                return Err(changed(
                    "permission repair name or owner changed after tightening",
                    &self.path,
                ));
            }
            after.pin.verify_private()?;
            self.observed = actual.clone();
            Ok(PermissionRepairWitness {
                before: expected.clone(),
                after: self.observed.clone(),
            })
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = expected;
            Err(failure(
                StateFileErrorCode::Unsupported,
                "permission repair requires Linux or Windows",
                &self.path,
            ))
        }
    }
}
