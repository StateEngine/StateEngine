//! A repair may remove grants, but must not manufacture owner or SYSTEM access.
//! Require explicit unconditional full-control grants rather than inferring token
//! groups, evaluating conditional ACEs, or discarding a deny during replacement.
use super::{User, equal, security, sid};
use crate::state_files::{Result, io_error, unsafe_path};
use std::{fs::File, path::Path};
use windows_sys::Win32::{Security::*, Storage::FileSystem::*};

pub(super) fn require_existing_access(file: &File, path: &Path, directory: bool) -> Result<()> {
    let user = User::current(path)?;
    let system = sid("S-1-5-18", path)?;
    let descriptor = security(file, path, true)?;
    let dacl = descriptor.dacl().ok_or_else(|| {
        unsafe_path(
            "tighten-only repair requires explicit owner and SYSTEM full-control grants",
            path,
        )
    })?;
    let mut current = [0u32; 2];
    let mut inherited = [0u32; 2];
    for index in 0..dacl.len() {
        let entry = dacl
            .ace(index)
            .map_err(|e| io_error("read repair access grant", path, e))?;
        // Removing a deny or a conditional/object ACE can grant access that the
        // new unconditional DACL would otherwise appear merely to preserve.
        let ace = entry.allowed().ok_or_else(|| {
            unsafe_path(
                "tighten-only repair refuses deny or uninterpretable ACEs",
                path,
            )
        })?;
        let principal = (&ace.SidStart as *const u32).cast_mut().cast();
        // SAFETY: SID is embedded in the retained native ACE allocation.
        if unsafe { IsValidSid(principal) } == 0 {
            return Err(unsafe_path(
                "tighten-only repair requires valid grant SIDs",
                path,
            ));
        }
        let flags = u32::from(entry.header().AceFlags);
        if flags
            & !(OBJECT_INHERIT_ACE
                | CONTAINER_INHERIT_ACE
                | INHERIT_ONLY_ACE
                | NO_PROPAGATE_INHERIT_ACE
                | INHERITED_ACE)
            != 0
        {
            return Err(unsafe_path(
                "tighten-only repair refuses uninterpretable ACE flags",
                path,
            ));
        }
        let mut mask = ace.Mask;
        let mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };
        // SAFETY: native mapping reads a retained mapping and updates one mask.
        unsafe { MapGenericMask(&mut mask, &mapping) };
        for (slot, expected) in [user.sid(), system.0].into_iter().enumerate() {
            if equal(principal, expected) {
                if flags & INHERIT_ONLY_ACE == 0 {
                    current[slot] |= mask;
                }
                // Canonical directory grants propagate to both files and
                // directories without a depth limit; do not add that authority.
                if flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                    == OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                    && flags & NO_PROPAGATE_INHERIT_ACE == 0
                {
                    inherited[slot] |= mask;
                }
            }
        }
    }
    if current
        .into_iter()
        .any(|mask| mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS)
        || (directory
            && inherited
                .into_iter()
                .any(|mask| mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS))
    {
        return Err(unsafe_path(
            "documented DACL would add missing owner or SYSTEM access; tighten-only repair refused",
            path,
        ));
    }
    Ok(())
}
