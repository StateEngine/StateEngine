//! Owner-only release CAS; native source and unknown population remain intact.
use super::*;
/// The owner's release of an uncontained StopUnproved process whose stop
/// could not be proved: its custody must retain the native source and carry an
/// ownership release for this lifecycle, host generation and resulting
/// revision. The state stays StopUnproved; no exit is invented.
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    p: &[u8],
    old: &ProcessIdentityRecord,
    identity: &ProcessIdentityRecord,
    rev: u64,
    lease: &LeaseIdentity,
) -> StoreResult<()> {
    let refuse = |why: &str| {
        Err(fail(
            StoreErrorCode::InvalidTransition,
            format!(
                "StopUnproved to StopUnproved is only the owner's uncontained ownership release: {why}"
            ),
        ))
    };
    if !super::project::is_owner(c, h, p)? {
        return refuse("the actor is not the project owner");
    }
    // Both the recorded and the new containment: a contained process cannot
    // be re-described as uncontained to claim a release.
    if !matches!(old.containment, ContainmentFact::Uncontained { .. })
        || !matches!(identity.containment, ContainmentFact::Uncontained { .. })
    {
        return refuse("the process is not an uncontained tracked group");
    }
    // se-proc owns the custody codec and se-store does not link it; read only
    // the release marker fields that section 20 says the store projects.
    let v: Value = serde_json::from_slice(&identity.custody.record).map_err(|e| {
        invalid(format!(
            "release custody is not the versioned JSON record: {e}"
        ))
    })?;
    let lifecycle = serde_json::to_value(&identity.record).map_err(invalid)?;
    let checkpoint = &v["checkpoint"];
    if identity.custody.format_version != 1 || v["lifecycle"] != lifecycle {
        return refuse("custody is not this lifecycle's version-1 checkpoint");
    }
    let marker = match checkpoint["kind"].as_str() {
        Some("process") => &checkpoint["value"]["ownership_release"],
        Some("released") => {
            let previous: Value = serde_json::from_slice(&old.custody.record)
                .map_err(|e| invalid(format!("recorded release source is not JSON: {e}")))?;
            let source = &checkpoint["value"]["source"];
            if !matches!(
                source["kind"].as_str(),
                Some("reservation" | "scope" | "root" | "process")
            ) || *source != previous["checkpoint"]
                || [
                    "format_version",
                    "lifecycle",
                    "principal",
                    "session",
                    "root_identity",
                ]
                .iter()
                .any(|field| v[field] != previous[field])
            {
                return refuse("released checkpoint changes its recorded source or binding");
            }
            &checkpoint["value"]["release"]
        }
        _ => return refuse("custody carries neither a process nor a released checkpoint"),
    };
    if !marker.is_object() {
        return refuse("custody carries no ownership release");
    }
    if marker["lifecycle"] != lifecycle
        || marker["generation"].as_u64() != Some(lease.generation)
        || marker["revision"].as_u64() != Some(rev)
    {
        return refuse("the release names another lifecycle, host generation or revision");
    }
    Ok(())
}
