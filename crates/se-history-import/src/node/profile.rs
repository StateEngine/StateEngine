//! Saved source profiles are adopted under the active owner's safe policy.
use super::registration::result;
use super::*;
pub(super) fn profile<R: Snapshot>(
    cx: &NodeContext,
    read: &mut R,
    row: &Value,
) -> StoreResult<DecodedRow> {
    let agent = agent(read, str_at(row, "agent_id")?)?;
    require(read.principal(Actor::Agent(agent.clone()))?)?;
    let provider = match str_at(row, "surface")? {
        "claude" => Provider::Claude,
        "codex" => Provider::Codex,
        _ => return Err(invalid("unsupported Node saved profile provider")),
    };
    let mut profile = safe_default(cx, Some(provider))?;
    match row.get("sandbox").and_then(Value::as_str) {
        None => (),
        Some("read-only") if profile.permission == PermissionProfile::ReadOnly => (),
        Some("workspace-write") => (),
        _ => {
            return Err(invalid(
                "source permission profile has no equally restrictive active owner default; no profile or bypass was invented",
            ));
        }
    }
    profile.model = optional(row, "model");
    profile.effort = optional(row, "effort");
    let key = format!(
        "profile:{agent}:{}",
        se_types::hex_lower(&Sha256::digest(serde_json::to_vec(row).map_err(invalid)?))
    );
    let mut out = result(
        ImportFamily::Profiles,
        key.clone(),
        LegacyTarget::Principal(Actor::Agent(agent.clone())),
    );
    let want = match read.profile(agent.clone())? {
        Read::Present { value } => {
            if value.current.header.door == Door::Import
                && value.current.header.event
                    == event_id(
                        &cx.admission.scope,
                        &format!("owner-default-profile:{agent}"),
                    )?
            {
                Expected::Revision(value.revision)
            } else {
                if !matches!(&value.current.body,EventBody::ProfileSaved{profile:existing,..} if serde_json::to_value(existing).map_err(invalid)?==serde_json::to_value(&profile).map_err(invalid)?)
                {
                    return Err(fail(
                        StoreErrorCode::NaturalKeyConflict,
                        "an existing profile differs; history cannot overwrite it",
                    ));
                }
                out.duplicate = true;
                return Ok(out);
            }
        }
        Read::Absent { .. } => Expected::Absent,
        Read::Unreadable { reason, .. } => return Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, what)),
    };
    out.retained = Some(
        json!({"source_sandbox":row.get("sandbox").and_then(Value::as_str),"source_permission_profile":row.get("permission_profile").and_then(Value::as_str),"import_policy":"current-owner-default-no-bypass"}),
    );
    // This is the current owner's configuration adoption, not a fabricated
    // historical profile creation date.
    out.events.push(event(
        cx,
        cx.admission.actor.clone(),
        &key,
        cx.observed_at_us,
        None,
        EventBody::ProfileSaved {
            agent,
            profile,
            expected: want,
        },
    )?);
    Ok(out)
}

/// Only rows corresponding to principals in this imported project can create
/// saved profiles. All host/factory settings around the array are ignored.
pub(super) fn profiles<R: Snapshot>(
    cx: &NodeContext,
    read: &mut R,
    row: &Value,
) -> StoreResult<DecodedRow> {
    let Some(rows) = row
        .as_array()
        .or_else(|| row.get("seats").and_then(Value::as_array))
    else {
        return profile(cx, read, row);
    };
    if rows.len() > 4096 {
        return Err(invalid(
            "Node profile document exceeds its 4096-row discovery bound",
        ));
    }
    let key = format!(
        "profiles:{}",
        se_types::hex_lower(
            &cx.source
                .sha256
                .ok_or_else(|| invalid("profile source digest missing"))?
        )
    );
    let mut out = result(
        ImportFamily::Profiles,
        key.clone(),
        LegacyTarget::Record(record_id("profiles", &key)?),
    );
    let mut policies = Vec::new();
    let mut excluded = 0u64;
    let mut counts = ImportCounts {
        read: rows.len() as u64,
        ..Default::default()
    };
    for row in rows {
        let id = str_at(row, "agent_id")?;
        let id = match agent(read, id) {
            Ok(id) => id,
            Err(error)
                if matches!(
                    error.code,
                    StoreErrorCode::EventInvalid | StoreErrorCode::ReferenceMissing
                ) =>
            {
                if cx.prerequisites_pending {
                    return Err(fail(
                        StoreErrorCode::ReferenceMissing,
                        "profile identity awaits an earlier source operation",
                    ));
                }
                excluded += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        match read.principal(Actor::Agent(id))? {
            Read::Absent { .. } => {
                if cx.prerequisites_pending {
                    return Err(fail(
                        StoreErrorCode::ReferenceMissing,
                        "profile identity awaits an earlier source operation",
                    ));
                }
                excluded += 1;
                continue;
            }
            Read::Present { .. } => (),
            Read::Unreadable { reason, .. } => {
                return Err(fail(StoreErrorCode::Unreadable, reason));
            }
            Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, what)),
        }
        let decoded = profile(cx, read, row)?;
        if decoded.duplicate {
            counts.duplicate += 1;
        } else if decoded.dropped_by_policy {
            counts.dropped_by_policy += 1;
        } else {
            counts.imported += 1;
        }
        out.events.extend(decoded.events);
        if let Some(policy) = decoded.retained {
            policies.push(policy);
        }
        if out.events.len() > 60 {
            return Err(invalid(
                "one complete profile document exceeds the atomic 60-profile import bound; preserve a smaller authenticated user-profile export",
            ));
        }
    }
    counts.dropped_by_policy += excluded;
    out.dispositions = Some(counts);
    out.retained = Some(json!({"excluded_outside_project":excluded,"profile_policies":policies}));
    Ok(out)
}

pub(crate) fn safe_default(cx: &NodeContext, provider: Option<Provider>) -> StoreResult<Profile> {
    let profiles = match &cx.owner_profiles {
        Read::Present { value } => value,
        Read::Absent { checked } => {
            return Err(fail(StoreErrorCode::ReadIncomplete, checked.clone()));
        }
        Read::Unreadable { reason, .. } => {
            return Err(fail(StoreErrorCode::ReadIncomplete, reason.clone()));
        }
        Read::Unknown { what } => return Err(fail(StoreErrorCode::ReadIncomplete, what.clone())),
    };
    profiles
        .iter()
        .find(|p| {
            provider.is_none_or(|provider| p.provider == provider)
                && p.named_profile == "default"
                && p.permission != PermissionProfile::NamedFullBypass
        })
        .cloned()
        .ok_or_else(|| invalid("the active owner's safe default provider profile is unavailable"))
}
