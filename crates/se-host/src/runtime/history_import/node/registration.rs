//! Source registrations carry user identity and roots, never machine authority.
use super::*;
use se_types::{NativePath, PathEncoding, ProjectId};
pub(super) fn result(family: ImportFamily, key: String, target: LegacyTarget) -> DecodedRow {
    DecodedRow {
        events: Vec::new(),
        family,
        legacy_id: key,
        target,
        retained: None,
        resume: Vec::new(),
        duplicate: false,
        dropped_by_policy: false,
        dispositions: None,
    }
}
fn path(text: &str) -> StoreResult<NativePath> {
    let encoding = if text.starts_with('/') {
        PathEncoding::UnixBytes(text.as_bytes().to_vec())
    } else if text.starts_with(r"\\")
        || text.as_bytes().get(1) == Some(&b':')
            && matches!(text.as_bytes().get(2), Some(b'/' | b'\\'))
    {
        PathEncoding::WindowsUtf16(text.encode_utf16().collect())
    } else {
        return Err(invalid(
            "source project root is not an absolute native path",
        ));
    };
    NativePath::from_encoded(encoding).map_err(invalid)
}
pub(super) fn project<R: ImportSnapshot>(
    cx: &NodeContext,
    read: &mut R,
    row: &Value,
) -> StoreResult<DecodedRow> {
    if cx.admission.scope != Scope::Registry {
        return Err(invalid("project import requires registry scope"));
    }
    let id = ProjectId::from_legacy(str_at(row, "project_id")?).map_err(invalid)?;
    if !matches!(
        row.get("schema_version").and_then(Value::as_u64),
        Some(1 | 2)
    ) {
        return Err(invalid("unsupported Node project registration version"));
    }
    let revision = row
        .get("revision")
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .ok_or_else(|| invalid("Node project revision absent"))?;
    let key = format!("project:{id}:{revision}");
    let mut out = result(
        ImportFamily::Projects,
        key.clone(),
        LegacyTarget::Project(id.clone()),
    );
    time::micros(str_at(row, "ts")?)?;
    out.retained = Some(
        json!({"project_id":id,"source_owner_human_id":row.get("owner_human_id").and_then(Value::as_str),"source_revision":revision,"source_timestamp":row.get("ts").and_then(Value::as_str),"record_type":row.get("record_type").and_then(Value::as_str)}),
    );
    if row.get("record_type").and_then(Value::as_str) == Some("project-decommission") {
        require(read.project(id)?)?;
        return Ok(out);
    }
    if row.get("record_type").and_then(Value::as_str) != Some("project-registration") {
        return Err(invalid("unsupported project source operation"));
    }
    let root = path(str_at(row, "repo_root")?)?;
    if seen(read, cx, event_id(&cx.admission.scope, &key)?)? {
        out.duplicate = true;
        return Ok(out);
    }
    let owner = match &cx.admission.actor {
        Actor::Human(owner) => owner.clone(),
        _ => return Err(invalid("owner import admission required")),
    };
    let name = optional(row, "name").unwrap_or_else(|| id.to_string());
    let canonical_key = serde_json::to_vec(&root).map_err(invalid)?;
    if let Some(current) = read.import_root_claim(&canonical_key)?
        && current != id
    {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            format!(
                "the historical root is registered to current project {current}; preserve that project and explicitly remove its registration before retrying this source; no root was reassigned"
            ),
        ));
    }
    let roots = vec![Root {
        path: root.clone(),
        canonical_key,
    }];
    let body = match read.project(id.clone())? {
        Read::Present { value } => {
            let original = value.original.as_deref().unwrap_or(&value.current);
            if original.header.door != Door::Import {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "source project ID already belongs to current user registration",
                ));
            }
            let current = match &value.current.body {
                EventBody::ProjectRegistered { roots, .. }
                | EventBody::ProjectUpdated { roots, .. } => roots,
                _ => {
                    return Err(fail(
                        StoreErrorCode::NaturalKeyConflict,
                        "source project is already removed; history remains available without reactivating it",
                    ));
                }
            };
            if current.iter().any(|r| r.path == root)
                && matches!(&value.current.body,EventBody::ProjectRegistered{name:old,..}|EventBody::ProjectUpdated{name:old,..} if old==&name)
            {
                out.duplicate = true;
                return Ok(out);
            }
            EventBody::ProjectUpdated {
                project: id,
                name,
                roots,
                expected: Expected::Revision(value.revision),
            }
        }
        Read::Absent { .. } => EventBody::ProjectRegistered {
            project: id,
            name,
            roots,
            owner,
            history_from: None,
            expected: Expected::Absent,
        },
        Read::Unreadable { reason, .. } => return Err(fail(StoreErrorCode::Unreadable, reason)),
        Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, what)),
    };
    // The new native owner adopts this registration now; the historical owner
    // and timestamp remain correspondence fields, never native ownership proof.
    out.events.push(event(
        cx,
        cx.admission.actor.clone(),
        &key,
        cx.observed_at_us,
        None,
        body,
    )?);
    Ok(out)
}
pub(super) fn owner<R: Snapshot>(
    cx: &NodeContext,
    read: &mut R,
    row: &Value,
) -> StoreResult<DecodedRow> {
    if row.get("record_type").and_then(Value::as_str) != Some("human-minted")
        || row.get("schema_version").and_then(Value::as_u64) != Some(1)
    {
        return Err(invalid("unsupported Node human identity format"));
    }
    if cx.admission.scope == Scope::Registry {
        return Err(invalid(
            "historical humans are project correspondence, never new home owners",
        ));
    }
    let human = HumanId::from_legacy(str_at(row, "human_id")?).map_err(invalid)?;
    let target = mapped_human(cx, human.clone());
    let principal = Actor::Human(target.clone());
    let key = format!("human:{human}");
    let mut out = result(
        ImportFamily::Owners,
        key.clone(),
        LegacyTarget::Principal(principal.clone()),
    );
    out.retained = Some(
        json!({"source_human_id":human,"display_name":str_at(row,"display_name")?,"mapped_human_id":target,"created_at":str_at(row,"created_at")?}),
    );
    let current = expected(read.principal(principal.clone())?)?;
    if current != Expected::Absent {
        out.duplicate = true;
        return Ok(out);
    }
    if target != human {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            "--map-human target must already be registered in this project; correspondence never creates another home owner",
        ));
    }
    let Actor::Human(owner) = &cx.admission.actor else {
        return Err(invalid("owner import admission required"));
    };
    let planned = cx
        .human_names
        .get(&human)
        .ok_or_else(|| invalid("source human name plan is absent"))?;
    let display_name = super::human_name::available(read, planned)?;
    if display_name != str_at(row, "display_name")? {
        let retained = out
            .retained
            .as_mut()
            .and_then(Value::as_object_mut)
            .ok_or_else(|| invalid("human provenance is absent"))?;
        retained.insert(
            "import_note".into(),
            Value::String("historical-human-name-disambiguated".into()),
        );
        retained.insert(
            "imported_display_name".into(),
            Value::String(display_name.clone()),
        );
    }
    out.events.push(event(
        cx,
        cx.admission.actor.clone(),
        &key,
        time::micros(str_at(row, "created_at")?)?,
        None,
        EventBody::PrincipalRegistered {
            principal,
            kind: PrincipalKind::Human,
            owner: owner.clone(),
            created_by: None,
            name: display_name,
            role: "historical human identity".into(),
            expected: Expected::Absent,
        },
    )?);
    Ok(out)
}
