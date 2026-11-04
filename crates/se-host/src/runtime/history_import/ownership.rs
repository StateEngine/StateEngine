//! Explicit correspondence is admission, never inferred from display names.
use super::source::SourceFile;
use crate::client::lease::Deadline;
use se_core::scope;
use se_types::{HumanId, Read, Result};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};
fn human(value: &Value, field: &str) -> Result<HumanId> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| scope::unreadable("Node source owner", &format!("missing exact {field}")))?;
    HumanId::from_legacy(text)
}
pub(super) fn check<'a>(
    state: &Path,
    owner: &HumanId,
    selected: Option<&HumanId>,
    registrations: impl Iterator<Item = &'a Value>,
    deadline: &Deadline,
) -> Result<HumanId> {
    let mut owners = BTreeSet::new();
    for row in registrations {
        owners.insert(human(row, "owner_human_id")?);
    }
    let mut humans = BTreeSet::new();
    match SourceFile::open(state.join("humans.jsonl"), None, deadline)? {
        Read::Present { mut value } => {
            while let Some(row) = value.next(deadline)? {
                let Some(row) = row.value else {
                    if selected.is_some() && value.next(deadline)?.is_none() {
                        break;
                    }
                    return Err(scope::unreadable(
                        "Node source humans",
                        "human identity is unreadable; preserve the source and name its exact project owner with --source-owner <human_id>",
                    ));
                };
                humans.insert(human(&row, "human_id")?);
                if humans.len() > 4096 {
                    return Err(scope::unreadable(
                        "Node source humans",
                        "source human discovery exceeds 4096 identities",
                    ));
                }
            }
            value.verify(deadline)?;
        }
        Read::Absent { .. } => (),
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("Node source humans", &what)),
    }
    let chosen = selected.unwrap_or(owner);
    let ids = |set: &BTreeSet<HumanId>| {
        set.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    if selected.is_none()
        && (humans.len() != 1 || !humans.contains(owner) || owners.iter().any(|id| id != owner))
    {
        return Err(scope::unreadable(
            "Node source owner correspondence",
            &format!(
                "source project owners [{}], humans [{}], importing owner {owner}; explicitly name the source human becoming this owner with --source-owner <human_id>",
                ids(&owners),
                ids(&humans)
            ),
        ));
    }
    if owners.iter().any(|id| id != chosen)
        || (!owners.is_empty() && !owners.contains(chosen))
        || (owners.is_empty() && !humans.contains(chosen))
    {
        return Err(scope::unreadable(
            "Node source owner correspondence",
            &format!(
                "--source-owner {chosen} does not own every source project [{}]; preserve separate owner-scoped copies rather than adopting another owner's project",
                ids(&owners)
            ),
        ));
    }
    Ok(chosen.clone())
}
