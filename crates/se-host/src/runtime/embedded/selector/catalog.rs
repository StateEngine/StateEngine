use super::*;
use se_store::{EventBody, ProjectionRecord, SqliteSnapshot};

pub(super) fn projects(
    read: &mut SqliteSnapshot,
    page: api::PageRequest,
    deadline: &crate::client::lease::Deadline,
) -> Result<api::Read<api::Page<api::ProjectInfo>>> {
    let mut limit = page.limit;
    loop {
        let source = read
            .selector_projects(paging::budget(&page, limit, deadline)?)
            .map_err(store_error)?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut fits = 0;
        let mut unreadable = 0;
        for row in source.items() {
            match project_info(row) {
                Ok((info, cost)) => {
                    bytes += cost;
                    items.push(info);
                }
                Err(_) => unreadable += 1,
            }
            // Count source slots, including unreadable records, so fitting a
            // prefix can re-read exactly the same frontier in this snapshot.
            if bytes <= u64::from(page.max_bytes) {
                fits += 1;
            }
        }
        if bytes <= u64::from(page.max_bytes) {
            return paging::finish(&source, items, bytes, &page, unreadable);
        }
        if fits == 0 {
            break;
        }
        limit = fits;
    }
    Err(error(
        api::ApiFailure::Incomplete,
        "selector-row-too-large",
        "The first selector row exceeds the byte budget; increase max_bytes.",
    ))
}
pub(super) fn agents(
    read: &mut SqliteSnapshot,
    project: se_types::ProjectId,
    page: api::PageRequest,
    deadline: &crate::client::lease::Deadline,
) -> Result<api::Read<api::Page<api::AgentInfo>>> {
    let mut limit = page.limit;
    loop {
        let source = read
            .selector_agents(paging::budget(&page, limit, deadline)?)
            .map_err(store_error)?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut fits = 0;
        for row in source.items() {
            let info = agent(row, &project)?;
            bytes += paging::cost(
                serde_json::json!({"project":info.project.0,"id":info.id.0,"name":info.name,"role":info.role,"revision":info.revision.0.get()}),
            )?;
            if bytes <= u64::from(page.max_bytes) {
                fits += 1;
            }
            items.push(info);
        }
        if bytes <= u64::from(page.max_bytes) {
            return paging::finish(&source, items, bytes, &page, 0);
        }
        if fits == 0 {
            break;
        }
        limit = fits;
    }
    Err(error(
        api::ApiFailure::Incomplete,
        "selector-row-too-large",
        "The first selector row exceeds the byte budget; increase max_bytes.",
    ))
}
fn agent(row: &ProjectionRecord, project: &se_types::ProjectId) -> Result<api::AgentInfo> {
    let original = row.original.as_deref().unwrap_or(&row.current);
    let EventBody::PrincipalRegistered {
        principal: Actor::Agent(agent),
        name,
        role,
        ..
    } = &original.body
    else {
        return Err(invalid());
    };
    let name = match &row.current.body {
        EventBody::PrincipalRenamed {
            principal: Actor::Agent(current),
            name,
            ..
        } if current == agent => name,
        EventBody::PrincipalRegistered { .. } => name,
        _ => return Err(invalid()),
    };
    id(agent.as_str())?;
    if name.len() > 256 || role.len() > 2048 {
        return Err(invalid());
    }
    Ok(api::AgentInfo {
        project: api::ProjectId(project.as_str().into()),
        id: api::AgentId(agent.as_str().into()),
        name: name.clone(),
        role: role.clone(),
        revision: api::Revision(row.revision.value),
    })
}

fn project_info(row: &ProjectionRecord) -> Result<(api::ProjectInfo, u64)> {
    let (project, name, roots) = match &row.current.body {
        EventBody::ProjectRegistered {
            project,
            name,
            roots,
            ..
        }
        | EventBody::ProjectUpdated {
            project,
            name,
            roots,
            ..
        } => (project, name, roots),
        _ => return Err(invalid()),
    };
    id(project.as_str())?;
    if name.len() > 256 {
        return Err(invalid());
    }
    let root = roots.first().ok_or_else(invalid)?;
    let cost = paging::cost(
        serde_json::json!({"id":project.as_str(),"name":name,"root":root.path,"revision":row.revision.value.get()}),
    )?;
    Ok((
        api::ProjectInfo {
            id: api::ProjectId(project.as_str().into()),
            name: name.clone(),
            root: root.path.to_local().map_err(|_| invalid())?,
            revision: api::Revision(row.revision.value),
        },
        cost,
    ))
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;
