//! A finite native Owner inventory; it is never exposed through agent grants.
use super::*;
use crate::remote::LaunchPermission;
use se_types::{Read, remote::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedLaunchProfile {
    pub provider: crate::Provider,
    pub permission: crate::PermissionProfile,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchCandidate {
    pub target: RemoteTarget,
    pub project_name: String,
    pub agent_name: String,
    pub profile: Read<SavedLaunchProfile>,
    pub permission: Read<LaunchPermission>,
}

impl ReadPhase {
    pub fn remote_launch_candidates(
        &self,
        grant: &RemoteGrantId,
        after: Option<&RemoteTarget>,
        limit: u16,
    ) -> StoreResult<(Vec<LaunchCandidate>, bool)> {
        ready(&self.info)?;
        if self.info.schema_version < 11 || !(1..=4).contains(&limit) {
            return Err(invalid("launch inventory schema or finite page size"));
        }
        grant_at(&self.db, grant)?.ok_or_else(denied)?;
        let after = after
            .map(|target| {
                let p = crate::identity::key(
                    &self.db,
                    "project",
                    target.project.as_str(),
                    &[0],
                    false,
                )?;
                let scope = crate::identity::scope_key(
                    &self.db,
                    &Scope::Project(target.project.clone()),
                    false,
                )?;
                let a =
                    crate::identity::key(&self.db, "agent", target.agent.as_str(), &scope, false)?;
                Ok::<_, Box<StoreError>>((p, a))
            })
            .transpose()?;
        let mut query=self.db.prepare("SELECT a.project_id,a.principal_id FROM principals a JOIN projects p USING(project_id) WHERE a.principal_kind='agent' AND p.state='active' AND (?1 IS NULL OR a.project_id>?1 OR (a.project_id=?1 AND a.principal_id>?2)) ORDER BY a.project_id,a.principal_id LIMIT ?3").map_err(sql)?;
        let rows = query
            .query_map(
                rusqlite::params![
                    after.as_ref().map(|(p, _)| p),
                    after.as_ref().map(|(_, a)| a),
                    i64::from(limit) + 1
                ],
                |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        let more = rows.len() > usize::from(limit);
        let candidates = rows
            .into_iter()
            .take(usize::from(limit))
            .map(|(p, a)| {
                let project: se_types::ProjectId =
                    crate::identity::wire(&self.db, "project", &p, &[0])?
                        .try_into()
                        .map_err(invalid)?;
                let scope =
                    crate::identity::scope_key(&self.db, &Scope::Project(project.clone()), false)?;
                let target = RemoteTarget {
                    project,
                    agent: crate::identity::wire(&self.db, "agent", &a, &scope)?
                        .try_into()
                        .map_err(invalid)?,
                };
                let facts = self.client_target_facts(&target)?;
                let agent_name = match facts.principal.current.body {
                    EventBody::PrincipalRegistered { name, .. }
                    | EventBody::PrincipalRenamed { name, .. } => name,
                    _ => return Err(invalid("launch inventory principal metadata is unreadable")),
                };
                let profile = match facts.profile {
                    Read::Present { value } => match value.current.body {
                        EventBody::ProfileSaved { profile, .. } => Read::Present {
                            value: SavedLaunchProfile {
                                provider: profile.provider,
                                permission: profile.permission,
                                name: profile.named_profile,
                            },
                        },
                        _ => {
                            return Err(invalid(
                                "launch inventory saved profile metadata is unreadable",
                            ));
                        }
                    },
                    Read::Absent { checked } => Read::Absent { checked },
                    Read::Unreadable {
                        source,
                        reason,
                        error,
                    } => Read::Unreadable {
                        source,
                        reason,
                        error,
                    },
                    Read::Unknown { what } => Read::Unknown { what },
                };
                Ok(LaunchCandidate {
                    permission: self.remote_launch_permission(grant, &target)?,
                    target,
                    project_name: facts.project_name,
                    agent_name,
                    profile,
                })
            })
            .collect::<StoreResult<Vec<_>>>()?;
        Ok((candidates, more))
    }
}
