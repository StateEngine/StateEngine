//! Scoped metadata reads, then existing exact-birth native observation after closing SQL.
use super::{auth::AuthorizedRemoteRequest, session::SecurityStore, *};
use se_core::{
    ops::{AgentRow, ConversationView, ResumeCommand},
    scope,
};
use se_store::{EventBody, RecordedIdentity, remote::TargetFacts};
use se_types::{Read, Result};
use std::time::Instant;

impl SecurityStore {
    pub(crate) fn watch_position(
        &self,
        request: &AuthorizedRemoteRequest,
        target: &RemoteTarget,
    ) -> Result<Option<se_store::StorePosition>> {
        let permit = request.admission();
        if *permit.verb() != RemoteVerb::Watch || !permit.targets().contains(target) {
            return Err(scope::unreadable(
                "remote watch",
                "target outside the admitted selection",
            ));
        }
        let at = super::session::now()?;
        self.read(|phase| {
            phase.remote_watch_position(
                &permit.grant().grant,
                permit.grant().authority_revision,
                target,
                at,
            )
        })
    }

    /// Bounded durable replay, retaining typed private positions for the shared cursor codec.
    pub fn changes(
        &self,
        request: &AuthorizedRemoteRequest,
        target: &RemoteTarget,
        query: se_store::remote::ChangeRequest<'_>,
    ) -> Result<se_store::remote::ChangePage> {
        let permit = request.admission();
        if *permit.verb() != RemoteVerb::Watch || !permit.targets().contains(target) {
            return Err(scope::unreadable(
                "remote replay",
                "watch target is outside this admitted selection",
            ));
        }
        let at = super::session::now()?;
        self.read(|phase| {
            Ok(phase.remote_changes(
                &permit.grant().grant,
                permit.grant().authority_revision,
                target,
                query,
                at,
            ))
        })?
        .map_err(|error| {
            if error.code != se_store::StoreErrorCode::ReadIncomplete {
                return se_core::store_error::store_error(&error);
            }
            let mut timed = se_types::SeError::new(se_types::Detail::DeadlineExceeded(
                se_types::details::DeadlineExceeded {
                    op: "remote replay read; original cursor retained".into(),
                    deadline_ms: 250,
                },
            ));
            timed.body = timed
                .body
                .with_retry(se_types::Retry::AfterReread)
                .with_remedy(se_types::Remedy {
                    text: "Retry this read with the same scoped cursor.".into(),
                    command: None,
                });
            timed.with_cause(error)
        })
    }
    /// Called on the existing bounded blocking pool. This method opens no network stream.
    pub fn targets(
        &self,
        request: &AuthorizedRemoteRequest,
        deadline: Instant,
    ) -> Result<Vec<RemoteAgentView>> {
        let permit = request.admission();
        if !matches!(permit.verb(), RemoteVerb::List | RemoteVerb::Watch) {
            return Err(scope::unreadable(
                "remote metadata",
                "list/watch permit required",
            ));
        }
        let now = super::session::now()?;
        let facts = self.read(|phase| {
            permit
                .targets()
                .iter()
                .map(|target| {
                    phase.remote_target(
                        &permit.grant().grant,
                        permit.grant().authority_revision,
                        *permit.verb(),
                        target,
                        now,
                    )
                })
                .collect::<se_store::StoreResult<Vec<_>>>()
        })?;
        facts
            .into_iter()
            .map(|facts| observe(facts, deadline))
            .collect()
    }
}
fn observe(facts: TargetFacts, deadline: Instant) -> Result<RemoteAgentView> {
    if Instant::now() >= deadline {
        return Err(scope::unreadable(
            "remote metadata",
            "original read deadline expired",
        ));
    }
    let name = match facts.principal.current.body {
        EventBody::PrincipalRegistered { name, .. } | EventBody::PrincipalRenamed { name, .. } => {
            name
        }
        _ => {
            return Err(scope::unreadable(
                "remote metadata",
                "target registration kind differs",
            ));
        }
    };
    let profile = scope::require_present(
        facts.profile,
        "remote saved provider",
        "Save a supported Claude or Codex agent profile locally.",
    )?;
    let EventBody::ProfileSaved { profile, .. } = profile.current.body else {
        return Err(scope::unreadable(
            "remote metadata",
            "saved profile kind differs",
        ));
    };
    let provider = match profile.provider {
        se_store::Provider::Claude => se_types::Provider::Claude,
        se_store::Provider::Codex => se_types::Provider::Codex,
        _ => {
            return Err(scope::unreadable(
                "remote metadata",
                "provider is unsupported in R0",
            ));
        }
    };
    let mut session = se_core::ops::unobserved_session();
    session.state = "never-launched".into();
    if let Read::Present { value: head } = &facts.session {
        let first = head.original.as_deref().unwrap_or(&head.current);
        let EventBody::SessionPrepared {
            session: id, agent, ..
        } = &first.body
        else {
            return Err(scope::unreadable(
                "remote session",
                "original session preparation absent",
            ));
        };
        if agent != &facts.target.agent {
            return Err(scope::unreadable("remote session", "agent differs"));
        }
        session.session_id = Some(id.clone());
        session.recorded_state = Some(
            match &head.current.body {
                EventBody::SessionPrepared { .. } => "prepared",
                EventBody::SessionActivated { .. } => "activated",
                EventBody::SessionEnded { .. } => "ended",
                EventBody::SessionRevoked { .. } => "revoked",
                _ => {
                    return Err(scope::unreadable(
                        "remote session",
                        "current session kind differs",
                    ));
                }
            }
            .into(),
        );
        session.state = "unknown".into();
    }
    let process = match facts.process {
        Read::Present { value: head } => match session.session_id.clone() {
            Some(id) => {
                let expected = match &facts.session {
                    Read::Present { value } => match &value.current.body {
                        EventBody::SessionActivated { process, .. } => process.as_ref(),
                        _ => None,
                    },
                    _ => None,
                };
                se_core::ops::process_from_record(
                    &facts.target.agent,
                    &id,
                    expected,
                    head,
                    &mut session,
                )?
            }
            None => Read::Absent {
                checked: "no session selected for this process".into(),
            },
        },
        Read::Absent { checked } => Read::Absent { checked },
        Read::Unknown { what } => Read::Unknown { what },
        Read::Unreadable {
            source,
            reason,
            error,
        } => Read::Unreadable {
            source,
            reason,
            error,
        },
    };
    let recovering = matches!(&session.process_state,Read::Present {value} if matches!(value.as_str(),"lost"|"stop-unproved"|"stop-requested"|"leader-exited"));
    let lifecycle = match &process {
        Read::Present { value } if matches!(value.instance, RecordedIdentity::Present(_)) => {
            Some(value.record.clone())
        }
        _ => None,
    };
    let mut row = AgentRow {
        id: facts.target.agent.clone(),
        name: name.clone(),
        role: None,
        provider,
        model: None,
        profile: String::new(),
        session,
        conversation: ConversationView {
            id: None,
            state: "unverified".into(),
        },
        resume: ResumeCommand {
            ready: false,
            mode: "unavailable".into(),
            reason: None,
            command: None,
            argv: None,
        },
        unread: Some(facts.pending),
        last_activity_at: None,
    };
    let recorded_session = match &facts.session {
        Read::Present { value } => Some(value),
        _ => None,
    };
    let plan = crate::AgentObservationPlan::remote(
        facts.target.project.clone(),
        row.clone(),
        process,
        recorded_session,
    );
    crate::observe_agent(plan, deadline)?.apply(&mut row)?;
    let status = if recovering || row.session.state == "recovery-pending" {
        Read::Present {
            value: RemoteAgentStatus::Recovering,
        }
    } else {
        match (&row.session.liveness,&row.session.session_id,lifecycle) {
            (Read::Present {value},Some(session),Some(lifecycle)) if value=="live" && row.session.state=="running" => Read::Present {value:RemoteAgentStatus::Running {session:session.clone(),lifecycle}},
            (_,None,_)=>Read::Present {value:RemoteAgentStatus::Stopped},
            (Read::Unreadable {source,reason,error},_,_)=>Read::Unreadable {source:source.clone(),reason:reason.clone(),error:error.clone()},
            (_,_,_) if row.session.recorded_state.as_deref()==Some("prepared")=>Read::Present {value:RemoteAgentStatus::Starting},
            (Read::Present {value},_,_) if value=="exited" && matches!(&row.session.process_state,Read::Present {value} if value=="exited")=>Read::Present {value:RemoteAgentStatus::Stopped},
            _=>Read::Unknown {what:"native custody/readback is incomplete; local Owner must reconcile the original session".into()},
        }
    };
    Ok(RemoteAgentView {
        target: facts.target,
        project_name: facts.project_name,
        agent_name: name,
        provider,
        status,
        pending: Read::Present {
            value: facts.pending,
        },
    })
}

impl SecurityStore {
    pub fn target_page(
        &self,
        request: &AuthorizedRemoteRequest,
        after: Option<&RemoteTarget>,
        limit: u16,
        deadline: Instant,
    ) -> Result<Vec<RemoteAgentView>> {
        let permit = request.admission();
        let now = super::session::now()?;
        let facts = self.read(|phase| {
            let targets = if permit.targets().is_empty() {
                phase.remote_list_targets(
                    &permit.grant().grant,
                    permit.grant().authority_revision,
                    after,
                    limit,
                    now,
                )?
            } else {
                let mut targets = permit.targets().to_vec();
                targets.sort();
                targets
                    .into_iter()
                    .filter(|t| after.is_none_or(|a| t > a))
                    .take(usize::from(limit))
                    .collect()
            };
            targets
                .iter()
                .map(|target| {
                    phase.remote_target(
                        &permit.grant().grant,
                        permit.grant().authority_revision,
                        RemoteVerb::List,
                        target,
                        now,
                    )
                })
                .collect::<se_store::StoreResult<Vec<_>>>()
        })?;
        facts
            .into_iter()
            .map(|facts| observe(facts, deadline))
            .collect()
    }
}
