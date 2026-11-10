//! A shared view retains its original native or remote authority at every read.
use super::*;
use se_store::{
    Admission, ReadPhase, StoreResult,
    remote::{ChangePage, ChangeRequest, TargetFacts},
};
use se_types::{Result, SeError};

pub(crate) enum ViewRequest {
    Remote(Box<auth::AuthorizedRemoteRequest>),
    Local {
        admission: Admission,
        owner: se_types::HumanId,
        request: Box<RemoteRequest>,
        targets: Vec<RemoteTarget>,
    },
}
impl ViewRequest {
    pub(crate) fn local(admission: Admission, request: RemoteWatch) -> Result<Self> {
        request.validate()?;
        let se_store::Actor::Human(owner) = &admission.actor else {
            return Err(SeError::invalid("local view", "native human authority"));
        };
        if admission.session.is_some() || request.targets.is_empty() {
            return Err(SeError::invalid(
                "local view",
                "native human authority and exact selected targets",
            ));
        }
        let targets = request.targets.clone();
        let owner = owner.clone();
        Ok(Self::Local {
            admission,
            owner,
            request: Box::new(RemoteRequest::Watch(request)),
            targets,
        })
    }
    pub(crate) fn request(&self) -> &RemoteRequest {
        match self {
            Self::Remote(value) => value.request(),
            Self::Local { request, .. } => request,
        }
    }
    pub(crate) fn targets(&self) -> &[RemoteTarget] {
        match self {
            Self::Remote(value) => value.admission().targets(),
            Self::Local { targets, .. } => targets,
        }
    }
    pub(crate) fn verb(&self) -> RemoteVerb {
        match self {
            Self::Remote(value) => *value.admission().verb(),
            Self::Local { .. } => RemoteVerb::Watch,
        }
    }
    pub(crate) fn cursor_authority(&self, associated: &mut serde_json::Value) {
        match self {
            Self::Remote(value) => {
                let grant = value.admission().grant();
                associated["grant"] = serde_json::json!(grant.grant);
                associated["authority_revision"] = serde_json::json!(grant.authority_revision);
            }
            Self::Local {
                admission, owner, ..
            } => {
                associated["schema"] = serde_json::json!("stateengine.local-client-cursor/v1");
                associated["owner"] = serde_json::json!(owner);
                associated["generation"] = serde_json::json!(admission.generation);
            }
        }
    }
    pub(crate) fn target(
        &self,
        phase: &ReadPhase,
        target: &RemoteTarget,
        verb: RemoteVerb,
        now: i64,
    ) -> StoreResult<TargetFacts> {
        match self {
            Self::Remote(value) => {
                let grant = value.admission().grant();
                phase.remote_target(&grant.grant, grant.authority_revision, verb, target, now)
            }
            Self::Local { admission, .. } => phase.local_client_target(admission, target),
        }
    }
    pub(crate) fn position(
        &self,
        phase: &ReadPhase,
        target: &RemoteTarget,
        now: i64,
    ) -> StoreResult<Option<se_store::StorePosition>> {
        match self {
            Self::Remote(value) => {
                let grant = value.admission().grant();
                phase.remote_watch_position(&grant.grant, grant.authority_revision, target, now)
            }
            Self::Local { admission, .. } => phase.local_client_position(admission, target),
        }
    }
    pub(crate) fn changes(
        &self,
        phase: &ReadPhase,
        target: &RemoteTarget,
        query: ChangeRequest<'_>,
        now: i64,
    ) -> StoreResult<ChangePage> {
        match self {
            Self::Remote(value) => {
                let grant = value.admission().grant();
                phase.remote_changes(&grant.grant, grant.authority_revision, target, query, now)
            }
            Self::Local { admission, .. } => phase.local_client_changes(admission, target, query),
        }
    }
    pub(crate) fn page_targets(
        &self,
        phase: &ReadPhase,
        after: Option<&RemoteTarget>,
        limit: u16,
        now: i64,
    ) -> StoreResult<Vec<RemoteTarget>> {
        if let Self::Remote(value) = self
            && self.targets().is_empty()
        {
            let grant = value.admission().grant();
            return phase.remote_list_targets(
                &grant.grant,
                grant.authority_revision,
                after,
                limit,
                now,
            );
        }
        let mut targets = self.targets().to_vec();
        targets.sort();
        Ok(targets
            .into_iter()
            .filter(|target| after.is_none_or(|after| target > after))
            .take(usize::from(limit))
            .collect())
    }
}
