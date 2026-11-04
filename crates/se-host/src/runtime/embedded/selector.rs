//! Owner-only selector reads. SQL snapshots and host callbacks remain separate
//! sources; diagnostic host pages never confer a session grant.
mod catalog;
mod paging;
mod sessions;
use super::{EmbeddedHost, binding, store, support};
use crate::{HostedRouter, linked::FromLinked};
use se_store::{Actor, Admission, ReadScope, Scope, Snapshot, Visibility};
use secode_stateengine_api as api;
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<api::ApiError>>;

pub(super) fn error(kind: api::ApiFailure, code: &str, message: &str) -> Box<api::ApiError> {
    Box::new(api::ApiError {
        kind,
        code: code.into(),
        message: message.into(),
        remedy: api::ApiRemedy {
            text: "Refresh the selector and retry; inspect the local store if the error persists."
                .into(),
            command: None,
        },
        retry: if kind == api::ApiFailure::Conflict {
            api::ApiRetry::AfterRefresh
        } else {
            api::ApiRetry::Never
        },
    })
}
fn invalid() -> Box<api::ApiError> {
    error(
        api::ApiFailure::Unreadable,
        "selector-invalid-record",
        "Selector metadata is missing, invalid or exceeds its display bounds.",
    )
}
fn stale() -> Box<api::ApiError> {
    error(
        api::ApiFailure::Conflict,
        "selector-stale-cursor",
        "The selector generation, catalog revision or cursor scope changed.",
    )
}
fn store_error(e: Box<se_store::StoreError>) -> Box<api::ApiError> {
    use se_store::StoreErrorCode as C;
    match e.code {
        C::CursorStale => stale(),
        C::CursorInvalid => paging::usage(),
        C::ReadBudgetTooSmall => invalid(),
        _ => error(
            api::ApiFailure::Unreadable,
            "selector-store-unreadable",
            "The selector store snapshot could not be read.",
        ),
    }
}
fn bridge_error(e: se_types::SeError) -> Box<api::ApiError> {
    // Preserve error class, but never leak arbitrary record/provider bodies or
    // native paths through the selector error channel.
    let kind = support::api_error(&e).kind;
    error(
        kind,
        "selector-read-failed",
        "The ready host could not complete this selector read within the call's bounds.",
    )
}
fn id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn registry_scope(router: &HostedRouter) -> ReadScope {
    ReadScope {
        admission: Admission {
            scope: Scope::Registry,
            actor: Actor::Human(router.context.owner.clone()),
            session: None,
            generation: router.execution.generation.get(),
        },
        visibility: Visibility::Owner,
    }
}
fn project(read: &mut impl Snapshot, project: &se_types::ProjectId) -> Result<bool> {
    match read.project(project.clone()).map_err(store_error)? {
        se_types::Read::Present { value } => match value.current.body {
            se_store::EventBody::ProjectRegistered { .. }
            | se_store::EventBody::ProjectUpdated { .. } => Ok(true),
            se_store::EventBody::ProjectRemoved { .. } => Ok(false),
            _ => Err(invalid()),
        },
        se_types::Read::Absent { .. } | se_types::Read::Unknown { .. } => Ok(false),
        se_types::Read::Unreadable { .. } => Err(invalid()),
    }
}
fn unknown<T>() -> api::Read<T> {
    api::Read::Unknown {
        what: "The selected project is not registered and active.".into(),
    }
}
impl EmbeddedHost {
    async fn selector_ready(
        &self,
        options: &api::CallOptions,
    ) -> Result<(
        HostedRouter,
        crate::client::lease::Deadline,
        support::CallCancellation,
    )> {
        if options.generation != self.negotiated.generation {
            return Err(stale());
        }
        self.ready(options).await.map_err(bridge_error)
    }
    pub(super) async fn selector_projects(
        &self,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> Result<api::Read<api::Page<api::ProjectInfo>>> {
        paging::validate(&page)?;
        let (router, deadline, _cancel) = self.selector_ready(&options).await?;
        let bound = deadline.clone();
        store::read(&router, registry_scope(&router), &deadline, move |read| {
            Ok(catalog::projects(read, page, &bound))
        })
        .await
        .map_err(bridge_error)?
    }
    pub(super) async fn selector_agents(
        &self,
        selected: api::ProjectId,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> Result<api::Read<api::Page<api::AgentInfo>>> {
        paging::validate(&page)?;
        id(&selected.0)?;
        let selected = se_types::ProjectId::from_linked(selected).map_err(|_| invalid())?;
        let (router, deadline, _cancel) = self.selector_ready(&options).await?;
        let bound = deadline.clone();
        store::read(
            &router,
            binding::owner_scope(&router, selected.clone()),
            &deadline,
            move |read| {
                Ok((|| {
                    if project(read, &selected)? {
                        catalog::agents(read, selected, page, &bound)
                    } else {
                        Ok(unknown())
                    }
                })())
            },
        )
        .await
        .map_err(bridge_error)?
    }
}
