//! Revocation is a FULL session transition; grants have no credential rows.
use super::{EmbeddedHost, binding, store};
use crate::linked::FromLinked;
use se_core::{scope, store_error::store_error};
use se_store::{EventBody, Expected, InputText, Snapshot};
use se_types::{Result, SeError};
use secode_stateengine_api as api;

impl EmbeddedHost {
    pub(super) async fn revoke(
        &self,
        authority: &api::Authority,
        request: api::RevokeRequest,
        options: api::CallOptions,
    ) -> Result<api::Receipt<api::SessionIdentity>> {
        let (router, deadline, _cancel) = self.ready(&options).await?;
        let _serial = super::super::pool::within(&deadline, self.binding_gate.lock()).await?;
        if !matches!(authority, api::Authority::Owner(_)) {
            return Err(SeError::invalid(
                "linked revocation authority",
                "native Owner control; a session grant never becomes Owner",
            ));
        }
        let id = se_types::SessionId::from_linked(request.session.clone())?;
        let binding = self.bindings.for_revoke(&id)?;
        let scope = binding::owner_scope(
            &router,
            se_types::ProjectId::from_linked(binding.identity.project.clone())?,
        );
        let admission = scope.admission.clone();
        let key = request.key.clone();
        let identity = store::request(
            "session.revoke",
            key.clone(),
            serde_json::json!({
                "session":request.session.0,"reason":format!("{:?}",request.reason),"generation":options.generation.0
            }),
        )?;
        self.bindings.fence(&id)?;
        let batch = store::read(&router, scope.clone(), &deadline, move |read| {
            let record = scope::require_present(
                read.session(id.clone()).map_err(|e| store_error(&e))?,
                "linked revoke target",
                "Rebind the native Session.",
            )?;
            // A replay reaches the writer with its original keyed intent;
            // terminal head checks must not prevent that replay resolution.
            let facts = super::super::start::allocate_facts()?;
            Ok(se_store::AtomicBatch {
                expected_incarnation: read.info().incarnation,
                admission: admission.clone(),
                request: Some(identity),
                events: vec![store::event(
                    read,
                    &admission,
                    facts.event,
                    facts.occurred_at_us,
                    EventBody::SessionRevoked {
                        session: id,
                        expected: Expected::Revision(record.revision),
                        reason: InputText::Inline(format!("SE Code {:?}", request.reason)),
                    },
                )],
                import_checkpoint: None,
            })
        })
        .await?;
        let receipt = store::write(&router, batch, "session.revoke", &deadline).await?;
        let committed = store::known("session.revoke", &receipt);
        store::read(&router, scope, &deadline, move |read| {
            store::receipt(read, receipt, key, binding.identity)
        })
        .await
        .map_err(|e| committed.response_error(e))
    }
}
