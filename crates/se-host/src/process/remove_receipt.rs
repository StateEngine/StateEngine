//! Read committed revocation facts for the removal receipt. A stopped process
//! or an absent credential is not itself proof that a revocation committed.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{process_commit, project_remove::RevokedCredential};
use se_store::{Actor, Admission, EventBody, RecordIdentity, Snapshot};
use se_types::{Read, Result, SessionId};
impl LaunchCoordinator {
    pub(super) async fn revoked_credentials(
        &self,
        session: SessionId,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<Vec<RevokedCredential>> {
        self.store
            .read(admission, deadline, move |cx| {
                let key =
                    process_commit::phase_key(&session.as_str().parse()?, "revoke-credentials")?;
                let receipt = match cx
                    .read
                    .operation_receipt(cx.admission.actor.clone(), key)
                    .map_err(|e| se_core::store_error::store_error(&e))?
                {
                    Read::Present { value } => value,
                    Read::Absent { .. } => return Ok(Vec::new()),
                    Read::Unreadable { reason, .. } => {
                        return Err(error("removal revocation receipt", reason));
                    }
                    Read::Unknown { what } => {
                        return Err(error("removal revocation receipt", what));
                    }
                };
                if !matches!(cx.admission.actor, Actor::Human(_)) {
                    return Err(error(
                        "removal credential receipt",
                        "owner admission required",
                    ));
                }
                let mut revoked = Vec::new();
                for event in receipt.events {
                    let fact = se_core::scope::require_present(
                        cx.read
                            .event(event)
                            .map_err(|e| se_core::store_error::store_error(&e))?,
                        "committed revocation fact",
                        se_core::scope::COMMITTED_READ_RECOVERY,
                    )?;
                    if let EventBody::CredentialRevoked { credential, .. } = fact.body {
                        let purpose = if credential
                            == process_commit::session_credential_id(&session, "session")?
                        {
                            "session"
                        } else if credential
                            == process_commit::session_credential_id(&session, "http")?
                        {
                            "http"
                        } else {
                            return Err(error(
                                "removal revocation receipt",
                                "another credential appears in the retained phase",
                            ));
                        };
                        revoked.push(RevokedCredential {
                            credential_id: format_record(credential),
                            kind: purpose.into(),
                            session_id: Some(session.clone()),
                            state: "revoked".into(),
                            at: se_core::ops::receipt::timestamp(fact.recorded_at_us)?,
                        });
                    }
                }
                if revoked.len() != 2 {
                    return Err(error(
                        "removal revocation receipt",
                        "the both-purpose FULL revocation is incomplete",
                    ));
                }
                Ok(revoked)
            })
            .await
    }
}

fn format_record(id: se_store::RecordId) -> String {
    let bytes = id.as_bytes();
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
