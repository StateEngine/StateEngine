//! HTTP-only, finite reads under the same current credential/generation checks
//! as MCP. No transaction or machine credential leaves this blocking job.
use super::*;
use se_store::{
    Snapshot,
    mail::{MailSnapshot, MailThrough},
};
use std::{num::NonZeroU32, time::Duration};

impl AdmissionContext {
    pub(crate) fn mail_page(&self, secret: &se_types::Secret) -> Result<crate::http::mail::Page> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let admitted = (|| {
            self.check_generation(&phase)?;
            self.credential(&phase, secret, crate::MCP_BEARER_PURPOSE)
        })();
        let admission = match admitted {
            Ok(admission) => admission,
            Err(error) => return super::super::executor::close_read(Err(error), phase.close()),
        };
        let Actor::Agent(agent) = &admission.actor else {
            return super::super::executor::close_read(
                Err(SeError::invalid(
                    "mail authority",
                    "an active recipient session",
                )),
                phase.close(),
            );
        };
        let Scope::Project(project) = &admission.scope else {
            return super::super::executor::close_read(
                Err(SeError::invalid(
                    "mail authority",
                    "one bound recipient project",
                )),
                phase.close(),
            );
        };
        let recipient = super::super::mail::MailRecipient {
            project: project.clone(),
            agent: agent.clone(),
        };
        let session = admission
            .session
            .clone()
            .ok_or_else(|| SeError::invalid("mail session", "present"))?;
        let mut read = phase
            .into_snapshot(se_core::admission::read_scope(&admission))
            .map_err(|e| store_error(&e))?;
        let result = (|| {
            let page = read
                .mail_pending(
                    agent.clone(),
                    se_store::ReadBudget {
                        page: se_types::PageRequest {
                            after: None,
                            limit: NonZeroU32::new(32).unwrap_or(NonZeroU32::MIN),
                            max_bytes: NonZeroU32::new(262144).unwrap_or(NonZeroU32::MIN),
                        },
                        deadline: Duration::from_secs(1),
                    },
                )
                .map_err(|e| store_error(&e))?;
            let window = page.window().fields().ok_or_else(|| {
                se_core::scope::unreadable("mail wait", "the query has no measured window")
            })?;
            if page.items().is_empty() && !page.window().complete() {
                return Err(se_core::scope::unreadable(
                    "mail wait",
                    "an empty incomplete page is not an empty inbox",
                ));
            }
            let info = read.info();
            let cursor = read
                .mail_cursor(&MailThrough {
                    store: info.id,
                    incarnation: info.incarnation,
                    sequence: window.to.get(),
                })
                .map_err(|e| store_error(&e))?;
            let output = crate::http::mail::Page {
                session,
                recipient,
                ids: page
                    .items()
                    .iter()
                    .map(|item| item.message.clone())
                    .collect(),
                cursor,
                complete: page.window().complete(),
            };
            let encoded = serde_json::to_vec(&output)
                .map_err(|e| se_core::scope::unreadable("mail wait encoding", &e.to_string()))?;
            if encoded.len() > 8192 {
                return Err(SeError::too_large(
                    "complete mail IDs notification; use paginated msg list",
                    8192,
                    encoded.len(),
                ));
            }
            Ok(output)
        })();
        super::super::executor::close_read(result, read.close())
    }

    pub(crate) fn http_proof(
        &self,
        nonce: [u8; 32],
        origin: String,
        image: se_types::Sha256,
    ) -> Result<serde_json::Value> {
        use hmac::{Hmac, Mac};
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            let owner = se_core::scope::require_present(
                phase.runtime_owner().map_err(|e| store_error(&e))?,
                "HTTP proof owner",
                "Reconnect to the protected native endpoint.",
            )?;
            let at = super::super::start::now_unix_micros()?;
            let payload = serde_json::json!({ "domain": "se.http.server/v1", "nonce": nonce, "origin": origin, "image_sha256": image, "epoch": owner.epoch, "generation": self.generation, "issued_at_us": at });
            let bytes = serde_json::to_vec(&payload)
                .map_err(|e| se_core::scope::unreadable("HTTP proof", &e.to_string()))?;
            let key = self.machine_key()?;
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key.expose())
                .map_err(|_| SeError::invalid("HTTP server proof", "a protected machine key"))?;
            mac.update(b"se.http.server/v1\0");
            mac.update(&bytes);
            Ok(
                serde_json::json!({ "challenge": payload, "mac": se_types::hex_lower(&mac.finalize().into_bytes()) }),
            )
        })();
        super::super::executor::close_read(result, phase.close())
    }
}
