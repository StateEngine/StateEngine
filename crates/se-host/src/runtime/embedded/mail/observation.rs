//! Record actual native outcomes without confusing them with recipient reads.
use super::*;
use se_core::ops::mail as core;
use se_store::{
    EventBody, RecordId, RecordIdentity, Snapshot,
    mail::{OfferEvidence, OfferReport},
};
use sha2::{Digest, Sha256};
impl Generation {
    pub(super) async fn observe_native(
        &self,
        router: &HostedRouter,
        native: &api::HostSessionTarget,
        reserved: &core::Reservation,
        report: OfferReport,
        deadline: &crate::client::lease::Deadline,
    ) -> api::Result<()> {
        let effect = reserved.effect_id;
        let desired = serde_json::to_vec(&report).map_err(|e| {
            support::api_error(&scope::unreadable("native outcome", &e.to_string()))
        })?;
        let prior = store::read(
            router,
            scope(native, self.negotiated.generation).map_err(|e| support::api_error(&e))?,
            deadline,
            move |read| {
                let record = scope::require_present(
                    read.effect(effect).map_err(|e| store_error(&e))?,
                    "native notice outcome",
                    scope::COMMITTED_READ_RECOVERY,
                )?;
                if let EventBody::EffectOffered {
                    evidence: OfferEvidence::Observed(observed),
                    ..
                } = &record.current.body
                    && serde_json::to_vec(&observed.report)
                        .map_err(|e| scope::unreadable("native outcome", &e.to_string()))?
                        == desired
                {
                    return Ok(None);
                }
                Ok(Some(record.current.header.event.clone()))
            },
        )
        .await
        .map_err(|e| support::api_error(&e))?;
        let Some(prior) = prior else {
            return Ok(());
        };
        // Changed outcomes get a new attempt, tied to the previous durable
        // observation. A lost commit reply therefore retries the same identity;
        // repeated reconciliation of unchanged native evidence writes nothing.
        let mut hash = Sha256::new();
        hash.update(b"native.mail-outcome/v1");
        hash.update(effect.as_bytes());
        hash.update(prior.as_str().as_bytes());
        let digest = hash.finalize();
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&digest[..16]);
        // Keep the reservation's UUIDv7 time and derive only its random bits.
        // RecordId admits RFC UUIDv7, so a raw hash is not a legal identity.
        bytes[..6].copy_from_slice(&effect.as_bytes()[..6]);
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let attempt =
            RecordId::from_bytes(bytes).map_err(|e| support::api_error(&store_error(&e)))?;
        let request = core::ObserveOffer {
            target: reserved.target.clone(),
            effect,
            attempt,
            evidence: se_store::mail::OfferObservation {
                version: 1,
                notice_id: super::delivery::notice_record(&reserved.notice_id)
                    .map_err(|e| support::api_error(&e))?,
                target_agent: reserved.target.agent.clone(),
                session: reserved.target.session.clone(),
                epoch: reserved.target.epoch.clone(),
                generation: reserved.target.generation,
                fingerprint: reserved.target.fingerprint,
                observed_at_us: crate::runtime::start::now_unix_micros()
                    .map_err(|e| support::api_error(&e))?,
                digest: *reserved.digest.as_bytes(),
                report,
            },
        };
        step::run(
            router,
            native,
            self.negotiated.generation,
            deadline,
            move |kernel, cx| core::observe_offer(kernel, cx, request),
            core::observation_committed,
        )
        .await
        .map_err(|e| support::api_error(&e))?;
        Ok(())
    }
}
